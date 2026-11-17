"""Secure compiler core: type checking, ownership/borrow checking and C generation in one pass.

Design summary (see docs/SPEC.md):
  * value semantics; types that own resources (String, Vec, Task, structs containing them) MOVE,
    all other types copy
  * references are second-class: created only as call arguments, never stored/returned, hence no
    lifetimes are needed and aliasing is checked per call (exclusivity law)
  * integer arithmetic, indexing, casts and shifts are checked; failures panic (exit status 101)
  * no uninitialized variables, no null, no implicit numeric conversions
  * raw pointers / extern calls / unsafe fns require an explicit `unsafe` block
"""
import os
import re
from .lexer import SecError
from .parser import N, parse
from .ty import *

IDENT_RE = re.compile(r"[A-Za-z_]\w*")
LVAL_RE = re.compile(r"(?:_t|_r|v_)\w*")
BUILTIN_TYPES = set(INTS) | {"f64", "bool", "str", "String", "Vec", "Option", "Result", "Task", "Self"}
BUILTIN_FUNCS = {"print", "println", "exit", "panic", "assert", "read_line", "parse_i64", "str_eq", "ct_eq",
                 "zeroize", "spawn", "wrapping_add", "wrapping_sub", "wrapping_mul", "saturating_add",
                 "saturating_sub", "saturating_mul", "checked_add", "checked_sub", "checked_mul",
                 "Some", "Ok", "Err", "None"}
PLACE_KINDS = ("Var", "Field", "Index", "Deref")
ARITH = {"+": "add", "-": "sub", "*": "mul", "/": "div", "%": "rem"}
BITOPS = {"&", "|", "^"}
CMP = {"==", "!=", "<", "<=", ">", ">="}
MAX_ARRAY_BYTES = 1 << 20


class Var:
    __slots__ = ("name", "ty", "mut", "c", "flag", "level")

    def __init__(self, name, ty, mut, c, flag, level):
        self.name, self.ty, self.mut, self.c, self.flag, self.level = name, ty, mut, c, flag, level


class Sig:
    def __init__(self, name, params, ret, cname, node, unsafe=False, extern=False, selfty=None):
        self.name, self.params, self.ret, self.cname = name, params, ret, cname
        self.node, self.unsafe, self.extern, self.selfty = node, unsafe, extern, selfty


class Place:
    __slots__ = ("lv", "ty", "mut", "root", "var", "tmp")

    def __init__(self, lv, ty, mut, root=None, var=None, tmp=None):
        self.lv, self.ty, self.mut, self.root, self.var, self.tmp = lv, ty, mut, root, var, tmp


class Tmp:
    __slots__ = ("ty", "lv", "taken", "scope_depth")

    def __init__(self, ty, lv, scope_depth):
        self.ty, self.lv, self.taken, self.scope_depth = ty, lv, False, scope_depth


class Loop:
    def __init__(self, depth, level):
        self.depth, self.level, self.breaks, self.conts = depth, level, [], []


def c_int(v, name):
    if v >= 0:
        return f"(({name}){v}ULL)"
    return f"(({name})(-{-v - 1}LL-1))"


def c_str(b):
    return "".join(chr(x) if (32 <= x < 127 and chr(x) not in '"\\?') else "\\%03o" % x for x in b)


class Compiler:
    def __init__(self, src, filename, forbid_unsafe=False):
        self.src, self.file, self.forbid_unsafe = src, os.path.basename(filename), forbid_unsafe
        self.structs, self.enums, self.fns, self.methods, self.consts = {}, {}, {}, {}, {}
        self.enum_cnames = {}
        self.decls, self.protos, self.thunks, self.bodies = [], [], [], []
        self.vec_impls = []
        self.task_impls = []
        self.pending_types = {}
        self.pending_defs = []
        self.resolving_struct_fields = False
        self.defined, self.inprog, self.spawned = {"Slice_u8", "Vec_u8"}, set(), set()
        self.audit = {"unsafe_blocks": [], "unsafe_fns": [], "extern_fns": []}
        self.uid = 0
        self.out, self.scopes, self.moved, self.loops, self.stmt_temps = [], [], set(), [], []
        self.fn_ret, self.cur_self, self.unsafe_depth, self.pre = UNIT, None, 0, {}

    # ------------------------------------------------------------------ utils
    def err(self, msg, n):
        raise SecError(msg, getattr(n, "line", 0), getattr(n, "col", 0))

    def emit(self, s):
        self.out.append(s)

    def newid(self):
        self.uid += 1
        return self.uid

    def tmp(self, ct, c):
        nm = f"_t{self.newid()}"
        self.emit(f"{ct} {nm} = {c};")
        return nm

    def dummy(self, t):
        return self.tmp(self.ctype(t), "{0}")

    def loc(self, n):
        # File names are user-controlled filesystem data, not trusted C source.
        filename = c_str(os.fsencode(self.file))
        return f'"{filename}:{n.line}:{n.col}"'

    # ------------------------------------------------------------- type layer
    def storable(self, t, n):
        if has_ref(t):
            self.err("references are second-class in Secure: they may be passed as call arguments but not stored "
                     "in variables, fields or collections, nor returned", n)
        return t

    def const_type_hint(self, n):
        """Best-effort type hint for a constant integer expression (shift counts have their own type)."""
        if n.k == "Int":
            return n.suf
        if n.k == "Unary" and n.op == "-":
            return self.const_type_hint(n.e)
        if n.k == "Var" and self.lookup(n.name) is None and n.name in self.consts:
            ty = self.consts[n.name][0]
            return ty.name if ty.k == "int" else None
        if n.k == "Binary":
            return self.const_type_hint(n.l) or self.const_type_hint(n.r)
        return None

    def cval(self, n, tname):
        """Constant-evaluate an integer expression of type `tname`; None if not constant."""
        k = n.k
        if k == "Int":
            return n.val if (not n.suf or n.suf == tname) else None
        if k == "Unary" and n.op == "-":
            v = self.cval(n.e, tname)
            return None if v is None else self.chk(-v, tname, n)
        if k == "Binary" and (n.op in ARITH or n.op in BITOPS or n.op in ("<<", ">>")):
            op = n.op
            if op in ("<<", ">>"):
                # Shift counts are typed independently from the shifted value.
                rhs_type = self.const_type_hint(n.r) or "u32"
                a, b = self.cval(n.l, tname), self.cval(n.r, rhs_type)
            else:
                a, b = self.cval(n.l, tname), self.cval(n.r, tname)
            if a is None or b is None:
                return None
            if op in ("/", "%"):
                if b == 0:
                    self.err("division by zero in constant expression", n)
                lo, _ = int_range(tname)
                if is_signed(tname) and a == lo and b == -1:
                    self.err(f"arithmetic overflow in constant expression: {op} does not fit in `{tname}`", n)
                q = abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1)
                return self.chk(q if op == "/" else a - q * b, tname, n)
            if op in ("<<", ">>"):
                if not 0 <= b < int_bits(tname):
                    self.err("shift amount out of range in constant expression", n)
                if op == ">>":
                    return a >> b
                return self.chk(a << b, tname, n)
            r = {"+": a + b, "-": a - b, "*": a * b, "&": a & b, "|": a | b, "^": a ^ b}[op]
            return self.chk(r, tname, n)
        if k == "Var" and self.lookup(n.name) is None and n.name in self.consts:
            ty, val = self.consts[n.name]
            return val if ty.k == "int" and ty.name == tname else None
        return None

    def chk(self, v, tname, n):
        lo, hi = int_range(tname)
        if not lo <= v <= hi:
            self.err(f"arithmetic overflow in constant expression: {v} does not fit in `{tname}`", n)
        return v

    def rty(self, n, selfty=None):
        k = n.k
        selfty = selfty or self.cur_self
        if k == "TName":
            nm = n.name
            a = [self.rty(x, selfty) for x in n.args]

            def need(c):
                if len(a) != c:
                    self.err(f"type `{nm}` expects {c} type argument(s), found {len(a)}", n)
            if nm in INTS: need(0); return I(nm)
            if nm == "f64": need(0); return F64
            if nm == "bool": need(0); return BOOL
            if nm == "()": return UNIT
            if nm == "str": need(0); return STR
            if nm == "String": need(0); return STRING
            if nm == "Self":
                if selfty is None:
                    self.err("`Self` is only valid inside `impl`", n)
                return selfty
            if nm == "Vec": need(1); return vec(self.storable(a[0], n))
            if nm == "Option": need(1); return option(self.storable(a[0], n))
            if nm == "Result": need(2); return result(self.storable(a[0], n), self.storable(a[1], n))
            if nm == "Task": need(1); return task(self.storable(a[0], n))
            if nm in self.structs: need(0); return struct(nm)
            if nm in self.enums: need(0); return enum(nm)
            self.err(f"unknown type `{nm}`", n)
        if k == "TRef":
            if n.inner.k == "TSlice":
                return ref(slice_(self.storable(self.rty(n.inner.elem, selfty), n.inner)), n.mut)
            t = self.rty(n.inner, selfty)
            if t.k == "ref":
                self.err("references to references are not supported", n)
            return ref(t, n.mut)
        if k == "TSlice":
            self.err("unsized type `[T]` must be used behind a reference: `&[T]`", n)
        if k == "TArr":
            el = self.storable(self.rty(n.elem, selfty), n)
            size = self.cval(n.size, "usize")
            if size is None:
                self.err("array length must be a constant integer expression", n.size)
            if size < 1:
                self.err("array length must be at least 1", n.size)
            if not self.resolving_struct_fields and size * self.tsize(el) > MAX_ARRAY_BYTES:
                self.err("array too large for the stack (limit 1 MiB); use `Vec<T>` for large buffers", n)
            return array(el, size)
        if k == "TPtr":
            return ptr(self.rty(n.inner, selfty), n.mut)
        self.err("invalid type", n)

    def validate_array_sizes(self, t, n):
        if t.k == "array" and t.n * self.tsize(t.args[0]) > MAX_ARRAY_BYTES:
            self.err("array too large for the stack (limit 1 MiB); use `Vec<T>` for large buffers", n)
        for arg in t.args:
            self.validate_array_sizes(arg, n)

    def tsize(self, t):
        """Conservative upper bound for a value's stack footprint on the 64-bit C ABI.

        This is used to enforce MAX_ARRAY_BYTES, so underestimating aggregate padding
        or payloads is unsafe. The small fixed overheads deliberately overestimate
        C struct alignment/padding rather than attempting to predict exact layout.
        """
        k = t.k
        if k == "int": return int_bits(t.name) // 8
        if k == "float": return 8
        if k in ("bool", "unit"): return 1
        if k == "enum": return 4
        if k == "array": return t.n * self.tsize(t.args[0])
        if k == "struct":
            fields = self.structs[t.name]["fields"]
            # At most seven bytes of padding can precede each field or follow the
            # final field when all supported scalar alignments are <= 8 bytes.
            return max(1, sum(self.tsize(ft) + 8 for _, ft in fields))
        if k == "option":
            # Tag, alignment before the payload, and trailing struct padding.
            return self.tsize(t.args[0]) + 16
        if k == "result":
            # Tag plus worst-case alignment before each payload and at struct end.
            return self.tsize(t.args[0]) + self.tsize(t.args[1]) + 24
        # Slice/str, String/Vec, Task, pointers and references are conservatively
        # charged 32 bytes (Task can include a platform pthread_t).
        return 32

    def needs_drop(self, t):
        k = t.k
        if k in ("string", "vec", "task"): return True
        if k == "struct": return any(self.needs_drop(ft) for _, ft in self.structs[t.name]["fields"])
        if k in ("option", "result", "array"): return any(self.needs_drop(a) for a in t.args)
        return False

    def is_copy(self, t):
        return not self.needs_drop(t) and not (t.k == "ref" and t.name == "mut")

    def mangle(self, t):
        k = t.k
        if k == "int": return t.name
        if k == "float": return "f64"
        if k == "bool": return "bool"
        if k in ("unit", "never"): return "unit"
        if k == "str": return "str"
        if k == "string": return "String"
        if k in ("struct", "enum"): return "T_" + t.name
        if k == "array": return f"Arr_{self.mangle(t.args[0])}_{t.n}"
        if k == "slice": return "Slice_" + self.mangle(t.args[0])
        if k == "vec": return "Vec_" + self.mangle(t.args[0])
        if k == "option": return "Opt_" + self.mangle(t.args[0])
        if k == "result":
            ok_name, err_name = (self.mangle(arg) for arg in t.args)
            return f"Res_{len(ok_name)}_{ok_name}_{len(err_name)}_{err_name}"
        if k == "task": return "Task_" + self.mangle(t.args[0])
        if k == "ptr": return "Ptr_" + self.mangle(t.args[0])
        return "Ref_" + self.mangle(t.args[0])

    def ctype(self, t):
        k = t.k
        if k == "int": return t.name
        if k == "float": return "f64"
        if k == "bool": return "bool"
        if k in ("unit", "never"): return "sec_unit"
        if k == "str": return "Slice_u8"
        if k == "string": return "Vec_u8"
        if k == "enum": return "T_" + t.name
        if k == "struct":
            m = self.mangle(t)
            if m not in self.inprog:
                self.define(t)
            return m
        if k == "ref":
            i = t.args[0]
            return self.ctype(i) if i.k in ("slice", "str") else self.ctype(i) + "*"
        if k == "ptr":
            i = t.args[0]
            if i.k == "struct" and self.mangle(i) in self.inprog:
                return f"struct T_{i.name}*"
            return ("void" if i.k in ("unit", "never") else self.ctype(i)) + "*"
        self.define(t)
        return self.mangle(t)

    def drop_fn(self, t):
        if t.k == "string": return "Vec_u8_drop"
        if t.k in ("vec", "task"): return self.mangle(t) + "_drop"
        return "drop_" + self.mangle(t)

    def drop_stmt(self, t, lv):
        self.ctype(t)
        return f"{self.drop_fn(t)}(&{lv});"

    def dropname(self, t):
        return self.drop_fn(t) if self.needs_drop(t) else "sec_nodrop"

    def has_incomplete_inline(self, t):
        """Whether an inline aggregate contains a currently incomplete struct."""
        if t.k == "struct":
            return self.mangle(t) in self.inprog
        if t.k in ("array", "option", "result"):
            return any(self.has_incomplete_inline(arg) for arg in t.args)
        # Vec, Task, slices and pointers store their payload indirectly.
        return False

    def emit_pending_types(self):
        """Complete wrappers that were forward-declared around recursive indirection."""
        emitted, active = set(), set()

        def prepare(t):
            m = self.mangle(t)
            if m in self.pending_types:
                emit_one(m)
                return
            for arg in t.args:
                prepare(arg)
            self.ctype(t)

        def emit_one(m):
            if m in emitted:
                return
            if m in active:
                raise SecError(f"recursive inline type {m} has infinite size", 0, 0)
            active.add(m)
            t = self.pending_types[m]
            for arg in t.args:
                prepare(arg)
            if t.k == "array":
                el = t.args[0]
                ce = self.ctype(el)
                self.pending_defs.append(f"struct {m} {{ {ce} a[{t.n}]; }};")
                if self.needs_drop(t):
                    self.pending_defs.append(
                        f"static inline void drop_{m}({m} *p) {{ for (usize i = 0; i < {t.n}; i++) "
                        f"{self.drop_stmt(el, 'p->a[i]')} }}"
                    )
            elif t.k == "option":
                el = t.args[0]
                ce = self.ctype(el)
                self.pending_defs.append(f"struct {m} {{ bool some; {ce} v; }};")
                if self.needs_drop(el):
                    self.pending_defs.append(
                        f"static inline void drop_{m}({m} *p) {{ if (p->some) {self.drop_stmt(el, 'p->v')} }}"
                    )
            elif t.k == "result":
                ok_ty, err_ty = t.args
                ct, et = self.ctype(ok_ty), self.ctype(err_ty)
                self.pending_defs.append(f"struct {m} {{ bool ok; {ct} v; {et} e; }};")
                if self.needs_drop(t):
                    drop_ok = self.drop_stmt(ok_ty, "p->v") if self.needs_drop(ok_ty) else ""
                    drop_err = self.drop_stmt(err_ty, "p->e") if self.needs_drop(err_ty) else ""
                    self.pending_defs.append(
                        f"static inline void drop_{m}({m} *p) {{ if (p->ok) {{ {drop_ok} }} else {{ {drop_err} }} }}"
                    )
            else:
                raise SecError(f"internal error: cannot complete pending type {tstr(t)}", 0, 0)
            active.remove(m)
            emitted.add(m)

        while True:
            todo = [m for m in self.pending_types if m not in emitted]
            if not todo:
                break
            emit_one(todo[0])

    def define(self, t):
        m = self.mangle(t)
        if m in self.defined:
            return
        k = t.k
        if k in ("array", "option", "result") and self.has_incomplete_inline(t):
            # These values embed their payload, so their C struct body must wait
            # until the recursive struct payload is complete. A forward typedef
            # is enough for a Vec/Task descriptor that stores a pointer to them.
            self.decls.append(f"typedef struct {m} {m};")
            self.defined.add(m)
            self.pending_types[m] = t
            return
        if k == "struct":
            if m in self.inprog:
                raise SecError(f"recursive type `{t.name}` has infinite size", 0, 0)
            if self.needs_drop(t):
                self.decls.append(f"static inline void drop_{m}({m} *p);")
            self.inprog.add(m)
            fields = self.structs[t.name]["fields"]
            cts = [(f, self.ctype(ft)) for f, ft in fields]
            self.inprog.discard(m)
            body = "".join(f" {ct} f_{f};" for f, ct in cts) or " char _;"
            # Struct aliases are forward-declared in compile().
            self.decls.append(f"struct {m} {{{body} }};")
            self.defined.add(m)
            if self.needs_drop(t):
                inner = " ".join(self.drop_stmt(ft, f"p->f_{f}") for f, ft in fields if self.needs_drop(ft))
                self.decls.append(f"static inline void drop_{m}({m} *p) {{ {inner} }}")
            return
        el = t.args[0]
        ce = self.ctype(el) if k != "result" else None
        # Resolving an element type can recursively finish this Vec while its
        # owner struct is being defined (e.g. struct Node { children: Vec<Node> }).
        if m in self.defined:
            return
        if k == "array":
            self.decls.append(f"typedef struct {{ {ce} a[{t.n}]; }} {m};")
            self.defined.add(m)
            if self.needs_drop(t):
                self.decls.append(f"static inline void drop_{m}({m} *p) {{ for (usize i = 0; i < {t.n}; i++) "
                                  f"{self.drop_stmt(el, 'p->a[i]')} }}")
        elif k == "slice":
            self.decls.append(f"SEC_DEF_SLICE({m}, {ce})")
            self.defined.add(m)
        elif k == "vec":
            dn = self.dropname(el)
            # The Vec descriptor only stores a T pointer, so it can be declared
            # before T is complete. Its value-taking helpers are emitted later.
            self.decls.append(f"typedef struct {{ {ce} *p; usize len; usize cap; }} {m};")
            self.decls.append(f"static inline void {m}_drop({m} *v);")
            self.defined.add(m)
            self.vec_impls.append(f"SEC_IMPL_VEC({m}, {ce}, {dn})")
        elif k == "option":
            self.decls.append(f"SEC_DEF_OPT({m}, {ce})")
            self.defined.add(m)
            if self.needs_drop(el):
                self.decls.append(f"static inline void drop_{m}({m} *p) {{ if (p->some) {self.drop_stmt(el, 'p->v')} }}")
        elif k == "result":
            ct, et = self.ctype(t.args[0]), self.ctype(t.args[1])
            # A nested payload may have recursively declared this Result as a
            # deferred wrapper while the payload struct was being completed.
            if m in self.defined:
                return
            self.decls.append(f"SEC_DEF_RES({m}, {ct}, {et})")
            self.defined.add(m)
            if self.needs_drop(t):
                a = self.drop_stmt(t.args[0], "p->v") if self.needs_drop(t.args[0]) else ""
                b = self.drop_stmt(t.args[1], "p->e") if self.needs_drop(t.args[1]) else ""
                self.decls.append(f"static inline void drop_{m}({m} *p) {{ if (p->ok) {{ {a} }} else {{ {b} }} }}")
        elif k == "task":
            # Task stores only a result pointer, so its descriptor can be
            # declared while the result type is incomplete. Its join helper
            # (which returns R by value) is emitted after all structs complete.
            dn = self.dropname(el)
            self.decls.append(f"typedef struct {{ pthread_t th; {ce} *res; bool joined; }} {m};")
            self.decls.append(f"static inline void {m}_drop({m} *t);")
            self.defined.add(m)
            self.task_impls.append(f"SEC_IMPL_TASK({m}, {ce}, {dn})")
        else:
            raise SecError(f"internal error: cannot define type {tstr(t)}", 0, 0)

    # ------------------------------------------------------------ declarations
    def compile(self):
        items = parse(self.src)
        seen = set()
        for it in items:
            if it.k in ("Struct", "Enum"):
                if it.name in seen or it.name in BUILTIN_TYPES:
                    self.err(f"type `{it.name}` is already defined or reserved", it)
                seen.add(it.name)
                if it.k == "Struct":
                    self.structs[it.name] = {"fields": None, "node": it}
                else:
                    if not it.variants or len(set(it.variants)) != len(it.variants):
                        self.err("enums need at least one variant and no duplicates", it)
                    self.enums[it.name] = it.variants
                    self.decls.append(f"typedef i32 T_{it.name};")
                    enumerators = []
                    for i, variant in enumerate(it.variants):
                        # C enumerators share one global ordinary-identifier namespace.
                        cname = f"SEC_ENUM_{len(self.enum_cnames)}"
                        self.enum_cnames[(it.name, variant)] = cname
                        enumerators.append(f"{cname} = {i}")
                    self.decls.append("enum { " + ", ".join(enumerators) + " };")
        for name in self.structs:
            self.decls.append(f"typedef struct T_{name} T_{name};")
        self.resolving_struct_fields = True
        for name, info in self.structs.items():
            fields, fseen = [], set()
            for fname, tn, fp in info["node"].fields:
                if fname in fseen:
                    raise SecError(f"duplicate field `{fname}`", fp[0], fp[1])
                fseen.add(fname)
                fields.append((fname, self.storable(self.rty(tn, struct(name)), tn)))
            info["fields"] = fields
        self.resolving_struct_fields = False
        self.check_cycles()
        # Array limits are checked only after every user struct has a resolved
        # layout. That lets a legal Vec-indirected recursive array element refer
        # to an in-progress struct without leaking a TypeError from tsize().
        for info in self.structs.values():
            for _, field_ty in info["fields"]:
                self.validate_array_sizes(field_ty, info["node"])
        for it in items:
            if it.k == "Const":
                self.add_const(it)
        for it in items:
            if it.k == "Fn":
                self.add_fn(it)
            elif it.k == "Impl":
                tn = it.name
                if tn not in self.structs and tn not in self.enums:
                    self.err(f"cannot implement methods for unknown type `{tn}`", it)
                st = struct(tn) if tn in self.structs else enum(tn)
                for f in it.fns:
                    self.add_fn(f, st)
        if "main" not in self.fns:
            raise SecError("program has no `main` function", 1, 1)
        m = self.fns["main"]
        if m.params or m.ret not in (UNIT, I32):
            self.err("`main` must be `fn main()` or `fn main() -> i32`", m.node)
        for sig in list(self.fns.values()) + list(self.methods.values()):
            if sig.node.body is not None:
                self.compile_fn(sig)
        return self.assemble()

    def check_cycles(self):
        def visit_type(t, stack):
            if t.k == "struct":
                visit(t.name, stack)
            elif t.k in ("array", "option"):
                visit_type(t.args[0], stack)
            elif t.k == "result":
                # Both Result payloads are stored inline and therefore contribute
                # to the containing value's size.
                visit_type(t.args[0], stack)
                visit_type(t.args[1], stack)
            # Vec, Task and raw pointers are indirections, not inline recursion.

        def visit(name, stack):
            if name in stack:
                self.err(f"recursive type `{name}` has infinite size (use `Vec<T>` for indirection)",
                         self.structs[name]["node"])
            next_stack = stack | {name}
            for _, ft in self.structs[name]["fields"]:
                visit_type(ft, next_stack)

        for nm in self.structs:
            visit(nm, frozenset())

    def add_const(self, it):
        if it.name in self.consts or it.name in self.fns:
            self.err(f"duplicate definition of `{it.name}`", it)
        ty = self.storable(self.rty(it.ty), it)
        if ty.k == "int":
            v = self.cval(it.e, ty.name)
            if v is None:
                self.err("constant initializer must be a constant integer expression", it.e)
            self.chk(v, ty.name, it.e)
        elif ty.k == "float" and it.e.k == "Float":
            v = it.e.val
        elif ty.k == "float" and it.e.k == "Unary" and it.e.op == "-" and it.e.e.k == "Float":
            v = -it.e.e.val
        elif ty.k == "bool" and it.e.k == "Bool":
            v = it.e.val
        elif ty.k == "str" and it.e.k == "Str":
            v = it.e.val
        else:
            self.err(f"unsupported constant of type `{tstr(ty)}` (ints, f64, bool and str literals only)", it)
        self.consts[it.name] = (ty, v)

    def add_fn(self, n, selfty=None):
        if selfty is None and (n.name in self.fns or n.name in self.consts):
            self.err(f"duplicate definition of function `{n.name}`", n)
        if selfty is None and n.name in BUILTIN_FUNCS:
            self.err(f"`{n.name}` is a built-in and cannot be redefined", n)
        params, pseen = [], set()
        for i, p in enumerate(n.params):
            if p.name in pseen:
                self.err(f"duplicate parameter `{p.name}`", p)
            pseen.add(p.name)
            if p.name == "self" and i != 0:
                self.err("`self` must be the first parameter", p)
            t = self.rty(p.ty, selfty)
            if t.k == "ref" and has_ref(t.args[0]):
                self.err("nested references are not supported", p)
            params.append((p.name, p.mut, t))
        ret = self.rty(n.ret, selfty) if n.ret else UNIT
        if has_ref(ret):
            self.err("functions cannot return references (references are second-class)", n)
        if selfty is not None:
            key = (selfty.name, n.name)
            if key in self.methods:
                self.err(f"duplicate method `{n.name}`", n)
            # Length-prefix both components; plain underscore joining is ambiguous.
            cname = f"m_{len(selfty.name)}_{selfty.name}_{len(n.name)}_{n.name}"
        else:
            cname = f"f_{n.name}"
        sig = Sig(n.name, params, ret, cname, n, n.unsafe, n.extern, selfty)
        if n.extern:
            for _, _, t in params + [("", False, ret)]:
                if t.k not in ("int", "float", "bool", "unit", "ptr"):
                    self.err("extern functions may only use integer, f64, bool and pointer types", n)
            sig.cname = f"sec_ext_{n.name}"
            sig.unsafe = True
            self.audit["extern_fns"].append({"name": n.name, "line": n.line})
            if self.forbid_unsafe:
                self.err("`extern` declarations are forbidden by --forbid-unsafe", n)
            self.protos.append(f"extern {self.ctype_ret(ret)} {sig.cname}({self.cparams(params)}) __asm__(\"{n.name}\");")
        elif n.unsafe:
            if self.forbid_unsafe:
                self.err("`unsafe fn` is forbidden by --forbid-unsafe", n)
            self.audit["unsafe_fns"].append({"name": n.name, "line": n.line})
        if selfty is not None:
            self.methods[(selfty.name, n.name)] = sig
        else:
            self.fns[n.name] = sig

    def ctype_ret(self, t):
        return "void" if t.k == "unit" else self.ctype(t)

    def cparams(self, params, names=None):
        if not params:
            return "void"
        return ", ".join(self.ctype(t) + (f" {names[i]}" if names else "") for i, (_, _, t) in enumerate(params))

    # ---------------------------------------------------------------- scopes
    def lookup(self, name):
        for sc in reversed(self.scopes):
            for v in reversed(sc):
                if v.name == name:
                    return v
        return None

    def push(self):
        self.scopes.append([])

    def pop(self):
        self.scopes.pop()

    def declare(self, name, ty, mut):
        i = self.newid()
        v = Var(name, ty, mut, f"v_{name}_{i}", None, len(self.loops))
        if self.needs_drop(ty):
            v.flag = f"l_{name}_{i}"
        self.scopes[-1].append(v)
        return v

    def decl_var(self, v, init):
        self.emit(f"{self.ctype(v.ty)} {v.c} = {init};")
        if v.flag:
            self.emit(f"bool {v.flag} = true;")

    def drop_scope(self, sc):
        for v in reversed(sc):
            if v.flag:
                self.emit(f"if ({v.flag}) {self.drop_stmt(v.ty, v.c)}")

    def drops_down_to(self, depth):
        for sc in reversed(self.scopes[depth:]):
            self.drop_scope(sc)

    def drop_temps(self, mark):
        for t in reversed(self.stmt_temps[mark:]):
            if not t.taken:
                self.emit(self.drop_stmt(t.ty, t.lv))
        del self.stmt_temps[mark:]

    def drop_temps_on_exit(self, deeper_than=None, keep=()):
        """Emit cleanup for live expression temporaries on an abrupt control-flow path.

        Unlike drop_temps(), this does not mutate the compile-time list: sibling
        branches and the normal path still need their own cleanup code.
        When leaving a loop, only temporaries created inside that loop are dropped.
        Values transferred by this exit path can be kept without affecting sibling paths.
        """
        keep = set(keep)
        for t in reversed(self.stmt_temps):
            if t.taken or t.lv in keep:
                continue
            if deeper_than is not None and t.scope_depth <= deeper_than:
                continue
            self.emit(self.drop_stmt(t.ty, t.lv))

    def take_temp(self, lv):
        """Transfer ownership out of a tracked expression temporary."""
        if not isinstance(lv, str) or not IDENT_RE.fullmatch(lv):
            return
        for t in reversed(self.stmt_temps):
            if t.lv == lv:
                t.taken = True
                return

    def snap(self):
        return None if self.moved is None else set(self.moved)

    @staticmethod
    def merge(*states):
        live = [s for s in states if s is not None]
        if not live:
            return None
        r = set()
        for s in live:
            r |= s
        return r

    # --------------------------------------------------------------- functions
    def compile_fn(self, sig):
        n = sig.node
        self.out, self.scopes, self.moved, self.loops, self.stmt_temps = [], [[]], set(), [], []
        self.fn_ret, self.cur_self, self.unsafe_depth = sig.ret, sig.selfty, (1 if sig.unsafe else 0)
        names = []
        for pn, pm, pt in sig.params:
            v = self.declare(pn, pt, pm)
            names.append(v.c)
            if v.flag:
                self.emit(f"bool {v.flag} = true;")
        ret = sig.ret
        dest = "_ret" if ret.k not in ("unit", "never") else None
        lines, bt = self.block(n.body, ret, dest)
        if bt.k != "never" and bt != ret:
            where = n.body.tail or n.body
            self.err(f"mismatched types: function `{sig.name}` must return `{tstr(ret)}` on every path, "
                     f"but its body has type `{tstr(bt)}`", where)
        self.emit("{")
        self.out.extend(lines)
        self.emit("}")
        if self.moved is not None:
            self.drop_scope(self.scopes[0])
        if dest:
            self.emit("return _ret;")
        head = f"static {self.ctype_ret(ret)} {sig.cname}({self.cparams(sig.params, names)}) {{"
        body = [head] + ([f"{self.ctype(ret)} _ret;"] if dest else []) + self.out + ["}"]
        self.protos.append(f"static {self.ctype_ret(ret)} {sig.cname}({self.cparams(sig.params)});")
        self.bodies.append("\n".join(body))

    def assemble(self):
        self.emit_pending_types()
        main = self.fns["main"]
        call = "    i32 r = f_main();" if main.ret == I32 else "    f_main();\n    i32 r = 0;"
        return "\n".join(['#include "secure_rt.h"'] + self.decls + self.pending_defs + self.vec_impls + self.task_impls + self.protos + self.thunks + self.bodies +
                         ["int main(void) {", call, "    fflush(stdout);", "    return (int)r;", "}"]) + "\n"

    # --------------------------------------------------------------- statements
    def block(self, n, expected, dest, binds=()):
        saved, self.out = self.out, []
        self.push()
        for name, ty, init, mut in binds:
            v = self.declare(name, ty, mut)
            self.decl_var(v, init)
        for s in n.stmts:
            self.stmt(s)
        mark = len(self.stmt_temps)
        if n.tail is not None:
            tc, tt = self.expr(n.tail, expected)
        else:
            tc, tt = "SEC_UNIT", (NEVER if self.moved is None else UNIT)
        if dest and tt.k not in ("unit", "never"):
            self.emit(f"{dest} = {tc};")
        self.drop_temps(mark)
        if self.moved is not None:
            self.drop_scope(self.scopes[-1])
        self.pop()
        lines, self.out = self.out, saved
        return lines, tt

    def stmt(self, s):
        mark = len(self.stmt_temps)
        if s.k == "Let":
            self.s_let(s)
        else:
            c, t = self.expr(s.e, None)
            if t.k == "result":
                self.err("unused `Result`: handle it with `match`, `?` or `unwrap()` (errors must not be ignored)", s.e)
            if t.k not in ("unit", "never") and self.needs_drop(t):
                self.emit(self.drop_stmt(t, c))
        self.drop_temps(mark)

    def s_let(self, s):
        ann = self.storable(self.rty(s.ty), s.ty) if s.ty else None
        c, t = self.expr(s.init, ann)
        if t.k == "never":
            return
        if ann is not None and t != ann:
            self.err(f"mismatched types: expected `{tstr(ann)}`, found `{tstr(t)}`", s.init)
        if t.k == "unit":
            self.err("cannot bind a unit `()` value to a variable", s)
        v = self.declare(s.name, ann or t, s.mut)
        self.decl_var(v, c)

    def value_block(self, n, expected):
        dest = f"_r{self.newid()}"
        lines, t = self.block(n, expected, dest)
        valued = t.k not in ("unit", "never")
        if valued:
            self.emit(f"{self.ctype(t)} {dest};")
        self.emit("{")
        self.out.extend(lines)
        self.emit("}")
        return (dest if valued else ("SEC_UNIT" if t.k == "unit" else None)), t

    # ------------------------------------------------------------------ places
    def peek_ty(self, n):
        """Type of a place expression without emitting code (None if unknown)."""
        k = n.k
        if k == "Var":
            v = self.lookup(n.name)
            if v is None:
                return None
            return v.ty.args[0] if v.ty.k == "ref" else v.ty
        if k == "Field":
            t = self.peek_ty(n.e)
            if t is not None and t.k == "struct":
                return dict(self.structs[t.name]["fields"]).get(n.name)
        if k == "Index":
            t = self.peek_ty(n.e)
            if t is not None:
                if t.k in ("array", "slice", "vec"):
                    return t.args[0]
                if t.k in ("string", "str"):
                    return U8
        if k == "Deref":
            t = None
            if n.e.k == "Var":
                v = self.lookup(n.e.name)
                if v is not None and v.ty.k in ("ref", "ptr"):
                    return v.ty.args[0]
        return None

    def recv_ty(self, n):
        pre = self.pre.get(id(n))
        if isinstance(pre, Place):
            return pre.ty
        return self.peek_ty(n)

    def prep(self, n):
        """Evaluate, left to right, every index operand and rvalue base inside a place expression,
        before any pointer into a container is formed (prevents dangling pointers)."""
        if id(n) in self.pre:
            return
        k = n.k
        if k == "Index":
            self.prep(n.e)
            if n.idx.k != "Range":
                ic, it = self.expr(n.idx, USIZE)
                if it.k != "never" and it != USIZE:
                    self.err(f"index must be `usize`, found `{tstr(it)}` (use an explicit `as usize`)", n.idx)
                self.pre[id(n)] = (ic, it)
        elif k in ("Field", "Deref"):
            self.prep(n.e)
        elif k == "Var":
            if self.lookup(n.name) is None:
                self.pre[id(n)] = self.rvalue_place(n)
        else:
            self.pre[id(n)] = self.rvalue_place(n)

    def place(self, n):
        self.prep(n)
        return self.place_(n)

    def rvalue_place(self, n):
        c, t = self.expr(n, None, True)
        if t.k == "ref":
            inner = t.args[0]
            return Place(c if inner.k in ("slice", "str") else f"(*{c})", inner, t.name == "mut")
        if t.k == "never":
            self.err("expression never produces a value here", n)
        if t.k == "unit":
            return Place("SEC_UNIT", t, False)
        if not LVAL_RE.fullmatch(c):
            c = self.tmp(self.ctype(t), c)
        tm = None
        if self.needs_drop(t):
            tm = Tmp(t, c, len(self.scopes))
            self.stmt_temps.append(tm)
        return Place(c, t, True, None, None, tm)

    def pointee(self, v, n):
        inner = v.ty.args[0]
        lv = v.c if inner.k in ("slice", "str") else f"(*{v.c})"
        return Place(lv, inner, v.ty.name == "mut", v.name)

    def place_(self, n):
        pre = self.pre.get(id(n))
        if isinstance(pre, Place):
            return pre
        k = n.k
        if k == "Var":
            v = self.lookup(n.name)
            if self.moved is not None and v in self.moved:
                self.err(f"use of moved value `{n.name}`", n)
            if v.ty.k == "ref":
                return self.pointee(v, n)
            return Place(v.c, v.ty, v.mut, v.name, v)
        if k == "Field":
            b = self.place_(n.e)
            if b.ty.k != "struct":
                self.err(f"type `{tstr(b.ty)}` has no field `{n.name}`", n)
            fields = dict(self.structs[b.ty.name]["fields"])
            if n.name not in fields:
                self.err(f"struct `{b.ty.name}` has no field `{n.name}`", n)
            return Place(f"{b.lv}.f_{n.name}", fields[n.name], b.mut, b.root)
        if k == "Index":
            if n.idx.k == "Range":
                self.err("a range index produces a reference: write `&x[a..b]` and pass it as a call argument", n)
            b = self.place_(n.e)
            t, L = b.ty, self.loc(n)
            if t.k not in ("array", "slice", "vec", "string", "str"):
                self.err(f"type `{tstr(t)}` cannot be indexed", n)
            ic, it = self.pre[id(n)]
            if t.k == "array":
                ln, data, el = str(t.n), f"{b.lv}.a", t.args[0]
                cv = self.cval(n.idx, "usize")
                if cv is not None and cv >= t.n:
                    self.err(f"index out of bounds: the length is {t.n} but the index is {cv}", n.idx)
            elif t.k in ("slice", "str"):
                ln, data, el = f"{b.lv}.n", f"{b.lv}.p", (t.args[0] if t.k == "slice" else U8)
            else:
                ln, data, el = f"{b.lv}.len", f"{b.lv}.p", (t.args[0] if t.k == "vec" else U8)
            p = self.tmp(self.ctype(el) + "*", f"&{data}[SEC_IDX({ic}, {ln}, {L})]")
            return Place(f"(*{p})", el, b.mut and t.k not in ("str", "string"), b.root)
        if k == "Deref":
            e = n.e
            if e.k == "Var" and self.lookup(e.name) is not None:
                v = self.lookup(e.name)
                if v.ty.k == "ref":
                    if v.ty.args[0].k in ("slice", "str"):
                        self.err("a slice cannot be dereferenced; index it instead", n)
                    return self.pointee(v, n)
                if v.ty.k == "ptr":
                    self.need_unsafe("dereference of a raw pointer", n)
                    return Place(f"(*{v.c})", v.ty.args[0], v.ty.name == "mut")
                self.err(f"type `{tstr(v.ty)}` cannot be dereferenced", n)
            c, t = self.expr(e, None, True)
            if t.k == "ptr":
                self.need_unsafe("dereference of a raw pointer", n)
                return Place(f"(*{c})", t.args[0], t.name == "mut")
            self.err(f"type `{tstr(t)}` cannot be dereferenced", n)
        self.err("expected a place expression", n)

    def need_unsafe(self, what, n):
        if self.unsafe_depth == 0:
            self.err(f"{what} requires an `unsafe` block", n)

    def contains_raw_pointer(self, t, seen=None):
        """Inspect aggregate fields as well as generic type arguments."""
        if t.k == "ptr":
            return True
        seen = set() if seen is None else seen
        if t.k == "struct":
            if t.name in seen:
                return False
            next_seen = seen | {t.name}
            return any(
                self.contains_raw_pointer(field_ty, next_seen)
                for _, field_ty in self.structs[t.name]["fields"]
            )
        return any(self.contains_raw_pointer(arg, seen) for arg in t.args)

    def consume(self, pl, n):
        t = pl.ty
        if t.k == "slice":
            self.err("cannot use an unsized slice as a value", n)
        if not self.is_copy(t):
            if pl.var is not None:
                v = pl.var
                c = self.tmp(self.ctype(t), v.c)
                self.emit(f"{v.flag} = false;")
                if self.moved is not None:
                    self.moved.add(v)
                return c, t
            if pl.tmp is not None:
                pl.tmp.taken = True
                return pl.lv, t
            self.err(f"cannot move out of a field, index or reference: `{tstr(t)}` owns resources and is not Copy", n)
        if t.k == "unit":
            return "SEC_UNIT", t
        return self.tmp(self.ctype(t), pl.lv), t

    # ------------------------------------------------------------- expressions
    def expr(self, n, expected=None, allow_ref=False):
        h = getattr(self, "e_" + n.k, None)
        if h is None:
            self.err(f"unsupported expression `{n.k}`", n)
        c, t = h(n, expected, allow_ref)
        if t.k == "ref" and not allow_ref:
            self.err("references can only be passed directly as call arguments; they cannot be stored, "
                     "returned or used as values", n)
        if t.k == "never":
            self.moved = None
        return c, t

    def e_Int(self, n, expected, allow_ref):
        ty = I(n.suf) if n.suf else (expected if expected is not None and expected.k == "int" else I32)
        lo, hi = int_range(ty.name)
        if not lo <= n.val <= hi:
            self.err(f"integer literal `{n.val}` is out of range for `{ty.name}`", n)
        return c_int(n.val, ty.name), ty

    def e_Float(self, n, expected, allow_ref):
        return repr(float(n.val)), F64

    def e_Bool(self, n, expected, allow_ref):
        return ("true" if n.val else "false"), BOOL

    def e_Unit(self, n, expected, allow_ref):
        return "SEC_UNIT", UNIT

    def e_Str(self, n, expected, allow_ref):
        return f'((Slice_u8){{(u8 *)"{c_str(n.val)}", {len(n.val)}}})', STR

    def e_Var(self, n, expected, allow_ref):
        nm = n.name
        v = self.lookup(nm)
        if v is not None:
            if v.ty.k == "ref":
                if self.moved is not None and v in self.moved:
                    self.err(f"use of moved value `{nm}`", n)
                return v.c, v.ty
            return self.consume(self.place(n), n)
        if nm in self.consts:
            ty, val = self.consts[nm]
            if ty.k == "int": return c_int(val, ty.name), ty
            if ty.k == "float": return repr(float(val)), ty
            if ty.k == "bool": return ("true" if val else "false"), ty
            return f'((Slice_u8){{(u8 *)"{c_str(val)}", {len(val)}}})', ty
        if nm == "None":
            if expected is None or expected.k != "option":
                self.err("cannot infer the type of `None`; add a type annotation", n)
            ct = self.ctype(expected)
            return self.tmp(ct, "{0}"), expected
        if nm in self.fns or nm in BUILTIN_FUNCS:
            self.err(f"`{nm}` is a function; call it with `{nm}(...)`", n)
        self.err(f"unknown variable `{nm}`", n)

    def e_Path(self, n, expected, allow_ref):
        segs = n.segs
        if len(segs) == 2:
            a, b = segs
            if a == "Self" and self.cur_self is not None:
                a = self.cur_self.name
            if a in self.enums:
                if b not in self.enums[a]:
                    self.err(f"enum `{a}` has no variant `{b}`", n)
                return self.enum_cnames[(a, b)], enum(a)
            if a in INTS and b in ("MAX", "MIN"):
                lo, hi = int_range(a)
                return c_int(hi if b == "MAX" else lo, a), I(a)
        self.err(f"`{'::'.join(segs)}` is not a value", n)

    def e_Field(self, n, expected, allow_ref):
        return self.consume(self.place(n), n)

    def e_Index(self, n, expected, allow_ref):
        return self.consume(self.place(n), n)

    def e_Deref(self, n, expected, allow_ref):
        return self.consume(self.place(n), n)

    def e_Ref(self, n, expected, allow_ref):
        self.err("a reference expression `&x` is only allowed as a direct call argument", n)

    def e_Range(self, n, expected, allow_ref):
        self.err("ranges are only valid in `for` loops and slice expressions `&x[a..b]`", n)

    def e_Unary(self, n, expected, allow_ref):
        L = self.loc(n)
        if n.op == "-":
            e = n.e
            if e.k == "Int":
                ty = I(e.suf) if e.suf else (expected if expected is not None and expected.k == "int" else I32)
                if not is_signed(ty.name):
                    self.err(f"cannot negate unsigned type `{ty.name}`", n)
                lo, hi = int_range(ty.name)
                if not lo <= -e.val <= hi:
                    self.err(f"integer literal `-{e.val}` is out of range for `{ty.name}`", n)
                return c_int(-e.val, ty.name), ty
            c, t = self.expr(e, expected)
            if t.k == "int" and is_signed(t.name):
                return self.tmp(t.name, f"sec_neg_{t.name}({c}, {L})"), t
            if t.k == "float":
                return self.tmp("f64", f"(-{c})"), t
            if t.k == "never":
                return None, t
            if t.k == "int":
                self.err(f"cannot negate unsigned type `{t.name}` (use `0 - x` with a signed type, or `wrapping_sub`)", n)
            self.err(f"cannot negate type `{tstr(t)}`", n)
        c, t = self.expr(n.e, expected)
        if t.k == "bool":
            return self.tmp("bool", f"!{c}"), t
        if t.k == "int":
            return self.tmp(t.name, f"sec_not_{t.name}({c})"), t
        if t.k == "never":
            return None, t
        self.err(f"cannot apply `!` to type `{tstr(t)}`", n)

    # ---- binary operators
    def is_lit(self, n):
        return (n.k == "Int" and not n.suf) or (n.k == "Unary" and n.op == "-" and n.e.k == "Int" and not n.e.suf)

    @staticmethod
    def strish(t):
        return t.k == "str" or (t.k == "ref" and t.args[0].k == "str")

    def e_Binary(self, n, expected, allow_ref):
        op = n.op
        if op in ("&&", "||"):
            return self.logical(n)
        ar = op in ("==", "!=")
        if op in CMP:
            exp = None
        elif expected is not None and (expected.k in ("int", "float") or (op in BITOPS and expected.k == "bool")):
            exp = expected
        else:
            exp = None
        if op in ("<<", ">>"):
            lc, lt = self.expr(n.l, exp)
            rc, rt = self.expr(n.r, U32)
        elif self.is_lit(n.l) and not self.is_lit(n.r):
            rc, rt = self.expr(n.r, exp, ar)
            lc, lt = self.expr(n.l, rt)
        else:
            lc, lt = self.expr(n.l, exp, ar)
            rc, rt = self.expr(n.r, lt if lt.k in ("int", "float") else None, ar)
        if lt.k == "never" or rt.k == "never":
            return None, NEVER
        return self.binop(op, lc, lt, rc, rt, n, n)

    def binop(self, op, lc, lt, rc, rt, n, fold):
        L = self.loc(n)
        if op in ("<<", ">>"):
            if lt.k != "int" or rt.k != "int":
                self.err(f"shift operands must be integers, found `{tstr(lt)}` and `{tstr(rt)}`", n)
            if fold is not None:
                cv = self.cval(fold, lt.name)
                if cv is not None:
                    return c_int(cv, lt.name), lt
            amt = rc if rt == U64 else (f"(u64){rc}" if not is_signed(rt.name) else
                                        f"SEC_CAST(u64, SEC_MIN_u64, SEC_MAX_u64, {rc}, {L})")
            fn = "shl" if op == "<<" else "shr"
            return self.tmp(lt.name, f"sec_{fn}_{lt.name}({lc}, {amt}, {L})"), lt
        if op in ("==", "!=") and self.strish(lt) and self.strish(rt):
            r = self.tmp("bool", f"sec_str_eq({lc}, {rc})")
            return (r if op == "==" else self.tmp("bool", f"!{r}")), BOOL
        if lt.k == "string" or rt.k == "string":
            self.err("`String` values cannot be compared directly; use `str_eq(&a, &b)`", n)
        if lt != rt:
            self.err(f"mismatched types in `{op}`: `{tstr(lt)}` and `{tstr(rt)}` (Secure has no implicit "
                     f"conversions; use `as`)", n)
        t = lt
        if op in CMP:
            if t.k in ("int", "float") or (t.k in ("bool", "enum") and op in ("==", "!=")):
                return self.tmp("bool", f"({lc} {op} {rc})"), BOOL
            self.err(f"cannot compare values of type `{tstr(t)}` with `{op}`", n)
        if op in ARITH:
            if t.k == "float":
                if op == "%":
                    self.err("`%` is not defined for f64", n)
                return self.tmp("f64", f"({lc} {op} {rc})"), t
            if t.k != "int":
                self.err(f"operator `{op}` cannot be applied to type `{tstr(t)}`", n)
            if fold is not None:
                cv = self.cval(fold, t.name)
                if cv is not None:
                    return c_int(cv, t.name), t
                if op in ("/", "%") and self.cval(fold.r, t.name) == 0:
                    self.err("division by zero", fold)
            return self.tmp(t.name, f"sec_{ARITH[op]}_{t.name}({lc}, {rc}, {L})"), t
        if op in BITOPS:
            if t.k == "bool":
                return self.tmp("bool", f"({lc} {op} {rc})"), t
            if t.k == "int":
                if fold is not None:
                    cv = self.cval(fold, t.name)
                    if cv is not None:
                        return c_int(cv, t.name), t
                return self.tmp(t.name, f"({t.name})({lc} {op} {rc})"), t
            self.err(f"operator `{op}` cannot be applied to type `{tstr(t)}`", n)
        self.err(f"unsupported operator `{op}`", n)

    def logical(self, n):
        lc, lt = self.expr(n.l, BOOL)
        if lt != BOOL:
            self.err(f"`{n.op}` needs `bool` operands, found `{tstr(lt)}`", n.l)
        r = self.tmp("bool", lc)
        s0 = self.snap()
        self.emit(f"if ({'' if n.op == '&&' else '!'}{r}) {{")
        mark = len(self.stmt_temps)
        rc, rt = self.expr(n.r, BOOL)
        if rt.k != "never":
            if rt != BOOL:
                self.err(f"`{n.op}` needs `bool` operands, found `{tstr(rt)}`", n.r)
            self.emit(f"{r} = {rc};")
        self.drop_temps(mark)
        self.emit("}")
        self.moved = self.merge(self.snap() if self.moved is not None else s0, s0)
        return r, BOOL

    # ---- assignment
    def e_Assign(self, n, expected, allow_ref):
        tgt = n.target
        if tgt.k not in PLACE_KINDS:
            self.err("invalid left-hand side of assignment", tgt)
        op = n.op[:-1] if n.op != "=" else None
        want = self.peek_ty(tgt)
        rc, rt = self.expr(n.value, U32 if op in ("<<", ">>") else want)
        if rt.k == "never":
            return None, NEVER
        v = self.lookup(tgt.name) if tgt.k == "Var" else None
        if tgt.k == "Var" and v is None:
            self.err(f"cannot assign to `{tgt.name}`", tgt)
        if v is not None:
            if v.ty.k == "ref":
                self.err(f"cannot assign to the reference parameter `{v.name}` itself; use `*{v.name} = ...`", tgt)
            if not v.mut:
                self.err(f"cannot assign to immutable variable `{v.name}` (declare it with `let mut`)", tgt)
            lv, ty = v.c, v.ty
            if op is None:
                if rt != ty:
                    self.err(f"mismatched types: expected `{tstr(ty)}`, found `{tstr(rt)}`", n.value)
                if v.flag:
                    self.emit(f"if ({v.flag}) {self.drop_stmt(ty, lv)}")
                self.emit(f"{lv} = {rc};")
                if v.flag:
                    self.emit(f"{v.flag} = true;")
                    if self.moved is not None:
                        self.moved.discard(v)
                return "SEC_UNIT", UNIT
            if self.moved is not None and v in self.moved:
                self.err(f"use of moved value `{v.name}`", tgt)
        else:
            pl = self.place(tgt)
            if not pl.mut:
                self.err("cannot assign through an immutable binding or shared reference "
                         "(declare it `mut`, or take `&mut`)", tgt)
            lv, ty = pl.lv, pl.ty
            if op is None:
                if rt != ty:
                    self.err(f"mismatched types: expected `{tstr(ty)}`, found `{tstr(rt)}`", n.value)
                if self.needs_drop(ty):
                    self.emit(self.drop_stmt(ty, lv))
                self.emit(f"{lv} = {rc};")
                return "SEC_UNIT", UNIT
        cur = self.tmp(self.ctype(ty), lv)
        if op in ("<<", ">>") and ty.k == "int":
            pass
        nc, nt = self.binop(op, cur, ty, rc, rt, n, None)
        if nt != ty:
            self.err(f"mismatched types in compound assignment: `{tstr(ty)}` and `{tstr(nt)}`", n)
        self.emit(f"{lv} = {nc};")
        return "SEC_UNIT", UNIT

    # ---- casts
    def e_Cast(self, n, expected, allow_ref):
        to = self.storable(self.rty(n.ty), n.ty)
        L = self.loc(n)
        exp = None
        if self.is_lit(n.e):
            val = n.e.val if n.e.k == "Int" else -n.e.e.val
            exp = U64 if val > int_range("i64")[1] else I64
        c, t = self.expr(n.e, exp)
        if t.k == "never":
            return None, t
        if t == to:
            return c, t
        if t.k == "int" and to.k == "int":
            slo, shi = int_range(t.name)
            tlo, thi = int_range(to.name)
            if n.wrapping or (tlo <= slo and shi <= thi):
                return self.tmp(to.name, f"({to.name}){c}"), to
            cv = self.cval(n.e, t.name)
            if cv is not None and not tlo <= cv <= thi:
                self.err(f"constant {cv} does not fit in `{to.name}` (use `as wrapping {to.name}` to truncate)", n)
            return self.tmp(to.name, f"SEC_CAST({to.name}, SEC_MIN_{to.name}, SEC_MAX_{to.name}, {c}, {L})"), to
        if n.wrapping:
            self.err("`as wrapping` applies to integer-to-integer conversions only", n)
        if t.k == "int" and to.k == "float":
            return self.tmp("f64", f"(f64){c}"), to
        if t.k == "float" and to.k == "int":
            return self.tmp(to.name, f"SEC_CAST({to.name}, SEC_MIN_{to.name}, SEC_MAX_{to.name}, sec_f2i({c}, {L}), {L})"), to
        if t.k in ("bool", "enum") and to.k == "int":
            return self.tmp(to.name, f"({to.name}){c}"), to
        self.err(f"cannot cast `{tstr(t)}` to `{tstr(to)}`", n)

    # ---- control flow
    def e_Block(self, n, expected, allow_ref):
        return self.value_block(n, expected)

    def e_Unsafe(self, n, expected, allow_ref):
        if self.forbid_unsafe:
            self.err("`unsafe` blocks are forbidden by --forbid-unsafe", n)
        self.audit["unsafe_blocks"].append({"line": n.line, "col": n.col})
        self.unsafe_depth += 1
        try:
            return self.value_block(n.body, expected)
        finally:
            self.unsafe_depth -= 1

    def e_If(self, n, expected, allow_ref):
        mark = len(self.stmt_temps)
        cc, ct = self.expr(n.cond, BOOL)
        if ct != BOOL:
            self.err(f"`if` condition must be `bool`, found `{tstr(ct)}`", n.cond)
        self.drop_temps(mark)
        s0 = self.snap()
        dest = f"_r{self.newid()}"
        l1, t1 = self.block(n.then, expected, dest)
        st1 = self.moved
        if n.els is None:
            if t1.k not in ("unit", "never"):
                self.err("`if` without `else` must have type `()`", n.then)
            self.moved = self.merge(st1, s0)
            self.emit(f"if ({cc}) {{")
            self.out.extend(l1)
            self.emit("}")
            return "SEC_UNIT", UNIT
        self.moved = None if s0 is None else set(s0)
        els = n.els if n.els.k == "Block" else N("Block", (n.els.line, n.els.col), stmts=[], tail=n.els)
        exp2 = t1 if t1.k not in ("unit", "never") else expected
        l2, t2 = self.block(els, exp2, dest)
        st2 = self.moved
        if t1.k == "never":
            t = t2
        elif t2.k == "never" or t1 == t2:
            t = t1
        else:
            self.err(f"`if` and `else` have incompatible types: `{tstr(t1)}` and `{tstr(t2)}`", n.els)
        self.moved = self.merge(st1, st2)
        valued = t.k not in ("unit", "never")
        if valued:
            self.emit(f"{self.ctype(t)} {dest};")
        self.emit(f"if ({cc}) {{")
        self.out.extend(l1)
        self.emit("} else {")
        self.out.extend(l2)
        self.emit("}")
        return (dest if valued else ("SEC_UNIT" if t.k == "unit" else None)), t

    def loop_finish(self, lp, s0, end_state, n):
        for cand in [end_state] + lp.conts:
            if cand is None:
                continue
            for v in cand - (s0 or set()):
                if v.level < lp.level:
                    self.err(f"value `{v.name}` is moved inside a loop and used again in the next iteration", n)

    def e_While(self, n, expected, allow_ref):
        s0 = self.snap()
        lp = Loop(len(self.scopes), len(self.loops) + 1)
        self.loops.append(lp)
        self.emit("for (;;) {")
        mark = len(self.stmt_temps)
        cc, ct = self.expr(n.cond, BOOL)
        if ct != BOOL:
            self.err(f"`while` condition must be `bool`, found `{tstr(ct)}`", n.cond)
        self.drop_temps(mark)
        self.emit(f"if (!{cc}) break;")
        lines, bt = self.block(n.body, UNIT, None)
        self.loop_finish(lp, s0, self.moved, n)
        self.emit("{")
        self.out.extend(lines)
        self.emit("}")
        self.emit("}")
        self.loops.pop()
        self.moved = self.merge(s0, *lp.breaks)
        return "SEC_UNIT", UNIT

    def e_Loop(self, n, expected, allow_ref):
        s0 = self.snap()
        lp = Loop(len(self.scopes), len(self.loops) + 1)
        self.loops.append(lp)
        self.emit("for (;;) {")
        lines, bt = self.block(n.body, UNIT, None)
        self.loop_finish(lp, s0, self.moved, n)
        self.emit("{")
        self.out.extend(lines)
        self.emit("}")
        self.emit("}")
        self.loops.pop()
        if not lp.breaks:
            self.moved = None
            return None, NEVER
        self.moved = self.merge(*lp.breaks)
        return "SEC_UNIT", UNIT

    def e_For(self, n, expected, allow_ref):
        if self.is_lit(n.lo) and not self.is_lit(n.hi):
            hc, ht = self.expr(n.hi, None)
            lc, lt = self.expr(n.lo, ht)
        else:
            lc, lt = self.expr(n.lo, None)
            hc, ht = self.expr(n.hi, lt if lt.k == "int" else None)
        if lt.k != "int" or lt != ht:
            self.err(f"range bounds must be the same integer type, found `{tstr(lt)}` and `{tstr(ht)}`", n)
        T = lt.name
        s0 = self.snap()
        lp = Loop(len(self.scopes), len(self.loops) + 1)
        self.loops.append(lp)
        k = f"_k{self.newid()}"
        if n.incl:
            sp = f"_sp{self.newid()}"
            self.emit(f"for (__int128 {k} = 0, {sp} = (__int128){hc} - (__int128){lc}; {k} <= {sp}; {k}++) {{")
            init = f"({T})((__int128){lc} + {k})"
        else:
            self.emit(f"for ({T} {k} = {lc}; {k} < {hc}; {k}++) {{")
            init = k
        lines, bt = self.block(n.body, UNIT, None, binds=[(n.var, lt, init, False)])
        self.loop_finish(lp, s0, self.moved, n)
        self.emit("{")
        self.out.extend(lines)
        self.emit("}")
        self.emit("}")
        self.loops.pop()
        self.moved = self.merge(s0, *lp.breaks)
        return "SEC_UNIT", UNIT

    def e_Break(self, n, expected, allow_ref):
        if not self.loops:
            self.err("`break` outside of a loop", n)
        lp = self.loops[-1]
        lp.breaks.append(self.snap())
        self.drop_temps_on_exit(deeper_than=lp.depth)
        self.drops_down_to(lp.depth)
        self.emit("break;")
        return None, NEVER

    def e_Continue(self, n, expected, allow_ref):
        if not self.loops:
            self.err("`continue` outside of a loop", n)
        lp = self.loops[-1]
        lp.conts.append(self.snap())
        self.drop_temps_on_exit(deeper_than=lp.depth)
        self.drops_down_to(lp.depth)
        self.emit("continue;")
        return None, NEVER

    def e_Return(self, n, expected, allow_ref):
        rt = self.fn_ret
        if n.e is None:
            if rt != UNIT:
                self.err(f"`return;` in a function returning `{tstr(rt)}`", n)
            self.drop_temps_on_exit()
            self.drops_down_to(0)
            self.emit("return;")
            return None, NEVER
        c, t = self.expr(n.e, rt)
        if t.k == "never":
            return None, NEVER
        if t != rt:
            self.err(f"mismatched types: function returns `{tstr(rt)}`, found `{tstr(t)}`", n.e)
        if rt.k == "unit":
            self.drop_temps_on_exit()
            self.drops_down_to(0)
            self.emit("return;")
        else:
            r = c if IDENT_RE.fullmatch(c) and c.startswith("_t") else self.tmp(self.ctype(rt), c)
            keep = (r,) if self.needs_drop(rt) else ()
            self.drop_temps_on_exit(keep=keep)
            self.drops_down_to(0)
            self.emit(f"return {r};")
        return None, NEVER

    def e_Try(self, n, expected, allow_ref):
        c, t = self.expr(n.e, None)
        if t.k == "never":
            return None, t
        fr = self.fn_ret
        r = c if IDENT_RE.fullmatch(c) else self.tmp(self.ctype(t), c)
        if self.needs_drop(t):
            # The result's active payload is transferred either to the caller
            # on the error path or to the value produced below on the success path.
            self.take_temp(r)
        if t.k == "result" and fr.k == "result" and t.args[1] == fr.args[1]:
            self.emit(f"if (!{r}.ok) {{")
            self.drop_temps_on_exit()
            self.drops_down_to(0)
            self.emit(f"return ({self.ctype(fr)}){{.ok = false, .e = {r}.e}};")
            self.emit("}")
            vt = t.args[0]
        elif t.k == "option" and fr.k == "option":
            self.emit(f"if (!{r}.some) {{")
            self.drop_temps_on_exit()
            self.drops_down_to(0)
            self.emit(f"return ({self.ctype(fr)}){{0}};")
            self.emit("}")
            vt = t.args[0]
        else:
            self.err(f"`?` on `{tstr(t)}` requires the enclosing function to return a matching "
                     f"`Result<_, {tstr(t.args[1]) if t.k == 'result' else '_'}>` / `Option<_>` "
                     f"(function returns `{tstr(fr)}`)", n)
        if vt.k == "unit":
            return "SEC_UNIT", vt
        return self.tmp(self.ctype(vt), f"{r}.v"), vt

    # ------------------------------------------------------------------- match
    def e_Match(self, n, expected, allow_ref):
        sc, st = self.expr(n.scrut, None)
        if st.k == "never":
            return None, st
        if st.k not in ("option", "result", "int", "bool", "enum"):
            self.err(f"cannot `match` on type `{tstr(st)}` (supported: integers, bool, enums, Option, Result)", n.scrut)
        if not n.arms:
            self.err("`match` needs at least one arm", n)
        s = sc if IDENT_RE.fullmatch(sc) else self.tmp(self.ctype(st), sc)
        L = self.loc(n)
        s0 = self.snap()
        dest = f"_r{self.newid()}"
        arms, states, rtype, covered = [], [], None, set()
        for pats, body, ap in n.arms:
            if len(pats) > 1 and any(p[0] not in ("lit", "enum") for p in pats):
                raise SecError("alternatives (`|`) are only supported between literal and enum patterns", ap[0], ap[1])
            conds, binds, prelude = [], [], []
            for p in pats:
                c1, b1, pre1, cov = self.pat(p, s, st)
                conds.append(c1)
                binds += b1
                prelude += pre1
                covered.add(cov)
            self.moved = None if s0 is None else set(s0)
            lines, bt = self.block(body, expected if expected is not None else rtype, dest, binds=binds)
            if bt.k != "never":
                if rtype is None:
                    rtype = bt
                elif rtype != bt:
                    self.err(f"`match` arms have incompatible types: `{tstr(rtype)}` and `{tstr(bt)}`", body)
            states.append(self.moved)
            arms.append((" || ".join(f"({c})" for c in conds), prelude + lines))
        self.moved = self.merge(*states)
        if "ALL" not in covered:
            if st.k == "option": need = {("c", "Some"), ("c", "None")}
            elif st.k == "result": need = {("c", "Ok"), ("c", "Err")}
            elif st.k == "enum": need = {("v", v) for v in self.enums[st.name]}
            elif st.k == "bool": need = {("lit", True), ("lit", False)}
            else: need = {"ALL"}
            missing = need - covered
            if missing:
                names = ", ".join(sorted(str(m[1]) if isinstance(m, tuple) else "`_`" for m in missing))
                self.err(f"non-exhaustive `match`: not covered: {names}", n)
        t = rtype if rtype is not None else NEVER
        valued = t.k not in ("unit", "never")
        if valued:
            self.emit(f"{self.ctype(t)} {dest};")
        for i, (cond, lines) in enumerate(arms):
            self.emit(("if" if i == 0 else "} else if") + f" ({cond}) {{")
            self.out.extend(lines)
        self.emit(f'}} else {{ sec_panic("unreachable match arm", {L}); }}')
        return (dest if valued else ("SEC_UNIT" if t.k == "unit" else None)), t

    def pat(self, p, s, st):
        kind = p[0]

        def e(msg):
            raise SecError(msg, p[1][0], p[1][1])
        if kind == "wild":
            return "1", [], ([self.drop_stmt(st, s)] if self.needs_drop(st) else []), "ALL"
        if kind == "bind":
            return "1", [(p[2], st, s, False)], [], "ALL"
        if kind == "lit":
            v = p[2]
            if isinstance(v, bool):
                if st.k != "bool":
                    e(f"boolean pattern on a value of type `{tstr(st)}`")
                return f"{s} == {'true' if v else 'false'}", [], [], ("lit", v)
            if st.k != "int":
                e(f"integer pattern on a value of type `{tstr(st)}`")
            lo, hi = int_range(st.name)
            if not lo <= v <= hi:
                e(f"pattern `{v}` is out of range for `{st.name}`")
            return f"{s} == {c_int(v, st.name)}", [], [], ("lit", v)
        if kind == "enum":
            if st.k != "enum" or st.name != p[2]:
                e(f"pattern `{p[2]}::{p[3]}` does not match a value of type `{tstr(st)}`")
            if p[3] not in self.enums[p[2]]:
                e(f"enum `{p[2]}` has no variant `{p[3]}`")
            return f"{s} == {self.enum_cnames[(p[2], p[3]) ]}", [], [], ("v", p[3])
        name, sub = p[2], p[3]
        if st.k == "option" and name == "Some":
            cond, pty, init = f"{s}.some", st.args[0], f"{s}.v"
        elif st.k == "option" and name == "None":
            return f"!{s}.some", [], [], ("c", "None")
        elif st.k == "result" and name == "Ok":
            cond, pty, init = f"{s}.ok", st.args[0], f"{s}.v"
        elif st.k == "result" and name == "Err":
            cond, pty, init = f"!{s}.ok", st.args[1], f"{s}.e"
        else:
            e(f"pattern `{name}` does not match a value of type `{tstr(st)}`")
        if sub[0] == "bind":
            return cond, [(sub[2], pty, init, False)], [], ("c", name)
        return cond, [], ([self.drop_stmt(pty, init)] if self.needs_drop(pty) else []), ("c", name)

    # --------------------------------------------------------------- aggregates
    def e_StructLit(self, n, expected, allow_ref):
        nm = self.cur_self.name if n.name == "Self" and self.cur_self is not None else n.name
        info = self.structs.get(nm)
        if info is None:
            self.err(f"unknown struct `{nm}`", n)
        decl = dict(info["fields"])
        seen, vals = set(), {}
        for fname, fe, fp in n.fields:
            if fname not in decl:
                raise SecError(f"struct `{nm}` has no field `{fname}`", fp[0], fp[1])
            if fname in seen:
                raise SecError(f"field `{fname}` specified twice", fp[0], fp[1])
            seen.add(fname)
            c, t = self.expr(fe, decl[fname])
            if t.k == "never":
                return None, t
            if t != decl[fname]:
                self.err(f"mismatched types in field `{fname}`: expected `{tstr(decl[fname])}`, found `{tstr(t)}`", fe)
            vals[fname] = c
        missing = [f for f in decl if f not in seen]
        if missing:
            self.err(f"missing field(s) in `{nm}` initializer: {', '.join(missing)} (no uninitialized memory in Secure)", n)
        st = struct(nm)
        ct = self.ctype(st)
        init = ", ".join(f".f_{f} = {vals[f]}" for f, _ in info["fields"]) or "0"
        return self.tmp(ct, f"({ct}){{{init}}}"), st

    def array_type(self, el, cnt, n):
        el = self.storable(el, n)
        if cnt * self.tsize(el) > MAX_ARRAY_BYTES:
            self.err("array too large for the stack (limit 1 MiB); use `Vec<T>`", n)
        return array(el, cnt)

    def e_ArrayLit(self, n, expected, allow_ref):
        el = expected.args[0] if expected is not None and expected.k == "array" else None
        cs = []
        for e in n.elems:
            c, t = self.expr(e, el)
            if t.k == "never":
                return None, t
            if el is None:
                el = t
            elif t != el:
                self.err(f"mismatched array element types: `{tstr(el)}` and `{tstr(t)}`", e)
            cs.append(c)
        at = self.array_type(el, len(cs), n)
        ct = self.ctype(at)
        return self.tmp(ct, f"({ct}){{{{ {', '.join(cs)} }}}}"), at

    def e_ArrayRep(self, n, expected, allow_ref):
        el = expected.args[0] if expected is not None and expected.k == "array" else None
        c, t = self.expr(n.elem, el)
        if t.k == "never":
            return None, t
        if not self.is_copy(t):
            self.err("array repeat expressions require a Copy element type", n.elem)
        cnt = self.cval(n.count, "usize")
        if cnt is None or cnt < 1:
            self.err("array repeat count must be a positive constant integer", n.count)
        at = self.array_type(t, cnt, n)
        ct = self.ctype(at)
        a = self.tmp(ct, "{0}")
        i = f"_i{self.newid()}"
        self.emit(f"for (usize {i} = 0; {i} < {cnt}; {i}++) {a}.a[{i}] = {c};")
        return a, at

    # -------------------------------------------------------------------- calls
    def root_of(self, n):
        if n.k == "Var":
            return n.name
        if n.k in ("Field", "Index", "Deref"):
            return self.root_of(n.e)
        return None

    def as_ref_form(self, a):
        if a.k == "MethodCall" and a.name in ("as_str", "as_bytes", "as_slice", "as_mut_slice") and not a.args:
            return N("Ref", (a.line, a.col), mut=(a.name == "as_mut_slice"), e=a.recv)
        return a

    def prep_ref_target(self, a):
        tgt = a.e
        if tgt.k == "Index" and tgt.idx.k == "Range":
            self.prep(tgt.e)
            r, vals = tgt.idx, []
            for e in (r.lo, r.hi):
                if e is None:
                    vals.append(None)
                    continue
                c, t = self.expr(e, USIZE)
                if t != USIZE:
                    self.err(f"slice bounds must be `usize`, found `{tstr(t)}`", e)
                vals.append(c)
            if r.incl and vals[1] is not None:
                vals[1] = self.tmp("usize", f"sec_add_usize({vals[1]}, 1, {self.loc(r)})")
            self.pre[id(tgt)] = tuple(vals)
        else:
            self.prep(tgt)

    def slice_place(self, tgt):
        b = self.place_(tgt.e)
        t = b.ty
        if t.k not in ("array", "slice", "vec", "string", "str"):
            self.err(f"type `{tstr(t)}` cannot be sliced", tgt)
        lo, hi = self.pre[id(tgt)]
        if t.k == "array": ln, data, el = str(t.n), f"{b.lv}.a", t.args[0]
        elif t.k == "slice": ln, data, el = f"{b.lv}.n", f"{b.lv}.p", t.args[0]
        elif t.k == "str": ln, data, el = f"{b.lv}.n", f"{b.lv}.p", U8
        elif t.k == "vec": ln, data, el = f"{b.lv}.len", f"{b.lv}.p", t.args[0]
        else: ln, data, el = f"{b.lv}.len", f"{b.lv}.p", U8
        lo_c = self.tmp("usize", lo or "0")
        hi_c = self.tmp("usize", hi or ln)
        self.emit(f"if ({lo_c} > {hi_c} || {hi_c} > {ln}) sec_oob_range({lo_c}, {hi_c}, {ln}, {self.loc(tgt)});")
        sl = slice_(el)
        ct = self.ctype(sl)
        r = self.tmp(ct, f"(({ct}){{{data} + {lo_c}, {hi_c} - {lo_c}}})")
        return Place(r, sl, b.mut and t.k not in ("str", "string"), b.root)

    def ref_coerce(self, pl, pt, n):
        inner, t = pt.args[0], pl.ty
        if t == inner:
            return pl.lv if t.k in ("slice", "str") else f"&{pl.lv}"
        sl = inner.k == "slice"
        if sl and t.k == "array" and t.args[0] == inner.args[0]:
            return f"(({self.ctype(inner)}){{{pl.lv}.a, {t.n}}})"
        if sl and t.k == "vec" and t.args[0] == inner.args[0]:
            return f"(({self.ctype(inner)}){{{pl.lv}.p, {pl.lv}.len}})"
        if sl and inner.args[0] == U8 and t.k == "string":
            return f"((Slice_u8){{{pl.lv}.p, {pl.lv}.len}})"
        if sl and inner.args[0] == U8 and t.k == "str":
            return pl.lv
        if inner.k == "str" and t.k == "string":
            return f"((Slice_u8){{{pl.lv}.p, {pl.lv}.len}})"
        self.err(f"mismatched types: expected `{tstr(pt)}`, found a reference to `{tstr(t)}`", n)

    def form_ref(self, a, pt, ents):
        inner, wantmut = pt.args[0], pt.name == "mut"
        if a.k == "Ref":
            tgt = a.e
            pl = self.slice_place(tgt) if (tgt.k == "Index" and tgt.idx.k == "Range") else self.place_(tgt)
            if wantmut and not a.mut:
                self.err("this parameter requires `&mut`; write `&mut x`", a)
            if a.mut and not pl.mut:
                self.err("cannot borrow as mutable: the binding is not declared `mut` (or is behind a shared reference)", a)
            if pl.root:
                ents.append((pl.root, "mut" if a.mut else "shared"))
            return self.ref_coerce(pl, pt, a)
        if a.k == "Str":
            c, t = self.expr(a, None)
            return self.ref_coerce(Place(c, STR, False), pt, a)
        if a.k == "Var":
            v = self.lookup(a.name)
            if v is None and a.name in self.consts and self.consts[a.name][0].k == "str":
                c, t = self.expr(a, None)
                return self.ref_coerce(Place(c, STR, False), pt, a)
            if v is not None and v.ty.k == "ref":
                if self.moved is not None and v in self.moved:
                    self.err(f"use of moved value `{a.name}`", a)
                if wantmut and v.ty.name != "mut":
                    self.err("cannot pass a shared reference where `&mut` is required", a)
                ents.append((v.name, "mut" if wantmut else "shared"))
                return self.ref_coerce(self.pointee(v, a), pt, a)
            if v is not None and v.ty.k == "str" and inner.k == "str":
                return v.c
        self.err(f"expected a reference of type `{tstr(pt)}`: pass `&x` or `&mut x`", a)

    def check_conflicts(self, ents, n):
        by = {}
        for root, kind in ents:
            by.setdefault(root, []).append(kind)
        for root, ks in by.items():
            if len(ks) > 1 and any(k in ("mut", "move") for k in ks):
                self.err(f"conflicting access to `{root}` in one call: a `&mut` borrow (or a move) must be "
                         f"the only access to `{root}`", n)

    def lower_args(self, params, args, n, recv=None):
        if len(args) != len(params):
            self.err(f"expected {len(params)} argument(s), found {len(args)}", n)
        ents = [recv] if recv and recv[0] else []
        plan = []
        for a, (pn, pm, pt) in zip(args, params):
            if pt.k == "ref":
                a = self.as_ref_form(a)
                if a.k == "Ref":
                    self.prep_ref_target(a)
            plan.append((a, pt))
        cs = [None] * len(args)
        for i, (a, pt) in enumerate(plan):           # phase 1: by-value arguments, left to right
            if pt.k != "ref":
                c, t = self.expr(a, pt)
                if t.k == "never":
                    c = self.dummy(pt)
                elif t != pt:
                    self.err(f"mismatched types: expected `{tstr(pt)}`, found `{tstr(t)}`", a)
                if a.k == "Var" and not self.is_copy(pt):
                    ents.append((a.name, "move"))
                cs[i] = c
        for i, (a, pt) in enumerate(plan):           # phase 2: form pointers/slices (no user code runs after)
            if pt.k == "ref":
                cs[i] = self.form_ref(a, pt, ents)
        self.check_conflicts(ents, n)
        return cs

    def emit_call(self, sig, cs, n):
        call = f"{sig.cname}({', '.join(cs)})"
        if sig.ret.k == "unit":
            self.emit(call + ";")
            return "SEC_UNIT", UNIT
        return self.tmp(self.ctype(sig.ret), call), sig.ret

    def call_sig(self, sig, args, n):
        if sig.unsafe:
            self.need_unsafe(f"call to unsafe function `{sig.name}`", n)
        return self.emit_call(sig, self.lower_args(sig.params, args, n), n)

    def e_Call(self, n, expected, allow_ref):
        f = n.fn
        if f.k == "Var":
            nm = f.name
            if self.lookup(nm) is not None:
                self.err(f"`{nm}` is a variable, not a function", f)
            if nm in ("Some", "Ok", "Err"):
                return self.ctor(n, nm, expected)
            if nm in BUILTIN_FUNCS:
                return self.builtin_func(n, nm, expected)
            sig = self.fns.get(nm)
            if sig is None:
                self.err(f"unknown function `{nm}`", f)
            return self.call_sig(sig, n.args, n)
        if f.k == "Path":
            return self.path_call(n, f, expected)
        self.err("only named functions can be called", f)

    def ctor(self, n, nm, expected):
        if len(n.args) != 1:
            self.err(f"`{nm}` takes exactly one argument (use `{nm}(())` for unit)", n)
        if nm == "Some":
            c, t = self.expr(n.args[0], expected.args[0] if expected is not None and expected.k == "option" else None)
            if t.k == "never":
                return None, t
            ot = option(self.storable(t, n))
            ct = self.ctype(ot)
            return self.tmp(ct, f"({ct}){{.some = true, .v = {c}}}"), ot
        if expected is None or expected.k != "result":
            self.err(f"cannot infer the `Result` type of `{nm}(...)`; add a type annotation or return it directly", n)
        want = expected.args[0 if nm == "Ok" else 1]
        c, t = self.expr(n.args[0], want)
        if t.k == "never":
            return None, t
        if t != want:
            self.err(f"mismatched types in `{nm}(...)`: expected `{tstr(want)}`, found `{tstr(t)}`", n.args[0])
        ct = self.ctype(expected)
        return self.tmp(ct, f"({ct}){{.ok = {'true' if nm == 'Ok' else 'false'}, .{'v' if nm == 'Ok' else 'e'} = {c}}}"), expected

    def path_call(self, n, f, expected):
        if len(f.segs) != 2:
            self.err("unsupported path expression", f)
        a, b = f.segs
        if a == "Self" and self.cur_self is not None:
            a = self.cur_self.name
        if a == "Vec" and b == "new":
            t = vec(self.rty(f.targs[0])) if f.targs else (expected if expected is not None and expected.k == "vec" else None)
            if t is None:
                self.err("cannot infer the element type of `Vec::new()`; write `let v: Vec<T> = Vec::new();`", n)
            if n.args:
                self.err("`Vec::new` takes no arguments", n)
            return self.tmp(self.ctype(t), f"{self.mangle(t)}_new()"), t
        if a == "String" and b == "new":
            return self.tmp("Vec_u8", "Vec_u8_new()"), STRING
        if a == "String" and b == "from":
            cs = self.lower_args([("s", False, ref(STR))], n.args, n)
            return self.tmp("Vec_u8", f"Vec_u8_from({cs[0]})"), STRING
        sig = self.methods.get((a, b))
        if sig is not None:
            return self.call_sig(sig, n.args, n)
        self.err(f"unknown function `{a}::{b}`", f)

    def e_MethodCall(self, n, expected, allow_ref):
        self.prep(n.recv)
        t = self.recv_ty(n.recv)
        if t is None:
            self.err("cannot determine the type of the method receiver", n.recv)
        if t.k in ("struct", "enum"):
            sig = self.methods.get((t.name, n.name))
            if sig is None or not sig.params or sig.params[0][0] != "self":
                self.err(f"no method `{n.name}` found for type `{t.name}`", n)
            return self.call_method(sig, n)
        return self.builtin_method(n, t, expected)

    def call_method(self, sig, n):
        if sig.unsafe:
            self.need_unsafe(f"call to unsafe method `{sig.name}`", n)
        st = sig.params[0][2]
        kind = ("mut" if st.name == "mut" else "shared") if st.k == "ref" else "move"
        cs = self.lower_args(sig.params[1:], n.args, n, recv=(self.root_of(n.recv), kind))
        pl = self.place_(n.recv)
        if st.k == "ref":
            if st.name == "mut" and not pl.mut:
                self.err(f"cannot call `&mut self` method `{sig.name}` on an immutable binding or shared reference", n)
            rc = f"&{pl.lv}"
        else:
            rc, _ = self.consume(pl, n.recv)
        return self.emit_call(sig, [rc] + cs, n)

    # ---- builtin methods
    def builtin_method(self, n, t, expected):
        name, args, recv, L, k = n.name, n.args, n.recv, self.loc(n), t.k
        if k in ("array", "slice", "vec", "string", "option", "result", "task"):
            self.ctype(t)

        def noargs():
            if args:
                self.err(f"`{name}` takes no arguments", n)

        def need_mut(pl):
            if not pl.mut:
                self.err(f"`{name}` needs a mutable receiver (declare it `let mut`, or take `&mut`)", n)

        def data_len(pl):
            lv = pl.lv
            if k == "array": return f"{lv}.a", str(t.n), t.args[0]
            if k == "slice": return f"{lv}.p", f"{lv}.n", t.args[0]
            if k == "str": return f"{lv}.p", f"{lv}.n", U8
            if k == "vec": return f"{lv}.p", f"{lv}.len", t.args[0]
            return f"{lv}.p", f"{lv}.len", U8

        def unit_or(el, c):
            return ("SEC_UNIT", el) if el.k == "unit" else (self.tmp(self.ctype(el), c), el)

        if name in ("as_str", "as_bytes", "as_slice", "as_mut_slice"):
            self.err(f"`{name}()` produces a reference; use it directly as a call argument", n)
        if name in ("len", "is_empty") and k in ("array", "slice", "vec", "string", "str"):
            noargs()
            data, ln, _ = data_len(self.place_(recv))
            return (self.tmp("usize", ln), USIZE) if name == "len" else (self.tmp("bool", f"({ln} == 0)"), BOOL)
        if name == "as_ptr" and k in ("array", "slice", "vec", "string", "str"):
            noargs()
            data, ln, el = data_len(self.place_(recv))
            pt = ptr(el)
            return self.tmp(self.ctype(pt), f"({self.ctype(pt)}){data}"), pt
        if name == "swap" and k in ("array", "slice", "vec"):
            if len(args) != 2:
                self.err("`swap` takes two indices", n)
            ic, it = self.expr(args[0], USIZE)
            jc, jt = self.expr(args[1], USIZE)
            if it != USIZE or jt != USIZE:
                self.err("`swap` indices must be `usize`", n)
            pl = self.place_(recv)
            need_mut(pl)
            data, ln, el = data_len(pl)
            x = f"_sw{self.newid()}"
            self.emit(f"{{ usize _a = SEC_IDX({ic}, {ln}, {L}); usize _b = SEC_IDX({jc}, {ln}, {L}); "
                      f"{self.ctype(el)} {x} = {data}[_a]; {data}[_a] = {data}[_b]; {data}[_b] = {x}; }}")
            return "SEC_UNIT", UNIT
        if k == "vec":
            el, m = t.args[0], self.mangle(t)
            if name == "push":
                if len(args) != 1:
                    self.err("`push` takes one argument", n)
                c, ct = self.expr(args[0], el)
                if ct.k == "never":
                    return None, ct
                if ct != el:
                    self.err(f"mismatched types: expected `{tstr(el)}`, found `{tstr(ct)}`", args[0])
                pl = self.place_(recv)
                need_mut(pl)
                self.emit(f"{m}_push(&{pl.lv}, {c});")
                return "SEC_UNIT", UNIT
            if name == "pop":
                noargs()
                pl = self.place_(recv)
                need_mut(pl)
                ot = option(el)
                r = self.tmp(self.ctype(ot), "{0}")
                self.emit(f"if ({pl.lv}.len > 0) {{ {r}.some = true; {r}.v = {pl.lv}.p[--{pl.lv}.len]; }}")
                return r, ot
            if name == "clear":
                noargs()
                pl = self.place_(recv)
                need_mut(pl)
                if self.needs_drop(el):
                    self.emit(f"for (usize _i = 0; _i < {pl.lv}.len; _i++) {self.drop_stmt(el, pl.lv + '.p[_i]')}")
                self.emit(f"{pl.lv}.len = 0;")
                return "SEC_UNIT", UNIT
            if name == "get":
                if len(args) != 1 or not self.is_copy(el):
                    self.err("`get(i)` takes one `usize` index and requires a Copy element type", n)
                ic, it = self.expr(args[0], USIZE)
                if it != USIZE:
                    self.err("index must be `usize`", args[0])
                pl = self.place_(recv)
                ot = option(el)
                r = self.tmp(self.ctype(ot), "{0}")
                self.emit(f"if ({ic} < {pl.lv}.len) {{ {r}.some = true; {r}.v = {pl.lv}.p[{ic}]; }}")
                return r, ot
        if k == "string":
            if name == "push":
                if len(args) != 1:
                    self.err("`push` takes one `u8`", n)
                c, ct = self.expr(args[0], U8)
                if ct != U8:
                    self.err(f"`String::push` takes a `u8`, found `{tstr(ct)}`", args[0])
                pl = self.place_(recv)
                need_mut(pl)
                self.emit(f"Vec_u8_push(&{pl.lv}, {c});")
                return "SEC_UNIT", UNIT
            if name == "push_str":
                cs = self.lower_args([("s", False, ref(STR))], args, n, recv=(self.root_of(recv), "mut"))
                pl = self.place_(recv)
                need_mut(pl)
                self.emit(f"Vec_u8_push_str(&{pl.lv}, {cs[0]});")
                return "SEC_UNIT", UNIT
            if name == "clear":
                noargs()
                pl = self.place_(recv)
                need_mut(pl)
                self.emit(f"{pl.lv}.len = 0;")
                return "SEC_UNIT", UNIT
        if k == "option":
            el = t.args[0]
            if name in ("is_some", "is_none"):
                noargs()
                pl = self.place_(recv)
                return self.tmp("bool", f"{'' if name == 'is_some' else '!'}{pl.lv}.some"), BOOL
            if name == "unwrap":
                noargs()
                c, _ = self.consume(self.place_(recv), recv)
                self.emit(f'if (!{c}.some) sec_panic("called `unwrap()` on a `None` value", {L});')
                return unit_or(el, f"{c}.v")
            if name == "unwrap_or":
                if len(args) != 1:
                    self.err("`unwrap_or` takes one argument", n)
                dc, dt = self.expr(args[0], el)
                if dt != el:
                    self.err(f"mismatched types: expected `{tstr(el)}`, found `{tstr(dt)}`", args[0])
                c, _ = self.consume(self.place_(recv), recv)
                r = self.tmp(self.ctype(el), f"{c}.some ? {c}.v : {dc}")
                if self.needs_drop(el):
                    self.emit(f"if ({c}.some) {self.drop_stmt(el, dc)}")
                return (r, el)
        if k == "result":
            el = t.args[0]
            if name in ("is_ok", "is_err"):
                noargs()
                pl = self.place_(recv)
                return self.tmp("bool", f"{'' if name == 'is_ok' else '!'}{pl.lv}.ok"), BOOL
            if name == "unwrap":
                noargs()
                c, _ = self.consume(self.place_(recv), recv)
                self.emit(f'if (!{c}.ok) sec_panic("called `unwrap()` on an `Err` value", {L});')
                return unit_or(el, f"{c}.v")
            if name == "unwrap_or":
                if len(args) != 1:
                    self.err("`unwrap_or` takes one argument", n)
                dc, dt = self.expr(args[0], el)
                if dt != el:
                    self.err(f"mismatched types: expected `{tstr(el)}`, found `{tstr(dt)}`", args[0])
                c, _ = self.consume(self.place_(recv), recv)
                r = self.tmp(self.ctype(el), f"{c}.ok ? {c}.v : {dc}")
                if self.needs_drop(t.args[1]):
                    self.emit(f"if (!{c}.ok) {self.drop_stmt(t.args[1], c + '.e')}")
                if self.needs_drop(el):
                    self.emit(f"if ({c}.ok) {self.drop_stmt(el, dc)}")
                return r, el
        if k == "task" and name == "join":
            noargs()
            c, _ = self.consume(self.place_(recv), recv)
            el = t.args[0]
            return self.tmp(self.ctype(el), f"{self.mangle(t)}_join(&{c})"), el
        if k == "int":
            T = t.name
            if name == "abs" and is_signed(T):
                noargs()
                return self.tmp(T, f"sec_abs_{T}({self.place_(recv).lv}, {L})"), t
            if name in ("min", "max") and len(args) == 1:
                ac, at = self.expr(args[0], t)
                if at != t:
                    self.err(f"mismatched types: expected `{T}`, found `{tstr(at)}`", args[0])
                return self.tmp(T, f"sec_{name}_{T}({self.place_(recv).lv}, {ac})"), t
            if name == "pow" and len(args) == 1:
                ac, at = self.expr(args[0], U32)
                if at != U32:
                    self.err("`pow` exponent must be `u32`", args[0])
                return self.tmp(T, f"sec_pow_{T}({self.place_(recv).lv}, {ac}, {L})"), t
        if k == "float" and name in ("sqrt", "abs", "floor") and not args:
            return self.tmp("f64", f"{ {'sqrt': 'sqrt', 'abs': 'fabs', 'floor': 'floor'}[name] }({self.place_(recv).lv})"), t
        if k == "ptr":
            if name == "is_null" and not args:
                return self.tmp("bool", f"({self.place_(recv).lv} == 0)"), BOOL
            if name == "add" and len(args) == 1:
                self.need_unsafe("raw pointer arithmetic", n)
                ac, at = self.expr(args[0], USIZE)
                if at != USIZE:
                    self.err("`add` offset must be `usize`", args[0])
                return self.tmp(self.ctype(t), f"({self.place_(recv).lv} + {ac})"), t
        self.err(f"no method `{name}` found for type `{tstr(t)}`", n)

    # ---- builtin free functions
    def print_arg(self, a):
        pl = self.place(a) if a.k in PLACE_KINDS else self.rvalue_place(a)
        t, lv = pl.ty, pl.lv
        if t.k == "int":
            self.emit(f"sec_print_i64((i64){lv});" if is_signed(t.name) else f"sec_print_u64((u64){lv});")
        elif t.k == "float": self.emit(f"sec_print_f64({lv});")
        elif t.k == "bool": self.emit(f"sec_print_bool({lv});")
        elif t.k == "enum": self.emit(f"sec_print_i64((i64){lv});")
        elif t.k == "str": self.emit(f"sec_print_str({lv});")
        elif t.k == "string": self.emit(f"sec_print_str((Slice_u8){{{lv}.p, {lv}.len}});")
        else:
            self.err(f"cannot print a value of type `{tstr(t)}`", a)

    def builtin_func(self, n, nm, expected):
        L, args = self.loc(n), n.args
        if nm in ("print", "println"):
            for a in args:
                self.print_arg(a)
            if nm == "println":
                self.emit("sec_print_nl();")
            return "SEC_UNIT", UNIT
        if nm == "None":
            self.err("`None` is a value, not a function", n)
        if nm == "exit":
            if len(args) != 1:
                self.err("`exit` takes one `i32`", n)
            c, t = self.expr(args[0], I32)
            if t != I32:
                self.err("`exit` takes an `i32` status code", args[0])
            self.drop_temps_on_exit()
            self.drops_down_to(0)
            self.emit(f"sec_exit({c});")
            return None, NEVER
        if nm == "panic":
            cs = self.lower_args([("m", False, ref(STR))], args, n)
            m = self.tmp("Slice_u8", cs[0])
            self.emit(f"sec_panic_str_raw({m}.p, {m}.n, {L});")
            return None, NEVER
        if nm == "assert":
            if len(args) != 1:
                self.err("`assert` takes one `bool`", n)
            c, t = self.expr(args[0], BOOL)
            if t != BOOL:
                self.err("`assert` needs a `bool`", args[0])
            self.emit(f'if (!{c}) sec_panic("assertion failed", {L});')
            return "SEC_UNIT", UNIT
        if nm == "read_line":
            if args:
                self.err("`read_line` takes no arguments", n)
            ot = option(STRING)
            r = self.tmp(self.ctype(ot), "{0}")
            self.emit(f"{r}.some = sec_read_line(&{r}.v);")
            return r, ot
        if nm == "parse_i64":
            cs = self.lower_args([("s", False, ref(STR))], args, n)
            ot = option(I64)
            r = self.tmp(self.ctype(ot), "{0}")
            self.emit(f"{r}.some = sec_parse_i64({cs[0]}, &{r}.v);")
            return r, ot
        if nm == "str_eq":
            cs = self.lower_args([("a", False, ref(STR)), ("b", False, ref(STR))], args, n)
            return self.tmp("bool", f"sec_str_eq({cs[0]}, {cs[1]})"), BOOL
        if nm == "ct_eq":
            sl = ref(slice_(U8))
            cs = self.lower_args([("a", False, sl), ("b", False, sl)], args, n)
            return self.tmp("bool", f"sec_ct_eq({cs[0]}, {cs[1]})"), BOOL
        if nm == "zeroize":
            cs = self.lower_args([("a", False, ref(slice_(U8), True))], args, n)
            self.emit(f"sec_zeroize({cs[0]});")
            return "SEC_UNIT", UNIT
        if nm == "spawn":
            return self.b_spawn(n)
        kind, op = nm.split("_")
        if len(args) != 2:
            self.err(f"`{nm}` takes two arguments", n)
        if self.is_lit(args[0]) and not self.is_lit(args[1]):
            bc, bt = self.expr(args[1], None)
            ac, at = self.expr(args[0], bt)
        else:
            ac, at = self.expr(args[0], None)
            bc, bt = self.expr(args[1], at)
        if at.k != "int" or at != bt:
            self.err(f"`{nm}` needs two integers of the same type, found `{tstr(at)}` and `{tstr(bt)}`", n)
        T = at.name
        if kind == "wrapping":
            return self.tmp(T, f"sec_w{op}_{T}({ac}, {bc})"), at
        if kind == "saturating":
            return self.tmp(T, f"sec_s{op}_{T}({ac}, {bc})"), at
        ot = option(at)
        r = self.tmp(self.ctype(ot), "{0}")
        self.emit(f"{r}.some = !__builtin_{op}_overflow({ac}, {bc}, &{r}.v);")
        return r, ot

    def b_spawn(self, n):
        L, a0 = self.loc(n), (n.args[0] if n.args else None)
        if a0 is None or a0.k != "Var" or a0.name not in self.fns:
            self.err("`spawn` expects a function name followed by its arguments: `spawn(work, a, b)`", n)
        sig = self.fns[a0.name]
        for _, _, pt in sig.params:
            if pt.k == "ref" or self.contains_raw_pointer(pt):
                self.err("a spawned function may only take owned, thread-safe values: no references or raw pointers", n)
        if sig.unsafe or self.contains_raw_pointer(sig.ret):
            self.err("a spawned function must be safe and must not return raw pointers", n)
        cs = self.lower_args(sig.params, n.args[1:], n)
        R = sig.ret
        rc, tk = self.ctype(R), task(R)
        tc, key = self.ctype(tk), sig.name
        if key not in self.spawned:
            self.spawned.add(key)
            fields = "".join(f" {self.ctype(pt)} a{i};" for i, (_, _, pt) in enumerate(sig.params))
            call = f"{sig.cname}({', '.join('s->a%d' % i for i in range(len(sig.params)))})"
            asg = f"s->r = {call};" if R.k != "unit" else f"{call}; s->r = SEC_UNIT;"
            self.thunks.append(f"typedef struct {{ {rc} r;{fields} }} SpawnArgs_{key};\n"
                               f"static void *spawn_{key}(void *p) {{ SpawnArgs_{key} *s = p; {asg} return NULL; }}")
        a = self.tmp(f"SpawnArgs_{key} *", f"(SpawnArgs_{key} *)malloc(sizeof(SpawnArgs_{key}))")
        self.emit(f'if (!{a}) sec_panic("out of memory", {L});')
        for i, c in enumerate(cs):
            self.emit(f"{a}->a{i} = {c};")
        t = self.tmp(tc, "{0}")
        self.emit(f"{t}.res = ({rc} *){a};")
        self.emit(f'if (pthread_create(&{t}.th, NULL, spawn_{key}, {a}) != 0) sec_panic("failed to create thread", {L});')
        return t, tk
