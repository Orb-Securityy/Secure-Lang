"""Recursive-descent parser for Secure. Produces a light-weight AST of N nodes."""
from .lexer import lex, SecError


class N:
    """Generic AST node: kind `k`, position, and arbitrary attributes."""

    def __init__(self, k, pos, **kw):
        self.k = k
        self.line, self.col = pos
        self.__dict__.update(kw)

    def __repr__(self):
        return "N(%s)" % ", ".join(f"{a}={b!r}" for a, b in self.__dict__.items() if a not in ("line", "col"))


BIN = {"||": 1, "&&": 2, "==": 3, "!=": 3, "<": 3, "<=": 3, ">": 3, ">=": 3, "|": 4, "^": 5,
       "&": 6, "<<": 7, ">>": 7, "+": 8, "-": 8, "*": 9, "/": 9, "%": 9}
ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}
BLOCKLIKE = {"If", "Match", "While", "Loop", "For", "Block", "Unsafe"}


class Parser:
    def __init__(self, toks):
        self.t, self.i, self.nostruct = toks, 0, 0

    # -- token helpers ------------------------------------------------
    @property
    def cur(self):
        return self.t[self.i]

    def peek(self, k=1):
        return self.t[min(self.i + k, len(self.t) - 1)]

    def pos(self):
        return (self.cur.line, self.cur.col)

    def err(self, msg):
        raise SecError(msg, self.cur.line, self.cur.col)

    def isop(self, v):
        c = self.cur
        return c.kind == "op" and c.val == v

    def iskw(self, v):
        c = self.cur
        return c.kind == "kw" and c.val == v

    def isid(self, v=None):
        c = self.cur
        return c.kind == "ident" and (v is None or c.val == v)

    def accept_op(self, v):
        if self.isop(v):
            self.i += 1
            return True
        return False

    def accept_kw(self, v):
        if self.iskw(v):
            self.i += 1
            return True
        return False

    def expect_op(self, v):
        if not self.accept_op(v):
            self.err(f"expected `{v}`, found {self.describe()}")

    def expect_kw(self, v):
        if not self.accept_kw(v):
            self.err(f"expected `{v}`, found {self.describe()}")

    def ident(self):
        if self.cur.kind != "ident":
            self.err(f"expected identifier, found {self.describe()}")
        v = self.cur.val
        self.i += 1
        return v

    def describe(self):
        c = self.cur
        return "end of file" if c.kind == "eof" else f"`{c.val}`" if c.kind != "str" else "string literal"

    # -- items ----------------------------------------------------------
    def program(self):
        items = []
        while self.cur.kind != "eof":
            items.append(self.item())
        return items

    def item(self):
        p = self.pos()
        if self.iskw("unsafe") and self.peek().kind == "kw" and self.peek().val == "fn":
            self.i += 1
            return self.fn(p, unsafe=True)
        if self.iskw("fn"):
            return self.fn(p)
        if self.iskw("extern"):
            self.i += 1
            self.expect_kw("fn")
            f = self.fn(p, extern=True)
            return f
        if self.iskw("struct"):
            self.i += 1
            name = self.ident()
            self.expect_op("{")
            fields = []
            while not self.isop("}"):
                fp = self.pos()
                fn = self.ident()
                self.expect_op(":")
                fields.append((fn, self.ty(), fp))
                if not self.accept_op(","):
                    break
            self.expect_op("}")
            return N("Struct", p, name=name, fields=fields)
        if self.iskw("enum"):
            self.i += 1
            name = self.ident()
            self.expect_op("{")
            vs = []
            while not self.isop("}"):
                vs.append(self.ident())
                if not self.accept_op(","):
                    break
            self.expect_op("}")
            return N("Enum", p, name=name, variants=vs)
        if self.iskw("impl"):
            self.i += 1
            name = self.ident()
            self.expect_op("{")
            fns = []
            while not self.isop("}"):
                fp = self.pos()
                un = self.accept_kw("unsafe")
                self.expect_kw("fn")
                fns.append(self.fn(fp, unsafe=un))
            self.expect_op("}")
            return N("Impl", p, name=name, fns=fns)
        if self.iskw("const"):
            self.i += 1
            name = self.ident()
            self.expect_op(":")
            ty = self.ty()
            self.expect_op("=")
            e = self.expr()
            self.expect_op(";")
            return N("Const", p, name=name, ty=ty, e=e)
        self.err(f"expected item (fn, struct, enum, impl, const), found {self.describe()}")

    def fn(self, p, unsafe=False, extern=False):
        if not extern:
            self.expect_kw("fn") if self.iskw("fn") else None
        name = self.ident()
        self.expect_op("(")
        params = []
        while not self.isop(")"):
            pp = self.pos()
            if self.isop("&") and (self.peek().kind == "ident" and self.peek().val == "self" or
                                   self.peek().kind == "kw" and self.peek().val == "mut" and
                                   self.peek(2).kind == "ident" and self.peek(2).val == "self"):
                self.i += 1
                mut = self.accept_kw("mut")
                self.ident()
                params.append(N("Param", pp, name="self", mut=False,
                                ty=N("TRef", pp, mut=mut, inner=N("TName", pp, name="Self", args=[]))))
            elif self.isid("self"):
                self.i += 1
                params.append(N("Param", pp, name="self", mut=False, ty=N("TName", pp, name="Self", args=[])))
            else:
                mut = self.accept_kw("mut")
                pn = self.ident()
                self.expect_op(":")
                params.append(N("Param", pp, name=pn, mut=mut, ty=self.ty()))
            if not self.accept_op(","):
                break
        self.expect_op(")")
        ret = self.ty() if self.accept_op("->") else None
        if extern:
            self.expect_op(";")
            body = None
        else:
            body = self.block()
        return N("Fn", p, name=name, params=params, ret=ret, body=body, unsafe=unsafe, extern=extern)

    # -- types ------------------------------------------------------------
    def ty(self):
        p = self.pos()
        if self.accept_op("&"):
            mut = self.accept_kw("mut")
            return N("TRef", p, mut=mut, inner=self.ty())
        if self.accept_op("*"):
            if self.accept_kw("mut"):
                mut = True
            else:
                self.expect_kw("const")
                mut = False
            return N("TPtr", p, mut=mut, inner=self.ty())
        if self.accept_op("["):
            el = self.ty()
            if self.accept_op(";"):
                size = self.expr()
                self.expect_op("]")
                return N("TArr", p, elem=el, size=size)
            self.expect_op("]")
            return N("TSlice", p, elem=el)
        if self.accept_op("("):
            self.expect_op(")")
            return N("TName", p, name="()", args=[])
        name = self.ident()
        args = []
        if self.accept_op("<"):
            args = self.type_args()
        return N("TName", p, name=name, args=args)

    def type_args(self):
        args = [self.ty()]
        while self.accept_op(","):
            args.append(self.ty())
        self.expect_gt()
        return args

    def expect_gt(self):
        if self.isop(">"):
            self.i += 1
        elif self.isop(">>"):
            self.cur.val = ">"          # split `>>` into two `>`
        else:
            self.err(f"expected `>`, found {self.describe()}")

    # -- statements -------------------------------------------------------
    def block(self):
        p = self.pos()
        self.expect_op("{")
        stmts, tail = [], None
        while not self.isop("}"):
            if self.cur.kind == "eof":
                self.err("unexpected end of file; missing `}`")
            if self.accept_op(";"):
                continue
            if self.iskw("let"):
                stmts.append(self.let())
                continue
            e = self.expr_stmt()
            if self.accept_op(";"):
                stmts.append(N("ExprStmt", (e.line, e.col), e=e))
            elif self.isop("}"):
                tail = e
            elif e.k in BLOCKLIKE:
                stmts.append(N("ExprStmt", (e.line, e.col), e=e))
            else:
                self.err(f"expected `;`, found {self.describe()}")
        self.expect_op("}")
        return N("Block", p, stmts=stmts, tail=tail)

    def let(self):
        p = self.pos()
        self.expect_kw("let")
        mut = self.accept_kw("mut")
        name = self.ident()
        ty = self.ty() if self.accept_op(":") else None
        if not self.isop("="):
            self.err("variables must be initialized at declaration (`let x = value;`)")
        self.i += 1
        init = self.expr()
        self.expect_op(";")
        return N("Let", p, name=name, mut=mut, ty=ty, init=init)

    def expr_stmt(self):
        e = self.expr()
        if self.cur.kind == "op" and self.cur.val in ASSIGN:
            p = self.pos()
            op = self.cur.val
            self.i += 1
            rhs = self.expr()
            return N("Assign", (e.line, e.col), op=op, target=e, value=rhs)
        return e

    # -- expressions --------------------------------------------------------
    def range_end_absent(self):
        c = self.cur
        return (c.kind == "op" and c.val in ("]", ")", ",", ";", "}")) or \
               (c.kind == "op" and c.val == "{" and self.nostruct > 0) or c.kind == "eof"

    def expr(self):
        p = self.pos()
        if self.isop("..") or self.isop("..="):
            incl = self.cur.val == "..="
            self.i += 1
            hi = None if self.range_end_absent() else self.binary(1)
            return N("Range", p, lo=None, hi=hi, incl=incl)
        lo = self.binary(1)
        if self.isop("..") or self.isop("..="):
            incl = self.cur.val == "..="
            self.i += 1
            hi = None if self.range_end_absent() else self.binary(1)
            return N("Range", p, lo=lo, hi=hi, incl=incl)
        return lo

    def binary(self, mp):
        l = self.cast()
        while self.cur.kind == "op" and self.cur.val in BIN and BIN[self.cur.val] >= mp:
            op = self.cur.val
            p = self.pos()
            self.i += 1
            r = self.binary(BIN[op] + 1)
            l = N("Binary", p, op=op, l=l, r=r)
        return l

    def cast(self):
        e = self.unary()
        while self.iskw("as"):
            p = self.pos()
            self.i += 1
            wrapping = False
            if self.isid("wrapping"):
                self.i += 1
                wrapping = True
            e = N("Cast", p, e=e, ty=self.ty(), wrapping=wrapping)
        return e

    def unary(self):
        p = self.pos()
        if self.isop("-") or self.isop("!"):
            op = self.cur.val
            self.i += 1
            return N("Unary", p, op=op, e=self.unary())
        if self.isop("&"):
            self.i += 1
            mut = self.accept_kw("mut")
            return N("Ref", p, mut=mut, e=self.unary())
        if self.isop("*"):
            self.i += 1
            return N("Deref", p, e=self.unary())
        return self.postfix()

    def args(self):
        args = []
        self.nostruct, saved = 0, self.nostruct
        while not self.isop(")"):
            args.append(self.expr())
            if not self.accept_op(","):
                break
        self.nostruct = saved
        self.expect_op(")")
        return args

    def postfix(self):
        e = self.primary()
        while True:
            p = self.pos()
            if self.isop("("):
                self.i += 1
                e = N("Call", p, fn=e, args=self.args())
            elif self.isop("."):
                self.i += 1
                name = self.ident()
                if self.isop("("):
                    self.i += 1
                    e = N("MethodCall", p, recv=e, name=name, args=self.args())
                else:
                    e = N("Field", p, e=e, name=name)
            elif self.isop("["):
                self.i += 1
                saved, self.nostruct = self.nostruct, 0
                idx = self.expr()
                self.nostruct = saved
                self.expect_op("]")
                e = N("Index", p, e=e, idx=idx)
            elif self.isop("?"):
                self.i += 1
                e = N("Try", p, e=e)
            else:
                return e

    def cond(self):
        self.nostruct += 1
        e = self.expr()
        self.nostruct -= 1
        return e

    def primary(self):
        c, p = self.cur, self.pos()
        if c.kind == "int":
            self.i += 1
            return N("Int", p, val=c.val, suf=c.suf)
        if c.kind == "float":
            self.i += 1
            return N("Float", p, val=c.val)
        if c.kind == "str":
            self.i += 1
            return N("Str", p, val=c.val)
        if c.kind == "kw":
            v = c.val
            if v in ("true", "false"):
                self.i += 1
                return N("Bool", p, val=(v == "true"))
            if v == "if":
                return self.if_expr()
            if v == "match":
                return self.match_expr()
            if v == "while":
                self.i += 1
                cond = self.cond()
                return N("While", p, cond=cond, body=self.block())
            if v == "loop":
                self.i += 1
                return N("Loop", p, body=self.block())
            if v == "for":
                self.i += 1
                var = self.ident()
                self.expect_kw("in")
                r = self.cond()
                if r.k != "Range" or r.lo is None or r.hi is None:
                    raise SecError("`for` loops require a bounded range such as `0..n`", r.line, r.col)
                return N("For", p, var=var, lo=r.lo, hi=r.hi, incl=r.incl, body=self.block())
            if v == "unsafe":
                self.i += 1
                return N("Unsafe", p, body=self.block())
            if v == "return":
                self.i += 1
                e = None if (self.isop(";") or self.isop("}") or self.isop(",")) else self.expr()
                return N("Return", p, e=e)
            if v == "break":
                self.i += 1
                return N("Break", p)
            if v == "continue":
                self.i += 1
                return N("Continue", p)
        if c.kind == "op":
            if c.val == "(":
                self.i += 1
                if self.accept_op(")"):
                    return N("Unit", p)
                saved, self.nostruct = self.nostruct, 0
                e = self.expr()
                self.nostruct = saved
                self.expect_op(")")
                return e
            if c.val == "{":
                saved, self.nostruct = self.nostruct, 0
                b = self.block()
                self.nostruct = saved
                return b
            if c.val == "[":
                self.i += 1
                saved, self.nostruct = self.nostruct, 0
                try:
                    if self.accept_op("]"):
                        raise SecError("empty array literals are not supported; use `Vec::new()`", p[0], p[1])
                    first = self.expr()
                    if self.accept_op(";"):
                        cnt = self.expr()
                        self.expect_op("]")
                        return N("ArrayRep", p, elem=first, count=cnt)
                    elems = [first]
                    while self.accept_op(","):
                        if self.isop("]"):
                            break
                        elems.append(self.expr())
                    self.expect_op("]")
                    return N("ArrayLit", p, elems=elems)
                finally:
                    self.nostruct = saved
        if c.kind == "ident":
            segs, targs = [c.val], None
            self.i += 1
            while self.isop("::"):
                self.i += 1
                if self.isop("<"):
                    self.i += 1
                    targs = self.type_args()
                    continue
                segs.append(self.ident())
            if len(segs) == 1 and segs[0][0].isupper() and self.isop("{") and not self.nostruct:
                return self.struct_lit(p, segs[0])
            if len(segs) == 1 and targs is None:
                return N("Var", p, name=segs[0])
            return N("Path", p, segs=segs, targs=targs)
        self.err(f"expected expression, found {self.describe()}")

    def struct_lit(self, p, name):
        self.expect_op("{")
        saved, self.nostruct = self.nostruct, 0
        fields = []
        while not self.isop("}"):
            fp = self.pos()
            fn = self.ident()
            self.expect_op(":")
            fields.append((fn, self.expr(), fp))
            if not self.accept_op(","):
                break
        self.nostruct = saved
        self.expect_op("}")
        return N("StructLit", p, name=name, fields=fields)

    def if_expr(self):
        p = self.pos()
        self.expect_kw("if")
        cond = self.cond()
        then = self.block()
        els = None
        if self.accept_kw("else"):
            els = self.if_expr() if self.iskw("if") else self.block()
        return N("If", p, cond=cond, then=then, els=els)

    def pattern(self):
        p = self.pos()
        pats = [self.pattern1()]
        while self.accept_op("|"):
            pats.append(self.pattern1())
        return pats

    def pattern1(self):
        c, p = self.cur, self.pos()
        if c.kind == "ident":
            if c.val == "_":
                self.i += 1
                return ("wild", p)
            if self.peek().kind == "op" and self.peek().val == "::":
                en = c.val
                self.i += 2
                return ("enum", p, en, self.ident())
            if c.val in ("Some", "Ok", "Err") and self.peek().kind == "op" and self.peek().val == "(":
                self.i += 2
                sub = self.pattern1()
                if sub[0] not in ("wild", "bind"):
                    raise SecError("only a binding or `_` is allowed inside `Some`/`Ok`/`Err` patterns", p[0], p[1])
                self.expect_op(")")
                return ("ctor", p, c.val, sub)
            if c.val == "None":
                self.i += 1
                return ("ctor", p, "None", None)
            self.i += 1
            return ("bind", p, c.val)
        if c.kind == "kw" and c.val in ("true", "false"):
            self.i += 1
            return ("lit", p, c.val == "true")
        neg = False
        if self.isop("-") and self.peek().kind == "int":
            neg = True
            self.i += 1
            c = self.cur
        if c.kind == "int":
            self.i += 1
            return ("lit", p, -c.val if neg else c.val)
        self.err(f"expected pattern, found {self.describe()}")

    def match_expr(self):
        p = self.pos()
        self.expect_kw("match")
        scrut = self.cond()
        self.expect_op("{")
        arms = []
        while not self.isop("}"):
            ap = self.pos()
            pats = self.pattern()
            self.expect_op("=>")
            body = self.expr_stmt()
            blocklike = body.k in BLOCKLIKE
            if body.k != "Block":
                body = N("Block", (body.line, body.col), stmts=[], tail=body)
            if not self.accept_op(",") and not (self.isop("}") or blocklike):
                self.err("expected `,` after match arm")
            arms.append((pats, body, ap))
        self.expect_op("}")
        return N("Match", p, scrut=scrut, arms=arms)


def parse(src):
    return Parser(lex(src)).program()
