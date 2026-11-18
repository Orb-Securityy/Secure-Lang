"""Python bootstrap frontend/lowering for the restricted native Secure subset."""
from .ir import IRExit, IRProgram, IRWrite
from .lexer import SecError
from .native_x86_64 import emit_native
from .parser import parse


I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1


def _error(message, node):
    raise SecError(message, getattr(node, "line", 1), getattr(node, "col", 1))


def _is_str_type(node):
    return node is not None and node.k == "TName" and node.name == "str" and not node.args


def _is_i32_type(node):
    return node is not None and node.k == "TName" and node.name == "i32" and not node.args


def _checked_i32(value, node):
    if not I32_MIN <= value <= I32_MAX:
        _error("i32 arithmetic overflow in native constant expression", node)
    return value


def _resolve_static_value(expr, bindings, constants):
    """Return a typed compile-time value: (str, bytes) or (i32, int)."""
    if expr.k == "Str":
        return ("str", expr.val)
    if expr.k == "Int":
        if expr.suf not in (None, "i32"):
            _error("native subset currently supports only i32 integer literals", expr)
        return ("i32", _checked_i32(expr.val, expr))
    if expr.k == "Var":
        if expr.name in bindings:
            return bindings[expr.name]
        if expr.name in constants:
            return constants[expr.name]
    if expr.k == "Unary" and expr.op == "-":
        if expr.e.k == "Int":
            if expr.e.suf not in (None, "i32"):
                _error("native subset currently supports only i32 integer literals", expr.e)
            return ("i32", _checked_i32(-expr.e.val, expr))
        kind, value = _resolve_static_value(expr.e, bindings, constants)
        if kind != "i32":
            _error("unary minus requires an i32 value", expr)
        return ("i32", _checked_i32(-value, expr))
    if expr.k == "Binary" and expr.op in ("+", "-", "*", "/", "%"):
        left_kind, left = _resolve_static_value(expr.l, bindings, constants)
        right_kind, right = _resolve_static_value(expr.r, bindings, constants)
        if left_kind != "i32" or right_kind != "i32":
            _error("native integer arithmetic requires two i32 operands", expr)
        if expr.op == "+":
            value = left + right
        elif expr.op == "-":
            value = left - right
        elif expr.op == "*":
            value = left * right
        else:
            if right == 0:
                _error("division by zero in native constant expression", expr)
            if left == I32_MIN and right == -1:
                _error("i32 arithmetic overflow in native constant expression", expr)
            quotient = abs(left) // abs(right) * (1 if (left < 0) == (right < 0) else -1)
            value = quotient if expr.op == "/" else left - quotient * right
        return ("i32", _checked_i32(value, expr))
    _error("native subset requires a statically known `str` or `i32` value", expr)


def _declared_kind(type_node, owner):
    if _is_str_type(type_node):
        return "str"
    if _is_i32_type(type_node):
        return "i32"
    _error("native subset supports only `str` and `i32` declarations", owner)


def lower_to_ir(items):
    """Type-check static str/i32 values and lower print calls into immutable IR."""
    constants = {}
    main = None
    for item in items:
        if item.k == "Const":
            if item.name in constants or item.name in ("main", "print", "println"):
                _error(f"duplicate or reserved native constant `{item.name}`", item)
            kind = _declared_kind(item.ty, item)
            if kind == "str":
                if item.e.k != "Str":
                    _error("native string constants must use a string literal", item.e)
                value = ("str", item.e.val)
            else:
                value = _resolve_static_value(item.e, {}, constants)
                if value[0] != "i32":
                    _error("i32 constant initializer must have type i32", item.e)
            constants[item.name] = value
        elif item.k == "Fn" and item.name == "main" and main is None:
            main = item
        else:
            _error("native subset accepts only `str`/`i32` constants and one `fn main()`", item)
    if main is None:
        raise SecError("program has no `main` function", 1, 1)
    if main.params or main.ret is not None or main.unsafe or main.extern or main.body is None:
        _error("native backend requires a safe `fn main()` with no parameters or return type", main)
    if main.body.tail is not None:
        _error("native backend requires a statement-only `main` body", main.body)

    bindings = {}
    instructions = []
    for stmt in main.body.stmts:
        if stmt.k == "Let":
            if stmt.mut:
                _error("native subset accepts only immutable `let` bindings", stmt)
            if stmt.name in bindings or stmt.name in constants or stmt.name in ("print", "println"):
                _error(f"duplicate, reserved, or shadowed native binding `{stmt.name}`", stmt)
            value = _resolve_static_value(stmt.init, bindings, constants)
            if stmt.ty is not None and _declared_kind(stmt.ty, stmt) != value[0]:
                _error("native binding type does not match its initializer", stmt)
            bindings[stmt.name] = value
            continue
        if stmt.k != "ExprStmt" or stmt.e.k != "Call":
            _error("native subset supports only immutable bindings and print calls", stmt)
        call = stmt.e
        if call.fn.k != "Var" or call.fn.name not in ("print", "println"):
            _error("native subset supports only `print` and `println`", call)
        output = bytearray()
        for arg in call.args:
            kind, value = _resolve_static_value(arg, bindings, constants)
            output += value if kind == "str" else str(value).encode("ascii")
        instructions.append(IRWrite(bytes(output), call.fn.name == "println"))
    instructions.append(IRExit(0))
    return IRProgram(tuple(instructions))


def compile_native_subset(source):
    """Parse, lower to verified IR, and emit a native ELF with the bootstrap frontend."""
    try:
        items = parse(source)
    except RecursionError as exc:
        raise SecError("source nesting exceeds the native backend limit", 0, 0) from exc
    return emit_native(lower_to_ir(items))