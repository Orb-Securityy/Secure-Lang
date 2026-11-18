"""Python bootstrap lowering for the restricted static-string native subset."""
from .ir import IRExit, IRProgram, IRWrite
from .lexer import SecError
from .native_x86_64 import emit_native
from .parser import parse


def _error(message, node):
    raise SecError(message, getattr(node, "line", 1), getattr(node, "col", 1))


def _is_str_type(node):
    return node is not None and node.k == "TName" and node.name == "str" and not node.args


def _resolve_static_str(expr, bindings, constants):
    if expr.k == "Str":
        return expr.val
    if expr.k == "Var":
        if expr.name in bindings:
            return bindings[expr.name]
        if expr.name in constants:
            return constants[expr.name]
    _error("native subset requires a statically known `str` value", expr)


def lower_to_ir(items):
    """Type-check the supported static-string subset and lower it to immutable IR."""
    constants = {}
    main = None
    for item in items:
        if item.k == "Const":
            if item.name in constants or item.name in ("main", "print", "println"):
                _error(f"duplicate or reserved native constant `{item.name}`", item)
            if not _is_str_type(item.ty) or item.e.k != "Str":
                _error("native subset supports only `const NAME: str = literal;`", item)
            constants[item.name] = item.e.val
        elif item.k == "Fn" and item.name == "main" and main is None:
            main = item
        else:
            _error("native subset accepts only `str` constants and one `fn main()`", item)
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
            if stmt.name in bindings or stmt.name in constants:
                _error(f"duplicate or shadowed native binding `{stmt.name}`", stmt)
            if stmt.ty is not None and not _is_str_type(stmt.ty):
                _error("native subset variables must have type `str`", stmt.ty)
            bindings[stmt.name] = _resolve_static_str(stmt.init, bindings, constants)
            continue
        if stmt.k != "ExprStmt" or stmt.e.k != "Call":
            _error("native subset supports only `str` bindings and print calls", stmt)
        call = stmt.e
        if call.fn.k != "Var" or call.fn.name not in ("print", "println"):
            _error("native subset supports only `print` and `println`", call)
        payload = b"".join(_resolve_static_str(arg, bindings, constants) for arg in call.args)
        instructions.append(IRWrite(payload, call.fn.name == "println"))
    instructions.append(IRExit(0))
    return IRProgram(tuple(instructions))


def compile_native_subset(source):
    """Parse, lower to verified IR, and emit a native ELF with the bootstrap frontend."""
    try:
        items = parse(source)
    except RecursionError as exc:
        raise SecError("source nesting exceeds the native backend limit", 0, 0) from exc
    ir = lower_to_ir(items)
    return emit_native(ir)