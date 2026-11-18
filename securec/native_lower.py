"""Python bootstrap frontend/lowering for the restricted native Secure subset."""
from .ir import (IRBinaryI32, IRCompareBranch, IRConstI32, IRExit, IRJump, IRLabel,
                 IRPrintI32, IRProgram, IRUnaryI32, IRValue, IRWrite)
from .lexer import SecError
from .native_x86_64 import emit_native
from .parser import parse


I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
ARITHMETIC = ("+", "-", "*", "/", "%")
COMPARISONS = ("==", "!=", "<", "<=", ">", ">=")


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
    """Return a statically known value: (str, bytes) or (i32, int)."""
    if expr.k == "Str":
        return ("str", expr.val)
    if expr.k == "Int":
        if expr.suf not in (None, "i32"):
            _error("native subset currently supports only i32 integer literals", expr)
        return ("i32", _checked_i32(expr.val, expr))
    if expr.k == "Var":
        if expr.name in bindings:
            value = bindings[expr.name]
        elif expr.name in constants:
            value = constants[expr.name]
        else:
            _error(f"unknown native variable `{expr.name}`", expr)
        if value[0] == "i32" and type(value[1]) is not int:
            _error("runtime i32 value is not a compile-time constant", expr)
        return value
    if expr.k == "Unary" and expr.op == "-":
        if expr.e.k == "Int":
            if expr.e.suf not in (None, "i32"):
                _error("native subset currently supports only i32 integer literals", expr.e)
            return ("i32", _checked_i32(-expr.e.val, expr))
        kind, value = _resolve_static_value(expr.e, bindings, constants)
        if kind != "i32":
            _error("unary minus requires an i32 value", expr)
        return ("i32", _checked_i32(-value, expr))
    if expr.k == "Binary" and expr.op in ARITHMETIC:
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


def _expression_kind(expr, bindings, constants):
    """Infer the restricted native subset type without evaluating runtime locals."""
    if expr.k == "Str":
        return "str"
    if expr.k == "Int":
        if expr.suf not in (None, "i32"):
            _error("native subset currently supports only i32 integer literals", expr)
        _checked_i32(expr.val, expr)
        return "i32"
    if expr.k == "Var":
        if expr.name in bindings:
            return bindings[expr.name][0]
        if expr.name in constants:
            return constants[expr.name][0]
        _error(f"unknown native variable `{expr.name}`", expr)
    if expr.k == "Unary" and expr.op == "-":
        if expr.e.k == "Int":
            if expr.e.suf not in (None, "i32"):
                _error("native subset currently supports only i32 integer literals", expr.e)
            _checked_i32(-expr.e.val, expr)
            return "i32"
        if _expression_kind(expr.e, bindings, constants) != "i32":
            _error("unary minus requires an i32 value", expr)
        return "i32"
    if expr.k == "Binary" and expr.op in ARITHMETIC:
        if (_expression_kind(expr.l, bindings, constants) != "i32"
                or _expression_kind(expr.r, bindings, constants) != "i32"):
            _error("native integer arithmetic requires two i32 operands", expr)
        return "i32"
    _error("native subset supports only `str`, `i32`, and checked i32 arithmetic", expr)


def _can_resolve_static(expr, bindings, constants):
    if expr.k in ("Str", "Int"):
        return True
    if expr.k == "Var":
        value = bindings.get(expr.name, constants.get(expr.name))
        return value is not None and (value[0] == "str" or type(value[1]) is int)
    if expr.k == "Unary" and expr.op == "-":
        return _can_resolve_static(expr.e, bindings, constants)
    if expr.k == "Binary" and expr.op in ARITHMETIC:
        return (_can_resolve_static(expr.l, bindings, constants)
                and _can_resolve_static(expr.r, bindings, constants))
    return False


def _declared_kind(type_node, owner):
    if _is_str_type(type_node):
        return "str"
    if _is_i32_type(type_node):
        return "i32"
    _error("native subset supports only `str` and `i32` declarations", owner)


def _emit_const(value, instructions, next_slot):
    slot = next_slot[0]
    next_slot[0] += 1
    instructions.append(IRConstI32(slot, value))
    return IRValue(slot)


def _lower_i32(expr, bindings, constants, instructions, next_slot):
    if _can_resolve_static(expr, bindings, constants):
        kind, value = _resolve_static_value(expr, bindings, constants)
        if kind != "i32":
            _error("expected an i32 expression", expr)
        return _emit_const(value, instructions, next_slot)
    if expr.k == "Var":
        value = bindings.get(expr.name)
        if value is None or value[0] != "i32" or type(value[1]) is not IRValue:
            _error("native i32 variable is unavailable", expr)
        return value[1]
    if expr.k == "Unary" and expr.op == "-":
        operand = _lower_i32(expr.e, bindings, constants, instructions, next_slot)
        dest = next_slot[0]
        next_slot[0] += 1
        instructions.append(IRUnaryI32(dest, "-", operand))
        return IRValue(dest)
    if expr.k == "Binary" and expr.op in ARITHMETIC:
        left = _lower_i32(expr.l, bindings, constants, instructions, next_slot)
        right = _lower_i32(expr.r, bindings, constants, instructions, next_slot)
        dest = next_slot[0]
        next_slot[0] += 1
        instructions.append(IRBinaryI32(dest, expr.op, left, right))
        return IRValue(dest)
    _error("unsupported runtime i32 expression", expr)


def lower_to_ir(items):
    """Type-check native str/i32 code and lower expressions and conditionals to IR."""
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
    instructions = []
    next_slot = [0]
    next_label = [0]

    def new_label():
        label = next_label[0]
        next_label[0] += 1
        return label

    def lower_if(node, bindings):
        cond = node.cond
        if cond.k != "Binary" or cond.op not in COMPARISONS:
            _error("native `if` currently requires an i32 comparison", cond)
        if (_expression_kind(cond.l, bindings, constants) != "i32"
                or _expression_kind(cond.r, bindings, constants) != "i32"):
            _error("native `if` comparisons require two i32 operands", cond)
        left = _lower_i32(cond.l, bindings, constants, instructions, next_slot)
        right = _lower_i32(cond.r, bindings, constants, instructions, next_slot)
        then_label = new_label()
        end_label = new_label()
        else_label = new_label() if node.els is not None else end_label
        instructions.append(IRCompareBranch(left, cond.op, right, then_label, else_label))
        instructions.append(IRLabel(then_label))
        lower_block(node.then, bindings)
        if node.els is not None:
            instructions.append(IRJump(end_label))
            instructions.append(IRLabel(else_label))
            if node.els.k == "Block":
                lower_block(node.els, bindings)
            elif node.els.k == "If":
                lower_if(node.els, bindings)
            else:
                _error("unsupported native `else` body", node.els)
        instructions.append(IRLabel(end_label))

    def lower_print(call, bindings):
        if call.fn.k != "Var" or call.fn.name not in ("print", "println"):
            _error("native subset supports only `print` and `println`", call)
        for arg in call.args:
            kind = _expression_kind(arg, bindings, constants)
            if kind == "str":
                value = _resolve_static_value(arg, bindings, constants)[1]
                if value:
                    instructions.append(IRWrite(value, False))
            else:
                value = _lower_i32(arg, bindings, constants, instructions, next_slot)
                instructions.append(IRPrintI32(value, False))
        if call.fn.name == "println":
            instructions.append(IRWrite(b"", True))

    def lower_block(block, outer_bindings):
        if block.tail is not None and block.tail.k != "If":
            _error("native blocks only support `if` as a tail expression", block)
        bindings = dict(outer_bindings)
        for stmt in block.stmts:
            if stmt.k == "Let":
                if stmt.mut:
                    _error("native subset accepts only immutable `let` bindings", stmt)
                if stmt.name in bindings or stmt.name in constants or stmt.name in ("print", "println"):
                    _error(f"duplicate, reserved, or shadowed native binding `{stmt.name}`", stmt)
                inferred = _expression_kind(stmt.init, bindings, constants)
                declared = _declared_kind(stmt.ty, stmt) if stmt.ty is not None else inferred
                if declared != inferred:
                    _error("native binding type does not match its initializer", stmt)
                if declared == "str":
                    value = _resolve_static_value(stmt.init, bindings, constants)
                    bindings[stmt.name] = value
                else:
                    value = _lower_i32(stmt.init, bindings, constants, instructions, next_slot)
                    bindings[stmt.name] = ("i32", value)
            elif stmt.k == "ExprStmt" and stmt.e.k == "Call":
                lower_print(stmt.e, bindings)
            elif stmt.k == "ExprStmt" and stmt.e.k == "If":
                lower_if(stmt.e, bindings)
            else:
                _error("native subset supports only immutable bindings, print calls, and if/else", stmt)
        if block.tail is not None:
            lower_if(block.tail, bindings)

    lower_block(main.body, {})
    instructions.append(IRExit(0))
    return IRProgram(tuple(instructions))


def compile_native_subset(source):
    """Parse, lower, verify, and emit a native ELF with the Python bootstrap frontend."""
    try:
        items = parse(source)
        ir = lower_to_ir(items)
        return emit_native(ir)
    except RecursionError as exc:
        raise SecError("source nesting exceeds the native backend limit", 0, 0) from exc