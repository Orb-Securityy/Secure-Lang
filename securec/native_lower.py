"""Python bootstrap frontend/lowering for the restricted native Secure subset."""
from .ir import (IRBinaryI32, IRCallI32, IRCompareBranch, IRConstI32, IRExit, IRFunction, IRJump,
                 IRLabel, IRLocalI32, IRParamI32, IRPrintI32, IRProgram, IRReturnI32,
                 IRStoreI32, IRUnaryI32, IRValue, IRWrite, MAX_NATIVE_ARGS)
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


def _expression_kind(expr, bindings, constants, function_signatures=None):
    """Infer the restricted native subset type without evaluating runtime locals."""
    function_signatures = function_signatures or {}
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
        if _expression_kind(expr.e, bindings, constants, function_signatures) != "i32":
            _error("unary minus requires an i32 value", expr)
        return "i32"
    if expr.k == "Binary" and expr.op in ARITHMETIC:
        if (_expression_kind(expr.l, bindings, constants, function_signatures) != "i32"
                or _expression_kind(expr.r, bindings, constants, function_signatures) != "i32"):
            _error("native integer arithmetic requires two i32 operands", expr)
        return "i32"
    if expr.k == "Call":
        if expr.fn.k != "Var" or expr.fn.name not in function_signatures:
            _error("native expression calls must target a declared i32 function", expr)
        expected = function_signatures[expr.fn.name]
        if len(expr.args) != expected:
            _error(f"native function `{expr.fn.name}` expects {expected} argument(s)", expr)
        for argument in expr.args:
            if _expression_kind(argument, bindings, constants, function_signatures) != "i32":
                _error("native function arguments must be i32 values", argument)
        return "i32"
    _error("native subset supports only `str`, `i32`, checked arithmetic, and i32 function calls", expr)

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


def _lower_i32(expr, bindings, constants, instructions, next_slot, function_signatures=None):
    function_signatures = function_signatures or {}
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
        operand = _lower_i32(expr.e, bindings, constants, instructions, next_slot, function_signatures)
        dest = next_slot[0]
        next_slot[0] += 1
        instructions.append(IRUnaryI32(dest, "-", operand))
        return IRValue(dest)
    if expr.k == "Binary" and expr.op in ARITHMETIC:
        left = _lower_i32(expr.l, bindings, constants, instructions, next_slot, function_signatures)
        right = _lower_i32(expr.r, bindings, constants, instructions, next_slot, function_signatures)
        dest = next_slot[0]
        next_slot[0] += 1
        instructions.append(IRBinaryI32(dest, expr.op, left, right))
        return IRValue(dest)
    if expr.k == "Call":
        if expr.fn.k != "Var" or expr.fn.name not in function_signatures:
            _error("native expression calls must target a declared i32 function", expr)
        expected = function_signatures[expr.fn.name]
        if len(expr.args) != expected:
            _error(f"native function `{expr.fn.name}` expects {expected} argument(s)", expr)
        args = tuple(
            _lower_i32(argument, bindings, constants, instructions, next_slot, function_signatures)
            for argument in expr.args
        )
        dest = next_slot[0]
        next_slot[0] += 1
        instructions.append(IRCallI32(dest, expr.fn.name, args))
        return IRValue(dest)
    _error("unsupported runtime i32 expression", expr)

def lower_to_ir(items):
    """Type-check the native subset and lower main plus real i32 functions to verified IR."""
    raw_functions = {}
    constants = {}
    for item in items:
        if item.k == "Fn":
            if item.name in raw_functions or item.name in ("print", "println"):
                _error(f"duplicate or reserved native function `{item.name}`", item)
            raw_functions[item.name] = item
        elif item.k != "Const":
            _error("native subset accepts only constants and function declarations", item)

    main = raw_functions.get("main")
    if main is None:
        raise SecError("program has no `main` function", 1, 1)
    if main.params or main.ret is not None or main.unsafe or main.extern or main.body is None:
        _error("native backend requires a safe `fn main()` with no parameters or return type", main)

    function_signatures = {}
    for name, function in raw_functions.items():
        if name == "main":
            continue
        if function.unsafe or function.extern or function.body is None or not _is_i32_type(function.ret):
            _error("native user functions must be safe, defined, and return i32 explicitly", function)
        if len(function.params) > MAX_NATIVE_ARGS:
            _error(f"native functions support at most {MAX_NATIVE_ARGS} i32 parameters", function)
        seen_params = set()
        for parameter in function.params:
            if parameter.name in seen_params or not _is_i32_type(parameter.ty):
                _error("native function parameters must have unique names and type i32", parameter)
            seen_params.add(parameter.name)
        function_signatures[name] = len(function.params)

    for item in items:
        if item.k != "Const":
            continue
        if item.name in constants or item.name in raw_functions or item.name in ("print", "println"):
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

    ctx = None

    def new_label():
        label = ctx["next_label"][0]
        ctx["next_label"][0] += 1
        return label

    def lower_if(node, bindings):
        instructions = ctx["instructions"]
        next_slot = ctx["next_slot"]
        cond = node.cond
        if cond.k != "Binary" or cond.op not in COMPARISONS:
            _error("native `if` currently requires an i32 comparison", cond)
        if (_expression_kind(cond.l, bindings, constants, function_signatures) != "i32"
                or _expression_kind(cond.r, bindings, constants, function_signatures) != "i32"):
            _error("native `if` comparisons require two i32 operands", cond)
        left = _lower_i32(cond.l, bindings, constants, instructions, next_slot, function_signatures)
        right = _lower_i32(cond.r, bindings, constants, instructions, next_slot, function_signatures)
        then_label = new_label()
        end_label = new_label()
        else_label = new_label() if node.els is not None else end_label
        instructions.append(IRCompareBranch(left, cond.op, right, then_label, else_label))
        instructions.append(IRLabel(then_label))
        then_terminates = lower_block(node.then, bindings)
        if node.els is None:
            instructions.append(IRLabel(end_label))
            return False
        if not then_terminates:
            instructions.append(IRJump(end_label))
        instructions.append(IRLabel(else_label))
        if node.els.k == "Block":
            else_terminates = lower_block(node.els, bindings)
        elif node.els.k == "If":
            else_terminates = lower_if(node.els, bindings)
        else:
            _error("unsupported native `else` body", node.els)
        if then_terminates and else_terminates:
            return True
        instructions.append(IRLabel(end_label))
        return False

    def lower_while(node, bindings):
        instructions = ctx["instructions"]
        next_slot = ctx["next_slot"]
        cond_label = new_label()
        body_label = new_label()
        end_label = new_label()
        instructions.append(IRLabel(cond_label))
        cond = node.cond
        if cond.k != "Binary" or cond.op not in COMPARISONS:
            _error("native while conditions must compare two i32 values", cond)
        if (_expression_kind(cond.l, bindings, constants, function_signatures) != "i32"
                or _expression_kind(cond.r, bindings, constants, function_signatures) != "i32"):
            _error("native while comparisons require two i32 operands", cond)
        left = _lower_i32(cond.l, bindings, constants, instructions, next_slot, function_signatures)
        right = _lower_i32(cond.r, bindings, constants, instructions, next_slot, function_signatures)
        instructions.append(IRCompareBranch(left, cond.op, right, body_label, end_label))
        instructions.append(IRLabel(body_label))
        ctx["loop_stack"].append([cond_label, end_label, False])
        body_terminates = lower_block(node.body, bindings)
        ctx["loop_stack"].pop()
        if not body_terminates:
            instructions.append(IRJump(cond_label))
        instructions.append(IRLabel(end_label))
        return False

    def lower_for(node, bindings):
        instructions = ctx["instructions"]
        next_slot = ctx["next_slot"]
        if node.var in bindings or node.var in constants or node.var in ("print", "println"):
            _error(f"duplicate, reserved, or shadowed native loop variable `{node.var}`", node)
        if (_expression_kind(node.lo, bindings, constants, function_signatures) != "i32"
                or _expression_kind(node.hi, bindings, constants, function_signatures) != "i32"):
            _error("native for bounds must be i32 values", node)
        lower = _lower_i32(node.lo, bindings, constants, instructions, next_slot, function_signatures)
        upper = _lower_i32(node.hi, bindings, constants, instructions, next_slot, function_signatures)
        counter_slot = next_slot[0]
        next_slot[0] += 1
        instructions.append(IRLocalI32(counter_slot, lower))
        limit_slot = next_slot[0]
        next_slot[0] += 1
        instructions.append(IRLocalI32(limit_slot, upper))
        counter = IRValue(counter_slot)
        limit = IRValue(limit_slot)
        cond_label = new_label()
        body_label = new_label()
        step_label = new_label()
        end_label = new_label()
        instructions.append(IRLabel(cond_label))
        instructions.append(IRCompareBranch(counter, "<=" if node.incl else "<", limit, body_label, end_label))
        instructions.append(IRLabel(body_label))
        body_bindings = dict(bindings)
        body_bindings[node.var] = ("i32", counter)
        frame = [step_label, end_label, False]
        ctx["loop_stack"].append(frame)
        body_terminates = lower_block(node.body, body_bindings)
        ctx["loop_stack"].pop()
        if body_terminates and not frame[2]:
            instructions.append(IRLabel(end_label))
            return
        if not body_terminates:
            instructions.append(IRJump(step_label))
        instructions.append(IRLabel(step_label))
        if node.incl:
            increment_label = new_label()
            instructions.append(IRCompareBranch(counter, "==", limit, end_label, increment_label))
            instructions.append(IRLabel(increment_label))
        one_slot = next_slot[0]
        next_slot[0] += 1
        instructions.append(IRConstI32(one_slot, 1))
        sum_slot = next_slot[0]
        next_slot[0] += 1
        instructions.append(IRBinaryI32(sum_slot, "+", counter, IRValue(one_slot)))
        instructions.append(IRStoreI32(counter_slot, IRValue(sum_slot)))
        instructions.append(IRJump(cond_label))
        instructions.append(IRLabel(end_label))

    def lower_print(call, bindings):
        instructions = ctx["instructions"]
        next_slot = ctx["next_slot"]
        if call.fn.k != "Var" or call.fn.name not in ("print", "println"):
            _error("native print statement must call `print` or `println`", call)
        for arg in call.args:
            kind = _expression_kind(arg, bindings, constants, function_signatures)
            if kind == "str":
                value = _resolve_static_value(arg, bindings, constants)[1]
                if value:
                    instructions.append(IRWrite(value, False))
            else:
                value = _lower_i32(arg, bindings, constants, instructions, next_slot, function_signatures)
                instructions.append(IRPrintI32(value, False))
        if call.fn.name == "println":
            instructions.append(IRWrite(b"", True))

    def lower_return(node, bindings):
        if not ctx["allow_return"]:
            _error("native `return` is only supported inside an i32 function", node)
        if node.e is None or _expression_kind(
                node.e, bindings, constants, function_signatures) != "i32":
            _error("native functions must return an i32 expression", node)
        value = _lower_i32(node.e, bindings, constants, ctx["instructions"],
                           ctx["next_slot"], function_signatures)
        ctx["instructions"].append(IRReturnI32(value))

    def lower_block(block, outer_bindings):
        if block.tail is not None and block.tail.k not in ("If", "While", "For", "Return"):
            _error("native blocks only support if/while/for and return as tail expressions", block)
        bindings = dict(outer_bindings)
        terminated = False
        for stmt_index, stmt in enumerate(block.stmts):
            if stmt.k == "Let":
                if (stmt.name in bindings or stmt.name in constants
                        or stmt.name in raw_functions or stmt.name in ("print", "println")):
                    _error(f"duplicate, reserved, or shadowed native binding `{stmt.name}`", stmt)
                inferred = _expression_kind(stmt.init, bindings, constants, function_signatures)
                declared = _declared_kind(stmt.ty, stmt) if stmt.ty is not None else inferred
                if declared != inferred:
                    _error("native binding type does not match its initializer", stmt)
                if declared == "str":
                    if stmt.mut:
                        _error("native subset supports mutable i32 locals only", stmt)
                    value = _resolve_static_value(stmt.init, bindings, constants)
                    bindings[stmt.name] = value
                else:
                    value = _lower_i32(stmt.init, bindings, constants, ctx["instructions"],
                                       ctx["next_slot"], function_signatures)
                    if stmt.mut:
                        dest = ctx["next_slot"][0]
                        ctx["next_slot"][0] += 1
                        ctx["instructions"].append(IRLocalI32(dest, value))
                        bindings[stmt.name] = ("i32", IRValue(dest), True)
                    else:
                        bindings[stmt.name] = ("i32", value)
            elif stmt.k == "ExprStmt" and stmt.e.k == "Call":
                if stmt.e.fn.k == "Var" and stmt.e.fn.name in ("print", "println"):
                    lower_print(stmt.e, bindings)
                else:
                    _lower_i32(stmt.e, bindings, constants, ctx["instructions"],
                               ctx["next_slot"], function_signatures)
            elif stmt.k == "ExprStmt" and stmt.e.k == "Assign":
                assignment = stmt.e
                if assignment.target.k != "Var":
                    _error("native assignment target must be a local variable", assignment.target)
                binding = bindings.get(assignment.target.name)
                if binding is None or binding[0] != "i32" or len(binding) < 3 or binding[2] is not True:
                    _error("native assignment requires a mutable i32 local or parameter", assignment.target)
                destination = binding[1]
                if type(destination) is not IRValue:
                    _error("invalid native mutable local slot", assignment.target)
                if assignment.op == "=":
                    source = _lower_i32(assignment.value, bindings, constants, ctx["instructions"],
                                        ctx["next_slot"], function_signatures)
                else:
                    compound_ops = {"+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%"}
                    if assignment.op not in compound_ops:
                        _error("native mutable i32 supports only =, +=, -=, *=, /=, and %=", assignment)
                    if _expression_kind(assignment.value, bindings, constants, function_signatures) != "i32":
                        _error("native compound assignment requires an i32 value", assignment.value)
                    right = _lower_i32(assignment.value, bindings, constants, ctx["instructions"],
                                       ctx["next_slot"], function_signatures)
                    dest = ctx["next_slot"][0]
                    ctx["next_slot"][0] += 1
                    ctx["instructions"].append(IRBinaryI32(dest, compound_ops[assignment.op], destination, right))
                    source = IRValue(dest)
                ctx["instructions"].append(IRStoreI32(destination.slot, source))
            elif stmt.k == "ExprStmt" and stmt.e.k == "If":
                terminated = lower_if(stmt.e, bindings)
                if terminated:
                    if stmt_index != len(block.stmts) - 1 or block.tail is not None:
                        _error("unreachable statement after a terminating if", stmt)
                    break
            elif stmt.k == "ExprStmt" and stmt.e.k == "While":
                lower_while(stmt.e, bindings)
            elif stmt.k == "ExprStmt" and stmt.e.k == "For":
                lower_for(stmt.e, bindings)
            elif stmt.k == "ExprStmt" and stmt.e.k in ("Break", "Continue"):
                if not ctx["loop_stack"]:
                    _error("native break/continue must appear inside a loop", stmt.e)
                continue_label, end_label, _ = ctx["loop_stack"][-1]
                if stmt.e.k == "Continue":
                    ctx["loop_stack"][-1][2] = True
                ctx["instructions"].append(IRJump(end_label if stmt.e.k == "Break" else continue_label))
                terminated = True
                if stmt_index != len(block.stmts) - 1 or block.tail is not None:
                    _error("unreachable statement after break/continue", stmt)
                break
            elif stmt.k == "ExprStmt" and stmt.e.k == "Return":
                lower_return(stmt.e, bindings)
                terminated = True
                if stmt_index != len(block.stmts) - 1 or block.tail is not None:
                    _error("unreachable statement after return", stmt)
                break
            else:
                _error("native subset supports bindings, assignments, calls, print, control flow, and return", stmt)

        if not terminated and block.tail is not None:
            if block.tail.k == "If":
                terminated = lower_if(block.tail, bindings)
            elif block.tail.k == "While":
                terminated = lower_while(block.tail, bindings)
            elif block.tail.k == "For":
                lower_for(block.tail, bindings)
            elif block.tail.k == "Return":
                lower_return(block.tail, bindings)
                terminated = True
        return terminated

    # Compile the entry function first; its calls may refer forward to any declaration.
    ctx = {"instructions": [], "next_slot": [0], "next_label": [0],
           "loop_stack": [], "allow_return": False}
    lower_block(main.body, {})
    main_instructions = tuple(ctx["instructions"] + [IRExit(0)])

    lowered_functions = []
    for name, function in raw_functions.items():
        if name == "main":
            continue
        ctx = {"instructions": [], "next_slot": [0], "next_label": [0],
               "loop_stack": [], "allow_return": True}
        bindings = {}
        for index, parameter in enumerate(function.params):
            slot = ctx["next_slot"][0]
            ctx["next_slot"][0] += 1
            ctx["instructions"].append(IRParamI32(slot, index, parameter.mut))
            bindings[parameter.name] = ("i32", IRValue(slot), parameter.mut)
        terminated = lower_block(function.body, bindings)
        if not terminated:
            _error(f"native function `{name}` can reach its end without returning i32", function)
        lowered_functions.append(IRFunction(name, len(function.params), tuple(ctx["instructions"])))

    return IRProgram(main_instructions, tuple(lowered_functions))


def compile_native_subset(source):
    """Parse, lower, verify, and emit native ELF with the Python bootstrap frontend."""
    try:
        items = parse(source)
        ir = lower_to_ir(items)
        return emit_native(ir)
    except RecursionError as exc:
        raise SecError("source nesting exceeds the native backend limit", 0, 0) from exc
