"""Small immutable, backend-neutral IR shared by Secure native compiler stages."""
from dataclasses import dataclass


MAX_OUTPUT = 1 << 20
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1


@dataclass(frozen=True)
class IRValue:
    slot: int


@dataclass(frozen=True)
class IRConstI32:
    dest: int
    value: int


@dataclass(frozen=True)
class IRUnaryI32:
    dest: int
    op: str
    operand: IRValue


@dataclass(frozen=True)
class IRBinaryI32:
    dest: int
    op: str
    left: IRValue
    right: IRValue


@dataclass(frozen=True)
class IRWrite:
    data: bytes
    newline: bool


@dataclass(frozen=True)
class IRPrintI32:
    value: object
    newline: bool


@dataclass(frozen=True)
class IRLabel:
    label: int


@dataclass(frozen=True)
class IRJump:
    target: int


@dataclass(frozen=True)
class IRBranchI32:
    op: str
    left: IRValue
    right: IRValue
    if_true: int
    if_false: int


@dataclass(frozen=True)
class IRExit:
    status: int


@dataclass(frozen=True)
class IRProgram:
    instructions: tuple


def verify_ir(ir):
    """Validate typed slots, forward control-flow targets, and bounded output."""
    if type(ir) is not IRProgram or type(ir.instructions) is not tuple or not ir.instructions:
        raise ValueError("invalid native IR program")
    if type(ir.instructions[-1]) is not IRExit or type(ir.instructions[-1].status) is not int:
        raise ValueError("native IR must end in a valid exit instruction")
    if ir.instructions[-1].status != 0:
        raise ValueError("native IR currently supports only exit(0)")

    defined = set()
    labels = set()
    targets = []
    next_slot = 0
    total = 0
    for index, instruction in enumerate(ir.instructions):
        if type(instruction) is IRConstI32:
            if type(instruction.dest) is not int or instruction.dest != next_slot:
                raise ValueError("native IR slots must be defined once in increasing order")
            if type(instruction.value) is not int or not I32_MIN <= instruction.value <= I32_MAX:
                raise ValueError("native i32 constant is out of range")
            defined.add(instruction.dest)
            next_slot += 1
        elif type(instruction) is IRUnaryI32:
            if type(instruction.dest) is not int or instruction.dest != next_slot:
                raise ValueError("native IR slots must be defined once in increasing order")
            if instruction.op != "-" or type(instruction.operand) is not IRValue:
                raise ValueError("invalid native unary i32 operation")
            if type(instruction.operand.slot) is not int or instruction.operand.slot not in defined:
                raise ValueError("native IR uses an undefined i32 slot")
            defined.add(instruction.dest)
            next_slot += 1
        elif type(instruction) is IRBinaryI32:
            if type(instruction.dest) is not int or instruction.dest != next_slot:
                raise ValueError("native IR slots must be defined once in increasing order")
            if instruction.op not in ("+", "-", "*", "/", "%"):
                raise ValueError("unsupported native binary i32 operation")
            if type(instruction.left) is not IRValue or type(instruction.right) is not IRValue:
                raise ValueError("native binary operands must be i32 slot references")
            if (type(instruction.left.slot) is not int or instruction.left.slot not in defined
                    or type(instruction.right.slot) is not int or instruction.right.slot not in defined):
                raise ValueError("native IR uses an undefined i32 slot")
            defined.add(instruction.dest)
            next_slot += 1
        elif type(instruction) is IRBranchI32:
            if instruction.op not in ("==", "!=", "<", "<=", ">", ">="):
                raise ValueError("unsupported native i32 branch comparison")
            if type(instruction.left) is not IRValue or type(instruction.right) is not IRValue:
                raise ValueError("native branch operands must be i32 slot references")
            if (type(instruction.left.slot) is not int or instruction.left.slot not in defined
                    or type(instruction.right.slot) is not int or instruction.right.slot not in defined):
                raise ValueError("native branch uses an undefined i32 slot")
            for target in (instruction.if_true, instruction.if_false):
                if type(target) is not int or target < 0:
                    raise ValueError("invalid native branch target")
                targets.append(target)
        elif type(instruction) is IRLabel:
            if type(instruction.label) is not int or instruction.label < 0 or instruction.label in labels:
                raise ValueError("duplicate or invalid native IR label")
            labels.add(instruction.label)
        elif type(instruction) is IRJump:
            if type(instruction.target) is not int or instruction.target < 0:
                raise ValueError("invalid native jump target")
            targets.append(instruction.target)
        elif type(instruction) is IRWrite:
            if index == len(ir.instructions) - 1 or type(instruction.data) is not bytes:
                raise ValueError("invalid native write instruction")
            if type(instruction.newline) is not bool:
                raise ValueError("invalid native write newline flag")
            total += len(instruction.data) + int(instruction.newline)
        elif type(instruction) is IRPrintI32:
            if index == len(ir.instructions) - 1 or type(instruction.newline) is not bool:
                raise ValueError("invalid native i32 print instruction")
            if type(instruction.value) is int:
                if not I32_MIN <= instruction.value <= I32_MAX:
                    raise ValueError("native i32 print operand is out of range")
            elif type(instruction.value) is IRValue:
                if type(instruction.value.slot) is not int or instruction.value.slot not in defined:
                    raise ValueError("native print references an undefined i32 slot")
            else:
                raise ValueError("native i32 print operand must be an integer or slot reference")
            total += 11 + int(instruction.newline)
        elif type(instruction) is IRExit:
            if index != len(ir.instructions) - 1 or type(instruction.status) is not int or instruction.status != 0:
                raise ValueError("invalid or misplaced native exit instruction")
        else:
            raise ValueError("unknown native IR instruction")
        if total > MAX_OUTPUT:
            raise ValueError("native output exceeds the 1 MiB limit")
    if any(target not in labels for target in targets):
        raise ValueError("native IR branch references an undefined label")
    return total