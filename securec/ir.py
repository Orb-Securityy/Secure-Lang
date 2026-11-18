"""Small immutable, backend-neutral IR shared by Secure native compiler stages."""
from dataclasses import dataclass


MAX_OUTPUT = 1 << 20
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
COMPARE_OPS = ("==", "!=", "<", "<=", ">", ">=")


@dataclass(frozen=True)
class IRValue:
    slot: int


@dataclass(frozen=True)
class IRConstI32:
    dest: int
    value: int


@dataclass(frozen=True)
class IRLocalI32:
    dest: int
    initial: IRValue


@dataclass(frozen=True)
class IRStoreI32:
    dest: int
    value: IRValue


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
class IRCompareBranch:
    left: IRValue
    op: str
    right: IRValue
    true_target: int
    false_target: int


@dataclass(frozen=True)
class IRExit:
    status: int


@dataclass(frozen=True)
class IRProgram:
    instructions: tuple


def verify_ir(ir):
    """Validate SSA-like slots, control-flow labels, definite assignment, and output bounds."""
    if type(ir) is not IRProgram or type(ir.instructions) is not tuple or not ir.instructions:
        raise ValueError("invalid native IR program")
    if type(ir.instructions[-1]) is not IRExit or type(ir.instructions[-1].status) is not int:
        raise ValueError("native IR must end in a valid exit instruction")
    if ir.instructions[-1].status != 0:
        raise ValueError("native IR currently supports only exit(0)")

    instructions = ir.instructions
    labels = {}
    definitions = [set() for _ in instructions]
    uses = [set() for _ in instructions]
    output_size = 0
    next_slot = 0
    mutable_slots = set()

    for index, instruction in enumerate(instructions):
        if type(instruction) is IRLabel:
            if type(instruction.label) is not int or instruction.label < 0 or instruction.label in labels:
                raise ValueError("invalid or duplicate native IR label")
            labels[instruction.label] = index
        elif type(instruction) is IRConstI32:
            if type(instruction.dest) is not int or instruction.dest != next_slot:
                raise ValueError("native IR slots must be defined once in increasing order")
            if type(instruction.value) is not int or not I32_MIN <= instruction.value <= I32_MAX:
                raise ValueError("native i32 constant is out of range")
            definitions[index].add(instruction.dest)
            next_slot += 1
        elif type(instruction) is IRLocalI32:
            if type(instruction.dest) is not int or instruction.dest != next_slot:
                raise ValueError("native IR slots must be defined once in increasing order")
            if type(instruction.initial) is not IRValue or type(instruction.initial.slot) is not int:
                raise ValueError("native mutable local requires an initialized i32 slot")
            uses[index].add(instruction.initial.slot)
            definitions[index].add(instruction.dest)
            mutable_slots.add(instruction.dest)
            next_slot += 1
        elif type(instruction) is IRStoreI32:
            if type(instruction.dest) is not int or instruction.dest not in mutable_slots:
                raise ValueError("native IR may only assign to a declared mutable local")
            if type(instruction.value) is not IRValue or type(instruction.value.slot) is not int:
                raise ValueError("native mutable assignment requires an i32 slot reference")
            uses[index].update((instruction.dest, instruction.value.slot))
        elif type(instruction) is IRUnaryI32:
            if type(instruction.dest) is not int or instruction.dest != next_slot:
                raise ValueError("native IR slots must be defined once in increasing order")
            if instruction.op != "-" or type(instruction.operand) is not IRValue:
                raise ValueError("invalid native unary i32 operation")
            if type(instruction.operand.slot) is not int:
                raise ValueError("invalid native i32 slot reference")
            uses[index].add(instruction.operand.slot)
            definitions[index].add(instruction.dest)
            next_slot += 1
        elif type(instruction) is IRBinaryI32:
            if type(instruction.dest) is not int or instruction.dest != next_slot:
                raise ValueError("native IR slots must be defined once in increasing order")
            if instruction.op not in ("+", "-", "*", "/", "%"):
                raise ValueError("unsupported native binary i32 operation")
            if type(instruction.left) is not IRValue or type(instruction.right) is not IRValue:
                raise ValueError("native binary operands must be i32 slot references")
            if type(instruction.left.slot) is not int or type(instruction.right.slot) is not int:
                raise ValueError("invalid native i32 slot reference")
            uses[index].update((instruction.left.slot, instruction.right.slot))
            definitions[index].add(instruction.dest)
            next_slot += 1
        elif type(instruction) is IRWrite:
            if index == len(instructions) - 1 or type(instruction.data) is not bytes:
                raise ValueError("invalid native write instruction")
            if type(instruction.newline) is not bool:
                raise ValueError("invalid native write newline flag")
            output_size += len(instruction.data) + int(instruction.newline)
        elif type(instruction) is IRPrintI32:
            if index == len(instructions) - 1 or type(instruction.newline) is not bool:
                raise ValueError("invalid native i32 print instruction")
            if type(instruction.value) is int:
                if not I32_MIN <= instruction.value <= I32_MAX:
                    raise ValueError("native i32 print operand is out of range")
            elif type(instruction.value) is IRValue and type(instruction.value.slot) is int:
                uses[index].add(instruction.value.slot)
            else:
                raise ValueError("native i32 print operand must be an integer or slot reference")
            output_size += 11 + int(instruction.newline)
        elif type(instruction) is IRLabel:
            pass
        elif type(instruction) is IRJump:
            if type(instruction.target) is not int or instruction.target < 0:
                raise ValueError("invalid native jump target")
        elif type(instruction) is IRCompareBranch:
            if instruction.op not in COMPARE_OPS:
                raise ValueError("unsupported native comparison operator")
            if type(instruction.left) is not IRValue or type(instruction.right) is not IRValue:
                raise ValueError("native branch operands must be i32 slot references")
            if type(instruction.left.slot) is not int or type(instruction.right.slot) is not int:
                raise ValueError("invalid native branch operand slot")
            if (type(instruction.true_target) is not int or instruction.true_target < 0
                    or type(instruction.false_target) is not int or instruction.false_target < 0):
                raise ValueError("invalid native conditional target")
            uses[index].update((instruction.left.slot, instruction.right.slot))
        elif type(instruction) is IRExit:
            if index != len(instructions) - 1 or type(instruction.status) is not int or instruction.status != 0:
                raise ValueError("invalid or misplaced native exit instruction")
        else:
            raise ValueError("unknown native IR instruction")
        if output_size > MAX_OUTPUT:
            raise ValueError("native output exceeds the 1 MiB limit")

    for instruction in instructions:
        if type(instruction) is IRJump and instruction.target not in labels:
            raise ValueError("native jump references an undefined label")
        if type(instruction) is IRCompareBranch:
            if instruction.true_target not in labels or instruction.false_target not in labels:
                raise ValueError("native conditional branch references an undefined label")

    successors = [[] for _ in instructions]
    predecessors = [[] for _ in instructions]
    for index, instruction in enumerate(instructions):
        if type(instruction) is IRExit:
            targets = []
        elif type(instruction) is IRJump:
            targets = [labels[instruction.target]]
        elif type(instruction) is IRCompareBranch:
            targets = [labels[instruction.true_target], labels[instruction.false_target]]
        else:
            if index + 1 >= len(instructions):
                raise ValueError("native IR falls through without an exit")
            targets = [index + 1]
        successors[index] = targets
        for target in targets:
            predecessors[target].append(index)

    reachable = set()
    pending = [0]
    while pending:
        index = pending.pop()
        if index in reachable:
            continue
        reachable.add(index)
        pending.extend(successors[index])
    if len(reachable) != len(instructions):
        raise ValueError("native IR contains unreachable instructions")

    all_slots = set(range(next_slot))
    in_sets = [set(all_slots) for _ in instructions]
    out_sets = [set(all_slots) for _ in instructions]
    in_sets[0] = set()
    changed = True
    while changed:
        changed = False
        for index in sorted(reachable):
            if index == 0:
                incoming = set()  # function entry is an additional predecessor with no values
            else:
                incoming = set.intersection(*(out_sets[pred] for pred in predecessors[index]))
            outgoing = incoming | definitions[index]
            if incoming != in_sets[index] or outgoing != out_sets[index]:
                in_sets[index], out_sets[index] = incoming, outgoing
                changed = True

    for index in sorted(reachable):
        if not uses[index].issubset(in_sets[index]):
            raise ValueError("native IR uses an undefined i32 value on at least one control-flow path")
    return output_size