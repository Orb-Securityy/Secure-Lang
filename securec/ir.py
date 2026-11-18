"""Small immutable, backend-neutral IR shared by Secure native compiler stages."""
from collections import deque
from dataclasses import dataclass


MAX_OUTPUT = 1 << 20
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
COMPARE_OPS = ("==", "!=", "<", "<=", ">", ">=")
MAX_NATIVE_ARGS = 32
MAX_NATIVE_FUNCTIONS = 128
MAX_NATIVE_CONSTANTS = 512
MAX_NATIVE_INSTRUCTIONS = 2048
MAX_NATIVE_ARRAYS = 32
MAX_NATIVE_ARRAY_LENGTH = 65536
MAX_NATIVE_ARRAY_BYTES = 1 << 16


@dataclass(frozen=True)
class IRValue:
    slot: int


@dataclass(frozen=True)
class IRConstI32:
    dest: int
    value: int


@dataclass(frozen=True)
class IRParamI32:
    dest: int
    index: int
    mutable: bool = False


@dataclass(frozen=True)
class IRLocalI32:
    dest: int
    initial: IRValue


@dataclass(frozen=True)
class IRStoreI32:
    dest: int
    value: IRValue


@dataclass(frozen=True)
class IRArrayCreate:
    array_id: int
    length: int
    element_size: int
    mutable: bool
    initial: IRValue


@dataclass(frozen=True)
class IRArrayLoadI32:
    dest: int
    array_id: int
    index: IRValue


@dataclass(frozen=True)
class IRArrayStoreI32:
    array_id: int
    index: IRValue
    value: IRValue


@dataclass(frozen=True)
class IRReadByte:
    """Read one byte from stdin; returns 0..255 or -1 at EOF."""
    dest: int


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
class IRCallI32:
    dest: int
    function: str
    args: tuple


@dataclass(frozen=True)
class IRReturnI32:
    value: IRValue


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
class IRFunction:
    name: str
    param_count: int
    instructions: tuple


@dataclass(frozen=True)
class IRProgram:
    instructions: tuple
    functions: tuple = ()


def verify_ir(ir):
    """Validate every native function's slots, calls, CFG, and definite assignment."""
    if type(ir) is not IRProgram or type(ir.instructions) is not tuple or not ir.instructions:
        raise ValueError("invalid native IR program")
    if type(ir.functions) is not tuple:
        raise ValueError("native IR functions must be a tuple")
    if len(ir.instructions) > MAX_NATIVE_INSTRUCTIONS:
        raise ValueError("native IR exceeds the instruction limit")
    if len(ir.functions) > MAX_NATIVE_FUNCTIONS:
        raise ValueError("native IR exceeds the function limit")

    total_instructions = len(ir.instructions)
    functions = {}
    for function in ir.functions:
        if (type(function) is not IRFunction or type(function.name) is not str
                or not function.name or function.name == "main"
                or type(function.param_count) is not int
                or not 0 <= function.param_count <= MAX_NATIVE_ARGS
                or type(function.instructions) is not tuple or not function.instructions):
            raise ValueError("invalid native IR function")
        if function.name in functions:
            raise ValueError("duplicate native IR function")
        total_instructions += len(function.instructions)
        if total_instructions > MAX_NATIVE_INSTRUCTIONS:
            raise ValueError("native IR exceeds the total instruction limit")
        functions[function.name] = function

    signatures = {name: function.param_count for name, function in functions.items()}
    output_size = [0]

    def verify_stream(instructions, is_entry, param_count):
        if type(instructions) is not tuple or not instructions:
            raise ValueError("native IR stream must not be empty")
        if is_entry:
            if type(instructions[-1]) is not IRExit or type(instructions[-1].status) is not int:
                raise ValueError("native entry IR must end in a valid exit instruction")
            if instructions[-1].status != 0:
                raise ValueError("native IR currently supports only exit(0)")
        elif not any(type(ins) is IRReturnI32 for ins in instructions):
            raise ValueError("native function must return an i32 value")

        labels = {}
        definitions = [set() for _ in instructions]
        uses = [set() for _ in instructions]
        array_definitions = [set() for _ in instructions]
        array_uses = [set() for _ in instructions]
        arrays = {}
        array_bytes = 0
        next_slot = 0
        mutable_slots = set()
        expected_param = 0
        non_param_seen = False

        for index, instruction in enumerate(instructions):
            if type(instruction) is IRLabel:
                if (type(instruction.label) is not int or instruction.label < 0
                        or instruction.label in labels):
                    raise ValueError("invalid or duplicate native IR label")
                labels[instruction.label] = index
            elif type(instruction) is IRParamI32:
                if (is_entry or non_param_seen or type(instruction.dest) is not int
                        or instruction.dest != next_slot or type(instruction.index) is not int
                        or instruction.index != expected_param or instruction.index >= param_count
                        or type(instruction.mutable) is not bool):
                    raise ValueError("invalid or misplaced native i32 parameter")
                definitions[index].add(instruction.dest)
                if instruction.mutable:
                    mutable_slots.add(instruction.dest)
                next_slot += 1
                expected_param += 1
            elif type(instruction) is IRConstI32:
                non_param_seen = True
                if type(instruction.dest) is not int or instruction.dest != next_slot:
                    raise ValueError("native IR slots must be defined once in increasing order")
                if type(instruction.value) is not int or not I32_MIN <= instruction.value <= I32_MAX:
                    raise ValueError("native i32 constant is out of range")
                definitions[index].add(instruction.dest)
                next_slot += 1
            elif type(instruction) is IRLocalI32:
                non_param_seen = True
                if type(instruction.dest) is not int or instruction.dest != next_slot:
                    raise ValueError("native IR slots must be defined once in increasing order")
                if type(instruction.initial) is not IRValue or type(instruction.initial.slot) is not int:
                    raise ValueError("native mutable local requires an initialized i32 slot")
                uses[index].add(instruction.initial.slot)
                definitions[index].add(instruction.dest)
                mutable_slots.add(instruction.dest)
                next_slot += 1
            elif type(instruction) is IRStoreI32:
                non_param_seen = True
                if type(instruction.dest) is not int or instruction.dest not in mutable_slots:
                    raise ValueError("native IR may only assign to a declared mutable local")
                if type(instruction.value) is not IRValue or type(instruction.value.slot) is not int:
                    raise ValueError("native mutable assignment requires an i32 slot reference")
                uses[index].update((instruction.dest, instruction.value.slot))
            elif type(instruction) is IRArrayCreate:
                non_param_seen = True
                if (type(instruction.array_id) is not int or instruction.array_id != len(arrays)
                        or type(instruction.length) is not int or not 1 <= instruction.length <= MAX_NATIVE_ARRAY_LENGTH
                        or type(instruction.element_size) is not int or instruction.element_size not in (1, 4)
                        or type(instruction.mutable) is not bool
                        or type(instruction.initial) is not IRValue
                        or type(instruction.initial.slot) is not int):
                    raise ValueError("invalid native fixed-array declaration")
                array_bytes += instruction.length * instruction.element_size
                if len(arrays) + 1 > MAX_NATIVE_ARRAYS or array_bytes > MAX_NATIVE_ARRAY_BYTES:
                    raise ValueError("native fixed arrays exceed their count or stack-byte budget")
                arrays[instruction.array_id] = (
                    instruction.length, instruction.element_size, instruction.mutable
                )
                array_definitions[index].add(instruction.array_id)
                uses[index].add(instruction.initial.slot)
            elif type(instruction) is IRArrayLoadI32:
                non_param_seen = True
                if type(instruction.dest) is not int or instruction.dest != next_slot:
                    raise ValueError("native array-load result slot must be defined in sequence")
                if (type(instruction.array_id) is not int or instruction.array_id not in arrays
                        or type(instruction.index) is not IRValue
                        or type(instruction.index.slot) is not int):
                    raise ValueError("native array load references an invalid array or index")
                array_uses[index].add(instruction.array_id)
                uses[index].add(instruction.index.slot)
                definitions[index].add(instruction.dest)
                next_slot += 1
            elif type(instruction) is IRArrayStoreI32:
                non_param_seen = True
                if type(instruction.array_id) is not int or instruction.array_id not in arrays:
                    raise ValueError("native array store references an unknown array")
                if not arrays[instruction.array_id][2]:
                    raise ValueError("native IR may only store to a mutable fixed array")
                if (type(instruction.index) is not IRValue or type(instruction.index.slot) is not int
                        or type(instruction.value) is not IRValue or type(instruction.value.slot) is not int):
                    raise ValueError("native array store requires valid index and value slots")
                array_uses[index].add(instruction.array_id)
                uses[index].update((instruction.index.slot, instruction.value.slot))
            elif type(instruction) is IRReadByte:
                non_param_seen = True
                if type(instruction.dest) is not int or instruction.dest != next_slot:
                    raise ValueError("native read-byte result slot must be defined in sequence")
                definitions[index].add(instruction.dest)
                next_slot += 1
            elif type(instruction) is IRUnaryI32:
                non_param_seen = True
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
                non_param_seen = True
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
            elif type(instruction) is IRCallI32:
                non_param_seen = True
                if type(instruction.dest) is not int or instruction.dest != next_slot:
                    raise ValueError("native call result slot must be defined in sequence")
                if type(instruction.function) is not str or instruction.function not in signatures:
                    raise ValueError("native call references an unknown function")
                if type(instruction.args) is not tuple or len(instruction.args) != signatures[instruction.function]:
                    raise ValueError("native call argument count does not match its function")
                for argument in instruction.args:
                    if type(argument) is not IRValue or type(argument.slot) is not int:
                        raise ValueError("native call arguments must be i32 slot references")
                    uses[index].add(argument.slot)
                definitions[index].add(instruction.dest)
                next_slot += 1
            elif type(instruction) is IRReturnI32:
                non_param_seen = True
                if is_entry or type(instruction.value) is not IRValue or type(instruction.value.slot) is not int:
                    raise ValueError("invalid native i32 return instruction")
                uses[index].add(instruction.value.slot)
            elif type(instruction) is IRWrite:
                non_param_seen = True
                if type(instruction.data) is not bytes or type(instruction.newline) is not bool:
                    raise ValueError("invalid native write instruction")
                output_size[0] += len(instruction.data) + int(instruction.newline)
            elif type(instruction) is IRPrintI32:
                non_param_seen = True
                if type(instruction.newline) is not bool:
                    raise ValueError("invalid native i32 print instruction")
                if type(instruction.value) is int:
                    if not I32_MIN <= instruction.value <= I32_MAX:
                        raise ValueError("native i32 print operand is out of range")
                elif type(instruction.value) is IRValue and type(instruction.value.slot) is int:
                    uses[index].add(instruction.value.slot)
                else:
                    raise ValueError("native i32 print operand must be an integer or slot reference")
                output_size[0] += 11 + int(instruction.newline)
            elif type(instruction) is IRJump:
                non_param_seen = True
                if type(instruction.target) is not int or instruction.target < 0:
                    raise ValueError("invalid native jump target")
            elif type(instruction) is IRCompareBranch:
                non_param_seen = True
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
                non_param_seen = True
                if (not is_entry or index != len(instructions) - 1
                        or type(instruction.status) is not int or instruction.status != 0):
                    raise ValueError("invalid or misplaced native exit instruction")
            else:
                raise ValueError("unknown native IR instruction")

            if output_size[0] > MAX_OUTPUT:
                raise ValueError("native output exceeds the 1 MiB limit")

        if expected_param != param_count:
            raise ValueError("native function parameter layout is incomplete")

        for instruction in instructions:
            if type(instruction) is IRJump and instruction.target not in labels:
                raise ValueError("native jump references an undefined label")
            if type(instruction) is IRCompareBranch:
                if instruction.true_target not in labels or instruction.false_target not in labels:
                    raise ValueError("native conditional branch references an undefined label")

        successors = [[] for _ in instructions]
        predecessors = [[] for _ in instructions]
        for index, instruction in enumerate(instructions):
            if type(instruction) in (IRExit, IRReturnI32):
                targets = []
            elif type(instruction) is IRJump:
                targets = [labels[instruction.target]]
            elif type(instruction) is IRCompareBranch:
                targets = [labels[instruction.true_target], labels[instruction.false_target]]
            else:
                if index + 1 >= len(instructions):
                    raise ValueError("native IR falls through without an exit or return")
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

        # Forward must-analysis. Start non-entry nodes at TOP (all slots);
        # the empty entry state then monotonically removes slots not defined on
        # every path. Only successors of changed nodes need to be revisited.
        all_slots = set(range(next_slot))
        all_arrays = set(arrays)
        in_sets = [set(all_slots) for _ in instructions]
        out_sets = [set(all_slots) for _ in instructions]
        in_arrays = [set(all_arrays) for _ in instructions]
        out_arrays = [set(all_arrays) for _ in instructions]
        in_sets[0] = set()
        out_sets[0] = set(definitions[0])
        in_arrays[0] = set()
        out_arrays[0] = set(array_definitions[0])
        worklist = deque(successors[0])
        queued = set(worklist)
        while worklist:
            index = worklist.popleft()
            queued.discard(index)
            # The entry has an implicit predecessor carrying the empty
            # state. A back-edge to instruction zero must never erase that
            # initial-path fact.
            if index == 0:
                incoming = set()
                incoming_arrays = set()
            else:
                pred_states = [out_sets[pred] for pred in predecessors[index]]
                pred_array_states = [out_arrays[pred] for pred in predecessors[index]]
                incoming = (set.intersection(*pred_states) if pred_states else set())
                incoming_arrays = (
                    set.intersection(*pred_array_states) if pred_array_states else set()
                )
            outgoing = incoming | definitions[index]
            outgoing_arrays = incoming_arrays | array_definitions[index]
            if (incoming != in_sets[index] or outgoing != out_sets[index]
                    or incoming_arrays != in_arrays[index] or outgoing_arrays != out_arrays[index]):
                in_sets[index] = incoming
                out_sets[index] = outgoing
                in_arrays[index] = incoming_arrays
                out_arrays[index] = outgoing_arrays
                for successor in successors[index]:
                    if successor not in queued:
                        queued.add(successor)
                        worklist.append(successor)

        for index in sorted(reachable):
            if not uses[index].issubset(in_sets[index]):
                raise ValueError("native IR uses an undefined i32 value on at least one control-flow path")
            if not array_uses[index].issubset(in_arrays[index]):
                raise ValueError("native IR uses a fixed array before it is initialized on every control-flow path")

    verify_stream(ir.instructions, True, 0)
    for function in ir.functions:
        verify_stream(function.instructions, False, function.param_count)
    return output_size[0]
