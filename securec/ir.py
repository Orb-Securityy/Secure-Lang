"""Small immutable, backend-neutral IR shared by Secure native compiler stages."""
from dataclasses import dataclass


MAX_OUTPUT = 1 << 20
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1


@dataclass(frozen=True)
class IRWrite:
    data: bytes
    newline: bool


@dataclass(frozen=True)
class IRPrintI32:
    value: int
    newline: bool


@dataclass(frozen=True)
class IRExit:
    status: int


@dataclass(frozen=True)
class IRProgram:
    instructions: tuple


def verify_ir(ir):
    """Validate the IR contract and bound the maximum stdout byte count."""
    if type(ir) is not IRProgram or type(ir.instructions) is not tuple or not ir.instructions:
        raise ValueError("invalid native IR program")
    if type(ir.instructions[-1]) is not IRExit or type(ir.instructions[-1].status) is not int:
        raise ValueError("native IR must end in a valid exit instruction")
    if ir.instructions[-1].status != 0:
        raise ValueError("native IR currently supports only exit(0)")
    total = 0
    for index, instruction in enumerate(ir.instructions):
        if type(instruction) is IRWrite:
            if index == len(ir.instructions) - 1 or type(instruction.data) is not bytes:
                raise ValueError("invalid native write instruction")
            if type(instruction.newline) is not bool:
                raise ValueError("invalid native write newline flag")
            total += len(instruction.data) + int(instruction.newline)
        elif type(instruction) is IRPrintI32:
            if index == len(ir.instructions) - 1 or type(instruction.value) is not int:
                raise ValueError("invalid native i32 print instruction")
            if not I32_MIN <= instruction.value <= I32_MAX or type(instruction.newline) is not bool:
                raise ValueError("native i32 print operand is out of range")
            total += 11 + int(instruction.newline)
        elif type(instruction) is IRExit:
            if index != len(ir.instructions) - 1 or type(instruction.status) is not int or instruction.status != 0:
                raise ValueError("invalid or misplaced native exit instruction")
        else:
            raise ValueError("unknown native IR instruction")
        if total > MAX_OUTPUT:
            raise ValueError("native output exceeds the 1 MiB limit")
    return total