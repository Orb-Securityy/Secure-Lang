"""Atheris target for Secure's native lowering, IR verifier, and ELF writer.

Expected rejections are limited to Secure diagnostics and explicit validation
errors. Unexpected Python exceptions must escape so Atheris reports defects.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import atheris

with atheris.instrument_imports():
    import struct
    from securec.ir import (
        MAX_OUTPUT, IRBinaryI32, IRCallI32, IRCompareBranch, IRConstI32, IRExit,
        IRFunction, IRJump, IRLabel, IRLocalI32, IRParamI32, IRPrintI32,
        IRProgram, IRReturnI32, IRStoreI32, IRUnaryI32, IRValue, IRWrite,
    )
    from securec.lexer import SecError
    from securec.native_lower import compile_native_subset
    from securec.native_x86_64 import CODE_OFFSET, MAX_NATIVE_CODE, emit_native

MAX_INPUT_BYTES = 16 * 1024
MAX_IR_INSTRUCTIONS = 24
MAX_IR_PAYLOAD = 256


def _byte(data: bytes, index: int) -> int:
    return data[index % len(data)] if data else 0


def _i32(data: bytes, index: int) -> int:
    raw = bytes(_byte(data, index + offset) for offset in range(4))
    return struct.unpack("<i", raw)[0]


def _value(data: bytes, index: int):
    if _byte(data, index) & 1:
        return IRValue(_i32(data, index + 1))
    return _i32(data, index + 1)


def _random_instruction(data: bytes, offset: int):
    opcode = _byte(data, offset) % 14
    a = _i32(data, offset + 1)
    b = _i32(data, offset + 5)
    c = _byte(data, offset + 9)
    value_a = IRValue(a)
    value_b = IRValue(b)
    if opcode == 0:
        return IRConstI32(a, b)
    if opcode == 1:
        size = _byte(data, offset + 10) % (MAX_IR_PAYLOAD + 1)
        start = offset + 11
        payload = bytes(_byte(data, start + i) for i in range(size))
        return IRWrite(payload, bool(c & 1))
    if opcode == 2:
        return IRPrintI32(_value(data, offset + 1), bool(c & 1))
    if opcode == 3:
        return IRLabel(a)
    if opcode == 4:
        return IRJump(a)
    if opcode == 5:
        operators = ("==", "!=", "<", "<=", ">", ">=", "invalid")
        return IRCompareBranch(value_a, operators[c % len(operators)], value_b, a, b)
    if opcode == 6:
        return IRLocalI32(a, value_b)
    if opcode == 7:
        return IRStoreI32(a, value_b)
    if opcode == 8:
        return IRUnaryI32(a, "-" if c & 1 else "invalid", value_b)
    if opcode == 9:
        operators = ("+", "-", "*", "/", "%", "&")
        return IRBinaryI32(a, operators[c % len(operators)], value_a, value_b)
    if opcode == 10:
        return IRParamI32(a, b, bool(c & 1))
    if opcode == 11:
        argc = c % 8
        args = tuple(IRValue(_i32(data, offset + 10 + i * 4)) for i in range(argc))
        return IRCallI32(a, "f", args)
    if opcode == 12:
        return IRReturnI32(value_a)
    return "unknown-instruction"


def _validate_elf(image: bytes) -> None:
    """Require the exact static-PIE segment contract emitted by this backend."""
    if len(image) < 64 or image[:4] != b"\x7fELF":
        raise AssertionError("native emitter returned a truncated ELF image")
    if image[4:7] != bytes((2, 1, 1)):
        raise AssertionError("native emitter returned an unexpected ELF class or encoding")
    elf_type, machine = struct.unpack_from("<HH", image, 16)
    if (elf_type, machine) != (3, 62):
        raise AssertionError("native emitter returned the wrong ELF target")
    entry = struct.unpack_from("<Q", image, 24)[0]
    phoff = struct.unpack_from("<Q", image, 32)[0]
    ehsize = struct.unpack_from("<H", image, 52)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    if ehsize != 64 or phoff != 64 or phentsize != 56:
        raise AssertionError("native emitter returned a malformed ELF header")
    if phnum not in (2, 3) or phoff + phentsize * phnum > len(image):
        raise AssertionError("native emitter returned an invalid program-header table")
    if entry != 0x1000:
        raise AssertionError("native ELF entrypoint is not the backend entry offset")

    code_found = False
    code_segment_filesz = 0
    data_found = False
    stack_found = False
    for index in range(phnum):
        header = struct.unpack_from("<IIQQQQQQ", image, phoff + index * phentsize)
        kind, flags, offset, vaddr, paddr, filesz, memsz, align = header
        if kind == 1:
            if offset + filesz > len(image) or filesz > memsz:
                raise AssertionError("native ELF segment exceeds the file bounds")
            if align != 0x1000 or offset % align != vaddr % align:
                raise AssertionError("native ELF load segment has invalid alignment")
            if offset == 0:
                if code_found or flags != 5 or vaddr != 0 or paddr != 0:
                    raise AssertionError("native ELF code segment is not exactly RX")
                if filesz != memsz or not CODE_OFFSET < filesz <= CODE_OFFSET + MAX_NATIVE_CODE:
                    raise AssertionError("native ELF code segment has invalid size")
                if not vaddr <= entry < vaddr + memsz:
                    raise AssertionError("native ELF entrypoint is outside RX code")
                code_found = True
                code_segment_filesz = filesz
            elif code_found:
                expected_data_offset = (code_segment_filesz + 0xFFF) & ~0xFFF
                if (data_found or offset != expected_data_offset or flags != 4
                        or vaddr != expected_data_offset or paddr != expected_data_offset):
                    raise AssertionError("native ELF data segment is not exactly R-only after code")
                if not filesz or filesz != memsz or filesz > MAX_OUTPUT:
                    raise AssertionError("native ELF read-only data segment has invalid size")
                data_found = True
            else:
                raise AssertionError("native ELF contains a data segment before code")
        elif kind == 0x6474E551:
            if stack_found or flags != 6 or offset or vaddr or paddr or filesz or memsz or align != 16:
                raise AssertionError("native ELF stack segment is not exactly RW/NX")
            stack_found = True
        else:
            raise AssertionError("native ELF contains an unsupported program header")
    if not code_found or not stack_found or data_found != (phnum == 3):
        raise AssertionError("native ELF segment table does not match the static-PIE contract")


def _fuzz_ir(data: bytes) -> None:
    count = 1 + (_byte(data, 1) % MAX_IR_INSTRUCTIONS)
    instructions = tuple(_random_instruction(data, 2 + i * 13) for i in range(count))
    status = _i32(data, 2 + count * 13)
    if _byte(data, 0) & 4:
        param_count = _byte(data, 3) % 36
        function = IRFunction(
            "f" if _byte(data, 4) & 1 else "",
            param_count,
            instructions,
        )
        program = IRProgram((IRExit(0),), (function,))
    else:
        program = IRProgram(instructions + (IRExit(status),))
    try:
        image = emit_native(program)
    except ValueError:
        return
    _validate_elf(image)


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    if len(data) > MAX_INPUT_BYTES or not data:
        return
    payload = data[1:]
    if data[0] & 1:
        try:
            source = payload.decode("utf-8")
        except UnicodeDecodeError:
            return
        try:
            image = compile_native_subset(source)
        except (SecError, ValueError, OverflowError):
            return
        max_data_offset = (CODE_OFFSET + MAX_NATIVE_CODE + 0xFFF) & ~0xFFF
        if len(image) > max_data_offset + MAX_OUTPUT:
            raise AssertionError("native compiler emitted an oversized image")
        _validate_elf(image)
    else:
        _fuzz_ir(payload)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
