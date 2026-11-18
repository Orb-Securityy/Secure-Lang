"""Direct x86-64 Linux ELF backend for verified Secure IR.

This backend has no dependency on the Secure lexer, parser, Python compiler, C emitter,
assembler, linker, or C runtime. It consumes only the shared immutable IR contract.
"""
import struct

from .ir import (IRBinaryI32, IRBranchI32, IRConstI32, IRExit, IRJump, IRLabel, IRPrintI32, IRUnaryI32,
                 IRValue, IRWrite, MAX_OUTPUT, verify_ir)


ELF_BASE = 0  # position-independent image; Linux chooses the load base
CODE_OFFSET = 0x1000
DATA_OFFSET = 0x2000
MAX_STACK_FRAME = 1 << 20


def _patch_rel8(code, branch, target):
    displacement = target - (branch + 2)
    if not -128 <= displacement <= 127:
        raise ValueError("native short branch is out of range")
    code[branch + 1] = displacement & 0xFF


def _patch_rel32(code, position, target):
    displacement = target - (position + 4)
    if not -(1 << 31) <= displacement < (1 << 31):
        raise ValueError("native relative branch is out of range")
    code[position:position + 4] = struct.pack("<i", displacement)


def _emit_jcc32(code, opcode, fixups):
    code.extend((0x0F, opcode))
    fixups.append(len(code))
    code.extend(bytes(4))


def _emit_jmp32(code, fixups):
    code.append(0xE9)
    fixups.append(len(code))
    code.extend(bytes(4))


def _emit_call(code, fixups):
    code.append(0xE8)
    fixups.append(len(code))
    code.extend(bytes(4))


def _slot_disp(slot):
    if type(slot) is not int or slot < 0:
        raise ValueError("invalid native i32 slot")
    offset = 32 + slot * 4
    if offset > MAX_STACK_FRAME - 4:
        raise ValueError("native stack frame exceeds its limit")
    return offset


def _emit_load_eax(code, slot):
    code.extend(bytes.fromhex("8b8424"))
    code.extend(struct.pack("<I", _slot_disp(slot)))


def _emit_load_ecx(code, slot):
    code.extend(bytes.fromhex("8b8c24"))
    code.extend(struct.pack("<I", _slot_disp(slot)))


def _emit_store_eax(code, slot):
    code.extend(bytes.fromhex("898424"))
    code.extend(struct.pack("<I", _slot_disp(slot)))


def _emit_i32_formatter(code, value, newline, call_fixups):
    """Emit signed-i32 decimal conversion using a 32-byte stack buffer."""
    if type(value) is IRValue:
        _emit_load_eax(code, value.slot)
    elif type(value) is int:
        code.append(0xB8)
        code.extend(struct.pack("<i", value))
    else:
        raise ValueError("invalid native i32 print operand")
    code.extend(bytes.fromhex("41b8"))
    code.extend(bytes(4))                     # mov r8d, 0 (negative flag)
    code.extend(bytes.fromhex("85c0"))       # test eax, eax
    sign_branch = len(code)
    code.extend((0x79, 0))                    # jns positive
    code.extend(bytes.fromhex("f7d8"))       # neg eax (0x80000000 remains unsigned magnitude)
    code.extend(bytes.fromhex("41b8"))
    code.extend(struct.pack("<I", 1))        # mov r8d, 1 (negative)
    positive = len(code)
    _patch_rel8(code, sign_branch, positive)

    code.extend(bytes.fromhex("488d74241f")) # lea rsi, [rsp + 31]
    code.extend(bytes.fromhex("41b9"))
    code.extend(bytes(4))                     # mov r9d, 0 (output length)
    if newline:
        code.extend(bytes.fromhex("c6060a")) # mov byte [rsi], newline
        code.extend(bytes.fromhex("48ffce")) # dec rsi
        code.extend(bytes.fromhex("41ffc1")) # inc r9d
    loop_label = len(code)
    code.extend(bytes.fromhex("31d2"))       # xor edx, edx
    code.append(0xB9)
    code.extend(struct.pack("<I", 10))       # mov ecx, 10
    code.extend(bytes.fromhex("f7f1"))       # div ecx (unsigned magnitude)
    code.extend(bytes.fromhex("80c230"))     # add dl, '0'
    code.extend(bytes.fromhex("8816"))       # mov byte [rsi], dl
    code.extend(bytes.fromhex("48ffce"))     # dec rsi
    code.extend(bytes.fromhex("41ffc1"))     # inc r9d
    code.extend(bytes.fromhex("85c0"))       # test eax, eax
    digit_branch = len(code)
    code.extend((0x75, 0))                    # jnz digit loop
    _patch_rel8(code, digit_branch, loop_label)

    code.extend(bytes.fromhex("4585c0"))     # test r8d, r8d
    sign_skip = len(code)
    code.extend((0x74, 0))                    # jz no sign
    code.extend(bytes.fromhex("c6062d"))     # mov byte [rsi], '-'
    code.extend(bytes.fromhex("48ffce"))     # dec rsi
    code.extend(bytes.fromhex("41ffc1"))     # inc r9d
    no_sign = len(code)
    _patch_rel8(code, sign_skip, no_sign)
    code.extend(bytes.fromhex("48ffc6"))     # inc rsi to first output byte
    code.extend(bytes.fromhex("4489ca"))     # mov edx, r9d
    _emit_call(code, call_fixups)


def _emit_checked_arithmetic(code, instruction, trap_fixups):
    if type(instruction) is IRUnaryI32:
        _emit_load_eax(code, instruction.operand.slot)
        code.extend(bytes.fromhex("3d00000080"))  # cmp eax, INT32_MIN
        _emit_jcc32(code, 0x84, trap_fixups)       # je panic
        code.extend(bytes.fromhex("f7d8"))        # neg eax
        _emit_store_eax(code, instruction.dest)
        return

    if type(instruction) is not IRBinaryI32:
        raise ValueError("unknown native arithmetic IR instruction")
    _emit_load_eax(code, instruction.left.slot)
    _emit_load_ecx(code, instruction.right.slot)
    if instruction.op == "+":
        code.extend(bytes.fromhex("01c8"))        # add eax, ecx
        _emit_jcc32(code, 0x80, trap_fixups)       # jo panic
    elif instruction.op == "-":
        code.extend(bytes.fromhex("29c8"))        # sub eax, ecx
        _emit_jcc32(code, 0x80, trap_fixups)       # jo panic
    elif instruction.op == "*":
        code.extend(bytes.fromhex("0fafc1"))      # imul eax, ecx
        _emit_jcc32(code, 0x80, trap_fixups)       # jo panic
    elif instruction.op in ("/", "%"):
        code.extend(bytes.fromhex("85c9"))        # test ecx, ecx
        _emit_jcc32(code, 0x84, trap_fixups)       # jz panic
        code.extend(bytes.fromhex("3d00000080"))  # cmp eax, INT32_MIN
        skip_min_check = []
        _emit_jcc32(code, 0x85, skip_min_check)    # jne safe
        code.extend(bytes.fromhex("83f9ff"))      # cmp ecx, -1
        _emit_jcc32(code, 0x85, skip_min_check)    # jne safe
        _emit_jmp32(code, trap_fixups)             # INT32_MIN / -1 panics
        safe = len(code)
        for position in skip_min_check:
            _patch_rel32(code, position, safe)
        code.extend(bytes.fromhex("99"))          # cdq
        code.extend(bytes.fromhex("f7f9"))        # idiv ecx
        if instruction.op == "%":
            code.extend(bytes.fromhex("89d0"))    # mov eax, edx (remainder)
    else:
        raise ValueError("unsupported native i32 arithmetic operator")
    _emit_store_eax(code, instruction.dest)


def _emit_program_code(ir):
    code = bytearray()
    rodata = bytearray()
    call_fixups = []
    lea_fixups = []
    trap_fixups = []
    needs_write_helper = False
    label_offsets = {}
    control_fixups = []
    slot_count = sum(type(ins) in (IRConstI32, IRUnaryI32, IRBinaryI32) for ins in ir.instructions)
    needs_stack_buffer = any(type(ins) is IRPrintI32 for ins in ir.instructions)
    frame_size = 0
    if slot_count or needs_stack_buffer:
        frame_size = ((32 + slot_count * 4 + 15) // 16) * 16
        if frame_size > MAX_STACK_FRAME:
            raise ValueError("native stack frame exceeds its limit")
        code.extend(bytes.fromhex("4881ec"))      # sub rsp, imm32
        code.extend(struct.pack("<I", frame_size))

    for instruction in ir.instructions:
        if type(instruction) is IRConstI32:
            code.extend(bytes.fromhex("c78424"))
            code.extend(struct.pack("<I", _slot_disp(instruction.dest)))
            code.extend(struct.pack("<i", instruction.value))
        elif type(instruction) in (IRUnaryI32, IRBinaryI32):
            _emit_checked_arithmetic(code, instruction, trap_fixups)
        elif type(instruction) is IRWrite:
            output = instruction.data + (b"\n" if instruction.newline else b"")
            if not output:
                continue
            data_offset = len(rodata)
            rodata.extend(output)
            code.extend(bytes.fromhex("488d35"))
            lea_fixups.append((len(code), data_offset))
            code.extend(bytes(4))
            code.append(0xBA)                   # mov edx, imm32
            code.extend(struct.pack("<I", len(output)))
            _emit_call(code, call_fixups)
            needs_write_helper = True
        elif type(instruction) is IRPrintI32:
            _emit_i32_formatter(code, instruction.value, instruction.newline, call_fixups)
            needs_write_helper = True
        elif type(instruction) is IRBranchI32:
            _emit_load_eax(code, instruction.left.slot)
            _emit_load_ecx(code, instruction.right.slot)
            code.extend(bytes.fromhex("39c8"))  # cmp eax, ecx
            condition_codes = {"==": 0x84, "!=": 0x85, "<": 0x8C,
                               "<=": 0x8E, ">": 0x8F, ">=": 0x8D}
            branch_fixups = []
            _emit_jcc32(code, condition_codes[instruction.op], branch_fixups)
            control_fixups.append((branch_fixups[0], instruction.if_true))
            jump_fixups = []
            _emit_jmp32(code, jump_fixups)
            control_fixups.append((jump_fixups[0], instruction.if_false))
        elif type(instruction) is IRJump:
            jump_fixups = []
            _emit_jmp32(code, jump_fixups)
            control_fixups.append((jump_fixups[0], instruction.target))
        elif type(instruction) is IRLabel:
            if instruction.label in label_offsets:
                raise ValueError("duplicate native code label")
            label_offsets[instruction.label] = len(code)
        elif type(instruction) is IRExit:
            continue  # verify_ir requires this to be the final instruction
        else:
            raise ValueError("unknown native IR instruction")

    code.extend(bytes.fromhex("b83c00000031ff0f05"))  # exit(0)
    if needs_write_helper:
        helper = len(code)
        loop = helper
        code.extend(bytes.fromhex("b801000000"))  # mov eax, 1 (write)
        code.extend(bytes.fromhex("bf01000000"))  # mov edi, 1 (stdout)
        code.extend(bytes.fromhex("0f05"))        # syscall
        code.extend(bytes.fromhex("4883f8fc"))    # cmp rax, -EINTR
        retry_branch = len(code)
        code.extend((0x74, 0))
        code.extend(bytes.fromhex("4885c0"))      # test rax, rax
        fail_branch = len(code)
        code.extend((0x7E, 0))
        code.extend(bytes.fromhex("4801c6"))      # add rsi, rax
        code.extend(bytes.fromhex("4829c2"))      # sub rdx, rax
        again_branch = len(code)
        code.extend((0x75, 0))
        code.append(0xC3)                          # ret
        fail_label = len(code)
        code.extend(bytes.fromhex("b83c000000bf010000000f05"))  # exit(1)
        _patch_rel8(code, retry_branch, loop)
        _patch_rel8(code, fail_branch, fail_label)
        _patch_rel8(code, again_branch, loop)
        for position in call_fixups:
            _patch_rel32(code, position, helper)

    if trap_fixups:
        panic_label = len(code)
        code.extend(bytes.fromhex("b83c000000bf650000000f05"))  # exit(101)
        for position in trap_fixups:
            _patch_rel32(code, position, panic_label)

    for position, target_label in control_fixups:
        if target_label not in label_offsets:
            raise ValueError("native branch targets an unknown code label")
        _patch_rel32(code, position, label_offsets[target_label])

    for position, data_offset in lea_fixups:
        target = ELF_BASE + DATA_OFFSET + data_offset
        next_ip = ELF_BASE + CODE_OFFSET + position + 4
        code[position:position + 4] = struct.pack("<i", target - next_ip)

    if len(code) > DATA_OFFSET - CODE_OFFSET:
        raise ValueError("native code exceeds the first backend page")
    if len(rodata) > MAX_OUTPUT:
        raise ValueError("native data exceeds the 1 MiB limit")
    return bytes(code), bytes(rodata)


def _write_elf64(code, data):
    """Write a static PIE (ET_DYN) with RX code, R-only data, and an RW non-exec stack."""
    code_segment_size = CODE_OFFSET + len(code)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)
    program_headers = [
        struct.pack("<IIQQQQQQ", 1, 5, 0, ELF_BASE, ELF_BASE,
                    code_segment_size, code_segment_size, 0x1000),
    ]
    if data:
        program_headers.append(struct.pack(
            "<IIQQQQQQ", 1, 4, DATA_OFFSET, ELF_BASE + DATA_OFFSET, ELF_BASE + DATA_OFFSET,
            len(data), len(data), 0x1000,
        ))
    program_headers.append(struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16))
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, CODE_OFFSET, 64, 0, 0, 64, 56,
        len(program_headers), 64, 0, 0,
    )
    header = ehdr + b"".join(program_headers)
    if len(header) > CODE_OFFSET:
        raise AssertionError("ELF headers exceed code offset")
    image = header + bytes(CODE_OFFSET - len(header)) + code
    if data:
        if len(image) > DATA_OFFSET:
            raise AssertionError("native code overlaps read-only data segment")
        image += bytes(DATA_OFFSET - len(image)) + data
    return image


def emit_native(ir):
    """Verify IR and directly emit a static x86-64 Linux ELF executable."""
    verify_ir(ir)
    code, data = _emit_program_code(ir)
    return _write_elf64(code, data)