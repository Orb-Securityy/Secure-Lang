"""Direct x86-64 Linux ELF backend for verified Secure IR.

This backend has no dependency on the Secure lexer, parser, Python compiler, C emitter,
assembler, linker, or C runtime. It consumes only the shared immutable IR contract.
"""
import struct

from .ir import (IRArrayCreate, IRArrayLoadI32, IRArrayStoreI32, IRBinaryI32, IRCallI32,
                 IRCompareBranch, IRConstI32, IRExit, IRFunction, IRJump, IRLabel,
                 IRLocalI32, IRParamI32, IRPrintI32, IRReturnI32, IRStoreI32,
                 IRUnaryI32, IRValue, IRWrite, MAX_OUTPUT, MAX_NATIVE_ARGS,
                 MAX_NATIVE_ARRAY_BYTES, verify_ir)


ELF_BASE = 0  # position-independent image; Linux chooses the load base
CODE_OFFSET = 0x1000
MAX_NATIVE_CODE = 1 << 20
MAX_STACK_FRAME = 1 << 20
SYSV_INTEGER_ARGUMENT_REGISTERS = 6


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


def _emit_array_bounds_check(code, index_slot, length, trap_fixups):
    _emit_load_ecx(code, index_slot)
    code.extend(bytes.fromhex("81f9"))
    code.extend(struct.pack("<I", length))
    _emit_jcc32(code, 0x83, trap_fixups)  # jae: reject negative and index >= length


def _emit_array_address(code, base_disp, element_size):
    if type(base_disp) is not int or not 32 <= base_disp <= MAX_STACK_FRAME - 1:
        raise ValueError("native fixed-array frame offset is invalid")
    if element_size == 1:
        code.extend(bytes.fromhex("0fb6840c"))  # movzx eax, byte [rsp + rcx + disp32]
    elif element_size == 4:
        code.extend(bytes.fromhex("8b848c"))    # mov eax, dword [rsp + rcx*4 + disp32]
    else:
        raise ValueError("unsupported native fixed-array element size")
    code.extend(struct.pack("<I", base_disp))


def _emit_array_store(code, base_disp, element_size, trap_fixups):
    if element_size == 1:
        code.append(0xA9)                       # test eax, 0xffffff00
        code.extend(struct.pack("<I", 0xFFFFFF00))
        _emit_jcc32(code, 0x85, trap_fixups)    # jnz: u8 value must fit
        code.extend(bytes.fromhex("88840c"))    # mov byte [rsp + rcx + disp32], al
    elif element_size == 4:
        code.extend(bytes.fromhex("89848c"))    # mov dword [rsp + rcx*4 + disp32], eax
    else:
        raise ValueError("unsupported native fixed-array element size")
    code.extend(struct.pack("<I", base_disp))


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


def _emit_param_store(code, slot, index, frame_size):
    """Store a SysV AMD64 i32 argument from its register/stack ABI slot."""
    encodings = (
        bytes.fromhex("89bc24"),  # edi
        bytes.fromhex("89b424"),  # esi
        bytes.fromhex("899424"),  # edx
        bytes.fromhex("898c24"),  # ecx
        bytes.fromhex("44898424"),  # r8d
        bytes.fromhex("44898c24"),  # r9d
    )
    if type(index) is not int or not 0 <= index < MAX_NATIVE_ARGS:
        raise ValueError("native parameter index is out of range")
    if index < len(encodings):
        code.extend(encodings[index])
        code.extend(struct.pack("<I", _slot_disp(slot)))
    else:
        source_offset = frame_size + 8 + (index - SYSV_INTEGER_ARGUMENT_REGISTERS) * 8
        if source_offset > 0xFFFFFFFF:
            raise ValueError("native stack argument displacement is out of range")
        code.extend(bytes.fromhex("8b8424"))  # mov eax, dword [rsp + incoming stack arg]
        code.extend(struct.pack("<I", source_offset))
        _emit_store_eax(code, slot)


def _emit_load_argument(code, slot, index):
    """Load one i32 call argument into its SysV AMD64 register."""
    encodings = (
        bytes.fromhex("8bbc24"),  # edi
        bytes.fromhex("8bb424"),  # esi
        bytes.fromhex("8b9424"),  # edx
        bytes.fromhex("8b8c24"),  # ecx
        bytes.fromhex("448b8424"),  # r8d
        bytes.fromhex("448b8c24"),  # r9d
    )
    if type(index) is not int or not 0 <= index < len(encodings):
        raise ValueError("native register argument index is out of range")
    code.extend(encodings[index])
    code.extend(struct.pack("<I", _slot_disp(slot)))


def _emit_program_code(ir):
    code = bytearray()
    rodata = bytearray()
    write_call_fixups = []
    function_call_fixups = []
    lea_fixups = []
    trap_fixups = []
    needs_write_helper = False
    label_offsets = {}
    control_fixups = []
    function_offsets = {}

    def emit_stream(instructions, scope, is_entry, param_count):
        nonlocal needs_write_helper
        slot_types = (
            IRConstI32, IRParamI32, IRLocalI32, IRUnaryI32,
            IRBinaryI32, IRCallI32, IRArrayLoadI32,
        )
        slot_count = sum(type(ins) in slot_types for ins in instructions)
        # The first 32 bytes are reserved for the integer formatter; scalar
        # slots follow, then fixed arrays with their required element alignment.
        local_bytes = 32 + slot_count * 4
        array_layout = {}
        for candidate in instructions:
            if type(candidate) is IRArrayCreate:
                alignment = candidate.element_size
                local_bytes = (local_bytes + alignment - 1) & ~(alignment - 1)
                array_layout[candidate.array_id] = (
                    local_bytes, candidate.length, candidate.element_size, candidate.mutable
                )
                local_bytes += candidate.length * candidate.element_size
        if local_bytes - (32 + slot_count * 4) > MAX_NATIVE_ARRAY_BYTES:
            raise ValueError("native fixed arrays exceed their stack-byte budget")
        if is_entry:
            frame_size = ((local_bytes + 15) // 16) * 16
        else:
            # At a SysV function entry RSP is 8 mod 16. Reserve a frame
            # that both covers locals and restores 16-byte call alignment.
            frame_size = ((local_bytes + 8 + 15) // 16) * 16 - 8
            if frame_size < local_bytes:
                frame_size += 16
        if frame_size > MAX_STACK_FRAME:
            raise ValueError("native stack frame exceeds its limit")
        if frame_size:
            code.extend(bytes.fromhex("4881ec"))  # sub rsp, imm32
            code.extend(struct.pack("<I", frame_size))

        for instruction in instructions:
            if type(instruction) is IRConstI32:
                code.extend(bytes.fromhex("c78424"))
                code.extend(struct.pack("<I", _slot_disp(instruction.dest)))
                code.extend(struct.pack("<i", instruction.value))
            elif type(instruction) is IRParamI32:
                _emit_param_store(code, instruction.dest, instruction.index, frame_size)
            elif type(instruction) is IRLocalI32:
                _emit_load_eax(code, instruction.initial.slot)
                _emit_store_eax(code, instruction.dest)
            elif type(instruction) is IRArrayCreate:
                layout = array_layout.get(instruction.array_id)
                if layout is None:
                    raise ValueError("native fixed-array layout is missing")
                base_disp, length, element_size, _mutable = layout
                _emit_load_eax(code, instruction.initial.slot)
                if element_size == 1:
                    code.append(0xA9)                   # test eax, 0xffffff00
                    code.extend(struct.pack("<I", 0xFFFFFF00))
                    _emit_jcc32(code, 0x85, trap_fixups)
                code.extend(bytes.fromhex("488dbc24"))  # lea rdi, [rsp + array base]
                code.extend(struct.pack("<I", base_disp))
                code.append(0xB9)                       # mov ecx, array length
                code.extend(struct.pack("<I", length))
                code.extend(bytes.fromhex("f3aa" if element_size == 1 else "f3ab"))
            elif type(instruction) is IRArrayLoadI32:
                layout = array_layout.get(instruction.array_id)
                if layout is None:
                    raise ValueError("native array load has no stack layout")
                base_disp, length, element_size, _mutable = layout
                _emit_array_bounds_check(code, instruction.index.slot, length, trap_fixups)
                _emit_array_address(code, base_disp, element_size)
                _emit_store_eax(code, instruction.dest)
            elif type(instruction) is IRArrayStoreI32:
                layout = array_layout.get(instruction.array_id)
                if layout is None:
                    raise ValueError("native array store has no stack layout")
                base_disp, length, element_size, mutable = layout
                if not mutable:
                    raise ValueError("native array store targets an immutable array")
                _emit_array_bounds_check(code, instruction.index.slot, length, trap_fixups)
                _emit_load_eax(code, instruction.value.slot)
                _emit_array_store(code, base_disp, element_size, trap_fixups)
            elif type(instruction) is IRStoreI32:
                _emit_load_eax(code, instruction.value.slot)
                _emit_store_eax(code, instruction.dest)
            elif type(instruction) in (IRUnaryI32, IRBinaryI32):
                _emit_checked_arithmetic(code, instruction, trap_fixups)
            elif type(instruction) is IRCallI32:
                register_args = instruction.args[:SYSV_INTEGER_ARGUMENT_REGISTERS]
                stack_args = instruction.args[len(register_args):]
                for index, argument in enumerate(register_args):
                    _emit_load_argument(code, argument.slot, index)
                outgoing_size = ((len(stack_args) * 8 + 15) // 16) * 16
                if outgoing_size:
                    if outgoing_size > MAX_STACK_FRAME:
                        raise ValueError("native outgoing argument area exceeds its limit")
                    code.extend(bytes.fromhex("4881ec"))  # sub rsp, outgoing argument area
                    code.extend(struct.pack("<I", outgoing_size))
                    for index, argument in enumerate(stack_args):
                        source_offset = outgoing_size + _slot_disp(argument.slot)
                        target_offset = index * 8
                        if source_offset > 0xFFFFFFFF or target_offset > 0xFFFFFFFF:
                            raise ValueError("native outgoing argument displacement is out of range")
                        code.extend(bytes.fromhex("8b8424"))  # load local after rsp adjustment
                        code.extend(struct.pack("<I", source_offset))
                        code.extend(bytes.fromhex("898424"))  # store low i32 into 8-byte ABI slot
                        code.extend(struct.pack("<I", target_offset))
                call_fixups = []
                _emit_call(code, call_fixups)
                function_call_fixups.append((call_fixups[0], instruction.function))
                if outgoing_size:
                    code.extend(bytes.fromhex("4881c4"))  # restore caller frame
                    code.extend(struct.pack("<I", outgoing_size))
                _emit_store_eax(code, instruction.dest)
            elif type(instruction) is IRReturnI32:
                _emit_load_eax(code, instruction.value.slot)
                if frame_size:
                    code.extend(bytes.fromhex("4881c4"))  # add rsp, imm32
                    code.extend(struct.pack("<I", frame_size))
                code.append(0xC3)  # ret
            elif type(instruction) is IRWrite:
                output = instruction.data + (b"\n" if instruction.newline else b"")
                if not output:
                    continue
                data_offset = len(rodata)
                rodata.extend(output)
                code.extend(bytes.fromhex("488d35"))
                lea_fixups.append((len(code), data_offset))
                code.extend(bytes(4))
                code.append(0xBA)  # mov edx, imm32
                code.extend(struct.pack("<I", len(output)))
                call_fixups = []
                _emit_call(code, call_fixups)
                write_call_fixups.append(call_fixups[0])
                needs_write_helper = True
            elif type(instruction) is IRPrintI32:
                _emit_i32_formatter(code, instruction.value, instruction.newline, write_call_fixups)
                needs_write_helper = True
            elif type(instruction) is IRCompareBranch:
                _emit_load_eax(code, instruction.left.slot)
                _emit_load_ecx(code, instruction.right.slot)
                code.extend(bytes.fromhex("39c8"))  # cmp eax, ecx
                condition_codes = {"==": 0x84, "!=": 0x85, "<": 0x8C,
                                   "<=": 0x8E, ">": 0x8F, ">=": 0x8D}
                branch_fixups = []
                _emit_jcc32(code, condition_codes[instruction.op], branch_fixups)
                control_fixups.append((branch_fixups[0], scope, instruction.true_target))
                jump_fixups = []
                _emit_jmp32(code, jump_fixups)
                control_fixups.append((jump_fixups[0], scope, instruction.false_target))
            elif type(instruction) is IRJump:
                jump_fixups = []
                _emit_jmp32(code, jump_fixups)
                control_fixups.append((jump_fixups[0], scope, instruction.target))
            elif type(instruction) is IRLabel:
                key = (scope, instruction.label)
                if key in label_offsets:
                    raise ValueError("duplicate native code label")
                label_offsets[key] = len(code)
            elif type(instruction) is IRExit:
                code.extend(bytes.fromhex("b83c00000031ff0f05"))  # exit(0)
            else:
                raise ValueError("unknown native IR instruction")

    emit_stream(ir.instructions, None, True, 0)
    for function in ir.functions:
        if type(function) is not IRFunction or function.name in function_offsets:
            raise ValueError("invalid or duplicate native function")
        function_offsets[function.name] = len(code)
        emit_stream(function.instructions, function.name, False, function.param_count)

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
        for position in write_call_fixups:
            _patch_rel32(code, position, helper)

    if trap_fixups:
        panic_label = len(code)
        code.extend(bytes.fromhex("b83c000000bf650000000f05"))  # exit(101)
        for position in trap_fixups:
            _patch_rel32(code, position, panic_label)

    for position, function_name in function_call_fixups:
        target = function_offsets.get(function_name)
        if target is None:
            raise ValueError("native call references an unknown function")
        _patch_rel32(code, position, target)

    for position, scope, target_label in control_fixups:
        target = label_offsets.get((scope, target_label))
        if target is None:
            raise ValueError("native branch targets an unknown code label")
        _patch_rel32(code, position, target)

    if len(code) > MAX_NATIVE_CODE:
        raise ValueError("native code exceeds the 1 MiB limit")
    if len(rodata) > MAX_OUTPUT:
        raise ValueError("native data exceeds the 1 MiB limit")
    code_segment_size = CODE_OFFSET + len(code)
    data_segment_offset = (code_segment_size + 0xFFF) & ~0xFFF
    for position, data_offset in lea_fixups:
        target = ELF_BASE + data_segment_offset + data_offset
        next_ip = ELF_BASE + CODE_OFFSET + position + 4
        code[position:position + 4] = struct.pack("<i", target - next_ip)

    return bytes(code), bytes(rodata), data_segment_offset


def _write_elf64(code, data, data_segment_offset):
    """Write a static PIE with RX code, optional R data, and an RW/NX stack."""
    if type(code) is not bytes or type(data) is not bytes:
        raise ValueError("native ELF segments must be immutable byte strings")
    if len(code) > MAX_NATIVE_CODE or len(data) > MAX_OUTPUT:
        raise ValueError("native ELF segment exceeds its configured size limit")
    code_segment_size = CODE_OFFSET + len(code)
    expected_data_offset = (code_segment_size + 0xFFF) & ~0xFFF
    if type(data_segment_offset) is not int or data_segment_offset != expected_data_offset:
        raise ValueError("native ELF data segment offset is not page-aligned after code")
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)
    program_headers = [
        struct.pack("<IIQQQQQQ", 1, 5, 0, ELF_BASE, ELF_BASE,
                    code_segment_size, code_segment_size, 0x1000),
    ]
    if data:
        program_headers.append(struct.pack(
            "<IIQQQQQQ", 1, 4, data_segment_offset, ELF_BASE + data_segment_offset,
            ELF_BASE + data_segment_offset, len(data), len(data), 0x1000,
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
        if len(image) > data_segment_offset:
            raise AssertionError("native code overlaps read-only data segment")
        image += bytes(data_segment_offset - len(image)) + data
    return image


def emit_native(ir):
    """Verify IR and directly emit a static x86-64 Linux ELF executable."""
    verify_ir(ir)
    code, data, data_segment_offset = _emit_program_code(ir)
    return _write_elf64(code, data, data_segment_offset)