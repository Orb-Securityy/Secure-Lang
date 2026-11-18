"""Direct x86-64 Linux ELF backend for verified Secure IR.

This backend has no dependency on the Secure lexer, parser, Python compiler, C emitter,
assembler, linker, or C runtime. It consumes only the small shared IR contract.
"""
import struct

from .ir import MAX_OUTPUT, ir_output, verify_ir


ELF_BASE = 0x400000
CODE_OFFSET = 0x1000
DATA_OFFSET = 0x2000


def _machine_code(data_length):
    """Build _start with EINTR and partial-write handling via Linux syscalls."""
    if data_length == 0:
        return bytes.fromhex("b83c00000031ff0f05")
    if not 0 < data_length <= MAX_OUTPUT:
        raise ValueError("native write length is out of range")

    code = bytearray()
    code += bytes.fromhex("b801000000")       # mov eax, 1 (write)
    code += bytes.fromhex("bf01000000")       # mov edi, 1 (stdout)
    code += bytes.fromhex("488d35")            # lea rsi, [rip + disp32]
    lea_next_ip_offset = len(code) + 4
    displacement = DATA_OFFSET - (CODE_OFFSET + lea_next_ip_offset)
    code += struct.pack("<i", displacement)
    code += b"\\xba" + struct.pack("<I", data_length)  # mov edx, bytes remaining

    loop_label = len(code)
    code += bytes.fromhex("0f05")               # syscall: write
    code += bytes.fromhex("4883f8fc")           # cmp rax, -EINTR
    retry_branch = len(code)
    code += bytes((0x74, 0))                    # je retry on EINTR
    code += bytes.fromhex("4885c0")             # test rax, rax
    fail_branch = len(code)
    code += bytes((0x7E, 0))                    # jle fail on error or zero write
    code += bytes.fromhex("4801c6")             # add rsi, rax
    code += bytes.fromhex("4829c2")             # sub rdx, rax
    again_branch = len(code)
    code += bytes((0x75, 0))                    # jnz while bytes remain

    code += bytes.fromhex("b83c00000031ff0f05") # exit(0)
    fail_label = len(code)
    code += bytes.fromhex("b83c000000bf010000000f05")  # exit(1)

    for branch, target in ((retry_branch, loop_label),
                           (fail_branch, fail_label),
                           (again_branch, loop_label)):
        displacement = target - (branch + 2)
        if not -128 <= displacement <= 127:
            raise AssertionError("native short branch is out of range")
        code[branch + 1] = displacement & 0xFF

    if len(code) != 64:
        raise AssertionError("internal native backend layout error")
    return bytes(code)


def build_elf64(data):
    """Return a static x86-64 Linux ELF with RX code, R-only data, and an RW non-exec stack."""
    if type(data) is not bytes:
        raise TypeError("native ELF data must be bytes")
    if len(data) > MAX_OUTPUT:
        raise ValueError("native output exceeds the 1 MiB limit")
    code = _machine_code(len(data))
    if len(code) > 0x1000:
        raise ValueError("native code exceeds the first backend page")
    code_segment_size = CODE_OFFSET + len(code)
    ident = b"\\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)
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
        "<HHIQQQIHHHHHH", 2, 62, 1, ELF_BASE + CODE_OFFSET, 64, 0, 0, 64, 56,
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
    """Verify the IR and lower it directly to a static x86-64 Linux ELF image."""
    verify_ir(ir)
    return build_elf64(ir_output(ir))