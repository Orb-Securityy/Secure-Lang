"""Experimental direct x86-64 Linux ELF backend for a deliberately tiny Secure subset.

This is a bootstrap milestone, not the final self-hosted compiler. It emits machine code
and ELF64 metadata directly; it does not emit C or invoke an assembler/linker.
"""
import struct

from .lexer import SecError
from .parser import parse


ELF_BASE = 0x400000
CODE_OFFSET = 0x1000
MAX_OUTPUT = 1 << 20


def _program_output(items):
    """Accept only `fn main() { println("literal"); ... }` and return exact output bytes."""
    if len(items) != 1:
        raise SecError("native backend currently accepts exactly one `main` function", 1, 1)
    fn = items[0]
    if fn.k != "Fn" or fn.name != "main" or fn.params or fn.ret is not None or fn.unsafe or fn.extern:
        raise SecError("native backend requires a safe `fn main()` with no parameters or return type",
                       getattr(fn, 'line', 1), getattr(fn, 'col', 1))
    if fn.body is None or fn.body.tail is not None:
        raise SecError("native backend requires a statement-only `main` body", fn.line, fn.col)
    chunks = []
    for stmt in fn.body.stmts:
        expr = stmt.e if stmt.k == 'ExprStmt' else None
        if (expr is None or expr.k != 'Call' or expr.fn.k != 'Var' or expr.fn.name != 'println'
                or len(expr.args) != 1 or expr.args[0].k != 'Str'):
            raise SecError("native subset supports only `println(\"string literal\");` statements",
                           getattr(stmt, 'line', fn.line), getattr(stmt, 'col', fn.col))
        chunks.append(expr.args[0].val + b'\n')
    output = b''.join(chunks)
    if len(output) > MAX_OUTPUT:
        raise SecError("native subset output exceeds the 1 MiB limit", fn.line, fn.col)
    return output


def _machine_code(data_length):
    """Build _start using Linux x86-64 write(1, data, len) and exit syscalls."""
    if data_length == 0:
        return bytes.fromhex('b83c00000031ff0f05')
    if data_length > 0x7FFFFFFF:
        raise ValueError("output does not fit the x86-64 syscall length field")
    code = bytearray()
    code += bytes.fromhex('b801000000')       # mov eax, 1 (write)
    code += bytes.fromhex('bf01000000')       # mov edi, 1 (stdout)
    code += bytes.fromhex('488d35')            # lea rsi, [rip + disp32]
    lea_next_ip_offset = len(code) + 4
    data_offset = CODE_OFFSET + 50
    displacement = data_offset - (CODE_OFFSET + lea_next_ip_offset)
    code += struct.pack('<i', displacement)
    code += b'\xba' + struct.pack('<I', data_length)  # mov edx, len
    code += bytes.fromhex('0f05')               # syscall
    code += bytes.fromhex('4839d0')             # cmp rax, rdx
    code += bytes.fromhex('7509')               # jne short failure exit
    code += bytes.fromhex('b83c00000031ff0f05') # exit(0)
    code += bytes.fromhex('b83c000000bf010000000f05')  # exit(1) on short/error write
    if len(code) != 50:
        raise AssertionError("internal native backend layout error")
    return bytes(code)


def build_elf64(data):
    """Return a minimal static x86-64 Linux ET_EXEC image containing one RX load segment."""
    data = bytes(data)
    if len(data) > MAX_OUTPUT:
        raise ValueError("native output exceeds the 1 MiB limit")
    code = _machine_code(len(data))
    if len(code) > 0x1000:
        raise ValueError("native code exceeds the first backend page")
    image_size = CODE_OFFSET + len(code) + len(data)
    ident = b'\x7fELF' + bytes((2, 1, 1, 0, 0)) + bytes(7)
    ehdr = ident + struct.pack(
        '<HHIQQQIHHHHHH',
        2,                 # ET_EXEC
        62,                # EM_X86_64
        1,                 # EV_CURRENT
        ELF_BASE + CODE_OFFSET,
        64,                # e_phoff
        0,                 # e_shoff (no section table needed by the loader)
        0,                 # e_flags
        64,                # e_ehsize
        56,                # e_phentsize
        2,                 # e_phnum
        64, 0, 0,
    )
    load = struct.pack(
        '<IIQQQQQQ',
        1, 5, 0, ELF_BASE, ELF_BASE, image_size, image_size, 0x1000,
    )
    stack = struct.pack(
        '<IIQQQQQQ',
        0x6474E551, 6, 0, 0, 0, 0, 0, 16,
    )
    header = ehdr + load + stack
    if len(header) > CODE_OFFSET:
        raise AssertionError("ELF headers exceed code offset")
    return header + bytes(CODE_OFFSET - len(header)) + code + data


def compile_native_subset(source):
    """Parse and compile the intentionally restricted native bootstrap subset."""
    try:
        items = parse(source)
    except RecursionError as exc:
        raise SecError("source nesting exceeds the native backend limit", 0, 0) from exc
    return build_elf64(_program_output(items))