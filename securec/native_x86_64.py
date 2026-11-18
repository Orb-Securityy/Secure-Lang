"""Direct x86-64 Linux ELF backend for a deliberately restricted Secure subset.

This bootstrap path lowers through a small immutable IR and writes machine code
and ELF64 metadata directly. The parser is still Python; this is not self-hosting.
"""
from dataclasses import dataclass
import struct

from .lexer import SecError
from .parser import parse


ELF_BASE = 0x400000
CODE_OFFSET = 0x1000
DATA_OFFSET = 0x2000
MAX_OUTPUT = 1 << 20


@dataclass(frozen=True)
class IRWrite:
    data: bytes
    newline: bool


@dataclass(frozen=True)
class IRExit:
    status: int


@dataclass(frozen=True)
class IRProgram:
    instructions: tuple


def _error(message, node):
    raise SecError(message, getattr(node, "line", 1), getattr(node, "col", 1))


def _is_str_type(node):
    return node is not None and node.k == "TName" and node.name == "str" and not node.args


def _resolve_static_str(expr, bindings, constants):
    if expr.k == "Str":
        return expr.val
    if expr.k == "Var":
        if expr.name in bindings:
            return bindings[expr.name]
        if expr.name in constants:
            return constants[expr.name]
    _error("native subset requires a statically known `str` value", expr)


def lower_to_ir(items):
    """Type-check the supported static-string subset and lower it to immutable IR."""
    constants = {}
    main = None
    for item in items:
        if item.k == "Const":
            if item.name in constants or item.name in ("main", "print", "println"):
                _error(f"duplicate or reserved native constant `{item.name}`", item)
            if not _is_str_type(item.ty) or item.e.k != "Str":
                _error("native subset supports only `const NAME: str = literal;`", item)
            constants[item.name] = item.e.val
        elif item.k == "Fn" and item.name == "main" and main is None:
            main = item
        else:
            _error("native subset accepts only `str` constants and one `fn main()`", item)
    if main is None:
        raise SecError("program has no `main` function", 1, 1)
    if main.params or main.ret is not None or main.unsafe or main.extern or main.body is None:
        _error("native backend requires a safe `fn main()` with no parameters or return type", main)
    if main.body.tail is not None:
        _error("native backend requires a statement-only `main` body", main.body)

    bindings = {}
    instructions = []
    for stmt in main.body.stmts:
        if stmt.k == "Let":
            if stmt.mut:
                _error("native subset accepts only immutable `let` bindings", stmt)
            if stmt.name in bindings or stmt.name in constants:
                _error(f"duplicate or shadowed native binding `{stmt.name}`", stmt)
            if stmt.ty is not None and not _is_str_type(stmt.ty):
                _error("native subset variables must have type `str`", stmt.ty)
            bindings[stmt.name] = _resolve_static_str(stmt.init, bindings, constants)
            continue
        if stmt.k != "ExprStmt" or stmt.e.k != "Call":
            _error("native subset supports only `str` bindings and print calls", stmt)
        call = stmt.e
        if call.fn.k != "Var" or call.fn.name not in ("print", "println"):
            _error("native subset supports only `print` and `println`", call)
        payload = b"".join(_resolve_static_str(arg, bindings, constants) for arg in call.args)
        instructions.append(IRWrite(payload, call.fn.name == "println"))
    instructions.append(IRExit(0))
    ir = IRProgram(tuple(instructions))
    verify_ir(ir)
    return ir


def verify_ir(ir):
    """Reject malformed native IR before machine code generation."""
    if not isinstance(ir, IRProgram) or not isinstance(ir.instructions, tuple) or not ir.instructions:
        raise ValueError("invalid native IR program")
    if not isinstance(ir.instructions[-1], IRExit) or type(ir.instructions[-1].status) is not int or ir.instructions[-1].status != 0:
        raise ValueError("native IR must end in exit(0)")
    total = 0
    for index, instruction in enumerate(ir.instructions):
        if isinstance(instruction, IRWrite):
            if index == len(ir.instructions) - 1 or not isinstance(instruction.data, bytes):
                raise ValueError("invalid native write instruction")
            if type(instruction.newline) is not bool:
                raise ValueError("invalid native newline flag")
            total += len(instruction.data) + int(instruction.newline)
        elif isinstance(instruction, IRExit):
            if index != len(ir.instructions) - 1 or type(instruction.status) is not int or instruction.status != 0:
                raise ValueError("invalid or misplaced native exit instruction")
        else:
            raise ValueError("unknown native IR instruction")
        if total > MAX_OUTPUT:
            raise ValueError("native output exceeds the 1 MiB limit")
    return total


def _ir_output(ir):
    verify_ir(ir)
    return b"".join(ins.data + (b"\\n" if ins.newline else b"")
                    for ins in ir.instructions if isinstance(ins, IRWrite))


def _machine_code(data_length):
    """Build _start using Linux x86-64 write(1, data, len) and exit syscalls."""
    if data_length == 0:
        return bytes.fromhex("b83c00000031ff0f05")
    code = bytearray()
    code += bytes.fromhex("b801000000")       # mov eax, 1 (write)
    code += bytes.fromhex("bf01000000")       # mov edi, 1 (stdout)
    code += bytes.fromhex("488d35")            # lea rsi, [rip + disp32]
    lea_next_ip_offset = len(code) + 4
    displacement = DATA_OFFSET - (CODE_OFFSET + lea_next_ip_offset)
    code += struct.pack("<i", displacement)
    code += b"\\xba" + struct.pack("<I", data_length)  # mov edx, len
    code += bytes.fromhex("0f05")               # syscall
    code += bytes.fromhex("4839d0")             # cmp rax, rdx
    code += bytes.fromhex("7509")               # jne short failure exit
    code += bytes.fromhex("b83c00000031ff0f05") # exit(0)
    code += bytes.fromhex("b83c000000bf010000000f05")  # exit(1) on short/error write
    if len(code) != 50:
        raise AssertionError("internal native backend layout error")
    return bytes(code)


def build_elf64(data):
    """Return a static x86-64 Linux ELF with RX code, R-only data, and an RW non-exec stack."""
    data = bytes(data)
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


def compile_native_subset(source):
    """Parse, lower, verify, and emit the restricted native subset."""
    try:
        items = parse(source)
    except RecursionError as exc:
        raise SecError("source nesting exceeds the native backend limit", 0, 0) from exc
    return build_elf64(_ir_output(lower_to_ir(items)))