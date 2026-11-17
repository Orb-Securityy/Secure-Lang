"""Lexer for Secure."""
import math
import re


class SecError(Exception):
    def __init__(self, msg, line=0, col=0):
        super().__init__(msg)
        self.msg, self.line, self.col = msg, line, col


class Tok:
    __slots__ = ("kind", "val", "line", "col", "suf")

    def __init__(self, kind, val, line, col, suf=None):
        self.kind, self.val, self.line, self.col, self.suf = kind, val, line, col, suf

    def __repr__(self):
        return f"Tok({self.kind},{self.val!r},{self.line}:{self.col})"


KEYWORDS = {
    "fn", "let", "mut", "if", "else", "while", "loop", "for", "in", "return", "break",
    "continue", "struct", "enum", "impl", "const", "unsafe", "extern", "match", "as",
    "true", "false",
}
NUM_RE = re.compile(r"0[xX][0-9a-fA-F_]+|0[bB][01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?")
SUF_RE = re.compile(r"(?:i8|i16|i32|i64|u8|u16|u32|u64|usize|f64)(?![A-Za-z0-9_])")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
OPS = ["<<=", ">>=", "..=", "->", "=>", "::", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>",
       "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", ".."] + list("+-*/%=<>!&|^~.,;:(){}[]?")
ESC = {"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34, "'": 39, "0": 0}


def _escape(src, i, line, col):
    """Parse escape at src[i] == '\\'; returns (bytes, new_i)."""
    c = src[i + 1] if i + 1 < len(src) else ""
    if c in ESC:
        return bytes([ESC[c]]), i + 2
    if c == "x":
        h = src[i + 2:i + 4]
        if len(h) == 2 and all(x in "0123456789abcdefABCDEF" for x in h):
            return bytes([int(h, 16)]), i + 4
    raise SecError("invalid escape sequence", line, col)


def lex(src):
    toks, i, n, line, ls = [], 0, len(src), 1, 0
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1; i += 1; ls = i; continue
        if c in " \t\r":
            i += 1; continue
        if src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
            continue
        col = i - ls + 1
        if src.startswith("/*", i):
            depth = 1; i += 2
            while i < n and depth:
                if src.startswith("/*", i): depth += 1; i += 2
                elif src.startswith("*/", i): depth -= 1; i += 2
                else:
                    if src[i] == "\n": line += 1; ls = i + 1
                    i += 1
            if depth:
                raise SecError("unterminated block comment", line, col)
            continue
        # Identifier and number patterns are deliberately ASCII-only.
        # Unicode isalpha()/isdigit() used to route unsupported characters into
        # ASCII regexes, where match() returned None and leaked AttributeError.
        if c == "_" or ("A" <= c <= "Z") or ("a" <= c <= "z"):
            m = IDENT_RE.match(src, i)
            if m is None:
                raise SecError(f"unexpected character {c!r}", line, col)
            w = m.group(0); i = m.end()
            toks.append(Tok("kw" if w in KEYWORDS else "ident", w, line, col)); continue
        if "0" <= c <= "9":
            m = NUM_RE.match(src, i)
            if m is None:
                raise SecError(f"invalid numeric literal starting with {c!r}", line, col)
            text = m.group(0).replace("_", ""); i = m.end()
            suf = None
            ms = SUF_RE.match(src, i)
            if ms:
                suf = ms.group(0); i = ms.end()
            low = text.lower()
            try:
                if low.startswith("0x"):
                    digits = text[2:].replace("_", "")
                    if not digits:
                        raise ValueError("missing hexadecimal digits")
                    v, isf = int(digits, 16), False
                elif low.startswith("0b"):
                    digits = text[2:].replace("_", "")
                    if not digits:
                        raise ValueError("missing binary digits")
                    v, isf = int(digits, 2), False
                elif "." in text or "e" in low:
                    v, isf = float(text.replace("_", "")), True
                else:
                    v, isf = int(text.replace("_", ""), 10), False
            except ValueError as exc:
                raise SecError("invalid numeric literal", line, col) from exc
            if suf == "f64":
                try:
                    v = float(v)
                except OverflowError as exc:
                    raise SecError("floating-point literal is out of range for f64", line, col) from exc
                isf, suf = True, None
            if isf and not math.isfinite(v):
                raise SecError("floating-point literal is out of range for f64", line, col)
            if isf:
                toks.append(Tok("float", v, line, col))
            else:
                toks.append(Tok("int", v, line, col, suf))
            continue
        if c == '"':
            j, buf = i + 1, bytearray()
            while True:
                if j >= n or src[j] == "\n":
                    raise SecError("unterminated string literal", line, col)
                if src[j] == '"':
                    break
                if src[j] == "\\":
                    b, j = _escape(src, j, line, col); buf += b
                else:
                    buf += src[j].encode("utf-8"); j += 1
            i = j + 1
            toks.append(Tok("str", bytes(buf), line, col)); continue
        if c == "'":
            j = i + 1
            if j < n and src[j] == "\\":
                b, j = _escape(src, j, line, col); v = b[0]
            elif j < n and ord(src[j]) < 128:
                v = ord(src[j]); j += 1
            else:
                raise SecError("character literal must be a single ASCII character", line, col)
            if j >= n or src[j] != "'":
                raise SecError("unterminated character literal", line, col)
            i = j + 1
            toks.append(Tok("int", v, line, col, "u8")); continue
        for op in OPS:
            if src.startswith(op, i):
                toks.append(Tok("op", op, line, col)); i += len(op); break
        else:
            raise SecError(f"unexpected character {c!r}", line, col)
    toks.append(Tok("eof", None, line, i - ls + 1))
    return toks
