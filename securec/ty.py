"""Type model for Secure."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Ty:
    k: str            # int float bool unit never str string struct enum array slice ref vec option result task ptr
    name: str = ""    # int/float/struct/enum name; 'mut' for &mut and *mut
    args: tuple = ()
    n: int = 0        # array length


INTS = {"i8": (8, True), "i16": (16, True), "i32": (32, True), "i64": (64, True),
        "u8": (8, False), "u16": (16, False), "u32": (32, False), "u64": (64, False),
        "usize": (64, False)}


def int_range(name):
    b, s = INTS[name]
    return (-(1 << (b - 1)), (1 << (b - 1)) - 1) if s else (0, (1 << b) - 1)


def int_bits(name):
    return INTS[name][0]


def is_signed(name):
    return INTS[name][1]


def I(name):
    return Ty("int", name)


I32, I64, U8, U32, U64, USIZE = I("i32"), I("i64"), I("u8"), I("u32"), I("u64"), I("usize")
F64, BOOL, UNIT, NEVER, STR, STRING = Ty("float", "f64"), Ty("bool"), Ty("unit"), Ty("never"), Ty("str"), Ty("string")


def ref(t, mut=False): return Ty("ref", "mut" if mut else "", (t,))
def slice_(t): return Ty("slice", "", (t,))
def array(t, n): return Ty("array", "", (t,), n)
def vec(t): return Ty("vec", "", (t,))
def option(t): return Ty("option", "", (t,))
def result(t, e): return Ty("result", "", (t, e))
def task(t): return Ty("task", "", (t,))
def ptr(t, mut=False): return Ty("ptr", "mut" if mut else "", (t,))
def struct(n): return Ty("struct", n)
def enum(n): return Ty("enum", n)


def tstr(t):
    k = t.k
    if k in ("int", "float", "struct", "enum"): return t.name
    if k == "bool": return "bool"
    if k == "unit": return "()"
    if k == "never": return "!"
    if k == "str": return "str"
    if k == "string": return "String"
    if k == "ref": return "&" + ("mut " if t.name == "mut" else "") + tstr(t.args[0])
    if k == "ptr": return ("*mut " if t.name == "mut" else "*const ") + tstr(t.args[0])
    if k == "slice": return "[" + tstr(t.args[0]) + "]"
    if k == "array": return f"[{tstr(t.args[0])}; {t.n}]"
    return {"vec": "Vec", "option": "Option", "result": "Result", "task": "Task"}[k] + "<" + ", ".join(map(tstr, t.args)) + ">"


def has_ref(t):
    return t.k == "ref" or any(has_ref(a) for a in t.args)


def has_ptr(t):
    return t.k == "ptr" or any(has_ptr(a) for a in t.args)
