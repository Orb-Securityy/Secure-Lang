"""Atheris target for Secure's source-to-C frontend.

Only source-level SecError exceptions are expected. Unexpected Python
exceptions must escape so Atheris reports them as compiler bugs.
"""
import sys

import atheris

with atheris.instrument_imports():
    from securec.compiler import Compiler
    from securec.lexer import SecError

MAX_INPUT_BYTES = 16 * 1024


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    if len(data) > MAX_INPUT_BYTES:
        return
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError:
        # Invalid UTF-8 file handling is covered by driver tests.
        return
    try:
        Compiler(source, "atheris-input.sec").compile()
    except SecError:
        # A proper compiler diagnostic is expected for arbitrary source.
        return


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
