"""Deterministic differential checks for Secure integer code generation."""

import os
import random
import subprocess
import tempfile
import unittest

from securec.compiler import Compiler
from securec.driver import cc_build


class IntegerCodegenDifferentialTests(unittest.TestCase):
    def test_seeded_integer_expressions_match_reference_model(self):
        rng = random.Random(0x5EC0C0DE)
        cases = []

        for op in ("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"):
            for _ in range(12):
                if op in ("<<", ">>"):
                    a, b = rng.randint(-100, 100), rng.randint(0, 6)
                elif op == "*":
                    a, b = rng.randint(-20, 20), rng.randint(-20, 20)
                else:
                    a, b = rng.randint(-100, 100), rng.randint(-100, 100)
                    if op in ("/", "%") and b == 0:
                        b = 1

                if op == "+":
                    value = a + b
                elif op == "-":
                    value = a - b
                elif op == "*":
                    value = a * b
                elif op in ("/", "%"):
                    quotient = abs(a) // abs(b)
                    if (a < 0) != (b < 0):
                        quotient = -quotient
                    value = quotient if op == "/" else a - quotient * b
                elif op == "&":
                    value = a & b
                elif op == "|":
                    value = a | b
                elif op == "^":
                    value = a ^ b
                elif op == "<<":
                    value = a << b
                else:
                    value = a >> b

                cases.append((f"({a}) {op} ({b})", str(value)))

        # Exercise precedence and mixed-expression lowering as well as isolated
        # operators. The generated values remain comfortably inside i32.
        for _ in range(32):
            a, b, c = (rng.randint(-12, 12) for _ in range(3))
            cases.append((f"({a}) + ({b}) * ({c})", str(a + b * c)))
            cases.append((f"(({a}) - ({b})) * ({c})", str((a - b) * c)))
            cases.append((f"(({a}) < ({b})) && (({b}) != ({c}))",
                          str((a < b) and (b != c)).lower()))

        cases.extend([
            ("false && ((1 / zero) == 0)", "false"),
            ("true || ((1 / zero) == 0)", "true"),
        ])

        source = "fn main() -> i32 {\n    let zero: i32 = 0;\n"
        source += "".join(f"    println({expr});\n" for expr, _ in cases)
        source += "    return 0;\n}\n"
        generated_c = Compiler(source, "differential_integer_codegen.sec").compile()
        expected = "\n".join(value for _, value in cases) + "\n"

        with tempfile.TemporaryDirectory(prefix="secure-differential-") as td:
            executable = os.path.join(td, "differential")
            self.assertTrue(cc_build(generated_c, executable, strict=True))
            result = subprocess.run(
                [executable],
                capture_output=True,
                text=True,
                timeout=10,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, expected)


if __name__ == "__main__":
    unittest.main()
