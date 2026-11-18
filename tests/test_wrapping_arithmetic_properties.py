"""Exhaustively compare signed/unsigned 8-bit wrapping operations to an independent model."""

import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


HARNESS = r"""
#include "secure_rt.h"

static i8 ref_i8(int value) {
    int low = value % 256;
    if (low < 0) low += 256;
    if (low >= 128) low -= 256;
    return (i8)low;
}

int main(void) {
    for (int ai = -128; ai <= 127; ++ai) {
        for (int bi = -128; bi <= 127; ++bi) {
            i8 a = (i8)ai, b = (i8)bi;
            if (sec_wadd_i8(a, b) != ref_i8(ai + bi)) return __LINE__;
            if (sec_wsub_i8(a, b) != ref_i8(ai - bi)) return __LINE__;
            if (sec_wmul_i8(a, b) != ref_i8(ai * bi)) return __LINE__;
        }
    }

    for (unsigned int a = 0; a <= 255; ++a) {
        for (unsigned int b = 0; b <= 255; ++b) {
            u8 x = (u8)a, y = (u8)b;
            if (sec_wadd_u8(x, y) != (u8)((a + b) & 255u)) return __LINE__;
            if (sec_wsub_u8(x, y) != (u8)((a - b) & 255u)) return __LINE__;
            if (sec_wmul_u8(x, y) != (u8)((a * b) & 255u)) return __LINE__;
        }
    }
    return 0;
}
"""


class WrappingArithmeticProperties(unittest.TestCase):
    def test_all_i8_and_u8_operand_pairs_match_modular_reference_model(self):
        with tempfile.TemporaryDirectory(prefix="secure-wrapping-") as td:
            source = pathlib.Path(td) / "properties.c"
            executable = pathlib.Path(td) / "properties"
            source.write_text(HARNESS, encoding="utf-8")
            build = subprocess.run(
                [
                    "gcc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-function", "-Wno-type-limits",
                    "-I", str(ROOT / "securec"), str(source), "-o", str(executable),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run(
                [str(executable)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(
                result.returncode,
                0,
                f"wrapping reference-model mismatch at C harness line {result.returncode}",
            )


if __name__ == "__main__":
    unittest.main()
