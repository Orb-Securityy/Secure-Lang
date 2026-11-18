"""Exhaustively compare 8-bit wrapping helpers with independent modular models."""

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
    return (i8)low; /* value is now guaranteed to be in the i8 range */
}

int main(void) {
    /* Exhaust every pair for signed and unsigned addition/subtraction/multiply. */
    for (int ai = -128; ai <= 127; ++ai) {
        for (int bi = -128; bi <= 127; ++bi) {
            i8 a = (i8)ai, b = (i8)bi;
            if (sec_wadd_i8(a, b) != ref_i8(ai + bi)) return __LINE__;
            if (sec_wsub_i8(a, b) != ref_i8(ai - bi)) return __LINE__;
            if (sec_wmul_i8(a, b) != ref_i8(ai * bi)) return __LINE__;
        }
    }

    for (unsigned int ai = 0; ai <= 255; ++ai) {
        for (unsigned int bi = 0; bi <= 255; ++bi) {
            u8 a = (u8)ai, b = (u8)bi;
            if (sec_wadd_u8(a, b) != (u8)((ai + bi) & 255u)) return __LINE__;
            if (sec_wsub_u8(a, b) != (u8)((ai - bi) & 255u)) return __LINE__;
            if (sec_wmul_u8(a, b) != (u8)((ai * bi) & 255u)) return __LINE__;
        }
    }

    /* Check the conversion helper over every 16-bit unsigned source pattern. */
    for (unsigned int value = 0; value <= 65535; ++value) {
        if (sec_wrap_i8((__uint128_t)value) != ref_i8((int)value)) return __LINE__;
        if (sec_wrap_u8((__uint128_t)value) != (u8)(value & 255u)) return __LINE__;
    }

    /* Negative signed sources must reduce modulo 256 as well. */
    for (int value = -32768; value <= 32767; ++value) {
        if (sec_wrap_i8((__uint128_t)(int64_t)value) != ref_i8(value)) return __LINE__;
        if (sec_wrap_u8((__uint128_t)(int64_t)value) != (u8)((unsigned int)value & 255u)) return __LINE__;
    }
    return 0;
}
"""


class WrappingArithmeticProperties(unittest.TestCase):
    def test_exhaustive_i8_u8_arithmetic_and_wrapping_conversions(self):
        with tempfile.TemporaryDirectory(prefix="secure-wrapping-") as td:
            source = pathlib.Path(td) / "properties.c"
            executable = pathlib.Path(td) / "properties"
            source.write_text(HARNESS, encoding="utf-8")
            build = subprocess.run(
                [
                    "gcc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-function", "-Wno-type-limits",
                    "-fsanitize=undefined", "-fno-sanitize-recover=all",
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
            "wrapping reference-model mismatch or UBSan finding "
            f"(harness line {result.returncode}):\n{result.stderr}",
        )
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
