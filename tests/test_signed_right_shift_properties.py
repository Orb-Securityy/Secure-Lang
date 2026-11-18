"""Exhaustively compare signed arithmetic right shifts with a portable floor model."""

import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


HARNESS = r"""
#include "secure_rt.h"
#include <stdint.h>

static int64_t ref_asr(int64_t value, unsigned int shift) {
    if (value >= 0) return (int64_t)((uint64_t)value >> shift);
    if (shift == 0) return value;
    return -1 - (int64_t)(((~(uint64_t)value) >> shift));
}

int main(void) {
    for (int value = -128; value <= 127; ++value) {
        for (unsigned int shift = 0; shift < 8; ++shift) {
            if (sec_shr_i8((i8)value, shift, "test") != ref_asr(value, shift)) return __LINE__;
        }
    }

    for (int value = -32768; value <= 32767; ++value) {
        for (unsigned int shift = 0; shift < 16; ++shift) {
            if (sec_shr_i16((i16)value, shift, "test") != ref_asr(value, shift)) return __LINE__;
        }
    }

    for (unsigned int value = 0; value <= 255; ++value) {
        for (unsigned int shift = 0; shift < 8; ++shift) {
            if (sec_shr_u8((u8)value, shift, "test") != (u8)(value >> shift)) return __LINE__;
        }
    }

    const int32_t samples32[] = {
        INT32_MIN, INT32_MIN + 1, -65537, -3, -2, -1, 0, 1, 2, 3,
        INT32_MAX - 1, INT32_MAX
    };
    for (unsigned int i = 0; i < sizeof(samples32) / sizeof(samples32[0]); ++i) {
        for (unsigned int shift = 0; shift < 32; ++shift) {
            if (sec_shr_i32(samples32[i], shift, "test") != ref_asr(samples32[i], shift)) return __LINE__;
        }
    }

    const int64_t samples64[] = {
        INT64_MIN, INT64_MIN + 1, INT64_MIN / 2, -((int64_t)1 << 62),
        -65537, -3, -2, -1, 0, 1, 2, 3, INT64_MAX / 2, INT64_MAX - 1, INT64_MAX
    };
    for (unsigned int i = 0; i < sizeof(samples64) / sizeof(samples64[0]); ++i) {
        for (unsigned int shift = 0; shift < 64; ++shift) {
            if (sec_shr_i64(samples64[i], shift, "test") != ref_asr(samples64[i], shift)) return __LINE__;
        }
    }

    const uint64_t samples_u64[] = {0, 1, 2, 3, UINT64_MAX / 2, UINT64_MAX - 1, UINT64_MAX};
    for (unsigned int i = 0; i < sizeof(samples_u64) / sizeof(samples_u64[0]); ++i) {
        for (unsigned int shift = 0; shift < 64; ++shift) {
            if (sec_shr_u64(samples_u64[i], shift, "test") != (samples_u64[i] >> shift)) return __LINE__;
        }
    }
    return 0;
}
"""


class SignedRightShiftProperties(unittest.TestCase):
    def test_arithmetic_shift_is_defined_for_all_i8_i16_and_wide_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="secure-shift-") as td:
            source = pathlib.Path(td) / "right_shift.c"
            executable = pathlib.Path(td) / "right_shift"
            source.write_text(HARNESS, encoding="utf-8")
            build = subprocess.run(
                [
                    "gcc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-function", "-Wno-type-limits",
                    "-fsanitize=undefined", "-fno-sanitize-recover=all",
                    "-I", str(ROOT / "securec"), str(source), "-o", str(executable),
                ],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
        self.assertEqual(
            result.returncode, 0,
            f"right-shift reference-model mismatch or UBSan finding (line {result.returncode}):\n{result.stderr}",
        )
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
