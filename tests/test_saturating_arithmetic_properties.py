"""Runtime property tests for saturating integer arithmetic.

The reference calculations use wider integer types, independently of the
runtime's overflow builtins. Every supported integer width is covered at
representative boundaries; 8-bit signed and unsigned domains are exhaustive.
"""
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


HARNESS = r"""
#include "secure_rt.h"

#define CHECK_SIGNED(N, T, MINV, MAXV, VALUES, COUNT) do {                 \
    for (usize i = 0; i < (COUNT); ++i) {                                  \
        for (usize j = 0; j < (COUNT); ++j) {                              \
            T a = (T)(VALUES)[i], b = (T)(VALUES)[j];                      \
            __int128 sum = (__int128)a + (__int128)b;                     \
            __int128 diff = (__int128)a - (__int128)b;                    \
            __int128 prod = (__int128)a * (__int128)b;                    \
            T es = sum < (__int128)(MINV) ? (T)(MINV) :                   \
                   sum > (__int128)(MAXV) ? (T)(MAXV) : (T)sum;           \
            T ed = diff < (__int128)(MINV) ? (T)(MINV) :                  \
                   diff > (__int128)(MAXV) ? (T)(MAXV) : (T)diff;         \
            T ep = prod < (__int128)(MINV) ? (T)(MINV) :                  \
                   prod > (__int128)(MAXV) ? (T)(MAXV) : (T)prod;         \
            if (sec_sadd_##N(a, b) != es ||                               \
                sec_ssub_##N(a, b) != ed ||                               \
                sec_smul_##N(a, b) != ep) return __LINE__;                \
        }                                                                  \
    }                                                                      \
} while (0)

#define CHECK_UNSIGNED(N, T, MAXV, VALUES, COUNT) do {                    \
    for (usize i = 0; i < (COUNT); ++i) {                                 \
        for (usize j = 0; j < (COUNT); ++j) {                             \
            T a = (T)(VALUES)[i], b = (T)(VALUES)[j];                     \
            __uint128_t sum = (__uint128_t)a + (__uint128_t)b;            \
            __uint128_t diff = a >= b ? (__uint128_t)(a - b) : 0;         \
            __uint128_t prod = (__uint128_t)a * (__uint128_t)b;           \
            T es = sum > (__uint128_t)(MAXV) ? (T)(MAXV) : (T)sum;        \
            T ed = (T)diff;                                                \
            T ep = prod > (__uint128_t)(MAXV) ? (T)(MAXV) : (T)prod;      \
            if (sec_sadd_##N(a, b) != es ||                               \
                sec_ssub_##N(a, b) != ed ||                               \
                sec_smul_##N(a, b) != ep) return __LINE__;                \
        }                                                                  \
    }                                                                      \
} while (0)

int main(void) {
    const i64 s8[] = { INT8_MIN, INT8_MIN + 1, -2, -1, 0, 1, 2, INT8_MAX - 1, INT8_MAX };
    const u64 u8v[] = { 0, 1, 2, 127, 254, 255 };
    const i64 s16[] = { INT16_MIN, INT16_MIN + 1, -2, -1, 0, 1, 2, INT16_MAX - 1, INT16_MAX };
    const u64 u16v[] = { 0, 1, 2, 32767, 65534, 65535 };
    const i64 s32[] = { INT32_MIN, INT32_MIN + 1, -2, -1, 0, 1, 2, INT32_MAX - 1, INT32_MAX };
    const u64 u32v[] = { 0, 1, 2, UINT32_MAX / 2, UINT32_MAX - 1, UINT32_MAX };
    const i64 s64[] = { INT64_MIN, INT64_MIN + 1, -2, -1, 0, 1, 2, INT64_MAX - 1, INT64_MAX };
    const u64 u64v[] = { 0, 1, 2, UINT64_MAX / 2, UINT64_MAX - 1, UINT64_MAX };

    CHECK_SIGNED(i8, i8, INT8_MIN, INT8_MAX, s8, sizeof s8 / sizeof *s8);
    CHECK_UNSIGNED(u8, u8, UINT8_MAX, u8v, sizeof u8v / sizeof *u8v);
    CHECK_SIGNED(i16, i16, INT16_MIN, INT16_MAX, s16, sizeof s16 / sizeof *s16);
    CHECK_UNSIGNED(u16, u16, UINT16_MAX, u16v, sizeof u16v / sizeof *u16v);
    CHECK_SIGNED(i32, i32, INT32_MIN, INT32_MAX, s32, sizeof s32 / sizeof *s32);
    CHECK_UNSIGNED(u32, u32, UINT32_MAX, u32v, sizeof u32v / sizeof *u32v);
    CHECK_SIGNED(i64, i64, INT64_MIN, INT64_MAX, s64, sizeof s64 / sizeof *s64);
    CHECK_UNSIGNED(u64, u64, UINT64_MAX, u64v, sizeof u64v / sizeof *u64v);
    CHECK_UNSIGNED(usize, usize, SIZE_MAX, u64v, sizeof u64v / sizeof *u64v);
    return 0;
}
"""


class SaturatingArithmeticProperties(unittest.TestCase):
    def test_all_integer_widths_match_wide_reference_model(self):
        with tempfile.TemporaryDirectory(prefix="secure-saturating-") as td:
            source = pathlib.Path(td) / "properties.c"
            executable = pathlib.Path(td) / "properties"
            source.write_text(HARNESS, encoding="utf-8")
            build = subprocess.run(
                [
                    "gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-function", "-I", str(ROOT / "securec"),
                    str(source), "-o", str(executable),
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
                f"reference-model mismatch at C harness line {result.returncode}",
            )


if __name__ == "__main__":
    unittest.main()
