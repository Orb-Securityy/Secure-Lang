/* secure_rt.h - Secure runtime support (small, auditable, no hidden state).
 * Every operation that can fail a safety property funnels into sec_panic(),
 * which flushes stdout, prints a diagnostic and terminates with status 101.
 * Requires GNU C11 (statement expressions, __builtin_*_overflow, __int128). */
#ifndef SECURE_RT_H
#define SECURE_RT_H
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>

typedef int8_t i8;   typedef int16_t i16;  typedef int32_t i32;  typedef int64_t i64;
typedef uint8_t u8;  typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef size_t usize; typedef double f64;
typedef struct { char _; } sec_unit;
#define SEC_UNIT ((sec_unit){0})

#define SEC_MIN_i8 INT8_MIN
#define SEC_MAX_i8 INT8_MAX
#define SEC_MIN_i16 INT16_MIN
#define SEC_MAX_i16 INT16_MAX
#define SEC_MIN_i32 INT32_MIN
#define SEC_MAX_i32 INT32_MAX
#define SEC_MIN_i64 INT64_MIN
#define SEC_MAX_i64 INT64_MAX
#define SEC_MIN_u8 0
#define SEC_MAX_u8 UINT8_MAX
#define SEC_MIN_u16 0
#define SEC_MAX_u16 UINT16_MAX
#define SEC_MIN_u32 0
#define SEC_MAX_u32 UINT32_MAX
#define SEC_MIN_u64 0
#define SEC_MAX_u64 UINT64_MAX
#define SEC_MIN_usize 0
#define SEC_MAX_usize SIZE_MAX

/* ---- panics ------------------------------------------------------------ */
__attribute__((noreturn, cold, noinline))
static void sec_panic(const char *msg, const char *loc) {
    fflush(stdout);
    fprintf(stderr, "secure: panic at %s: %s\n", loc, msg);
    fflush(stderr);
    _exit(101);
}
__attribute__((noreturn, cold, noinline))
static void sec_oob(usize i, usize n, const char *loc) {
    fflush(stdout);
    fprintf(stderr, "secure: panic at %s: index out of bounds: the index is %zu but the length is %zu\n", loc, i, n);
    fflush(stderr);
    _exit(101);
}
__attribute__((noreturn, cold, noinline))
static void sec_oob_range(usize lo, usize hi, usize n, const char *loc) {
    fflush(stdout);
    fprintf(stderr, "secure: panic at %s: slice range %zu..%zu is invalid for length %zu\n", loc, lo, hi, n);
    fflush(stderr);
    _exit(101);
}
__attribute__((noreturn, cold, noinline))
static void sec_panic_str_raw(const u8 *p, usize n, const char *loc) {
    fflush(stdout);
    fprintf(stderr, "secure: panic at %s: ", loc);
    if (n) fwrite(p, 1, n, stderr);
    fputc('\n', stderr);
    fflush(stderr);
    _exit(101);
}
__attribute__((noreturn))
static void sec_exit(i32 code) { fflush(stdout); fflush(stderr); _exit(code); }

#define SEC_IDX(i, n, loc) ({ usize _si = (i); usize _sn = (n); if (__builtin_expect(_si >= _sn, 0)) { sec_oob(_si, _sn, loc); } _si; })

/* ---- checked integer arithmetic ----------------------------------------- */
#define SEC_DEF_INT(N, T, UT, MINV, MAXV, BITS) \
static inline T sec_add_##N(T a, T b, const char *l) { T r; if (__builtin_expect(__builtin_add_overflow(a, b, &r), 0)) sec_panic("integer overflow in addition", l); return r; } \
static inline T sec_sub_##N(T a, T b, const char *l) { T r; if (__builtin_expect(__builtin_sub_overflow(a, b, &r), 0)) sec_panic("integer overflow in subtraction", l); return r; } \
static inline T sec_mul_##N(T a, T b, const char *l) { T r; if (__builtin_expect(__builtin_mul_overflow(a, b, &r), 0)) sec_panic("integer overflow in multiplication", l); return r; } \
static inline T sec_div_##N(T a, T b, const char *l) { if (__builtin_expect(b == 0, 0)) sec_panic("division by zero", l); if ((MINV) < 0 && a == (T)(MINV) && b == (T)-1) sec_panic("integer overflow in division", l); return (T)(a / b); } \
static inline T sec_rem_##N(T a, T b, const char *l) { if (__builtin_expect(b == 0, 0)) sec_panic("remainder by zero", l); if ((MINV) < 0 && a == (T)(MINV) && b == (T)-1) sec_panic("integer overflow in remainder", l); return (T)(a % b); } \
static inline T sec_shl_##N(T a, u64 b, const char *l) { \
    if (__builtin_expect(b >= (BITS), 0)) sec_panic("shift amount out of range", l); \
    if ((MINV) < 0) { \
        __int128 _sv = (__int128)a * ((__int128)1 << b); \
        if (__builtin_expect(_sv < (__int128)(MINV) || _sv > (__int128)(MAXV), 0)) sec_panic("integer overflow in left shift", l); \
        return (T)_sv; \
    } \
    __uint128_t _uv = (__uint128_t)a * ((__uint128_t)1 << b); \
    if (__builtin_expect(_uv > (__uint128_t)(MAXV), 0)) sec_panic("integer overflow in left shift", l); \
    return (T)_uv; \
} \
static inline T sec_shr_##N(T a, u64 b, const char *l) { if (__builtin_expect(b >= (BITS), 0)) sec_panic("shift amount out of range", l); return (T)(a >> b); } \
static inline T sec_wadd_##N(T a, T b) { return (T)((UT)a + (UT)b); } \
static inline T sec_wsub_##N(T a, T b) { return (T)((UT)a - (UT)b); } \
static inline T sec_wmul_##N(T a, T b) { return (T)((UT)a * (UT)b); } \
static inline T sec_sadd_##N(T a, T b) { T r; if (__builtin_add_overflow(a, b, &r)) return ((MINV) < 0 && b < 0) ? (T)(MINV) : (T)(MAXV); return r; } \
static inline T sec_ssub_##N(T a, T b) { T r; if (__builtin_sub_overflow(a, b, &r)) return (b > 0) ? (T)(MINV) : (T)(MAXV); return r; } \
static inline T sec_smul_##N(T a, T b) { T r; if (__builtin_mul_overflow(a, b, &r)) return ((a < 0) != (b < 0)) ? (T)(MINV) : (T)(MAXV); return r; } \
static inline T sec_min_##N(T a, T b) { return a < b ? a : b; } \
static inline T sec_max_##N(T a, T b) { return a > b ? a : b; } \
static inline T sec_pow_##N(T a, u32 e, const char *l) { T r = 1, base = a; while (e) { if (e & 1) r = sec_mul_##N(r, base, l); e >>= 1; if (e) base = sec_mul_##N(base, base, l); } return r; } \
static inline T sec_not_##N(T a) { return (T)~a; }
SEC_DEF_INT(i8, i8, u8, INT8_MIN, INT8_MAX, 8)
SEC_DEF_INT(i16, i16, u16, INT16_MIN, INT16_MAX, 16)
SEC_DEF_INT(i32, i32, u32, INT32_MIN, INT32_MAX, 32)
SEC_DEF_INT(i64, i64, u64, INT64_MIN, INT64_MAX, 64)
SEC_DEF_INT(u8, u8, u8, 0, UINT8_MAX, 8)
SEC_DEF_INT(u16, u16, u16, 0, UINT16_MAX, 16)
SEC_DEF_INT(u32, u32, u32, 0, UINT32_MAX, 32)
SEC_DEF_INT(u64, u64, u64, 0, UINT64_MAX, 64)
SEC_DEF_INT(usize, usize, usize, 0, SIZE_MAX, 64)
#define SEC_DEF_SIGNED(N, T, MINV) \
static inline T sec_neg_##N(T a, const char *l) { if (__builtin_expect(a == (T)(MINV), 0)) sec_panic("integer overflow in negation", l); return (T)-a; } \
static inline T sec_abs_##N(T a, const char *l) { if (__builtin_expect(a == (T)(MINV), 0)) sec_panic("integer overflow in abs()", l); return a < 0 ? (T)-a : a; }
SEC_DEF_SIGNED(i8, i8, INT8_MIN)
SEC_DEF_SIGNED(i16, i16, INT16_MIN)
SEC_DEF_SIGNED(i32, i32, INT32_MIN)
SEC_DEF_SIGNED(i64, i64, INT64_MIN)

/* Checked conversion between integer types (and from float via sec_f2i). */
#define SEC_CAST(TO, MINV, MAXV, x, loc) ({ __int128 _cv = (__int128)(x); \
    if (__builtin_expect(_cv < (__int128)(MINV) || _cv > (__int128)(MAXV), 0)) { sec_panic("checked conversion out of range", loc); } \
    (TO)_cv; })
static inline __int128 sec_f2i(f64 x, const char *l) {
    if (!(x > -1.0e30 && x < 1.0e30)) sec_panic("float to integer conversion of NaN/infinite/huge value", l);
    return (__int128)x;
}

/* ---- allocation ------------------------------------------------------- */
static inline void *sec_realloc(void *p, usize n, usize sz) {
    usize bytes;
    if (__builtin_mul_overflow(n, sz, &bytes)) sec_panic("allocation size overflow", "runtime");
    void *q = realloc(p, bytes ? bytes : 1);
    if (!q) sec_panic("out of memory", "runtime");
    return q;
}
#define sec_nodrop(p) ((void)(p))

/* ---- containers (instantiated by the compiler per element type) ----------- */
#define SEC_DEF_SLICE(S, T) typedef struct { T *p; usize n; } S;
#define SEC_IMPL_VEC(V, T, DROP) \
static inline V V##_new(void) { V v = {0, 0, 0}; return v; } \
static inline void V##_push(V *v, T x) { \
    if (v->len == v->cap) { usize nc; if (__builtin_mul_overflow(v->cap, (usize)2, &nc)) sec_panic("capacity overflow", "runtime"); if (nc < 4) nc = 4; \
        v->p = (T *)sec_realloc(v->p, nc, sizeof(T)); v->cap = nc; } \
    v->p[v->len++] = x; } \
static inline void V##_drop(V *v) { for (usize i = 0; i < v->len; i++) DROP(&v->p[i]); free(v->p); v->p = 0; v->len = 0; v->cap = 0; }
#define SEC_DEF_VEC(V, T, DROP) \
typedef struct { T *p; usize len; usize cap; } V; \
SEC_IMPL_VEC(V, T, DROP)
#define SEC_DEF_OPT(O, T) typedef struct { bool some; T v; } O;
#define SEC_DEF_RES(R, T, E) typedef struct { bool ok; T v; E e; } R;
#define SEC_IMPL_TASK(K, R, DROP) \
static inline R K##_join(K *t) { \
    if (t->joined) sec_panic("task already joined", "runtime"); \
    if (pthread_join(t->th, NULL) != 0) sec_panic("failed to join thread", "runtime"); \
    R v = *t->res; free(t->res); t->res = NULL; t->joined = true; return v; } \
static inline void K##_drop(K *t) { if (!t->joined) { \
    if (pthread_join(t->th, NULL) != 0) sec_panic("failed to join thread during drop", "runtime"); \
    DROP(t->res); free(t->res); t->res = NULL; t->joined = true; } }
#define SEC_DEF_TASK(K, R, DROP) \
typedef struct { pthread_t th; R *res; bool joined; } K; \
SEC_IMPL_TASK(K, R, DROP)

SEC_DEF_SLICE(Slice_u8, u8)
SEC_DEF_VEC(Vec_u8, u8, sec_nodrop)

static inline bool sec_str_eq(Slice_u8 a, Slice_u8 b) { return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, a.n) == 0); }
static inline void Vec_u8_push_str(Vec_u8 *v, Slice_u8 s) { for (usize i = 0; i < s.n; i++) Vec_u8_push(v, s.p[i]); }
static inline Vec_u8 Vec_u8_from(Slice_u8 s) { Vec_u8 v = Vec_u8_new(); Vec_u8_push_str(&v, s); return v; }

/* ---- security helpers ------------------------------------------------------ */
static inline bool sec_ct_eq(Slice_u8 a, Slice_u8 b) {   /* length is public; contents compared without early exit */
    if (a.n != b.n) return false;
    volatile u8 d = 0;
    for (usize i = 0; i < a.n; i++) d |= (u8)(a.p[i] ^ b.p[i]);
    return d == 0;
}
static inline void sec_zeroize(Slice_u8 s) { volatile u8 *p = s.p; for (usize i = 0; i < s.n; i++) p[i] = 0; }

/* ---- I/O ----------------------------------------------------------------- */
static inline void sec_print_i64(i64 x) { printf("%lld", (long long)x); }
static inline void sec_print_u64(u64 x) { printf("%llu", (unsigned long long)x); }
static inline void sec_print_bool(bool b) { fputs(b ? "true" : "false", stdout); }
static inline void sec_print_str(Slice_u8 s) { if (s.n) fwrite(s.p, 1, s.n, stdout); }
static inline void sec_print_nl(void) { fputc('\n', stdout); }
static inline void sec_print_f64(f64 x) {   /* shortest decimal that round-trips; plain notation for moderate magnitudes */
    char buf[64];
    if (isfinite(x) && (x == 0 || (fabs(x) >= 1e-5 && fabs(x) < 1e15))) {
        for (int d = 0; d <= 17; d++) { snprintf(buf, sizeof buf, "%.*f", d, x); if (strtod(buf, NULL) == x) { fputs(buf, stdout); return; } }
    }
    for (int p = 1; p <= 17; p++) { snprintf(buf, sizeof buf, "%.*g", p, x); if (strtod(buf, NULL) == x) break; }
    fputs(buf, stdout);
}
static inline bool sec_read_line(Vec_u8 *out) {
    char *line = NULL; size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);
    if (n < 0) {
        bool read_error = ferror(stdin) != 0;
        free(line);
        if (read_error) sec_panic("failed to read standard input", "runtime");
        return false;
    }
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) n--;
    for (ssize_t i = 0; i < n; i++) Vec_u8_push(out, (u8)line[i]);
    free(line);
    return true;
}
static inline bool sec_parse_i64(Slice_u8 s, i64 *out) {   /* strict: [+-]?[0-9]+, no whitespace, no overflow */
    usize i = 0; bool neg = false;
    if (s.n == 0) return false;
    if (s.p[0] == '-' || s.p[0] == '+') { neg = s.p[0] == '-'; i = 1; }
    if (i == s.n) return false;
    i64 acc = 0;
    for (; i < s.n; i++) {
        if (s.p[i] < '0' || s.p[i] > '9') return false;
        int d = s.p[i] - '0';
        if (__builtin_mul_overflow(acc, (i64)10, &acc)) return false;
        if (neg ? __builtin_sub_overflow(acc, (i64)d, &acc) : __builtin_add_overflow(acc, (i64)d, &acc)) return false;
    }
    *out = acc;
    return true;
}
#endif
