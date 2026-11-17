# Changelog

## 0.1.5 — aggregate stack-size accounting

- Compute a conservative upper bound for inline aggregate sizes, including `Option<T>`, both `Result<T, E>` payloads, and struct padding before applying the 1 MiB array limit.
- Traverse both `Result` payloads during recursive inline-type detection, so recursive error types are diagnosed consistently.
- Add rejection cases for oversized arrays containing large `Option`/`Result` payloads and recursive `Result` error types.

## 0.1.4 — numeric literal diagnostics

- Reject non-finite floating-point literals as source errors instead of emitting invalid C identifiers such as `inf`.
- Convert integer literals with an `f64` suffix under overflow handling, reporting a source diagnostic instead of leaking Python `OverflowError`.
- Add lexer and conformance regressions for oversized decimal exponents and oversized integer-to-f64 literals.

## 0.1.3 — code generation and test-harness correctness

- Generate globally unique C enumerator names, avoiding collisions with other enums and C typedefs.
- Encode method owner/name components unambiguously in generated C symbols.
- Length-prefix both generic arguments in generated `Result<T, E>` type names to prevent underscore-based type collisions.
- Escape source basenames as C string literals before embedding them in panic locations.
- Reject raw pointers nested in struct fields when passing values to spawned tasks.
- Verify expected stdout for every executable conformance case, including panic cases and intentionally empty output.
- Add regressions for enum/method symbol collisions, nested raw pointers, source-location escaping, and strict output checking.

## 0.1.2 — ownership cleanup fix

- Track lexical scope depth for owned expression temporaries.
- Drop active temporaries on `return` and `?` propagation, preserving values whose ownership transfers to the caller.
- Drop only temporaries belonging to the loop being exited on `break` and `continue`; preserve outer-expression temporaries.
- Clean up active temporaries and local owners in the current function frame before explicit `exit()`; caller frames remain non-unwinding.
- Add ASan/UBSan/LSan regression cases for `Result` and `Option` propagation, early return, break and continue.

## 0.1.1 — hardening update

- Check explicitly typed compile-time shift counts independently from the shifted integer type.
- Reject malformed hexadecimal and binary literals with a source diagnostic instead of leaking a Python exception.
- Harden the conformance runner with timeouts, temporary-directory cleanup, and sanitizer checks on expected-panic paths.
- Add deterministic malformed-input tests for the lexer and parser, plus sanitizer-classification unit tests.
- Extend shift tests to cover negative operands, valid boundary values, and typed shift-count overflow.
- Pin the GitHub checkout action and run Python unit tests in CI.

This is a development update, not a formal verification result or production security certification.
