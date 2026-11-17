# Changelog

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
