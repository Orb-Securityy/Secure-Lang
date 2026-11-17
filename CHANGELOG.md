# Changelog

## 0.1.10 — ASCII-only numeric tokenization

- Use explicit ASCII digit ranges throughout decimal, fractional, and exponent portions of numeric literals.
- Reject mixed ASCII/Unicode decimal numerals as source diagnostics instead of accepting Unicode decimal digit classes inconsistently.
- Add frontend tests for Arabic-Indic and full-width digits inside integer, decimal, exponent, and separated-digit forms.

## 0.1.9 — lexer character classification

- Restrict identifier and decimal-digit recognition to the same ASCII character set used by the lexer regexes.
- Report unsupported non-ASCII identifier/digit characters as source diagnostics instead of leaking a Python `AttributeError`.
- Add regression tests for accented Latin, Greek, Arabic-Indic, and full-width digit characters.

## 0.1.8 — owned expression temporary tracking

- Track every owned expression result, not only temporaries created while forming borrowed call arguments.
- Transfer tracked ownership explicitly into locals, assignments, struct/array literals, Option/Result constructors, Vec elements, function arguments, and block/match results.
- Ensure earlier owned arguments are dropped if a later call argument exits early through `?`; transfer them to the callee only once all arguments are successfully evaluated.
- Add normal and ASan/LSan regressions for direct and wrapped owned arguments across both early-propagation and normal-call paths.

## 0.1.7 — recursive inline aggregate code generation

- Forward-declare `Option<T>`, `Result<T, E>`, and fixed-array wrapper types when their inline payload references a struct currently being defined through a `Vec` or `Task` indirection.
- Complete deferred wrapper definitions after all referenced struct layouts are available, then emit their drop helpers before deferred container implementations.
- Add regressions for `Vec<Option<Node>>`, `Vec<Result<Node, i32>>`, and `Vec<[Node; 1]>`.

## 0.1.6 — recursive owned containers

- Forward-declare user struct types and split generated `Vec<T>`/`Task<T>` descriptors from helper implementations that take or return `T` by value.
- Support recursive owned structures such as `struct Node { children: Vec<Node> }` and `Option<Task<Node>>` without emitting functions that use incomplete C types by value.
- Forward-declare struct drop helpers so recursive vector and task destructors can call one another safely.
- Add ASan/UBSan conformance cases that construct, read, and drop recursive node structures.

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
