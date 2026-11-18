# Changelog

## 0.1.22 — ABI, conversion, and ownership hardening

- Enforce the target ABI assumed by the compiler: 8-bit bytes, exact integer widths, 1-byte bool, 8-byte f64, full-range 64-bit usize/pointers, scalar alignment limits, and pthread layout bounds.
- Reject references hidden behind raw pointer types, preserving the rule that references exist only as direct call arguments.
- Reject mutable writes and borrows through immutable str literals, constants, views, and struct fields while preserving mutable access through owned String storage.
- Range-check enum-to-integer conversions instead of relying on unchecked C casts.
- Define wrapping arithmetic and wrapping casts through width-limited helpers, avoiding out-of-range unsigned-to-signed C conversions.
- Add exhaustive i8/u8 wrapping arithmetic and conversion property checks under UBSan, plus signed-width, enum-cast, immutable-string, and ABI regressions.
- Refresh security documentation to describe the enforced ABI, conversions, and current evidence accurately.

## 0.1.21 — call ordering and backend arithmetic hardening

- Enforce the documented three-phase call argument order: evaluate by-value arguments, evaluate every reference-place expression, then form borrowed pointers.
- Prevent null-pointer arithmetic when creating empty slices from Vec, String, existing slices, and str views.
- Use unsigned 128-bit intermediates for unsigned checked left shifts and wrapping multiplication, avoiding overflow in the safety checks themselves.
- Add sanitizer-backed regressions for argument ordering, container reallocation during borrow preparation, empty slices, maximum-width unsigned shifts, and small-width wrapping multiplication.
- Expand evidence with coverage-guided frontend fuzzing, deterministic differential arithmetic tests, ownership/borrow property tests, and GCC -fanalyzer.

## 0.1.20 — atomic build output installation

- Compile native executables in a temporary directory on the destination filesystem and install them with atomic replacement.
- Never follow a pre-existing output symlink or truncate a hard-link target; preserve the previous output when compilation fails.
- Add regressions for symlink targets, hard-link targets, and failed-build preservation.
- Add a dedicated CI workflow for the Python unit-test suite.

## 0.1.19 — numeric suffix type validation

- Reject integer suffixes (`i8` through `usize`) when attached to decimal floating-point literals instead of silently discarding the suffix and treating the token as `f64`.
- Keep suffix-free floats and explicit `f64` suffixes valid, including integer-valued literals such as `1f64`.
- Add frontend and compile-fail regressions for incompatible suffixes.

## 0.1.18 — build output path safety

- Prevent `securec build` from writing its executable over the source file, including when `-o` names the same path or a symlink/hard link to it.
- For source files without an extension, choose `<source>.out` instead of reusing and overwriting the source path.
- Add CLI regressions that verify the source remains unchanged in both cases.

## 0.1.17 — read_line I/O error handling

- Distinguish end-of-file from a real stdin read failure in the C runtime.
- Preserve `None` for EOF; fail fast with a runtime panic if `getline()` reports an I/O error.
- Add a regression that closes stdin before calling `read_line()` and verifies the I/O error is not silently treated as EOF.

## 0.1.16 — numeric separator validation

- Require `_` separators to appear strictly between digits in decimal, fractional, exponent, hexadecimal, and binary literals.
- Reject trailing and repeated separators instead of silently removing them (for example, `1__2` must not be interpreted as `12`).
- Reject incomplete hexadecimal and binary prefixes as malformed numeric literals.
- Add frontend and conformance regressions for valid and invalid separator placement.

## 0.1.15 — terminal-safe diagnostics

- Escape terminal control and Unicode format characters in compiler diagnostics, including source excerpts, error messages, filenames, and native compiler output.
- Preserve diagnostic line breaks while escaping other control characters in external compiler output.
- Recalculate the source caret position after escaping the displayed source prefix.
- Add regressions for ANSI escape sequences and bidirectional formatting controls in source text, messages, and filenames.

## Test harness — deterministic standard input

- Add `EXPECT-IN:` directives to executable conformance cases so tests can feed exact lines to stdin, including empty lines and leading/trailing spaces.
- Pass supplied input through `subprocess.run(input=...)` rather than always closing stdin with `/dev/null`.
- Exercise `read_line` and `parse_i64` with i64 minimum/maximum, numeric overflow, accumulator overflow, explicit plus, malformed signs, empty lines, whitespace, and trailing junk.
- Add unit tests for stdin header parsing and serialization.

## 0.1.14 — native toolchain launch diagnostics

- Convert failures to start GCC, access temporary build files, create a run directory, or launch a compiled program into concise CLI diagnostics instead of leaking Python tracebacks.
- Use an automatically cleaned temporary directory for `securec run`; compiled executables are removed after the program exits.
- Preserve normal compile-failure reporting and exit status conventions.
- Add driver tests for a missing native compiler, failed executable launch, temporary run-directory failure, and cleanup after a successful run.

## 0.1.13 — parser nesting diagnostics

- Convert parser/compiler `RecursionError` from deeply nested source expressions into a concise source diagnostic instead of leaking a Python traceback.
- Add a driver regression using 1,200 nested parentheses; verify exit status 1 and traceback-free stderr.

## 0.1.12 — source file input diagnostics

- Convert invalid UTF-8 source files into a clear CLI diagnostic instead of leaking `UnicodeDecodeError` tracebacks.
- Convert missing, unreadable, and other source file I/O errors into a concise CLI diagnostic.
- Add driver tests verifying nonzero exit status and traceback-free output for invalid UTF-8 and missing files.

## 0.1.11 — recursive inline dependency ordering

- Complete deferred `Option<T>`, `Result<T, E>`, and fixed-array wrappers as soon as their by-value struct dependencies are fully defined.
- Resolve by-value struct field dependencies before emitting the containing C struct body, independent of source declaration order.
- Keep `Vec<T>` and `Task<T>` payloads indirect so recursive ownership remains supported; defer their helper implementations until all element/result types are complete.
- Add a regression where `Holder` embeds `Option<Node>` before `Node` is defined, while `Node` itself contains `Vec<Option<Node>>`.

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
