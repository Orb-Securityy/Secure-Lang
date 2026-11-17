# Secure security model (v0.1)

**Nothing here claims perfect security.** Each property below states *what is enforced, where, and which tests
demonstrate it*. Tests live in `tests/cases` (`fail_*` must be rejected at compile time, `panic_*` must trap
with status 101, `pass_*` must run and, under ASan/UBSan/LeakSanitizer, produce no findings). Run
`python3 tests/run_tests.py` (the runner reports the exact execution count for the current checkout; compile-fail cases run once and executable cases run in normal and sanitizer modes).

## 1. Threat model
In scope: attacker-controlled *program inputs* (stdin, arguments, data) trying to trigger memory corruption,
integer wrap-around, type confusion, data races or silent error swallowing in code written in the safe subset.
Out of scope for v0.1: a malicious *programmer* inside `unsafe`/`extern`; side channels (beyond the best-effort
`ct_eq`); malicious toolchain components; denial of service by resource exhaustion (deep recursion, huge
allocations are not rate-limited).

## 2. Trusted computing base (what you must still trust)
`securec` (Python, ~3 kLOC) → generated C → **GCC 13** → glibc. The hand-written runtime is the single
file `securec/secure_rt.h` (~200 lines). A bug in any of these can void the guarantees. There is no formal
proof of the checker; the argument is by construction (§3) plus tests. Removing GCC from the TCB (own backend)
and mechanizing the ownership/borrow rules are roadmap items.

## 3. Guarantees, mechanisms, evidence
| Property | Mechanism | Evidence (tests) |
|---|---|---|
| **No out-of-bounds access** | every index/slice is range-checked (`SEC_IDX`, slice range check); constant indices into arrays rejected at compile time; index must be `usize` | `panic_array_oob_dynamic`, `panic_vec_oob`, `panic_vec_oob_write`, `panic_slice_oob_param`, `panic_slice_range_invalid/_reversed`, `fail_const_oob_index`, `fail_index_must_be_usize` |
| **Recursive owned aggregates** | user structs may contain `Vec` and `Task` handles whose payloads refer back to the struct, including inline `Option`, `Result`, and fixed-array wrappers; inline dependencies are completed before later structs embed them by value | `pass_recursive_vec_struct`, `pass_recursive_task_struct`, `pass_recursive_vec_option_struct`, `pass_recursive_vec_result_struct`, `pass_recursive_vec_array_struct`, `pass_recursive_pending_option_later_embedded` |
| **No dangling pointers after reallocation** | operands that run user code are evaluated *before* any pointer into a container is formed | `pass_realloc_in_args`, `panic_index_operand_clears_vec` (ASan-clean) |
| **No use-after-free / double free / invalid free** | linear ownership for `String`/`Vec`/`Task`/aggregates; flow-sensitive move checking; automatic drop with run-time drop flags | `fail_use_after_move`, `fail_move_in_loop`, `fail_maybe_moved_branch`, `fail_partial_move`, `pass_moves_flow`, `pass_ownership_torture`, all `pass_*` under ASan/LSan |
| **No dangling references** | references are second-class: only call arguments; cannot be stored, returned or put in collections | `fail_ref_in_let`, `fail_ref_stored_in_struct`, `fail_ref_returned`, `fail_ref_in_vec` |
| **No aliasing of `&mut`** | exclusivity law per call (`&mut x` excludes any other borrow/move of `x`) | `fail_alias_mut_and_shared`, `fail_alias_two_mut`, `fail_push_str_self_alias`, `fail_borrow_mut_of_immutable`, `fail_shared_ref_to_mut`, `fail_mutate_through_shared` |
| **No integer overflow/wrap** | checked `+ - * / % neg << >> pow abs`; signed `MIN / -1` and `MIN % -1` trap; left shifts are checked against the destination type's range for signed and unsigned integers; checked casts; compile-time folding of constants; wrapping is explicit (`wrapping_*`, `as wrapping`) | `panic_add_overflow_i32`, `panic_sub_overflow_u8`, `panic_mul_overflow_i64`, `panic_neg_min`, `panic_div_zero`, `panic_rem_zero`, `panic_div_min_neg1`, `panic_rem_min_neg1`, `panic_shift_too_far`, `panic_shift_signed_overflow`, `panic_shift_unsigned_overflow`, `panic_shift_negative_overflow`, `fail_const_shift_overflow`, `fail_const_shift_typed_rhs_overflow`, `fail_const_rem_min_neg1`, `pass_left_shift_negative`, `panic_cast_*`, `panic_pow_overflow`, `panic_abs_min`, `fail_const_overflow*`, `fail_literal_out_of_range`, `pass_int_ops` |
| **Null safety** | no null value; absence is `Option<T>`; `match` must be exhaustive | `fail_nonexhaustive_option`, `fail_nonexhaustive_enum`, `fail_none_uninferable`, `panic_unwrap_none` |
| **No uninitialized memory** | `let` requires an initializer; struct literals must set every field; generated C also compiled with `-ftrivial-auto-var-init=zero` | `fail_uninitialized_let`, `fail_missing_field` |
| **Bounded declared stack arrays** | a conservative aggregate-size upper bound (including inline `Option`/`Result` payloads and struct padding) rejects arrays above 1 MiB | `fail_huge_stack_array`, `fail_huge_nested_option_array`, `fail_huge_nested_result_array` |
| **No type confusion** | no implicit numeric conversions, no unions, no pointer/int casts, only listed `as` conversions | `fail_mismatched_int_types`, `fail_no_implicit_widening`, `fail_cast_bool_from_int`, `fail_cannot_negate_unsigned` |
| **Errors cannot be silently ignored** | a `Result` used as a statement is a compile error | `fail_unused_result` |
| **No data races (safe code)** | threads exchange only *moved owned values*; no global mutable state, no stored references, and `spawn` rejects raw pointers recursively through aggregate fields and generic containers | `pass_spawn`, `fail_spawn_with_ref_param`, `fail_spawn_with_nested_raw_pointer`, `fail_use_after_spawn_move`, `panic_in_spawned_thread`, `pass_example_parallel_sum` |
| **Unsafe is explicit and auditable** | `extern`, `unsafe fn`, raw deref and pointer arithmetic need `unsafe`; `audit` lists every site; `--forbid-unsafe` bans them | `fail_unsafe_call_needs_block`, `fail_raw_deref_needs_unsafe`, `fail_forbid_unsafe_flag`, `pass_unsafe_extern` |
| **Input validation helpers** | `parse_i64` is strict (no whitespace, sign only, overflow → `None`); `read_line` distinguishes EOF from stdin I/O errors (which panic) | `pass_option_result`, `pass_example_input_validation`, `panic_read_line_io_error` |
| **Malformed source handling** | malformed radix and numeric-separator literals, out-of-range floating-point literals, unsupported non-ASCII identifier/digit characters, Unicode digits embedded in numeric tokens, invalid UTF-8 source files, excessively nested source expressions, native toolchain/process launch failures, and terminal control/format characters in source diagnostics are handled safely; deterministic token-stream testing checks that malformed input does not escape as an unhandled front-end exception | `tests/test_frontend.py`, `tests/test_driver.py`, `fail_nonfinite_f64_literal`, `fail_numeric_separator_placement` |
| **Collision-free C symbols and composite types** | enum constants receive globally unique C names; method owner/name components and both `Result<T, E>` type arguments are length-prefixed | `pass_enum_c_name_collisions`, `pass_method_c_name_collisions`, `pass_result_c_type_mangle_collision` |
| **Safe generated source locations** | source basenames are encoded as bytes and C-escaped before being embedded in diagnostic literals | `tests/test_codegen.py` |
| **Cleanup on non-local exits** | all owned expression temporaries are tracked; values transferred into locals, aggregates, containers, and calls are removed from cleanup tracking; earlier call arguments are dropped if a later argument exits through `?` | `pass_try_drops_inflight_borrow`, `pass_option_try_drops_inflight_borrow`, `pass_try_transfers_owned_error`, `pass_return_drops_inflight_borrow`, `pass_return_preserves_owned_value`, `pass_loop_exit_drops_inflight_borrow`, `pass_loop_exit_preserves_outer_temps`, `pass_try_drops_owned_call_arg`, `pass_try_drops_wrapped_owned_call_arg` |
| **Compiler/binary hardening** | PIE, RELRO+BIND_NOW, NX stack, stack protector, stack-clash protection, CET (`-fcf-protection=full`), `_FORTIFY_SOURCE=2`, `-fwrapv`, `-fno-strict-aliasing` | `securec/driver.py: HARDEN` |
| **Build output safety** | the native output path is checked against the source path (including filesystem aliases); extensionless sources default to a separate `.out` path | `tests/test_driver.py` |
| **Deterministic code generation** | no timestamps or randomness; panic locations include only the escaped source basename and source span | verified: repeated `emit-c` runs for the same source identity hash identically |

### Why safe code cannot corrupt memory (sketch, not a proof)
1. All memory is reached through (a) locals, (b) bounds-checked indexing, (c) references that exist only for the
   duration of one call and are formed *after* all user code in the argument list has run, or (d) `unsafe`.
2. Heap objects have a single owner, released exactly once (move analysis + drop flags). References cannot be
   stored, so none can outlive the owner. The exclusivity law removes `&mut` aliasing for the call's duration.
3. Arithmetic that could produce an out-of-range size/index panics instead of wrapping; allocation size is
   overflow-checked; failed allocation panics.
4. Therefore the remaining undefined behaviour sources are: bugs in the TCB (§2) and `unsafe`.

## 4. Known gaps and limitations (be aware)
* **Not proven.** Soundness rests on construction + the current conformance suite, deterministic malformed-input tests for the lexer/parser and ASan/UBSan runs, not on a machine-checked proof. The exact run count is emitted by the test runner and changes as cases are added.
  Adversarial testing of the compiler (fuzzing, differential testing) has only begun (see `pass_realloc_in_args`).
* **Panics are fail-fast** (`_exit(101)`, no unwinding, no destructors): an attacker able to trigger a panic gets
  denial of service, not corruption. Resource exhaustion (huge `Vec`, deep recursion → guard-page crash) is not limited.
* **Panic is fail-fast** (`_exit(101)`): it does not unwind or run destructors. Temporary values and local owners are explicitly cleaned on `return`, `?` propagation, `break`, and `continue`. `exit()` cleans the current function frame only; caller frames do not unwind before process termination.
* **`ct_eq`/`zeroize` are best effort** (volatile accesses); constant-time behaviour is not verified at machine level.
* **Not implemented yet** (so *no* security claim is made): cryptographic API safety (no crypto library), secure
  networking/TLS, file I/O policy, dependency integrity / supply-chain tooling (no package manager; only the source
  SHA-256 in `audit`), mutexes/channels/atomics, user generics/traits/closures.
* `unsafe`/`extern` code is outside every guarantee above.
* Signed `>>` is an arithmetic shift (GCC-defined behaviour); enum values are plain `i32`.

## 5. Roadmap (priority order)
1. Fuzzing + differential testing of the checker; property tests for move/borrow analysis; formalize the rules.
2. Hoisting/elimination of redundant checks (range analysis) to close the matmul-style gap; iterator-style loops.
3. Generics + traits (enables a real standard library: collections, `Result` helpers, formatting).
4. Std: files, sockets, TLS/crypto bindings behind capability-typed handles; `Secret<T>` with zeroize-on-drop.
5. Package manager: lockfiles with content hashes, signed registry, reproducible builds, `--forbid-unsafe` per dependency.
6. Mutex/channel/atomic types with `Send`/`Sync`-style checking; scoped threads.
7. Native backend (LLVM or own) and self-hosting to shrink the TCB.
