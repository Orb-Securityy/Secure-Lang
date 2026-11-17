# Secure security model (v0.1)

**Nothing here claims perfect security.** Each property below states *what is enforced, where, and which tests
demonstrate it*. Tests live in `tests/cases` (`fail_*` must be rejected at compile time, `panic_*` must trap
with status 101, `pass_*` must run and, under ASan/UBSan/LeakSanitizer, produce no findings). Run
`python3 tests/run_tests.py` (139 runs at the time of writing).

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
| **No dangling pointers after reallocation** | operands that run user code are evaluated *before* any pointer into a container is formed | `pass_realloc_in_args`, `panic_index_operand_clears_vec` (ASan-clean) |
| **No use-after-free / double free / invalid free** | linear ownership for `String`/`Vec`/`Task`/aggregates; flow-sensitive move checking; automatic drop with run-time drop flags | `fail_use_after_move`, `fail_move_in_loop`, `fail_maybe_moved_branch`, `fail_partial_move`, `pass_moves_flow`, `pass_ownership_torture`, all `pass_*` under ASan/LSan |
| **No dangling references** | references are second-class: only call arguments; cannot be stored, returned or put in collections | `fail_ref_in_let`, `fail_ref_stored_in_struct`, `fail_ref_returned`, `fail_ref_in_vec` |
| **No aliasing of `&mut`** | exclusivity law per call (`&mut x` excludes any other borrow/move of `x`) | `fail_alias_mut_and_shared`, `fail_alias_two_mut`, `fail_push_str_self_alias`, `fail_borrow_mut_of_immutable`, `fail_shared_ref_to_mut`, `fail_mutate_through_shared` |
| **No integer overflow/wrap** | checked `+ - * / % neg << >> pow abs`; checked casts; compile-time folding of constants; wrapping is explicit (`wrapping_*`, `as wrapping`) | `panic_add_overflow_i32`, `panic_sub_overflow_u8`, `panic_mul_overflow_i64`, `panic_neg_min`, `panic_div_zero`, `panic_rem_zero`, `panic_div_min_neg1`, `panic_shift_too_far`, `panic_cast_*`, `panic_pow_overflow`, `panic_abs_min`, `fail_const_overflow*`, `fail_literal_out_of_range`, `pass_int_ops` |
| **Null safety** | no null value; absence is `Option<T>`; `match` must be exhaustive | `fail_nonexhaustive_option`, `fail_nonexhaustive_enum`, `fail_none_uninferable`, `panic_unwrap_none` |
| **No uninitialized memory** | `let` requires an initializer; struct literals must set every field; generated C also compiled with `-ftrivial-auto-var-init=zero` | `fail_uninitialized_let`, `fail_missing_field` |
| **No type confusion** | no implicit numeric conversions, no unions, no pointer/int casts, only listed `as` conversions | `fail_mismatched_int_types`, `fail_no_implicit_widening`, `fail_cast_bool_from_int`, `fail_cannot_negate_unsigned` |
| **Errors cannot be silently ignored** | a `Result` used as a statement is a compile error | `fail_unused_result` |
| **No data races (safe code)** | threads exchange only *moved owned values*; no global mutable state, no stored references, so nothing is shared; `spawn` rejects references/raw pointers | `pass_spawn`, `fail_spawn_with_ref_param`, `fail_use_after_spawn_move`, `panic_in_spawned_thread`, `pass_example_parallel_sum` |
| **Unsafe is explicit and auditable** | `extern`, `unsafe fn`, raw deref and pointer arithmetic need `unsafe`; `audit` lists every site; `--forbid-unsafe` bans them | `fail_unsafe_call_needs_block`, `fail_raw_deref_needs_unsafe`, `fail_forbid_unsafe_flag`, `pass_unsafe_extern` |
| **Input validation helpers** | `parse_i64` is strict (no whitespace, sign only, overflow → `None`) | `pass_option_result`, `pass_example_input_validation` |
| **Compiler/binary hardening** | PIE, RELRO+BIND_NOW, NX stack, stack protector, stack-clash protection, CET (`-fcf-protection=full`), `_FORTIFY_SOURCE=2`, `-fwrapv`, `-fno-strict-aliasing` | `securec/driver.py: HARDEN` |
| **Deterministic code generation** | no timestamps/paths/randomness in emitted C | verified: two runs of `emit-c` hash identically |

### Why safe code cannot corrupt memory (sketch, not a proof)
1. All memory is reached through (a) locals, (b) bounds-checked indexing, (c) references that exist only for the
   duration of one call and are formed *after* all user code in the argument list has run, or (d) `unsafe`.
2. Heap objects have a single owner, released exactly once (move analysis + drop flags). References cannot be
   stored, so none can outlive the owner. The exclusivity law removes `&mut` aliasing for the call's duration.
3. Arithmetic that could produce an out-of-range size/index panics instead of wrapping; allocation size is
   overflow-checked; failed allocation panics.
4. Therefore the remaining undefined behaviour sources are: bugs in the TCB (§2) and `unsafe`.

## 4. Known gaps and limitations (be aware)
* **Not proven.** Soundness rests on construction + 139 test runs + ASan/UBSan, not on a machine-checked proof.
  Adversarial testing of the compiler (fuzzing, differential testing) has only begun (see `pass_realloc_in_args`).
* **Panics are fail-fast** (`_exit(101)`, no unwinding, no destructors): an attacker able to trigger a panic gets
  denial of service, not corruption. Resource exhaustion (huge `Vec`, deep recursion → guard-page crash) is not limited.
* **Leaks are possible** when a temporary is in flight while `?`/`return` leaves an expression, and on `exit`/panic.
  Leaks are not memory-unsafe, but long-running services should avoid that pattern until fixed.
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
