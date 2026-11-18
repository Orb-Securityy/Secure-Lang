# Secure — a security-first systems language (v0.1.22, bootstrap)

**Orb Security · Orb Corporation · Proprietary project · public source repository**

Secure is a general-purpose, natively compiled language whose design goal is that *whole classes of
vulnerabilities cannot be expressed in safe code*: memory corruption, data races, integer wrap-around,
null dereference, uninitialized reads, silent numeric conversion, ignored errors.

This repository is the **bootstrap toolchain**: `securec`, a compiler written in Python (a memory-safe host)
that type-checks, ownership-checks and lowers Secure to hardened GNU C11, then to a native PIE binary via `gcc`.
The current backend requires 8-bit bytes, fixed integer/bool/f64 sizes, a 64-bit `size_t`/pointer ABI, and bounded scalar/thread alignments; unsupported targets are rejected at compile time.
It is a working, tested v0.1.22 safety-hardening update — not a finished production system. Read `docs/SECURITY.md` for exactly what is
and is not guaranteed.

```
bin/securec run   prog.sec          # compile + run
bin/securec build prog.sec -o prog  # native executable (hardened flags)
bin/securec check prog.sec          # type/ownership/borrow check only
bin/securec emit-c prog.sec         # inspect the generated C (deterministic)
bin/securec audit prog.sec          # JSON: source SHA-256, every unsafe/extern site
  flags for regular commands: --forbid-unsafe  --sanitize (ASan/UBSan/LSan)  -O0..-O3  --strict-cc
python3 tests/run_tests.py          # conformance: normal + ASan/UBSan/LSan
python3 -m unittest discover -s tests -p 'test_*.py'  # compiler/driver properties
python3 tests/run_analyzer.py       # GCC -fanalyzer on generated C
python tests/fuzz_frontend.py -atheris_runs=30000  # optional Atheris campaign
python tests/fuzz_native.py tests/native_fuzz_corpus -atheris_runs=50000  # native IR/ELF fuzzing
# Native arithmetic also has deterministic differential tests against an independent i32 reference model.
python3 bench/run_bench.py          # performance vs unchecked C
```

Experimental bootstrap command: `bin/securec native-build examples/native_hello.sec -o hello`.

Integer example: `bin/securec native-build examples/native_i32.sec -o answer`.
Mutable/control-flow example: `bin/securec native-build examples/native_mutable.sec -o mutable-example`.
Range-loop example: `bin/securec native-build examples/native_for.sec -o for-example`.
`native-build` is an experimental bootstrap path. It accepts `str` constants/immutable bindings; `i32` constants and immutable/mutable locals; checked runtime arithmetic and assignments (`=`, `+=`, `-=`, `*=`, `/=`, `%=`); comparison-based `if/else`; `while` loops; `for lo..hi` / `for lo..=hi` ranges; and nested `break/continue`. It also supports user-defined safe functions with up to 32 `i32` parameters, explicit `i32` returns, mutable parameters, forward calls, nested calls and recursion. The first six arguments use registers and remaining arguments use aligned System V AMD64 stack slots. `print/println` accepts strings and runtime `i32` values. These forms lower to verified control-flow IR and a static x86-64 Linux PIE ELF. The RX code segment may span multiple pages (up to 1 MiB); optional R-only data begins at the next 4 KiB-aligned offset after code, with a separate 1 MiB data cap. The verifier checks value-slot definitions, mutable-store targets, branch targets, reachability, and definite assignment, including loop back-edges and function call/return streams. Its forward must-analysis uses a worklist so only changed CFG nodes trigger successor re-evaluation. The generated code uses Linux syscalls directly and retries interrupted or partial writes. Arithmetic overflow, division by zero, and `INT32_MIN / -1` terminate with panic status 101. The native bootstrap enforces a 1 MiB UTF-8 source limit, a 512-global-constant limit, a 128-user-function limit, and a 2,048-instruction total IR limit; one cumulative instruction budget is enforced across `main` and all user functions while lowering, and the IR verifier independently checks the aggregate again. The path does not invoke C, GCC, an assembler, linker, or libc; the parser, source-to-IR lowering and driver are still Python, so this is not a self-hosted release. Dynamic memory, input, file/network APIs, and a general native standard library remain unsupported.

```
enum Error { Overflow }
struct Account { id: u32, balance: u64 }
impl Account {
    fn deposit(&mut self, amt: u64) -> Result<u64, Error> {
        match checked_add(self.balance, amt) {
            Some(b) => { self.balance = b; Ok(b) }
            None => Err(Error::Overflow),
        }
    }
}
```

## Layout
| Path | Purpose |
|---|---|
| `securec/lexer.py parser.py ty.py compiler.py driver.py` | compiler (front end, checker, C backend, CLI) |
| `securec/secure_rt.h` | the *entire* runtime: ~200 lines of auditable C (panics, checked ops, containers, I/O) |
| `tests/cases/*.sec`, `tests/run_tests.py` | conformance suite: must-run, must-reject, must-trap |
| `bench/` | benchmark programs in Secure and C |
| `examples/` | input validation, parallel sum, ledger |
| `docs/SPEC.md` `docs/SECURITY.md` `docs/AUDIT.md` | language reference, security model, audit workflow |
| `docs/FUZZING.md` `docs/STATIC_ANALYSIS.md` | bounded frontend fuzzing and generated-C analyzer workflow |

## Status (v0.1.22)
| Area | Status |
|---|---|
| Native compilation, hardened flags | Implemented (via GCC) |
| Memory safety in safe code (bounds, ownership, second-class refs) | Implemented, tested, not formally proven |
| Checked integer arithmetic / casts / shifts, compile-time constant checks | Implemented |
| Null safety, no uninitialized memory, no implicit conversions | Implemented |
| Data-race freedom (ownership-transfer threads: `spawn`/`join`) | Implemented (no shared mutable state yet) |
| `unsafe` / `extern` gating + `audit` report + `--forbid-unsafe` | Implemented |
| Option / Result / `?`, must-use Results | Implemented |
| Generics for user code, traits, closures, modules | **Not yet** |
| Package manager, dependency pinning/signing | **Not yet** |
| Standard library beyond core types (files, sockets, TLS, crypto) | **Not yet** (only `ct_eq`, `zeroize`, `parse_i64`, stdin) |
| Mutex / channels / atomics | **Not yet** |
| Self-hosting; own backend (removing GCC from the trusted base) | **Not yet** |
| Formal verification of the checker | **Not yet** |
