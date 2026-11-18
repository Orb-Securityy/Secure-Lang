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
python3 bench/run_bench.py          # performance vs unchecked C
```

Experimental bootstrap command: `bin/securec native-build examples/native_hello.sec -o hello`.
`native-build` is an experimental bootstrap path: it accepts `str` constants, immutable `str` bindings, and `print`/`println` calls whose arguments resolve to static strings. Those forms lower to a verified immutable IR, then a static x86-64 Linux ELF. The generated code uses Linux syscalls directly and retries interrupted or partial writes. The path does not invoke GCC, an assembler, a linker, or libc. The parser/driver are still Python; this restricted path is **not** the normal compiler or a self-hosted release.

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
