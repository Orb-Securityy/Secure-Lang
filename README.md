# Secure — a security-first systems language (v0.1, bootstrap)

**Orb Security · Orb Corporation · Proprietary & confidential**

Secure is a general-purpose, natively compiled language whose design goal is that *whole classes of
vulnerabilities cannot be expressed in safe code*: memory corruption, data races, integer wrap-around,
null dereference, uninitialized reads, silent numeric conversion, ignored errors.

This repository is the **bootstrap toolchain**: `securec`, a compiler written in Python (a memory-safe host)
that type-checks, ownership-checks and lowers Secure to hardened C11, then to a native PIE binary via `gcc`.
It is a working, tested v0.1 — not a finished production system. Read `docs/SECURITY.md` for exactly what is
and is not guaranteed.

```
bin/securec run   prog.sec          # compile + run
bin/securec build prog.sec -o prog  # native executable (hardened flags)
bin/securec check prog.sec          # type/ownership/borrow check only
bin/securec emit-c prog.sec         # inspect the generated C (deterministic)
bin/securec audit prog.sec          # JSON: source SHA-256, every unsafe/extern site
  flags: --forbid-unsafe  --sanitize (ASan/UBSan/LSan)  -O0..-O3  --strict-cc
python3 tests/run_tests.py          # full conformance suite
python3 bench/run_bench.py          # performance vs unchecked C
```

```
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

## Status (v0.1)
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
