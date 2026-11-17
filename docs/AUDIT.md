# Auditing a closed-source toolchain

Secure's implementation is proprietary and **must not be published**. Independent audit is still possible
because everything an auditor needs about a *program* is derivable without the compiler's source:

1. **`securec emit-c prog.sec`** — the full generated C (deterministic: same input ⇒ same bytes). Auditors review
   and rebuild exactly what ships. Pair it with `securec/secure_rt.h` (the whole runtime, ~200 lines, shippable
   under NDA or publishable independently because it contains no compiler internals).
2. **`securec audit prog.sec`** — JSON with the source SHA-256, every `unsafe` block, `unsafe fn` and `extern`
   declaration with line numbers, and `safe_subset: true/false`. CI policy: fail the build when `safe_subset` is false
   unless the sites are reviewed; or compile with `--forbid-unsafe`.
3. **Conformance suite** — `tests/cases` documents, executably, every guarantee (what must be rejected, what must
   trap). Customers can run it against the shipped `securec` binary to verify that the toolchain they received
   enforces the contract, without seeing the implementation.
4. **Sanitized builds** — `securec build --sanitize` produces ASan/UBSan/LeakSanitizer binaries of any program.
5. **Hardened build profile** — flags are fixed in one list (`driver.py: HARDEN`) and are visible in build logs.

Recommended (not yet implemented): signed release attestations binding {compiler binary hash, runtime hash,
conformance results}; source escrow for accredited auditors under NDA; reproducible-build verification of the
compiler binary itself; per-dependency audit reports once a package manager exists.
