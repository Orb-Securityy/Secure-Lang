# Frontend fuzzing

Secure's lexer, parser, type checker, ownership/borrow checker and C lowering
are security-critical parts of the trusted computing base. The conformance
suite checks known cases; coverage-guided fuzzing explores unexpected
combinations and malformed programs.

## Run locally

Install the optional test dependency and run a bounded campaign:

```sh
python -m pip install -r requirements-fuzz.txt
python tests/fuzz_frontend.py -atheris_runs=30000
```

Atheris is a test-only dependency. It is not linked into generated programs or
required to use the Secure compiler. The target is bounded to 16 KiB per input
and does not invoke GCC or execute generated binaries.

## What counts as a finding

A normal Secure diagnostic (`SecError`) is expected for arbitrary input.
An uncaught Python exception, hang, process crash or unbounded resource use
is a finding. Do not broadly catch exceptions in the harness: that would hide
compiler defects.

For every finding:

1. Preserve the exact input as a regression fixture.
2. Reproduce it against the current main branch.
3. Minimize the input while preserving the failure.
4. Add a deterministic unit test before fixing the defect.
5. Re-run unit tests, conformance tests and the fuzz campaign.

The scheduled GitHub Actions job runs a bounded campaign weekly. A manual
campaign can be started with workflow dispatch. A clean campaign is evidence
only for the inputs explored; it is not a proof of compiler soundness or
memory safety.

## Third-party licensing

The harness uses Atheris as an optional development tool, pinned in
`requirements-fuzz.txt`. Atheris is distributed under Apache-2.0. No Atheris
implementation code is copied into Secure, and Atheris is not a runtime
dependency of Secure executables. Upstream: https://github.com/google/atheris
