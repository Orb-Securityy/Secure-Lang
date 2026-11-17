# Generated C static analysis

Secure emits GNU C11 and currently relies on GCC as part of its trusted
computing base. The normal conformance suite compiles and executes generated
programs; this additional check runs GCC's path-sensitive `-fanalyzer` over
the generated C translation unit for every `pass_*.sec` case.

## Run locally

```sh
python3 tests/run_analyzer.py
```

The analyzer compiles each generated translation unit separately with
warnings treated as errors. It does not execute the resulting object files.
The CI job uses the GCC version supplied by Ubuntu 24.04.

A clean analyzer run is useful static evidence, not a proof of memory safety.
GCC's analyzer has path and complexity limits, and it cannot establish the
soundness of Secure's type or ownership rules. Findings must be minimized,
reproduced, and added as regression cases before they are considered fixed.
