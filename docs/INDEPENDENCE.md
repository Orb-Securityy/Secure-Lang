# Independent toolchain architecture

Status: **target architecture; only a tiny native bootstrap slice exists** (see §8). This document defines the acceptance criteria for an independently buildable Secure toolchain. It is stricter than adding a second code-generation option.

## 1. Definition of independence

A release is independent only when:

1. The compiler implementation is written in Secure and the released compiler executable is produced by Secure itself (self-hosting).
2. The compiler emits target machine code and executable metadata directly. It does not emit C, C++, LLVM IR, or assembly for another toolchain to finish.
3. The normal build path does not invoke Python, GCC, Clang, LLVM, an assembler, a linker, or a C runtime.
4. The language runtime is part of the Secure toolchain and is emitted as native code. Core operations do not require glibc, libgcc, libstdc++, or another language runtime.
5. The compiler, runtime, executable writer, and their security tests are maintained in this repository, so defects in the toolchain can be fixed and rebuilt here.

The target OS and CPU remain external interfaces. The first target is **x86-64 Linux, System V AMD64 ABI, Linux syscall ABI**. The Linux kernel is not part of Secure. Independence does not imply the ability to patch CPU, firmware, kernel, or application-dependency vulnerabilities; it means the production toolchain has no required external language compiler or runtime.

## 2. Bootstrap boundary

A compiler cannot compile its first executable before some compiler exists. Secure therefore needs a finite bootstrap chain:

- **Stage 0 — temporary seed:** the current Python compiler and C/GCC backend. Construction-only; not the intended release compiler.
- **Stage 1 — Secure-written compiler:** compiler source written in Secure and compiled once by Stage 0.
- **Stage 2 — native self-hosted compiler:** Stage 1 compiles that same source to a native executable using Secure's own backend.
- **Stage 3 — rebuild verification:** Stage 2 compiles the same source again. The resulting compiler must reproduce the prior artifact, or any allowed nondeterminism must be specified and independently checked.

After verification, Stage 0 may remain as a clearly labelled recovery seed, but it must not be invoked by normal compile, build, test, or release commands. Publish bootstrap artifacts with their source revision, hashes, provenance, and rebuild procedure. A bootstrap artifact is a root of trust, not a proof; the project must not claim zero bootstrap or zero trust.

## 3. Target architecture

### 3.1 Frontend and typed intermediate representation

The current implementation combines type/ownership checking and C text emission in `securec/compiler.py`. That coupling must be removed before the native backend can be added safely.

Split the frontend into explicit stages:

1. byte-safe source loading and lexing;
2. parsing into an AST;
3. name and type resolution;
4. flow-sensitive ownership, borrow, and must-use checking;
5. lowering into a typed, backend-neutral IR;
6. verification of IR invariants;
7. target-specific native code generation.

The IR must preserve source locations, concrete types, signedness and width, ownership transfers, drop obligations, and checked-operation semantics. Backends must not re-infer ownership from untyped syntax. Reject malformed IR before code generation.

### 3.2 Native executable backend

The first backend is a direct x86-64 Linux backend. It must encode x86-64 instructions, implement a documented calling convention and stack-frame discipline, allocate registers and spills, resolve labels/branches/calls/relocations, and write ELF64 executable metadata and loadable segments itself.

Every size, offset, alignment, displacement, and file-range calculation must be checked for overflow. The writer must enforce a non-executable stack and prohibit writable-executable segments. Unsupported instructions, relocations, or ABI features must be rejected rather than guessed.

The first milestone may emit a minimal static `ET_EXEC`. PIE, shared objects, dynamic linking, and other architectures are later milestones and must not be claimed without dedicated tests. No generated C or assembly is allowed in the production path. Debug-only disassembly is acceptable; Secure itself must produce the machine bytes and ELF image.

### 3.3 Runtime and system interface

Replace `securec/secure_rt.h` with a small, audited native runtime. Initial scope: process entry/exit, stdin/stdout/stderr, checked integer helpers, panic reporting, allocation/deallocation, memory primitives, and the `String`/`Vec` operations required by the supported subset.

On the first target, OS services use a documented Linux syscall layer. Generated programs must not secretly call glibc or compiler helper libraries. Unsupported operations must be rejected. Keep the syscall boundary small and explicit; safe user code must not gain arbitrary syscall access.

## 4. Migration phases and exit gates

| Phase | Deliverable | Exit gate |
|---|---|---|
| A | Extract typed IR from the current compiler | Existing conformance suite still passes; IR verifier rejects malformed states |
| B | Direct x86-64 encoder and ELF writer | Tiny programs run without GCC, assembler, linker, or libc; ELF layout and bounds are tested |
| C | Native core runtime | I/O, panic, checked arithmetic, and owned containers pass without a C runtime |
| D | Secure-written frontend and checker | Secure source parses, type-checks, and lowers itself; existing safety rules have equivalent tests |
| E | Self-hosted native compiler | Stage 1 emits Stage 2; Stage 2 compiles itself; rebuild verification succeeds |
| F | Remove external toolchain from normal path | Release build and conformance CI run without Python/GCC/Clang/LLVM/assembler/linker; dependency audit confirms no hidden runtime imports |
| G | Expand targets and standard library | Each target has its own ABI, codegen, runtime, and adversarial test matrix |

These are gates, not marketing milestones. A sample program running is not sufficient evidence to mark a phase complete.

## 5. Security acceptance criteria

The native backend becomes part of the trusted computing base. It needs stronger validation, not fewer tests:

- unit tests for every instruction encoder, immediate width, displacement, relocation, and ELF field;
- property tests for integer layout, alignment, bounds, and address calculations;
- adversarial tests for malformed AST/IR, extreme nesting, oversized programs, duplicate symbols, and invalid control-flow targets;
- executable tests for stack alignment, calling convention, register preservation, syscall argument layout, and exit status;
- differential tests against separate reference models for checked arithmetic and selected language semantics (test-only, never a production dependency);
- fuzzing at source-byte, token, AST, IR, object, and executable-loader boundaries;
- reproducible builds and independent inspection of ELF headers, segments, imports, and unresolved symbols;
- self-host rebuild verification with exact hashes and toolchain provenance.

A passing test suite is evidence, not a mathematical proof. Document unproven assumptions and the remaining trusted computing base.

## 6. First-release non-goals

The first independent release will not claim Windows, macOS, ARM, dynamic linking, shared libraries, a package registry, a cryptographic standard library, TLS, or a formally verified compiler. Unsupported features must fail closed.

## 7. Current blockers

The current repository does **not** satisfy the independence definition:

- `bin/securec` launches Python;
- `securec/compiler.py` emits C source;
- `securec/driver.py` invokes GCC;
- `securec/secure_rt.h` is a C runtime and depends on libc/pthreads;
- the CI workflow requires Python and GCC.

These are architectural dependencies, not packaging issues. Each must be removed from the release path while preserving a temporary, auditable bootstrap boundary until self-hosting is established.
## 8. Prototype status

The `independence/self-hosted-native-toolchain` branch contains a direct-ELF vertical slice exposed as `securec native-build`. The subset supports `str` constants/bindings; `i32` constants and immutable/mutable locals; checked runtime arithmetic and assignments (`=`, `+=`, `-=`, `*=`, `/=`, `%=`); comparison-based `if`/`else`; `while` loops; and `for lo..hi` / `for lo..=hi` ranges with nested `break`/`continue`. Inclusive ranges branch out at the upper endpoint before incrementing, avoiding overflow at `i32::MAX`. The frontend lowers to verified control-flow IR with SSA-like temporary slots, explicit mutable-local slots, branches, labels, loop back-edges, range-step blocks, and loop-exit/continue jumps. The IR verifier checks unique slot definitions, mutable-store targets, branch targets, reachability, and definite assignment across all control-flow paths, including loop edges. The x86-64 backend emits a static PIE ELF directly, with non-executable stack and separate RX/R-only segments. It handles short writes and retries `EINTR`; arithmetic overflow, division by zero, and `INT32_MIN / -1` terminate with status 101. The native command does not import the C compiler or invoke GCC, an assembler, linker, libc, or another language runtime.

This is **not** completion of Phase B or overall independence: the host parser and source-to-IR lowering still run on Python, only local `i32` values and explicitly mutable `i32` parameters are mutable, the ordinary `build`/`run` path remains Python-to-C-to-GCC, and the existing C runtime remains in place. The native backend has a small bespoke runtime (integer formatting, writes, arithmetic traps), not a general standard library. User-defined functions are now supported only in the narrow native subset: safe functions with up to 32 `i32` parameters, explicit `i32` returns, forward calls, nested calls, mutable scalar parameters, and recursion. The first six arguments use System V AMD64 integer registers; remaining arguments use aligned stack slots. Dynamic memory, input/file/network APIs, general types, generics, ownership/borrow checking parity, multiple targets, and a formal soundness proof are still absent. The native checker is a narrow subset checker and does not inherit every guarantee of the existing full compiler. It is experimental; do not treat the current subset as a production security boundary.
