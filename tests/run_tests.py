#!/usr/bin/env python3
"""Secure test runner with bounded execution and universal sanitizer checks."""

import glob
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECUREC = os.path.join(ROOT, "bin", "securec")
SANITIZER_MARKERS = (
    "AddressSanitizer",
    "LeakSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
)


def sanitizer_diagnostics(stderr):
    """Return diagnostic lines emitted by ASan, LSan or UBSan."""
    return [
        line for line in stderr.splitlines()
        if any(marker in line for marker in SANITIZER_MARKERS)
    ]


def headers(path):
    h = {"out": [], "err": [], "panic": [], "exit": 0, "flags": []}
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            if not line.startswith("//"):
                break
            line = line[2:].strip()
            for key, name in (("EXPECT-OUT:", "out"), ("EXPECT-ERR:", "err"), ("EXPECT-PANIC:", "panic")):
                if line.startswith(key):
                    value = line[len(key):]
                    h[name].append(value.lstrip(" ").rstrip("\n") if name == "out" else value.strip())
            if line.startswith("EXPECT-EXIT:"):
                h["exit"] = int(line.split(":", 1)[1].strip())
            if line.startswith("FLAGS:"):
                h["flags"] = line.split(":", 1)[1].split()
    return h


def run_case(path, sanitize):
    h = headers(path)
    base = [SECUREC, "build", path, "--strict-cc"] + h["flags"]

    with tempfile.TemporaryDirectory(prefix="secure-test-") as td:
        exe = os.path.join(td, "test-program")
        try:
            build = subprocess.run(
                base + ["-o", exe] + (["--sanitize"] if sanitize else []),
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return "compiler timed out after 60 seconds"

        if h["err"]:
            if sanitize:
                return None
            if build.returncode != 1:
                return f"expected compile error, got rc={build.returncode}\nstderr: {build.stderr[:500]}"
            for expected in h["err"]:
                if expected not in build.stderr:
                    return f"error message missing {expected!r}; got:\n{build.stderr[:600]}"
            return ""

        if build.returncode != 0:
            return f"compile failed (rc={build.returncode}):\n{build.stderr[:1500]}"

        env = dict(
            os.environ,
            ASAN_OPTIONS="detect_leaks=1:abort_on_error=0",
            UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=0",
        )
        try:
            result = subprocess.run(
                [exe],
                capture_output=True,
                text=True,
                env=env,
                timeout=60,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return "program timed out after 60 seconds"

        if sanitize:
            findings = sanitizer_diagnostics(result.stderr)
            if findings:
                return "sanitizer finding(s):\n" + "\n".join(findings[:12])

        if h["panic"]:
            if result.returncode != 101:
                return f"expected panic (exit 101), got {result.returncode}\nstderr: {result.stderr[:500]}"
            for expected in h["panic"]:
                if expected not in result.stderr:
                    return f"panic message missing {expected!r}; stderr: {result.stderr[:400]}"
        else:
            if result.returncode != h["exit"]:
                return f"exit status {result.returncode}, expected {h['exit']}\nstderr: {result.stderr[:800]}"
            if h["out"] and result.stdout.splitlines() != h["out"]:
                return "stdout mismatch:\n--- expected\n" + "\n".join(h["out"]) + "\n--- got\n" + result.stdout
            if sanitize and result.stderr.strip():
                return "unexpected stderr in sanitizer run:\n" + result.stderr[:800]
    return ""


def main():
    patterns = [arg for arg in sys.argv[1:] if not arg.startswith("-")]
    skip_san = "--no-sanitize" in sys.argv
    files = sorted(glob.glob(os.path.join(ROOT, "tests", "cases", "*.sec")))
    if patterns:
        files = [path for path in files if any(pattern in path for pattern in patterns)]

    failures = total = 0
    for path in files:
        for sanitize in ([False] if skip_san else [False, True]):
            result = run_case(path, sanitize)
            if result is None:
                continue
            total += 1
            tag = "san " if sanitize else "std "
            if result:
                failures += 1
                print(f"FAIL [{tag}] {os.path.basename(path)}\n{result}\n")
            else:
                print(f"ok   [{tag}] {os.path.basename(path)}")

    print(f"\n{total - failures}/{total} passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
