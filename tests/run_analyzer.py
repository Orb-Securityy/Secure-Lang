#!/usr/bin/env python3
"""Run GCC's path-sensitive static analyzer over generated C from pass cases."""

import glob
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECUREC = os.path.join(ROOT, "bin", "securec")
CASES = sorted(glob.glob(os.path.join(ROOT, "tests", "cases", "pass_*.sec")))


def run_case(source_path, temp_dir):
    source_name = os.path.basename(source_path)
    emitted = subprocess.run(
        [SECUREC, "emit-c", source_path],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if emitted.returncode != 0:
        return f"Secure failed to emit C (exit {emitted.returncode}):\n{emitted.stderr[:1200]}"

    c_path = os.path.join(temp_dir, source_name + ".c")
    obj_path = os.path.join(temp_dir, source_name + ".o")
    with open(c_path, "w", encoding="utf-8") as stream:
        stream.write(emitted.stdout)

    command = [
        "gcc",
        "-std=gnu11",
        "-O0",
        "-fanalyzer",
        "-Wall",
        "-Werror",
        "-Wno-unused",
        "-Wno-type-limits",
        "-I",
        os.path.join(ROOT, "securec"),
        "-c",
        c_path,
        "-o",
        obj_path,
    ]
    try:
        analyzed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return "GCC -fanalyzer timed out after 60 seconds"

    if analyzed.returncode != 0:
        diagnostics = (analyzed.stderr or analyzed.stdout)[:5000]
        return f"GCC -fanalyzer rejected generated C (exit {analyzed.returncode}):\n{diagnostics}"
    return ""


def main():
    if not CASES:
        print("error: no pass_*.sec conformance cases found", file=sys.stderr)
        return 2

    failures = 0
    with tempfile.TemporaryDirectory(prefix="secure-analyzer-") as temp_dir:
        for source_path in CASES:
            try:
                result = run_case(source_path, temp_dir)
            except (OSError, subprocess.TimeoutExpired) as exc:
                result = f"analyzer infrastructure error: {exc}"
            if result:
                failures += 1
                print(f"FAIL {os.path.basename(source_path)}\n{result}\n")
            else:
                print(f"ok   {os.path.basename(source_path)}")

    passed = len(CASES) - failures
    print(f"\nGCC analyzer: {passed}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
