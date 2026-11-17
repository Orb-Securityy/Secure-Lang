#!/usr/bin/env python3
"""Secure test runner.

Each tests/cases/*.sec starts with header comments:
  // EXPECT-OUT: <line of expected stdout>     (repeatable, in order)
  // EXPECT-ERR: <substring of compile error>  (compile must fail)
  // EXPECT-PANIC: <substring of stderr>       (run must exit 101)
  // EXPECT-EXIT: <n>                          (expected exit status, default 0)
  // FLAGS: <extra securec flags>
Runnable cases are built twice: normal (-Wall -Werror on the generated C) and with ASan+UBSan+LSan.
"""
import glob, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECUREC = os.path.join(ROOT, "bin", "securec")
SANITIZER_MARKERS = (
    "AddressSanitizer",
    "LeakSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
)


def sanitizer_issue(stderr):
    lowered = stderr.lower()
    for marker in SANITIZER_MARKERS:
        if marker.lower() in lowered:
            return marker
    return None


def headers(path):
    h = {"out": [], "err": [], "panic": [], "exit": 0, "flags": []}
    for line in open(path, encoding="utf-8"):
        if not line.startswith("//"):
            break
        line = line[2:].strip()
        for key, name in (("EXPECT-OUT:", "out"), ("EXPECT-ERR:", "err"), ("EXPECT-PANIC:", "panic")):
            if line.startswith(key):
                h[name].append(line[len(key):].strip() if name != "out" else line[len(key):].lstrip(" ").rstrip("\n"))
        if line.startswith("EXPECT-EXIT:"):
            h["exit"] = int(line.split(":")[1])
        if line.startswith("FLAGS:"):
            h["flags"] = line.split(":", 1)[1].split()
    return h


def run_case(path, sanitize):
    h = headers(path)
    name = os.path.basename(path)
    base = [SECUREC, "build", path, "--strict-cc"] + h["flags"]
    exe = os.path.join(tempfile.mkdtemp(), "t")
    r = subprocess.run(base + ["-o", exe] + (["--sanitize"] if sanitize else []), capture_output=True, text=True)
    if h["err"]:
        if sanitize:
            return None
        if r.returncode != 1:
            return f"expected compile error, got rc={r.returncode}\n{r.stderr[:500]}"
        for e in h["err"]:
            if e not in r.stderr:
                return f"error message missing {e!r}; got:\n{r.stderr[:600]}"
        return ""
    if r.returncode != 0:
        return f"compile failed (rc={r.returncode}):\n{r.stderr[:1500]}"
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=0", UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=0")
    p = subprocess.run([exe], capture_output=True, text=True, env=env, timeout=60, stdin=subprocess.DEVNULL)
    if sanitize:
        finding = sanitizer_issue(p.stderr)
        if finding:
            return f"sanitizer finding ({finding}) even when this case expected a Secure panic:\\n{p.stderr[:1200]}"
    if h["panic"]:
        if p.returncode != 101:
            return f"expected panic (exit 101), got {p.returncode}\nstderr: {p.stderr[:500]}"
        for e in h["panic"]:
            if e not in p.stderr:
                return f"panic message missing {e!r}; stderr: {p.stderr[:400]}"
    else:
        if p.returncode != h["exit"]:
            return f"exit status {p.returncode}, expected {h['exit']}\nstderr: {p.stderr[:800]}"
        if h["out"] and p.stdout.splitlines() != h["out"]:
            return "stdout mismatch:\n--- expected\n" + "\n".join(h["out"]) + "\n--- got\n" + p.stdout
        if sanitize and p.stderr.strip():
            return "sanitizer output:\n" + p.stderr[:800]
    return ""


def main():
    pats = [a for a in sys.argv[1:] if not a.startswith("-")]
    skip_san = "--no-sanitize" in sys.argv
    files = sorted(glob.glob(os.path.join(ROOT, "tests", "cases", "*.sec")))
    if pats:
        files = [f for f in files if any(p in f for p in pats)]
    fails = total = 0
    for f in files:
        for san in ([False] if skip_san else [False, True]):
            res = run_case(f, san)
            if res is None:
                continue
            total += 1
            tag = "san " if san else "std "
            if res:
                fails += 1
                print(f"FAIL [{tag}] {os.path.basename(f)}\n{res}\n")
            else:
                print(f"ok   [{tag}] {os.path.basename(f)}")
    print(f"\n{total - fails}/{total} passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
