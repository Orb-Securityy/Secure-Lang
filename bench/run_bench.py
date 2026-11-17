#!/usr/bin/env python3
"""Compare Secure (checked, hardened) against plain unchecked C -O2. Median of 5 runs, outputs must match."""
import os, statistics, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
SECUREC = os.path.join(HERE, "..", "bin", "securec")
def t(exe, n=5):
    ts, out = [], None
    for _ in range(n):
        s = time.perf_counter(); r = subprocess.run([exe], capture_output=True, text=True); ts.append(time.perf_counter() - s)
        out = r.stdout.strip()
    return statistics.median(ts), out
td = tempfile.mkdtemp()
print(f"{'benchmark':10} {'C -O2 (s)':>10} {'Secure (s)':>11} {'ratio':>7}  output-match")
for name in sys.argv[1:] or ["sieve", "matmul", "collatz", "fnv"]:
    sec, c = os.path.join(td, name + "_sec"), os.path.join(td, name + "_c")
    assert subprocess.run([SECUREC, "build", os.path.join(HERE, name + ".sec"), "-o", sec]).returncode == 0
    assert subprocess.run(["gcc", "-O2", os.path.join(HERE, name + ".c"), "-o", c, "-lm"]).returncode == 0
    tc, oc = t(c); ts, os_ = t(sec)
    print(f"{name:10} {tc:10.3f} {ts:11.3f} {ts/tc:7.2f}x  {'yes' if oc == os_ else 'NO: ' + repr(oc) + ' vs ' + repr(os_)}")
