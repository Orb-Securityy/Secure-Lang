"""Command line driver: securec {build,run,check,emit-c,audit} file.sec"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from securec import VERSION
from securec.lexer import SecError
from securec.compiler import Compiler

HERE = os.path.dirname(os.path.abspath(__file__))
HARDEN = ["-std=gnu11", "-fstack-protector-strong", "-fstack-clash-protection", "-fcf-protection=full",
          "-D_FORTIFY_SOURCE=2", "-fPIE", "-pie", "-fwrapv", "-fno-strict-aliasing",
          "-ftrivial-auto-var-init=zero", "-Wl,-z,relro,-z,now,-z,noexecstack", "-pthread"]


def report(e, path, src):
    lines = src.splitlines()
    print(f"error: {e.msg}", file=sys.stderr)
    if e.line:
        print(f"  --> {os.path.basename(path)}:{e.line}:{e.col}", file=sys.stderr)
        if 0 < e.line <= len(lines):
            print(f"   | {lines[e.line - 1]}", file=sys.stderr)
            print(f"   | {' ' * max(e.col - 1, 0)}^", file=sys.stderr)


def compile_source(path, forbid_unsafe=False):
    src = open(path, encoding="utf-8").read()
    comp = Compiler(src, path, forbid_unsafe)
    try:
        csrc = comp.compile()
    except SecError as e:
        report(e, path, src)
        return None, None, src
    return csrc, comp, src


def cc_build(csrc, out, opt="-O2", strict=False, sanitize=False):
    with tempfile.TemporaryDirectory() as td:
        cpath = os.path.join(td, "out.c")
        open(cpath, "w").write(csrc)
        cmd = ["gcc", opt, "-I", HERE] + HARDEN + (["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g"] if sanitize else []) + (["-Wall", "-Wno-unused", "-Wno-type-limits", "-Werror"] if strict
                                                    else ["-w"]) + [cpath, "-o", out, "-lm"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("internal compiler error: generated C failed to build (this is a bug in securec)", file=sys.stderr)
            print(r.stderr[:4000], file=sys.stderr)
            return False
    return True


def audit_report(path, src, comp):
    return {"tool": "securec " + VERSION, "source": os.path.basename(path),
            "sha256": hashlib.sha256(src.encode()).hexdigest(),
            "unsafe_blocks": comp.audit["unsafe_blocks"], "unsafe_fns": comp.audit["unsafe_fns"],
            "extern_fns": comp.audit["extern_fns"],
            "safe_subset": not (comp.audit["unsafe_blocks"] or comp.audit["unsafe_fns"] or comp.audit["extern_fns"])}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="securec", description="Secure language compiler")
    ap.add_argument("cmd", choices=["build", "run", "check", "emit-c", "audit"])
    ap.add_argument("file")
    ap.add_argument("-o", "--output")
    ap.add_argument("-O", dest="opt", default="2", choices=["0", "1", "2", "3"])
    ap.add_argument("--forbid-unsafe", action="store_true", help="reject unsafe blocks, unsafe fns and extern")
    ap.add_argument("--strict-cc", action="store_true", help="build generated C with -Wall -Werror (compiler testing)")
    ap.add_argument("--sanitize", action="store_true", help="build with ASan/UBSan/LeakSanitizer (testing)")
    ap.add_argument("args", nargs="*")
    a = ap.parse_args(argv)
    csrc, comp, src = compile_source(a.file, a.forbid_unsafe)
    if csrc is None:
        return 1
    if a.cmd == "check":
        return 0
    if a.cmd == "emit-c":
        sys.stdout.write(csrc)
        return 0
    if a.cmd == "audit":
        print(json.dumps(audit_report(a.file, src, comp), indent=2))
        return 0
    out = a.output or os.path.splitext(a.file)[0]
    if a.cmd == "run":
        out = os.path.join(tempfile.mkdtemp(), "secure_prog")
    if not cc_build(csrc, out, "-O" + a.opt, a.strict_cc, a.sanitize):
        return 2
    if a.cmd == "run":
        r = subprocess.run([out] + a.args)
        return r.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
