"""Command line driver: securec {build,run,check,emit-c,audit,native-build} file.sec"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from securec import VERSION
from securec.lexer import SecError
from securec.native_x86_64 import compile_native_subset

HERE = os.path.dirname(os.path.abspath(__file__))
HARDEN = ["-std=gnu11", "-fstack-protector-strong", "-fstack-clash-protection", "-fcf-protection=full",
          "-D_FORTIFY_SOURCE=2", "-fPIE", "-pie", "-fwrapv", "-fno-strict-aliasing",
          "-ftrivial-auto-var-init=zero", "-Wl,-z,relro,-z,now,-z,noexecstack", "-pthread"]


def terminal_safe(value, preserve_newlines=False):
    """Escape terminal control/format characters in untrusted diagnostic text."""
    out = []
    for ch in str(value):
        if ch == "\n" and preserve_newlines:
            out.append(ch)
        elif ch.isprintable():
            out.append(ch)
        else:
            code = ord(ch)
            if code <= 0xFF:
                out.append(f"\\x{code:02x}")
            elif code <= 0xFFFF:
                out.append(f"\\u{code:04x}")
            else:
                out.append(f"\\U{code:08x}")
    return "".join(out)


def report(e, path, src):
    lines = src.splitlines()
    print(f"error: {terminal_safe(e.msg)}", file=sys.stderr)
    if e.line:
        print(f"  --> {terminal_safe(os.path.basename(path))}:{e.line}:{e.col}", file=sys.stderr)
        if 0 < e.line <= len(lines):
            line = lines[e.line - 1]
            prefix = line[:max(e.col - 1, 0)]
            print(f"   | {terminal_safe(line)}", file=sys.stderr)
            print(f"   | {' ' * len(terminal_safe(prefix))}^", file=sys.stderr)


def compile_source(path, forbid_unsafe=False):
    from securec.compiler import Compiler

    try:
        with open(path, encoding="utf-8") as source_file:
            src = source_file.read()
    except UnicodeDecodeError as exc:
        print(
            f"error: {terminal_safe(os.path.basename(path))} is not valid UTF-8 "
            f"(invalid byte at offset {exc.start})",
            file=sys.stderr,
        )
        return None, None, None
    except OSError as exc:
        print(f"error: cannot read source file {terminal_safe(os.path.basename(path))}: {terminal_safe(exc.strerror or exc)}",
              file=sys.stderr)
        return None, None, None
    comp = Compiler(src, path, forbid_unsafe)
    try:
        csrc = comp.compile()
    except SecError as e:
        report(e, path, src)
        return None, None, src
    except RecursionError:
        print(
            f"error: source nesting exceeds the compiler's supported depth in {terminal_safe(os.path.basename(path))}",
            file=sys.stderr,
        )
        return None, None, src
    return csrc, comp, src


def cc_build(csrc, out, opt="-O2", strict=False, sanitize=False):
    try:
        # Stage the executable on the destination filesystem, then atomically
        # replace the directory entry. Passing the requested path directly to
        # GCC would follow an existing symlink (or truncate a hard-link target)
        # before the build had even succeeded.
        output_dir = os.path.dirname(os.path.abspath(out))
        with tempfile.TemporaryDirectory(prefix=".secure-build-", dir=output_dir) as td:
            cpath = os.path.join(td, "out.c")
            staged_out = os.path.join(td, "program")
            with open(cpath, "w", encoding="utf-8") as source_file:
                source_file.write(csrc)
            cmd = ["gcc", opt, "-I", HERE] + HARDEN + (["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g"] if sanitize else []) + (["-Wall", "-Wno-unused", "-Wno-type-limits", "-Werror"] if strict
                                                        else ["-w"]) + [cpath, "-o", staged_out, "-lm"]
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
            if r.returncode != 0:
                print("internal compiler error: generated C failed to build (this is a bug in securec)", file=sys.stderr)
                print(terminal_safe(r.stderr[:4000], preserve_newlines=True), file=sys.stderr)
                return False
            # os.replace replaces a symlink/hard-link directory entry itself;
            # it never follows the link and leaves its former target untouched.
            os.replace(staged_out, out)
    except OSError as exc:
        print(f"error: could not start native build or safely install build output: {terminal_safe(exc.strerror or exc)}",
              file=sys.stderr)
        return False
    return True



def native_build_file(path, output=None):
    """Build the experimental native subset without invoking C, GCC, or another linker."""
    try:
        with open(path, "rb") as source_file:
            raw = source_file.read()
        src = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        print(
            f"error: {terminal_safe(os.path.basename(path))} is not valid UTF-8 "
            f"(invalid byte at offset {exc.start})",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(f"error: cannot read source file {terminal_safe(os.path.basename(path))}: "
              f"{terminal_safe(exc.strerror or exc)}", file=sys.stderr)
        return 1

    try:
        image = compile_native_subset(src)
    except SecError as exc:
        report(exc, path, src)
        return 1
    except (ValueError, OverflowError) as exc:
        print(f"error: native backend rejected program: {terminal_safe(exc)}", file=sys.stderr)
        return 1

    if output is None:
        stem, extension = os.path.splitext(path)
        output = stem if extension else path + ".out"
    if same_file_path(path, output):
        print("error: output path must differ from the source file", file=sys.stderr)
        return 2

    try:
        output_dir = os.path.dirname(os.path.abspath(output))
        with tempfile.TemporaryDirectory(prefix=".secure-native-", dir=output_dir) as td:
            staged = os.path.join(td, "program")
            with open(staged, "xb") as executable:
                executable.write(image)
                executable.flush()
                os.fsync(executable.fileno())
            os.chmod(staged, 0o755)
            os.replace(staged, output)
    except OSError as exc:
        print(f"error: could not safely install native output: "
              f"{terminal_safe(exc.strerror or exc)}", file=sys.stderr)
        return 2
    return 0

def same_file_path(source, output):
    """Return true for identical paths, symlinks, or hard links."""
    source_path = os.path.realpath(os.path.abspath(source))
    output_path = os.path.realpath(os.path.abspath(output))
    try:
        if os.path.exists(source_path) and os.path.exists(output_path):
            if os.path.samefile(source_path, output_path):
                return True
    except OSError:
        pass
    return os.path.normcase(source_path) == os.path.normcase(output_path)


def audit_report(path, src, comp):
    return {"tool": "securec " + VERSION, "source": os.path.basename(path),
            "sha256": hashlib.sha256(src.encode()).hexdigest(),
            "unsafe_blocks": comp.audit["unsafe_blocks"], "unsafe_fns": comp.audit["unsafe_fns"],
            "extern_fns": comp.audit["extern_fns"],
            "safe_subset": not (comp.audit["unsafe_blocks"] or comp.audit["unsafe_fns"] or comp.audit["extern_fns"])}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="securec", description="Secure language compiler")
    ap.add_argument("cmd", choices=["build", "run", "check", "emit-c", "audit", "native-build"])
    ap.add_argument("file")
    ap.add_argument("-o", "--output")
    ap.add_argument("-O", dest="opt", default="2", choices=["0", "1", "2", "3"])
    ap.add_argument("--forbid-unsafe", action="store_true", help="reject unsafe blocks, unsafe fns and extern")
    ap.add_argument("--strict-cc", action="store_true", help="build generated C with -Wall -Werror (compiler testing)")
    ap.add_argument("--sanitize", action="store_true", help="build with ASan/UBSan/LeakSanitizer (testing)")
    ap.add_argument("args", nargs="*")
    a = ap.parse_args(argv)
    if a.cmd == "native-build":
        if a.args or a.strict_cc or a.sanitize or a.opt != "2":
            ap.error("native-build does not accept C compiler flags or program arguments")
        return native_build_file(a.file, a.output)
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
    if a.cmd == "run":
        try:
            with tempfile.TemporaryDirectory(prefix="secure-run-") as run_dir:
                out = os.path.join(run_dir, "secure_prog")
                if not cc_build(csrc, out, "-O" + a.opt, a.strict_cc, a.sanitize):
                    return 2
                try:
                    r = subprocess.run([out] + a.args)
                except OSError as exc:
                    print(f"error: cannot execute compiled program: {terminal_safe(exc.strerror or exc)}", file=sys.stderr)
                    return 2
                return r.returncode
        except OSError as exc:
            print(f"error: cannot create or clean temporary run directory: {terminal_safe(exc.strerror or exc)}",
                  file=sys.stderr)
            return 2

    if a.output is not None:
        out = a.output
    else:
        stem, extension = os.path.splitext(a.file)
        out = stem if extension else a.file + ".out"
    if same_file_path(a.file, out):
        print("error: output path must differ from the source file", file=sys.stderr)
        return 2
    if not cc_build(csrc, out, "-O" + a.opt, a.strict_cc, a.sanitize):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
