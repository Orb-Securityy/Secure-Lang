import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from securec.driver import cc_build, main, report, terminal_safe
from securec.lexer import SecError


class DriverInputTests(unittest.TestCase):
    def test_terminal_safe_escapes_control_and_bidi_characters(self):
        self.assertEqual(
            terminal_safe("hello\x1b[31m\u202e"),
            "hello\\x1b[31m\\u202e",
        )
        self.assertEqual(
            terminal_safe("line one\nline two", preserve_newlines=True),
            "line one\nline two",
        )

    def test_source_diagnostics_escape_terminal_controls_and_align_caret(self):
        stderr = io.StringIO()
        source = "a\x1b[2Jz"
        filename = "evil\x1b[2J.sec"
        with contextlib.redirect_stderr(stderr):
            report(SecError("bad\x1b[31m", 1, 2), filename, source)

        output = stderr.getvalue()
        self.assertNotIn("\x1b", output)
        self.assertIn("evil\\x1b[2J.sec", output)
        self.assertIn("bad\\x1b[31m", output)
        self.assertIn("a\\x1b[2Jz", output)
        self.assertIn("   |  ^", output)

    def test_invalid_utf8_source_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "invalid.sec")
            with open(path, "wb") as stream:
                stream.write(b"fn main() -> i32 { return 0; }\xff")

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = main(["check", path])

            self.assertEqual(result, 1)
            self.assertIn("is not valid UTF-8", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


    def test_deeply_nested_source_is_reported_without_traceback(self):
        nested = "(" * 1200 + "0" + ")" * 1200
        source = f"fn main() -> i32 {{ return {nested}; }}"
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "deep.sec")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(source)

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = main(["check", path])

            self.assertEqual(result, 1)
            self.assertIn("source nesting exceeds", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


    def test_missing_native_compiler_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            output = os.path.join(td, "program")
            stderr = io.StringIO()
            with patch("securec.driver.subprocess.run", side_effect=FileNotFoundError("gcc not found")):
                with contextlib.redirect_stderr(stderr):
                    result = cc_build("int main(void) { return 0; }", output)

            self.assertFalse(result)
            self.assertIn("could not start native build", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_failed_program_launch_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "program.sec")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("fn main() -> i32 { return 0; }")

            stderr = io.StringIO()
            with patch("securec.driver.cc_build", return_value=True):
                with patch("securec.driver.subprocess.run", side_effect=FileNotFoundError("program missing")):
                    with contextlib.redirect_stderr(stderr):
                        result = main(["run", path])

            self.assertEqual(result, 2)
            self.assertIn("cannot execute compiled program", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_build_without_extension_does_not_overwrite_source(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "program")
            source = "fn main() -> i32 { return 0; }"
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(source)

            outputs = []
            with patch("securec.driver.cc_build", side_effect=lambda csrc, out, *args: outputs.append(out) or True):
                result = main(["build", path])

            self.assertEqual(result, 0)
            self.assertEqual(outputs, [path + ".out"])
            with open(path, encoding="utf-8") as stream:
                self.assertEqual(stream.read(), source)

    def test_build_rejects_output_path_equal_to_source(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "program.sec")
            source = "fn main() -> i32 { return 0; }"
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(source)

            stderr = io.StringIO()
            with patch("securec.driver.cc_build") as build:
                with contextlib.redirect_stderr(stderr):
                    result = main(["build", path, "-o", path])

            self.assertEqual(result, 2)
            self.assertFalse(build.called)
            self.assertIn("output path must differ from the source file", stderr.getvalue())
            with open(path, encoding="utf-8") as stream:
                self.assertEqual(stream.read(), source)

    def test_build_rejects_symlink_output_alias_to_source(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "program.sec")
            alias = os.path.join(td, "program-link")
            source = "fn main() -> i32 { return 0; }"
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(source)
            os.symlink(path, alias)

            stderr = io.StringIO()
            with patch("securec.driver.cc_build") as build:
                with contextlib.redirect_stderr(stderr):
                    result = main(["build", path, "-o", alias])

            self.assertEqual(result, 2)
            self.assertFalse(build.called)
            self.assertIn("output path must differ from the source file", stderr.getvalue())
            with open(path, encoding="utf-8") as stream:
                self.assertEqual(stream.read(), source)

    def test_build_rejects_hardlink_output_alias_to_source(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "program.sec")
            alias = os.path.join(td, "program-hardlink")
            source = "fn main() -> i32 { return 0; }"
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(source)
            os.link(path, alias)

            stderr = io.StringIO()
            with patch("securec.driver.cc_build") as build:
                with contextlib.redirect_stderr(stderr):
                    result = main(["build", path, "-o", alias])

            self.assertEqual(result, 2)
            self.assertFalse(build.called)
            self.assertIn("output path must differ from the source file", stderr.getvalue())
            with open(path, encoding="utf-8") as stream:
                self.assertEqual(stream.read(), source)

    def test_build_replaces_symlink_without_overwriting_its_target(self):
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "important-data")
            output = os.path.join(td, "program")
            with open(target, "w", encoding="utf-8") as stream:
                stream.write("keep this data")
            os.symlink(target, output)

            self.assertTrue(cc_build("int main(void) { return 0; }", output))

            with open(target, encoding="utf-8") as stream:
                self.assertEqual(stream.read(), "keep this data")
            self.assertFalse(os.path.islink(output))
            self.assertTrue(os.access(output, os.X_OK))

    def test_build_replaces_hardlink_without_overwriting_its_target(self):
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "important-data")
            output = os.path.join(td, "program")
            with open(target, "w", encoding="utf-8") as stream:
                stream.write("keep this data")
            os.link(target, output)

            self.assertTrue(cc_build("int main(void) { return 0; }", output))

            with open(target, encoding="utf-8") as stream:
                self.assertEqual(stream.read(), "keep this data")
            self.assertFalse(os.path.samefile(target, output))
            self.assertTrue(os.access(output, os.X_OK))

    def test_failed_build_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as td:
            output = os.path.join(td, "program")
            with open(output, "w", encoding="utf-8") as stream:
                stream.write("previous working output")
            stderr = io.StringIO()
            failed = subprocess.CompletedProcess(["gcc"], 1, "", "synthetic compiler failure")
            with patch("securec.driver.subprocess.run", return_value=failed):
                with contextlib.redirect_stderr(stderr):
                    self.assertFalse(cc_build("int main(void) { return 0; }", output))

            with open(output, encoding="utf-8") as stream:
                self.assertEqual(stream.read(), "previous working output")
            self.assertIn("synthetic compiler failure", stderr.getvalue())

    def test_run_temp_directory_failure_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "program.sec")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("fn main() -> i32 { return 0; }")

            stderr = io.StringIO()
            with patch("securec.driver.tempfile.TemporaryDirectory", side_effect=OSError("no temporary space")):
                with contextlib.redirect_stderr(stderr):
                    result = main(["run", path])

            self.assertEqual(result, 2)
            self.assertIn("cannot create or clean temporary run directory", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


    def test_run_temp_directory_is_removed_after_execution(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "program.sec")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("fn main() -> i32 { return 0; }")

            build_outputs = []

            def fake_build(csrc, output, *args):
                build_outputs.append(output)
                return True

            with patch("securec.driver.cc_build", side_effect=fake_build):
                with patch(
                    "securec.driver.subprocess.run",
                    return_value=subprocess.CompletedProcess(["program"], 0),
                ):
                    result = main(["run", path])

            self.assertEqual(result, 0)
            self.assertEqual(len(build_outputs), 1)
            self.assertFalse(os.path.exists(os.path.dirname(build_outputs[0])))

    def test_missing_source_file_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "missing.sec")

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = main(["check", path])

            self.assertEqual(result, 1)
            self.assertIn("cannot read source file", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
