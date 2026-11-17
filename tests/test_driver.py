import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

from securec.driver import cc_build, main


class DriverInputTests(unittest.TestCase):
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

    def test_run_temp_directory_failure_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "program.sec")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("fn main() -> i32 { return 0; }")

            stderr = io.StringIO()
            with patch("securec.driver.tempfile.mkdtemp", side_effect=OSError("no temporary space")):
                with contextlib.redirect_stderr(stderr):
                    result = main(["run", path])

            self.assertEqual(result, 2)
            self.assertIn("cannot create temporary run directory", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

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
