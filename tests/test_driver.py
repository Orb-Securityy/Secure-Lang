import contextlib
import io
import os
import tempfile
import unittest

from securec.driver import main


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
