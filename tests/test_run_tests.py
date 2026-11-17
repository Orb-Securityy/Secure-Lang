import unittest

from run_tests import sanitizer_diagnostics


class SanitizerDiagnosticTests(unittest.TestCase):
    def test_address_sanitizer_is_detected(self):
        self.assertTrue(sanitizer_diagnostics("==123==ERROR: AddressSanitizer: heap-use-after-free"))

    def test_leak_sanitizer_is_detected(self):
        self.assertTrue(sanitizer_diagnostics("ERROR: LeakSanitizer: detected memory leaks"))

    def test_undefined_behavior_is_detected(self):
        self.assertTrue(sanitizer_diagnostics("runtime error: signed integer overflow"))

    def test_secure_panic_is_not_a_sanitizer_diagnostic(self):
        self.assertEqual(
            sanitizer_diagnostics("secure: panic at example.sec:1:1: integer overflow"),
            [],
        )

    def test_empty_stderr_is_clean(self):
        self.assertEqual(sanitizer_diagnostics(""), [])


if __name__ == "__main__":
    unittest.main()
