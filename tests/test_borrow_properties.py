"""Deterministic property-style tests for Secure's call-scoped borrow rules.

The reference model is intentionally tiny and independent of the compiler:
for each root place, multiple shared borrows are allowed; any mutable borrow
must be the sole access to that root in the call. These tests exhaustively
enumerate small argument lists and vary argument order.
"""
import itertools
import unittest

from securec.compiler import Compiler
from securec.lexer import SecError


class BorrowExclusivityProperties(unittest.TestCase):
    @staticmethod
    def source(arguments):
        params = []
        actuals = []
        for index, (root, mutable) in enumerate(arguments):
            marker = "&mut " if mutable else "&"
            params.append(f"p{index}: {marker}i32")
            actuals.append(f"{marker}{root}")
        return (
            f"fn probe({', '.join(params)}) {{}}\n"
            "fn main() {\n"
            "    let mut x: i32 = 1;\n"
            "    let mut y: i32 = 2;\n"
            f"    probe({', '.join(actuals)});\n"
            "}\n"
        )

    @staticmethod
    def model_rejects(arguments):
        by_root = {}
        for root, mutable in arguments:
            by_root.setdefault(root, []).append(mutable)
        return any(
            len(accesses) > 1 and any(accesses)
            for accesses in by_root.values()
        )

    def assert_matches_model(self, arguments):
        source = self.source(arguments)
        rejected = False
        try:
            Compiler(source, "borrow-property.sec").compile()
        except SecError as exc:
            rejected = True
            self.assertIn("conflicting access", str(exc), source)
        self.assertEqual(
            rejected,
            self.model_rejects(arguments),
            msg=f"borrow checker disagreed with reference model: {arguments!r}",
        )

    def test_exhaustive_two_to_four_argument_access_patterns(self):
        # Every argument independently selects x/y and shared/mutable.
        # This checks alias grouping, not just adjacent argument pairs.
        for count in range(2, 5):
            choices = list(itertools.product(("x", "y"), (False, True)))
            for arguments in itertools.product(choices, repeat=count):
                with self.subTest(arguments=arguments):
                    self.assert_matches_model(arguments)

    def test_argument_permutations_do_not_change_exclusivity(self):
        patterns = (
            (("x", True), ("x", False), ("y", False)),
            (("x", False), ("x", False), ("y", True)),
            (("x", True), ("y", True), ("x", False)),
            (("x", False), ("y", False), ("x", False)),
        )
        for pattern in patterns:
            expected = self.model_rejects(pattern)
            for permutation in set(itertools.permutations(pattern)):
                with self.subTest(permutation=permutation):
                    self.assert_matches_model(permutation)
                    self.assertEqual(self.model_rejects(permutation), expected)


if __name__ == "__main__":
    unittest.main()
