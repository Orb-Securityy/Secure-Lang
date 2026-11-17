"""Exhaustive ownership-state checks for two-way control-flow joins."""
import itertools
import unittest

from securec.compiler import Compiler
from securec.lexer import SecError


class OwnershipBranchJoinProperties(unittest.TestCase):
    ACTIONS = ("keep", "move", "reinitialize")

    @staticmethod
    def action_source(action):
        if action == "keep":
            return ""
        if action == "move":
            return "consume(s);"
        if action == "reinitialize":
            return 'consume(s); s = String::from("restored");'
        raise AssertionError(action)

    def compile_pair(self, then_action, else_action):
        source = (
            "fn consume(value: String) {}\n"
            "fn main() {\n"
            '    let mut s = String::from("owned");\n'
            "    if true {\n"
            f"        {self.action_source(then_action)}\n"
            "    } else {\n"
            f"        {self.action_source(else_action)}\n"
            "    }\n"
            "    consume(s);\n"
            "}\n"
        )
        try:
            Compiler(source, "ownership-branch-join.sec").compile()
            return True
        except SecError as exc:
            if "moved value" not in str(exc):
                raise
            return False

    def test_all_branch_action_pairs_match_flow_model(self):
        # A value is definitely available after the join only when every
        # reachable branch leaves it initialized (kept or reinitialized).
        for then_action, else_action in itertools.product(self.ACTIONS, repeat=2):
            with self.subTest(then_action=then_action, else_action=else_action):
                expected_accept = all(
                    action != "move" for action in (then_action, else_action)
                )
                self.assertEqual(
                    self.compile_pair(then_action, else_action),
                    expected_accept,
                )


if __name__ == "__main__":
    unittest.main()
