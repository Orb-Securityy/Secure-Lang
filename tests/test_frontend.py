import random
import unittest

from securec.lexer import SecError, lex
from securec.parser import parse


class FrontendRobustnessTests(unittest.TestCase):
    def test_malformed_radix_literals_are_source_errors(self):
        for literal in ("0x_", "0x__", "0b_", "0b___"):
            with self.subTest(literal=literal):
                with self.assertRaises(SecError):
                    lex(literal)

    def test_deterministic_malformed_token_streams_do_not_crash(self):
        rng = random.Random(0x5EC0)
        fragments = (
            "fn", "let", "mut", "if", "else", "while", "for", "in",
            "return", "break", "continue", "struct", "enum", "impl",
            "const", "unsafe", "extern", "match", "as", "true", "false",
            "x", "_x", "0", "1", "255u8", "0x_", "0b_", "0x",
            "()", "{", "}", "[", "]", "(", ")", ",", ";", ":",
            "::", "->", "=>", "?", "+", "-", "*", "/", "%", "<<",
            ">>", "&", "|", "&&", "||", "=", "==", "!=", "<", ">",
            '"x"', "'a'", "/*", "*/", "// comment", "\n",
        )
        for case in range(512):
            source = " ".join(
                rng.choice(fragments) for _ in range(rng.randint(1, 20))
            )
            try:
                parse(source)
            except SecError:
                pass
            except Exception as exc:
                self.fail(
                    f"front end crashed on deterministic case {case}: "
                    f"{type(exc).__name__}: {exc}; source={source!r}"
                )


if __name__ == "__main__":
    unittest.main()
