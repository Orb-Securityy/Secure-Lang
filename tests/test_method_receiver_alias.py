"""Regression properties for receiver/argument alias checking."""
import unittest

from securec.compiler import Compiler
from securec.lexer import SecError


class MethodReceiverAliasProperties(unittest.TestCase):
    @staticmethod
    def compile_source(source):
        return Compiler(source, "method-alias-property.sec").compile()

    def assert_conflict(self, source):
        with self.assertRaises(SecError) as caught:
            self.compile_source(source)
        self.assertIn("conflicting access", str(caught.exception))

    def test_mutable_receiver_cannot_alias_shared_argument(self):
        self.assert_conflict(
            "struct Box { value: i32 }\n"
            "impl Box { fn update(&mut self, other: &i32) { self.value = *other; } }\n"
            "fn main() { let mut b = Box { value: 1 }; b.update(&b.value); }\n"
        )

    def test_moving_receiver_cannot_alias_shared_argument(self):
        self.assert_conflict(
            "struct Box { value: String }\n"
            "impl Box { fn consume(self, other: &str) {} }\n"
            'fn main() { let b = Box { value: String::from("x") }; b.consume(b.value.as_str()); }\n'
        )

    def test_shared_receiver_and_shared_argument_are_allowed(self):
        self.compile_source(
            "struct Box { value: i32 }\n"
            "impl Box { fn inspect(&self, other: &i32) -> i32 { self.value + *other } }\n"
            "fn main() { let b = Box { value: 1 }; let _n = b.inspect(&b.value); }\n"
        )

    def test_mutable_receiver_with_disjoint_root_is_allowed(self):
        self.compile_source(
            "struct Box { value: i32 }\n"
            "impl Box { fn update(&mut self, other: &i32) { self.value = *other; } }\n"
            "fn main() { let mut b = Box { value: 1 }; let other = 2; b.update(&other); }\n"
        )


if __name__ == "__main__":
    unittest.main()
