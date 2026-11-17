"""Thread-safety boundary tests for spawned call graphs."""
import unittest

from securec.compiler import Compiler
from securec.lexer import SecError


class SpawnUnsafeEffectTests(unittest.TestCase):
    def assert_spawn_rejected(self, source):
        with self.assertRaises(SecError) as caught:
            Compiler(source, "spawn-unsafe-effect.sec").compile()
        self.assertIn("unsafe operation", str(caught.exception))

    def test_rejects_direct_unsafe_block_in_spawn_target(self):
        self.assert_spawn_rejected(
            "extern fn mutate_global();\n"
            "fn worker() { unsafe { mutate_global(); } }\n"
            "fn main() { let task = spawn(worker); task.join(); }\n"
        )

    def test_rejects_transitive_unsafe_effect_through_safe_helper(self):
        self.assert_spawn_rejected(
            "extern fn mutate_global();\n"
            "fn helper() { unsafe { mutate_global(); } }\n"
            "fn worker() { helper(); }\n"
            "fn main() { let task = spawn(worker); task.join(); }\n"
        )

    def test_rejects_unsafe_effect_in_nested_spawn(self):
        self.assert_spawn_rejected(
            "extern fn mutate_global();\n"
            "fn unsafe_worker() { unsafe { mutate_global(); } }\n"
            "fn outer_worker() { let nested = spawn(unsafe_worker); nested.join(); }\n"
            "fn main() { let task = spawn(outer_worker); task.join(); }\n"
        )

    def test_allows_thread_worker_without_unsafe_effects(self):
        Compiler(
            "fn worker(value: i32) -> i32 { value + 1 }\n"
            "fn main() -> i32 { let task = spawn(worker, 4); return task.join(); }\n",
            "spawn-safe.sec",
        ).compile()


if __name__ == "__main__":
    unittest.main()
