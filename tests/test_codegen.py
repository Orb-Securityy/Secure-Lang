import unittest

from securec.compiler import Compiler


class CodeGenerationTests(unittest.TestCase):
    def test_source_filename_is_escaped_in_c_location_literals(self):
        filename = 'bad".sec\nnext\\?.sec'
        generated = Compiler('fn main() { panic("failure"); }', filename).compile()

        self.assertIn(r'bad\042.sec\012next\134\077.sec:1:', generated)
        self.assertNotIn(filename, generated)


if __name__ == "__main__":
    unittest.main()
