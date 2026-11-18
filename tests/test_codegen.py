import unittest

from securec.compiler import Compiler


class CodeGenerationTests(unittest.TestCase):

    def test_empty_slice_codegen_avoids_null_pointer_arithmetic(self):
        source = (
            "fn length(values: &[i32]) -> usize { values.len() }\n"
            "fn nested(values: &[i32]) -> usize { length(&values[0..0]) }\n"
            "fn main() {\n"
            "    let values: Vec<i32> = Vec::new();\n"
            "    let _n = nested(&values[0..0]);\n"
            "}\n"
        )
        generated = Compiler(source, "empty-slice.sec").compile()
        self.assertIn("== NULL ? NULL :", generated)

    def test_source_filename_is_escaped_in_c_location_literals(self):
        filename = 'bad".sec\nnext\\?.sec'
        generated = Compiler('fn main() { panic("failure"); }', filename).compile()

        self.assertIn(r'bad\042.sec\012next\134\077.sec:1:', generated)
        self.assertNotIn(filename, generated)


if __name__ == "__main__":
    unittest.main()
