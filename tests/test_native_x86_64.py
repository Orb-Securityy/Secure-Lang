import os
import platform
import struct
import subprocess
import sys
import tempfile
import unittest

from securec.lexer import SecError
from securec.driver import main
from securec.native_x86_64 import compile_native_subset


class NativeX8664Tests(unittest.TestCase):
    def test_minimal_elf_header_and_segment_permissions(self):
        image = compile_native_subset('fn main() { println("Hello, World!"); }')
        self.assertEqual(image[:4], b'\x7fELF')
        self.assertEqual(image[4], 2)  # ELFCLASS64
        self.assertEqual(image[5], 1)  # little endian
        e_type, e_machine = struct.unpack_from('<HH', image, 16)
        self.assertEqual(e_type, 2)      # ET_EXEC
        self.assertEqual(e_machine, 62) # EM_X86_64
        e_phoff = struct.unpack_from('<Q', image, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from('<HH', image, 54)
        self.assertEqual(e_phoff, 64)
        self.assertEqual(e_phentsize, 56)
        self.assertEqual(e_phnum, 3)
        headers = [struct.unpack_from('<IIQQQQQQ', image, e_phoff + i * e_phentsize)
                   for i in range(e_phnum)]
        loads = [h for h in headers if h[0] == 1]
        stack = next(h for h in headers if h[0] == 0x6474E551)
        self.assertEqual(len(loads), 2)
        code, rodata = loads
        self.assertEqual(code[1], 5)    # PF_R | PF_X
        self.assertEqual(rodata[1], 4)  # PF_R only; literals are not executable
        self.assertEqual(code[5], 0x1000 + 50)
        self.assertEqual(rodata[2], 0x2000)
        self.assertGreater(rodata[5], 0)
        self.assertEqual(stack[1], 6)   # PF_R | PF_W, never executable
        self.assertTrue(all(not (h[1] & 2 and h[1] & 1) for h in loads))

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_hello_world_executes_without_external_toolchain(self):
        image = compile_native_subset(
            'fn main() { println("Hello, World!"); println("Native ELF"); }'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'hello')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'Hello, World!\nNative ELF\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_build_cli_produces_executable_without_cc_build(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, 'hello.sec')
            output = os.path.join(directory, 'hello')
            with open(source, 'w', encoding='utf-8') as stream:
                stream.write('fn main() { println("Built by Secure"); }')
            self.assertEqual(main(['native-build', source, '-o', output]), 0)
            self.assertTrue(os.stat(output).st_mode & 0o111)
            result = subprocess.run([output], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'Built by Secure\\n')
    def test_rejects_constructs_outside_the_native_subset(self):
        unsupported = [
            'fn main() { let x: i32 = 1; }',
            'fn main() -> i32 { 0 }',
            'fn main() { print("not println"); }',
            'fn main() { println(1); }',
            'fn main() { println("ok"); let x: i32 = 3; }',
            'fn main() { unsafe { println("no"); } }',
        ]
        for source in unsupported:
            with self.subTest(source=source):
                with self.assertRaises(SecError):
                    compile_native_subset(source)

    def test_empty_main_emits_a_valid_exit_program(self):
        image = compile_native_subset('fn main() {}')
        self.assertEqual(image[:4], b'\x7fELF')
        self.assertGreater(len(image), 0x1000)


if __name__ == '__main__':
    unittest.main()