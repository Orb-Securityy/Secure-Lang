import os
import platform
import struct
import subprocess
import sys
import tempfile
import unittest

from securec.lexer import SecError
from securec.parser import parse
from securec.driver import main
from securec.ir import MAX_OUTPUT, IRExit, IRProgram, IRWrite, verify_ir
from securec.native_lower import compile_native_subset, lower_to_ir
from securec.native_x86_64 import emit_native


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
        self.assertEqual(code[5], 0x1000 + 64)
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

    def test_native_machine_code_has_eintr_and_partial_write_branches(self):
        image = compile_native_subset('fn main() { println("retry"); }')
        code = image[0x1000:0x1000 + 64]
        self.assertEqual(code[24:28], bytes.fromhex('4883f8fc'))
        self.assertEqual(code[28:30], bytes.fromhex('74f8'))
        self.assertEqual(code[33:35], bytes.fromhex('7e11'))
        self.assertEqual(code[41:43], bytes.fromhex('75eb'))

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_large_output_is_written_completely(self):
        payload = 'Z' * 100_000
        image = compile_native_subset('fn main() { print("' + payload + '"); }')
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'large-output')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, payload.encode('ascii'))
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
        self.assertEqual(result.stdout, b'Built by Secure\n')
    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_static_str_bindings_and_constants_execute(self):
        source = (
            'const GREETING: str = "Hello";\n'
            'fn main() {\n'
            '    let audience: str = "Secure";\n'
            '    let prefix = GREETING;\n'
            '    print(prefix, ", ");\n'
            '    println(audience, "!");\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'static-strings')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'Hello, Secure!\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_i32_constants_and_checked_arithmetic_execute(self):
        source = (
            'const BASE: i32 = 40;\
'
            'const NEGATIVE: i32 = -2;\
'
            'fn main() {\
'
            '    let increment: i32 = 2;\
'
            '    let answer = BASE + increment;\
'
            '    print("Answer: ", answer, "; ");\
'
            '    println(answer * 2, NEGATIVE);\
'
            '    println(-7 / 2, ":", -7 % 2);\
'
            '    println(-2147483648);\
'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'i32-native')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'Answer: 42; 84-2\
-3:-1\
-2147483648\
')

    def test_native_i32_rejects_overflow_division_errors_and_wrong_types(self):
        unsupported = [
            'fn main() { println(2147483648); }',
            'fn main() { println(2147483647 + 1); }',
            'fn main() { println(1 / 0); }',
            'fn main() { println(-2147483648 / -1); }',
            'const TOO_BIG: i32 = 2147483647 + 1; fn main() {}',
            'fn main() { println(1u8); }',
            'fn main() { let number: u32 = 1; println(number); }',
            'fn main() { let print: str = "shadow"; print("no"); }',
            'fn main() { let println: str = "shadow"; println("no"); }',
        ]
        for source in unsupported:
            with self.subTest(source=source):
                with self.assertRaises(SecError):
                    compile_native_subset(source)
    def test_native_subset_rejects_mutable_and_non_string_bindings(self):
        unsupported = [
            'fn main() { let mut name: str = "Secure"; println(name); }',
            'fn main() { let number: i32 = 7; println("ok"); }',
            'fn main() { let name: str = missing; println(name); }',
            'const VALUE: i32 = 7; fn main() { println("ok"); }',
            'const print: str = "shadow"; fn main() { println("ok"); }',
            'fn main() { let name = "Secure"; name = "changed"; println(name); }',
        ]
        for source in unsupported:
            with self.subTest(source=source):
                with self.assertRaises(SecError):
                    compile_native_subset(source)

    def test_native_ir_verifier_rejects_malformed_ir(self):
        valid = IRProgram((IRWrite(b"ok", True), IRExit(0)))
        self.assertEqual(verify_ir(valid), 3)
        invalid = [
            IRProgram(()),
            IRProgram((IRExit(0), IRWrite(b"late", False))),
            IRProgram((IRWrite("not-bytes", False), IRExit(0))),
            IRProgram((IRWrite(b"ok", 1), IRExit(0))),
            IRProgram((IRWrite(b"ok", False), IRExit(1))),
        ]
        for ir in invalid:
            with self.subTest(ir=ir):
                with self.assertRaises(ValueError):
                    verify_ir(ir)

    def test_native_ir_rejects_output_larger_than_limit(self):
        ir = IRProgram((IRWrite(b'x' * (MAX_OUTPUT + 1), False), IRExit(0)))
        with self.assertRaises(ValueError):
            verify_ir(ir)
    def test_native_ir_is_immutable_and_typed(self):
        ir = lower_to_ir(parse('fn main() { println("IR"); }'))
        image = emit_native(ir)
        self.assertEqual(image[:4], b'\x7fELF')
        self.assertIsInstance(ir, IRProgram)
        self.assertEqual(ir.instructions, (IRWrite(b"IR", True), IRExit(0)))
    def test_native_backend_imports_without_frontend_modules(self):
        script = (
            'import sys; import securec.native_x86_64; '
            + 'assert "securec.parser" not in sys.modules; '
            + 'assert "securec.lexer" not in sys.modules; '
            + 'assert "securec.compiler" not in sys.modules'
        )
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
    def test_native_build_does_not_import_legacy_c_compiler(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, 'isolated.sec')
            output = os.path.join(directory, 'isolated')
            with open(source, 'w', encoding='utf-8') as stream:
                stream.write('fn main() { println("isolated"); }')
            invocation = [sys.executable, '-c',
                'import sys; from securec.driver import main; '
                + f'code = main({["native-build", source, "-o", output]!r}); '
                + 'assert "securec.compiler" not in sys.modules; raise SystemExit(code)']
            result = subprocess.run(invocation, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            execution = subprocess.run([output], capture_output=True, check=False)
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertEqual(execution.stdout, b'isolated\n')
    def test_native_build_rejects_c_compiler_flags_and_program_args(self):
        with self.assertRaises(SystemExit):
            main(['native-build', 'unused.sec', '--sanitize'])
        with self.assertRaises(SystemExit):
            main(['native-build', 'unused.sec', 'runtime-argument'])

    def test_native_build_rejects_oversized_source_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, 'oversized.sec')
            with open(source, 'wb') as stream:
                stream.write(b' ' * ((1 << 20) + 1))
            self.assertEqual(main(['native-build', source]), 1)
    def test_native_build_never_overwrites_its_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, 'program.sec')
            original = b'fn main() {}'
            with open(source, 'wb') as stream:
                stream.write(original)
            self.assertEqual(main(['native-build', source, '-o', source]), 2)
            with open(source, 'rb') as stream:
                self.assertEqual(stream.read(), original)
    def test_rejects_constructs_outside_the_native_subset(self):
        unsupported = [
            'fn main() { let x: i32 = 1; }',
            'fn main() -> i32 { 0 }',
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