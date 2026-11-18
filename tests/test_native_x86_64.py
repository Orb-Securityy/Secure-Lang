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
from securec.ir import (MAX_OUTPUT, IRBinaryI32, IRCompareBranch, IRConstI32,
                        IRExit, IRJump, IRLabel, IRLocalI32, IRPrintI32, IRProgram,
                        IRStoreI32, IRUnaryI32, IRValue, IRWrite, verify_ir)
from securec.native_lower import compile_native_subset, lower_to_ir
from securec.native_x86_64 import emit_native


class NativeX8664Tests(unittest.TestCase):
    def test_minimal_elf_header_and_segment_permissions(self):
        image = compile_native_subset('fn main() { println("Hello, World!"); }')
        self.assertEqual(image[:4], b'\x7fELF')
        self.assertEqual(image[4], 2)  # ELFCLASS64
        self.assertEqual(image[5], 1)  # little endian
        e_type, e_machine = struct.unpack_from('<HH', image, 16)
        self.assertEqual(e_type, 3)      # ET_DYN static PIE
        self.assertEqual(e_machine, 62) # EM_X86_64
        self.assertEqual(struct.unpack_from('<Q', image, 24)[0], 0x1000)  # relative entry
        e_phoff = struct.unpack_from('<Q', image, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from('<HH', image, 54)
        self.assertEqual(e_phoff, 64)
        self.assertEqual(e_phentsize, 56)
        self.assertEqual(e_phnum, 3)
        headers = [struct.unpack_from('<IIQQQQQQ', image, e_phoff + i * e_phentsize)
                   for i in range(e_phnum)]
        loads = [h for h in headers if h[0] == 1]
        stack = next(h for h in headers if h[0] == 0x6474E551)
        self.assertFalse(any(h[0] in (2, 3) for h in headers))  # no PT_DYNAMIC / PT_INTERP
        self.assertEqual(len(loads), 2)
        code, rodata = loads
        self.assertEqual(code[1], 5)    # PF_R | PF_X
        self.assertEqual(rodata[1], 4)  # PF_R only; literals are not executable
        self.assertGreater(code[5], 0x1000)
        self.assertLessEqual(code[5], 0x2000)
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
        e_phoff = struct.unpack_from('<Q', image, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from('<HH', image, 54)
        headers = [struct.unpack_from('<IIQQQQQQ', image, e_phoff + i * e_phentsize)
                   for i in range(e_phnum)]
        code_segment = next(h for h in headers if h[0] == 1)
        code = image[0x1000:code_segment[5]]
        self.assertIn(bytes.fromhex('4883f8fc'), code)  # EINTR comparison
        self.assertIn(bytes.fromhex('4801c6'), code)    # advance after a partial write
        self.assertIn(bytes.fromhex('4829c2'), code)    # reduce remaining byte count
        self.assertIn(bytes.fromhex('0f05'), code)      # direct Linux syscall
        self.assertIn(bytes.fromhex('c3'), code)        # helper returns to caller

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
            'const BASE: i32 = 40;\n'
            'const NEGATIVE: i32 = -2;\n'
            'fn main() {\n'
            '    let increment: i32 = 2;\n'
            '    let answer = BASE + increment;\n'
            '    print("Answer: ", answer, "; ");\n'
            '    println(answer * 2, NEGATIVE);\n'
            '    println(-7 / 2, ":", -7 % 2);\n'
            '    println(-2147483648);\n'
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
        self.assertEqual(result.stdout, b'Answer: 42; 84-2\n-3:-1\n-2147483648\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_checked_in_native_i32_example_builds_and_runs(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        source = os.path.join(root, 'examples', 'native_i32.sec')
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, 'answer')
            self.assertEqual(main(['native-build', source, '-o', output]), 0)
            result = subprocess.run([output], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'Answer: 42\n')
    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_runtime_i32_arithmetic_executes_at_runtime(self):
        source = (
            'fn main() {\n'
            '    let a: i32 = 9;\n'
            '    let b: i32 = 4;\n'
            '    let sum = a + b;\n'
            '    let difference = a - b;\n'
            '    let product = a * b;\n'
            '    let quotient = a / b;\n'
            '    let remainder = a % b;\n'
            '    let negative = -a;\n'
            '    println(sum, ",", difference, ",", product, ",", quotient, ",", remainder, ",", negative);\n'
            '    let n: i32 = -7;\n'
            '    let d: i32 = 2;\n'
            '    println(n / d, ":", n % d);\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'runtime-arithmetic')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'13,5,36,2,1,-9\n-3:-1\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_if_else_executes_all_signed_comparisons(self):
        source = (
            'fn main() {\n'
            '    let a: i32 = 4;\n'
            '    let b: i32 = 9;\n'
            '    if a == b { print("1"); } else { print("0"); }\n'
            '    if a != b { print("1"); } else { print("0"); }\n'
            '    if a < b { print("1"); } else { print("0"); }\n'
            '    if a <= b { print("1"); } else { print("0"); }\n'
            '    if a > b { print("1"); } else { print("0"); }\n'
            '    if a >= b { println("1"); } else { println("0"); }\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'native-conditions')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'011100\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_if_else_if_nesting_and_no_else(self):
        source = (
            'fn main() {\n'
            '    let value: i32 = 7;\n'
            '    if value < 0 { println("negative"); } else if value == 7 {\n'
            '        println("seven");\n'
            '    } else { println("other"); }\n'
            '    if value > 100 { println("unreachable"); }\n'
            '    println("done");\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'nested-conditions')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'seven\ndone\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_mutable_i32_and_compound_assignments_execute(self):
        source = (
            'fn main() {\n'
            '    let mut count: i32 = 3;\n'
            '    count += 2;\n'
            '    count *= 4;\n'
            '    count -= 1;\n'
            '    count /= 3;\n'
            '    count %= 5;\n'
            '    let mut branch_value = 5;\n'
            '    if branch_value > 3 { branch_value = 20; } else { branch_value = 10; }\n'
            '    if branch_value == 20 { println(count, ":", branch_value); } else { println("wrong"); }\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'mutable-i32')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'1:20\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_while_loops_update_mutable_i32_values(self):
        source = (
            'fn main() {\n'
            '    let mut i: i32 = 0;\n'
            '    let mut total: i32 = 0;\n'
            '    while i < 5 {\n'
            '        total += i;\n'
            '        i += 1;\n'
            '    }\n'
            '    println(total, ":", i);\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'while-counter')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'10:5\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_nested_while_and_if_control_flow(self):
        source = (
            'fn main() {\n'
            '    let mut outer: i32 = 0;\n'
            '    let mut total: i32 = 0;\n'
            '    while outer < 4 {\n'
            '        let mut inner: i32 = 0;\n'
            '        while inner < outer {\n'
            '            if inner == 1 { total += 2; } else { total += 1; }\n'
            '            inner += 1;\n'
            '        }\n'
            '        outer += 1;\n'
            '    }\n'
            '    println(total);\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'nested-loops')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'8\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_break_and_continue_skip_and_exit_current_loop(self):
        source = (
            'fn main() {\n'
            '    let mut i: i32 = 0;\n'
            '    let mut total: i32 = 0;\n'
            '    while i < 10 {\n'
            '        i += 1;\n'
            '        if i == 3 { continue; }\n'
            '        if i == 7 { break; }\n'
            '        total += i;\n'
            '    }\n'
            '    println(total, ":", i);\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'break-continue')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'18:7\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_nested_break_targets_innermost_loop(self):
        source = (
            'fn main() {\n'
            '    let mut outer: i32 = 0;\n'
            '    let mut total: i32 = 0;\n'
            '    while outer < 3 {\n'
            '        outer += 1;\n'
            '        if outer == 2 { continue; }\n'
            '        let mut inner: i32 = 0;\n'
            '        while inner < 5 {\n'
            '            inner += 1;\n'
            '            if inner == 3 { break; }\n'
            '            total += 1;\n'
            '        }\n'
            '    }\n'
            '    println(total);\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'nested-break')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'4\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_if_both_branches_terminate_loop_body(self):
        source = (
            'fn main() {\n'
            '    let mut i: i32 = 0;\n'
            '    while i < 5 {\n'
            '        i += 1;\n'
            '        if i == 2 { break; } else { continue; }\n'
            '    }\n'
            '    println(i);\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'both-terminal-branches')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'2\n')

    def test_native_break_continue_rejects_invalid_context_and_unreachable_code(self):
        unsupported = [
            'fn main() { break; }',
            'fn main() { continue; }',
            'fn main() { let mut i: i32 = 0; while i < 2 { break; i += 1; } }',
            'fn main() { let mut i: i32 = 0; while i < 2 { if i == 0 { break; } else { continue; } println("unreachable"); } }',
        ]
        for source in unsupported:
            with self.subTest(source=source):
                with self.assertRaises(SecError):
                    compile_native_subset(source)
    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_while_zero_iterations_and_loop_overflow_trap(self):
        zero = 'fn main() { let mut i: i32 = 5; while i < 5 { i += 1; } println(i); }'
        image = compile_native_subset(zero)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'zero-loop')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'5\n')
            overflow = 'fn main() { let mut i: i32 = 2147483647; while i >= 0 { i += 1; } }'
            path2 = os.path.join(directory, 'loop-overflow')
            with open(path2, 'xb') as executable:
                executable.write(compile_native_subset(overflow))
            os.chmod(path2, 0o755)
            trapped = subprocess.run([path2], capture_output=True, check=False)
        self.assertEqual(trapped.returncode, 101, trapped.stderr)

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_break_and_continue_control_current_loop(self):
        source = (
            'fn main() {\n'
            '    let mut i: i32 = 0;\n'
            '    let mut total: i32 = 0;\n'
            '    while i < 10 {\n'
            '        i += 1;\n'
            '        if i == 3 { continue; }\n'
            '        if i == 7 { break; }\n'
            '        total += i;\n'
            '    }\n'
            '    println(total);\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'break-continue')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'18\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_nested_loop_break_and_continue_target_innermost_loop(self):
        source = (
            'fn main() {\n'
            '    let mut outer: i32 = 0;\n'
            '    let mut total: i32 = 0;\n'
            '    while outer < 3 {\n'
            '        outer += 1;\n'
            '        let mut inner: i32 = 0;\n'
            '        while inner < 5 {\n'
            '            inner += 1;\n'
            '            if inner == 2 { continue; }\n'
            '            if inner == 4 { break; }\n'
            '            total += outer * 10 + inner;\n'
            '        }\n'
            '    }\n'
            '    println(total);\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'nested-break-continue')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'132\n')

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_if_both_branches_break_or_continue_terminates_block(self):
        source = (
            'fn main() {\n'
            '    let mut i: i32 = 0;\n'
            '    while i < 2 {\n'
            '        i += 1;\n'
            '        if i == 1 { continue; } else { break; }\n'
            '    }\n'
            '    println("done");\n'
            '}'
        )
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'branch-loop-termination')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'done\n')

    def test_native_break_and_continue_are_rejected_outside_loops(self):
        unsupported = [
            'fn main() { break; }',
            'fn main() { continue; }',
            'fn main() { if true { break; } }',
            'fn main() { while 1 < 2 { break; } continue; }',
        ]
        for source in unsupported:
            with self.subTest(source=source):
                with self.assertRaises(SecError):
                    compile_native_subset(source)

    def test_native_break_and_continue_reject_following_unreachable_statements(self):
        unsupported = [
            'fn main() { while 1 < 2 { break; println("bad"); } }',
            'fn main() { while 1 < 2 { continue; println("bad"); } }',
        ]
        for source in unsupported:
            with self.subTest(source=source):
                with self.assertRaises(SecError):
                    compile_native_subset(source)
    def test_native_while_rejects_invalid_loop_conditions_and_immutable_stores(self):
        unsupported = [
            'fn main() { while true { println("bad"); } }',
            'fn main() { let i: i32 = 0; while i < 2 { i += 1; } }',
            'fn main() { let mut i: i32 = 0; while i < 2 { let x: str = "x"; x = "y"; } }',
        ]
        for source in unsupported:
            with self.subTest(source=source):
                with self.assertRaises(SecError):
                    compile_native_subset(source)
    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_checked_in_native_mutable_example_builds_and_runs(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        source = os.path.join(root, 'examples', 'native_mutable.sec')
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, 'mutable-example')
            self.assertEqual(main(['native-build', source, '-o', output]), 0)
            result = subprocess.run([output], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'total = 10\n')
    def test_native_mutable_i32_overflow_traps_with_101(self):
        source = 'fn main() { let mut n: i32 = 2147483647; n += 1; println(n); }'
        image = compile_native_subset(source)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'mutable-overflow')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 101, result.stderr)

    def test_native_rejects_invalid_mutable_i32_operations(self):
        unsupported = [
            'fn main() { let mut text: str = "no"; println(text); }',
            'fn main() { let value: i32 = 1; value = 2; }',
            'fn main() { missing = 2; }',
            'fn main() { let mut value: i32 = 1; value += 1.0; }',
            'fn main() { let mut value: i32 = 1; value &= 1; }',
        ]
        for source in unsupported:
            with self.subTest(source=source):
                with self.assertRaises(SecError):
                    compile_native_subset(source)
    def test_native_if_rejects_non_i32_and_non_comparison_conditions(self):
        unsupported = [
            'fn main() { if true { println("bad"); } }',
            'fn main() { if "x" == "x" { println("bad"); } }',
            'fn main() { if 1 { println("bad"); } }',
            'fn main() { let a: i32 = 1; if a + 1 { println("bad"); } }',
            'fn main() { let a: i32 = 1; if a == 1 { let b: i32 = 2; } println(b); }',
        ]
        for source in unsupported:
            with self.subTest(source=source):
                with self.assertRaises(SecError):
                    compile_native_subset(source)

    def test_native_ir_verifier_rejects_undefined_labels_and_branch_only_slots(self):
        missing_label = IRProgram((IRConstI32(0, 1), IRCompareBranch(
            IRValue(0), '<', IRValue(0), 1, 99), IRLabel(1), IRExit(0)))
        branch_only_slot = IRProgram((
            IRConstI32(0, 0),
            IRConstI32(1, 1),
            IRCompareBranch(IRValue(0), '<', IRValue(1), 1, 2),
            IRLabel(1),
            IRConstI32(2, 5),
            IRJump(3),
            IRLabel(2),
            IRLabel(3),
            IRPrintI32(IRValue(2), False),
            IRExit(0),
        ))
        for ir in (missing_label, branch_only_slot):
            with self.subTest(ir=ir):
                with self.assertRaises(ValueError):
                    verify_ir(ir)
    def test_native_runtime_i32_overflow_and_division_trap_with_101(self):
        programs = [
            'fn main() { let a: i32 = 2147483647; let b: i32 = 1; println(a + b); }',
            'fn main() { let a: i32 = -2147483648; let b: i32 = 1; println(a - b); }',
            'fn main() { let a: i32 = 50000; let b: i32 = 50000; println(a * b); }',
            'fn main() { let a: i32 = 5; let b: i32 = 0; println(a / b); }',
            'fn main() { let a: i32 = -2147483648; let b: i32 = -1; println(a / b); }',
            'fn main() { let a: i32 = -2147483648; let b: i32 = -1; println(a % b); }',
            'fn main() { let a: i32 = -2147483648; let b = -a; println(b); }',
        ]
        with tempfile.TemporaryDirectory() as directory:
            for index, source in enumerate(programs):
                with self.subTest(source=source):
                    path = os.path.join(directory, f'trap-{index}')
                    image = compile_native_subset(source)
                    with open(path, 'xb') as executable:
                        executable.write(image)
                    os.chmod(path, 0o755)
                    result = subprocess.run([path], capture_output=True, check=False)
                    self.assertEqual(result.returncode, 101, result.stderr)

    def test_native_ir_verifier_rejects_stores_to_immutable_slots(self):
        invalid = [
            IRProgram((IRConstI32(0, 1), IRStoreI32(0, IRValue(0)), IRExit(0))),
            IRProgram((IRLocalI32(0, IRValue(2)), IRExit(0))),
            IRProgram((IRConstI32(0, 1), IRLocalI32(1, IRValue(0)),
                      IRStoreI32(1, IRValue(9)), IRExit(0))),
        ]
        for ir in invalid:
            with self.subTest(ir=ir):
                with self.assertRaises(ValueError):
                    verify_ir(ir)
    def test_native_ir_verifier_rejects_invalid_i32_slots(self):
        invalid = [
            IRProgram((IRConstI32(1, 7), IRExit(0))),
            IRProgram((IRConstI32(0, 1), IRConstI32(0, 2), IRExit(0))),
            IRProgram((IRUnaryI32(0, '-', IRValue(3)), IRExit(0))),
            IRProgram((IRBinaryI32(0, '&', IRValue(0), IRValue(0)), IRExit(0))),
            IRProgram((IRPrintI32(IRValue(5), False), IRExit(0))),
        ]
        for ir in invalid:
            with self.subTest(ir=ir):
                with self.assertRaises(ValueError):
                    verify_ir(ir)
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
            'fn main() { let number: f64 = 7.0; println("ok"); }',
            'fn main() { let name: str = missing; println(name); }',
            'const VALUE: f64 = 7.0; fn main() { println("ok"); }',
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
            IRProgram((IRPrintI32(1 << 31, False), IRExit(0))),
            IRProgram((IRPrintI32("not-int", False), IRExit(0))),
            IRProgram((IRPrintI32(10, 1), IRExit(0))),
            IRProgram((IRWrite(b"ok", False), IRExit(1))),
        ]
        for ir in invalid:
            with self.subTest(ir=ir):
                with self.assertRaises(ValueError):
                    verify_ir(ir)

    @unittest.skipUnless(sys.platform.startswith('linux') and platform.machine().lower() in
                         ('x86_64', 'amd64'), 'requires x86-64 Linux execution')
    def test_native_i32_runtime_formatter_honors_ir_newline(self):
        ir = IRProgram((IRPrintI32(-2147483648, True), IRPrintI32(0, False), IRExit(0)))
        image = emit_native(ir)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'ir-i32')
            with open(path, 'xb') as executable:
                executable.write(image)
            os.chmod(path, 0o755)
            result = subprocess.run([path], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'-2147483648\n0')
    def test_native_ir_rejects_output_larger_than_limit(self):
        ir = IRProgram((IRWrite(b'x' * (MAX_OUTPUT + 1), False), IRExit(0)))
        with self.assertRaises(ValueError):
            verify_ir(ir)
    def test_native_ir_is_immutable_and_typed(self):
        ir = lower_to_ir(parse('fn main() { println("IR"); }'))
        image = emit_native(ir)
        self.assertEqual(image[:4], b'\x7fELF')
        self.assertIsInstance(ir, IRProgram)
        self.assertEqual(ir.instructions, (IRWrite(b"IR", False), IRWrite(b"", True), IRExit(0)))
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

    def test_native_lowering_normalizes_deep_expression_recursion(self):
        nested = 'fn main() { println(' + ('(' * 1500) + '1' + (')' * 1500) + '); }'
        with self.assertRaises(SecError):
            compile_native_subset(nested)
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
            'fn main() { let x: f64 = 1.0; }',
            'fn main() -> i32 { 0 }',
            'fn main() { println(1.0); }',
            'fn main() { println("ok"); let x: bool = true; }',
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