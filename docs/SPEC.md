# Secure language reference (v0.1)

## 1. Lexical
`//` and nested `/* */` comments. Integer literals: decimal, `0x`, `0b`, `_` separators (only between digits), optional suffix
(`i8 i16 i32 i64 u8 u16 u32 u64 usize`); these suffixes are valid only on integer literals. Float literals are `f64` by default and may use the `f64` suffix. `'a'` is a `u8` ASCII literal.
String literals are byte strings (UTF-8 source, escapes `\n \r \t \\ \" \' \0 \xHH`).
Keywords: `fn let mut if else while loop for in return break continue struct enum impl const unsafe extern match as true false`.

## 2. Types
| Type | Meaning | Copy? |
|---|---|---|
| `i8..i64`, `u8..u64`, `usize` | fixed-width integers | yes |
| `f64`, `bool`, `()` | | yes |
| `str` | immutable static string literal (ptr+len) | yes |
| `String` | owned growable byte string | **moves** |
| `[T; N]` | fixed array, `N` constant, ≤ 1 MiB | if `T` is Copy |
| `Vec<T>` | owned growable array | **moves** |
| `Option<T>`, `Result<T,E>` | no null, no exceptions | if payloads are Copy |
| `Task<T>` | handle to a running thread | **moves** |
| `struct`, C-like `enum` | | Copy iff no field owns resources |
| `&T`, `&mut T`, `&[T]`, `&mut [T]`, `&str` | **second-class** references (§6) | n/a |
| `*const T`, `*mut T` | raw pointers; dereference only in `unsafe` | yes |

Rule of thumb: a type that owns heap memory or a thread **moves**; everything else copies.
There are no implicit conversions between numeric types. Integer literals default to `i32` unless the
context fixes the type (`let x: u8 = 5;`, `a + 1`). Inference is local: `let v: Vec<i32> = Vec::new();`.

## 3. Items
```
fn name(a: T, mut b: U, p: &mut V, s: &[W]) -> R { ... }   // last expression is the result
unsafe fn f(...) -> R { ... }                               // callable only inside `unsafe`
extern fn abs(x: i32) -> i32;                               // C ABI import; callable only inside `unsafe`
struct S { f: T, g: U }     enum E { A, B, C }
impl S { fn new() -> S {..}  fn get(&self) -> i32 {..}  fn set(&mut self, v: i32) {..}  fn eat(self) {..} }
const N: usize = 4 * 1024;  // integer / f64 / bool / str literal constants, folded at compile time
```
`main` is `fn main()` or `fn main() -> i32` (the exit status).

## 4. Expressions
`if/else`, `match`, blocks and `unsafe { }` are expressions. `loop`, `while c {}`, `for i in lo..hi {}`,
`for i in lo..=hi {}` (the loop variable is immutable; inclusive ranges never overflow), `break`, `continue`, `return`.
`match` supports literals, `|` alternatives (literals/enum variants), `_`, bindings, enum variants `E::A`,
`Some(x) None Ok(x) Err(e)`; it must be **exhaustive**.
`e?` propagates `Err`/`None` out of the enclosing function (it must return a compatible `Result`/`Option`).
`x as T` is a **checked** conversion (panics if the value does not fit), including enum-to-integer conversions; `x as wrapping T` and `wrapping_{add,sub,mul}` reduce modulo 2^width. For signed destinations, the reduced bit pattern is interpreted as the corresponding two's-complement value.
`saturating_{add,sub,mul}` and `checked_{add,sub,mul}` (→ `Option`) make intent explicit.

### Integer semantics
`+ - * / %`, unary `-`, `<<`, `>>`, `.pow()`, `.abs()` are **checked**: overflow, division by zero,
`MIN / -1`, `MIN % -1`, a left shift whose mathematical result does not fit the destination type, shift amount ≥ width, `abs(MIN)` all panic. When both operands are compile-time constants the
error is reported **at compile time**, including when a shift count has an explicit type suffix. `>>` on signed integers is an arithmetic shift.

### Evaluation order
Left to right. For calls: all by-value arguments are evaluated first, left to right; then borrows are formed
(so no pointer can be invalidated by a later argument). In `place = value`, the value is evaluated first.

## 5. Ownership
A non-Copy value has exactly one owner. Using it by value *moves* it; the compiler tracks moves
flow-sensitively (branches, loops, `break`/`continue`/`return`) and rejects any later use. Owned values are
dropped automatically at scope exit (and on `return`, `break`, `continue`, `?`), with run-time drop flags when
a move is conditional. Assigning to an owned place drops the old value. You cannot move out of a field,
an index or a reference (no partial moves).

## 6. References (second-class)
`&x`, `&mut x`, `&x[a..b]`, `x.as_str()`, `x.as_slice()` exist **only as direct call arguments**.
They cannot be stored in variables, fields, collections, or returned. Consequently Secure needs no
lifetime annotations and a reference can never outlive what it points to.
**Exclusivity law** (checked per call): if an argument is `&mut x`, no other argument (or the receiver) may
borrow or move `x`. `&mut` requires the place to be declared `mut`. `&Vec<T>`/`&[T;N]` coerce to `&[T]`;
`&String` coerces to `&str`.

## 7. Errors and panics
Recoverable errors are `Result`/`Option` values. A `Result` may not be silently discarded (compile error). Every control-flow path must consume a bound `Result`; consuming it only in the conditionally evaluated right operand of `&&`/`||` does not count, because short-circuiting may skip that operand.
Contract violations (overflow, bounds, `unwrap` of `None`/`Err`, `assert`, `panic`) print
`secure: panic at file:line:col: message` to stderr, flush stdout, and terminate with status **101**.
There is no unwinding and no way to catch a panic (fail-fast).

## 8. `unsafe`
Allowed only inside `unsafe { }` or `unsafe fn`: calling `extern`/`unsafe` functions, dereferencing
raw pointers, pointer arithmetic (`p.add(n)`). Creating raw pointers (`x.as_ptr()`) is safe. Every unsafe site is
listed by `securec audit`; `--forbid-unsafe` rejects them all.

## 9. Concurrency
`spawn(f, a, b)` runs `f(a, b)` on a new thread and returns `Task<R>`; `t.join()` yields `R`. Arguments are
**moved** into the thread; they must be owned values (no references, no raw pointers). The target's reachable
call graph must also contain no `unsafe` block, `unsafe fn`, or `extern` operation. This conservative effect
check prevents a safe wrapper from hiding operations that can access shared state outside the ownership model.
Safe code has no global mutable state and no stored references, so threads share nothing: data races are not
expressible in the supported safe subset.
A `Task` dropped without `join` is joined automatically.

## 10. Built-ins
`print(..)`, `println(..)` (any number of int/float/bool/str/String/enum args), `exit(i32)`, `panic(&str)`,
`assert(bool)`, `read_line() -> Option<String>` (`None` on EOF; stdin I/O errors panic), `parse_i64(&str) -> Option<i64>` (strict, overflow-safe),
`str_eq(&str,&str)`, `ct_eq(&[u8],&[u8])` (no early exit), `zeroize(&mut [u8])` (not elided by the optimizer).
Methods: `len is_empty as_ptr swap` (arrays/slices/Vec), `Vec: push pop clear get`, `String: push push_str clear`,
`Option/Result: is_some is_none is_ok is_err unwrap unwrap_or`, `Task: join`, ints: `abs min max pow`,
f64: `sqrt abs floor`.

## 11. Known limitations (v0.1)
No generics/traits/closures/modules; one compile error reported per run; strings are bytes (no UTF-8 aware API);
`&s[a..b]` on strings yields `&[u8]`; fail-fast panic does not unwind or run destructors; deep recursion can exhaust the stack (guard-page crash, not corruption).
