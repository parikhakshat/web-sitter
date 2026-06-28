//! Grammar construct coverage tests for JavaScript (Phase 1).
//!
//! Tests are in the TDD red state — assertions about `IrNodeKind` will fail
//! until the real JsLifter is implemented.

use std::collections::HashSet;

use web_sitter::{IrNodeKind, LiteralKind, LoopKind, NodeId, TryKind};
use web_sitter::{CpgGenerator, GraphBuildOptions, SourceLanguage};

fn js_cpg(src: &str) -> web_sitter::Cpg {
    CpgGenerator::new_for_language(SourceLanguage::JavaScript)
        .expect("JavaScript parser init")
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("JavaScript CPG generation failed")
}

fn assert_cfg_valid(cpg: &web_sitter::Cpg) {
    let bb_keys: HashSet<&String> = cpg.basic_blocks.keys().collect();
    for bb in cpg.basic_blocks.values() {
        for succ in &bb.successors {
            assert!(
                bb_keys.contains(succ),
                "BB successor '{succ}' not found in basic_blocks"
            );
        }
        for exc in &bb.exception_successors {
            assert!(
                bb_keys.contains(exc),
                "Exception successor BB '{exc}' not found"
            );
        }
    }
}

fn assert_dfg_valid(cpg: &web_sitter::Cpg) {
    let ast_ids: HashSet<NodeId> = cpg.ast.keys().copied().collect();
    for edge in &cpg.dataflow.edges {
        assert!(ast_ids.contains(&edge.source), "DFG edge source {} not in AST", edge.source);
        assert!(ast_ids.contains(&edge.destination), "DFG edge dest {} not in AST", edge.destination);
    }
}

// ── Grammar Coverage ──────────────────────────────────────────────────────────

#[test]
fn test_program_lifts_to_file() {
    let cpg = js_cpg("var x = 1;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let file_nodes: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::File && n.node_type == "program")
        .collect();
    assert_eq!(file_nodes.len(), 1, "expected exactly one File node with node_type 'program'");
}

#[test]
fn test_function_declaration() {
    let cpg = js_cpg("function greet(name) { return 'hello ' + name; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let method = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("greet"))
        .expect("expected MethodDef for 'greet'");
    assert_eq!(method.name.as_deref(), Some("greet"));
}

#[test]
fn test_arrow_function_lifts_to_lambda_def() {
    let cpg = js_cpg("const double = (x) => x * 2;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let lambda = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::LambdaDef)
        .expect("expected LambdaDef for arrow function");
    let (lambda_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::LambdaDef)
        .unwrap();
    let meta = cpg.js_meta(*lambda_id).expect("arrow function should have JsNodeMetadata");
    assert!(meta.is_arrow, "is_arrow should be true for arrow function");
    let _ = lambda;
}

#[test]
fn test_async_function_declaration() {
    let cpg = js_cpg("async function fetchData(url) { return url; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("fetchData"))
        .expect("expected MethodDef for 'fetchData'");
    let meta = cpg.js_meta(*method_id).expect("fetchData should have JsNodeMetadata");
    assert!(meta.is_async, "is_async should be true for 'async function'");
}

#[test]
fn test_generator_function() {
    let cpg = js_cpg("function* gen() { yield 1; yield 2; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("gen"))
        .expect("expected MethodDef for 'gen'");
    let meta = cpg.js_meta(*method_id).expect("gen should have JsNodeMetadata");
    assert!(meta.is_generator, "is_generator should be true for 'function*'");
}

#[test]
fn test_class_declaration() {
    let cpg = js_cpg("class Animal { constructor(name) { this.name = name; } speak() {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let class_def = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Animal"))
        .expect("expected ClassDef for 'Animal'");
    assert_eq!(class_def.name.as_deref(), Some("Animal"));
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("speak"))
        .expect("expected MethodDef for 'speak'");
}

#[test]
fn test_class_constructor_marked() {
    let cpg = js_cpg("class C { constructor() {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (ctor_id, ctor_node) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("constructor"))
        .expect("expected MethodDef for 'constructor'");
    assert_eq!(ctor_node.is_constructor, Some(true), "constructor should have is_constructor=true");
    let meta = cpg.js_meta(*ctor_id).expect("constructor should have JsNodeMetadata");
    assert!(meta.is_constructor, "JsNodeMetadata.is_constructor should be true");
}

#[test]
fn test_class_extends() {
    let cpg = js_cpg("class Dog extends Animal { bark() {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Dog"))
        .expect("expected ClassDef for 'Dog'");
}

#[test]
fn test_static_method() {
    let cpg = js_cpg("class C { static create() { return new C(); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("create"))
        .expect("expected MethodDef for 'create'");
    let meta = cpg.js_meta(*method_id).expect("create should have JsNodeMetadata");
    assert!(meta.is_static, "is_static should be true for static 'create'");
}

#[test]
fn test_getter_setter() {
    let cpg = js_cpg("class C { get value() { return this._v; } set value(v) { this._v = v; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let getter = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("value"))
        .map(|(id, _)| *id)
        .expect("expected MethodDef for getter/setter 'value'");
    let meta = cpg.js_meta(getter).expect("getter should have JsNodeMetadata");
    assert!(meta.is_getter || meta.is_setter, "getter or setter flag should be set");
}

#[test]
fn test_private_field() {
    let cpg = js_cpg("class C { #secret = 42; getSecret() { return this.#secret; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let private_field = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::FieldDef && n.name.as_deref().unwrap_or("").contains("secret"))
        .expect("expected FieldDef for '#secret'");
    let (field_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::FieldDef && n.name.as_deref().unwrap_or("").contains("secret"))
        .unwrap();
    let meta = cpg.js_meta(*field_id).expect("private field should have JsNodeMetadata");
    assert!(meta.is_private, "is_private should be true for '#secret'");
    let _ = private_field;
}

#[test]
fn test_var_declaration() {
    let cpg = js_cpg("var x = 42;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("x"))
        .expect("expected LocalDef for 'x'");
}

#[test]
fn test_let_declaration() {
    let cpg = js_cpg("let x = 42;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("x"))
        .expect("expected LocalDef for 'let x'");
}

#[test]
fn test_const_declaration() {
    let cpg = js_cpg("const PI = 3.14;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("PI"))
        .expect("expected LocalDef for 'const PI'");
}

#[test]
fn test_assignment_expression() {
    let cpg = js_cpg("let x = 0; x = 5;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Assign)
        .expect("expected Assign node");
}

#[test]
fn test_if_statement() {
    let cpg = js_cpg("if (x > 0) { console.log(x); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Conditional)
        .expect("expected Conditional for 'if'");
}

#[test]
fn test_for_statement() {
    let cpg = js_cpg("for (let i = 0; i < 10; i++) {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'for'");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::For));
}

#[test]
fn test_for_in_statement() {
    let cpg = js_cpg("const obj = {}; for (let key in obj) {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'for...in'");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::ForEach));
}

#[test]
fn test_for_of_statement() {
    let cpg = js_cpg("const arr = [1,2,3]; for (const x of arr) {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (loop_id, loop_node) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'for...of'");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::ForEach));
    let meta = cpg.js_meta(*loop_id).expect("for-of loop should have JsNodeMetadata");
    assert!(meta.is_for_of, "is_for_of should be true for 'for...of'");
}

#[test]
fn test_while_statement() {
    let cpg = js_cpg("let x = 10; while (x > 0) { x--; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'while'");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::While));
}

#[test]
fn test_do_while_statement() {
    let cpg = js_cpg("let x = 0; do { x++; } while (x < 10);");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'do-while'");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::DoWhile));
}

#[test]
fn test_switch_statement() {
    let cpg = js_cpg("switch (x) { case 1: break; case 2: break; default: break; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Switch)
        .expect("expected Switch node");
    let cases: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::Case).collect();
    assert_eq!(cases.len(), 2, "expected 2 Case nodes");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SwitchDefault)
        .expect("expected SwitchDefault");
}

#[test]
fn test_try_catch() {
    let cpg = js_cpg("try { doSomething(); } catch (e) { console.log(e); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let try_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Try)
        .expect("expected Try node");
    assert_eq!(try_node.try_kind, Some(TryKind::Standard));
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Catch)
        .expect("expected Catch node");
}

#[test]
fn test_try_finally() {
    let cpg = js_cpg("try { work(); } finally { cleanup(); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Try)
        .expect("expected Try node");
}

#[test]
fn test_throw_statement() {
    let cpg = js_cpg("throw new Error('bad');");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Throw)
        .expect("expected Throw node");
}

#[test]
fn test_return_statement() {
    let cpg = js_cpg("function f(x) { return x * 2; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Return)
        .expect("expected Return node");
}

#[test]
fn test_break_continue() {
    let cpg = js_cpg("for (let i = 0; i < 10; i++) { if (i == 5) break; if (i == 3) continue; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Break)
        .expect("expected Break node");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Continue)
        .expect("expected Continue node");
}

#[test]
fn test_call_expression() {
    let cpg = js_cpg("console.log('hello');");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Call)
        .expect("expected Call node");
}

#[test]
fn test_new_expression() {
    let cpg = js_cpg("const obj = new Object();");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::NewExpr)
        .expect("expected NewExpr for 'new Object()'");
}

#[test]
fn test_await_expression() {
    let cpg = js_cpg("async function f() { const result = await fetch('/api'); return result; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::AwaitExpr)
        .expect("expected AwaitExpr for 'await fetch(...)'");
}

#[test]
fn test_yield_expression() {
    let cpg = js_cpg("function* gen() { yield 1; yield* other(); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let yield_nodes: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::YieldExpr)
        .collect();
    assert!(yield_nodes.len() >= 2, "expected at least 2 YieldExpr nodes");
    let (delegate_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::YieldExpr && n.node_type == "yield_expression"
            && n.text.as_deref().unwrap_or("").contains("*"))
        .expect("expected yield* expression");
    let meta = cpg.js_meta(*delegate_id).expect("yield* should have JsNodeMetadata");
    assert!(meta.is_delegate, "is_delegate should be true for 'yield*'");
}

#[test]
fn test_template_string() {
    let cpg = js_cpg("const name = 'world'; const s = `hello ${name}`;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TemplateStr)
        .expect("expected TemplateStr for template literal");
}

#[test]
fn test_spread_expression() {
    let cpg = js_cpg("const a = [1,2]; const b = [...a, 3];");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SpreadExpr)
        .expect("expected SpreadExpr for '...a'");
}

#[test]
fn test_optional_chaining() {
    let cpg = js_cpg("const len = obj?.name?.length;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::OptionalChain)
        .expect("expected OptionalChain for '?.' operator");
}

#[test]
fn test_sequence_expression() {
    let cpg = js_cpg("let x = (1, 2, 3);");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SequenceExpr)
        .expect("expected SequenceExpr for '(1, 2, 3)'");
}

#[test]
fn test_jsx_element() {
    // JSX is supported in the JS grammar
    let cpg = js_cpg("const el = <div className=\"test\">Hello</div>;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::JsxElement)
        .expect("expected JsxElement for JSX '<div>...</div>'");
}

#[test]
fn test_import_statement() {
    let cpg = js_cpg("import { foo } from './foo';");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Import)
        .expect("expected Import node");
}

#[test]
fn test_export_default() {
    let cpg = js_cpg("function f() {} export default f;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Export)
        .expect("expected Export node for 'export default'");
}

#[test]
fn test_export_named() {
    let cpg = js_cpg("export function greet(name) { return name; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Export)
        .expect("expected Export node for named export");
}

#[test]
fn test_object_expression() {
    let cpg = js_cpg("const obj = { a: 1, b: 2 };");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::CompositeLit && n.node_type == "object")
        .expect("expected CompositeLit with node_type 'object'");
}

#[test]
fn test_array_expression() {
    let cpg = js_cpg("const arr = [1, 2, 3];");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::CollectionExpr && n.node_type == "array")
        .expect("expected CollectionExpr with node_type 'array'");
}

#[test]
fn test_binary_expression() {
    let cpg = js_cpg("const x = 1 + 2;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::BinaryOp && n.operator.as_deref() == Some("+"))
        .expect("expected BinaryOp with operator '+'");
}

#[test]
fn test_unary_expression() {
    let cpg = js_cpg("const x = !true;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::UnaryOp && n.operator.as_deref() == Some("!"))
        .expect("expected UnaryOp with operator '!'");
}

#[test]
fn test_ternary_expression() {
    let cpg = js_cpg("const x = 1; const y = x > 0 ? x : 0;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TernaryOp)
        .expect("expected TernaryOp for '? :' expression");
}

#[test]
fn test_member_access() {
    let cpg = js_cpg("const len = 'hello'.length;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MemberAccess)
        .expect("expected MemberAccess for '.length'");
}

#[test]
fn test_subscript_access() {
    let cpg = js_cpg("const arr = [1,2,3]; const x = arr[0];");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Subscript)
        .expect("expected Subscript for 'arr[0]'");
}

#[test]
fn test_string_literal() {
    let cpg = js_cpg("const s = 'hello';");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::String))
        .expect("expected String Literal");
}

#[test]
fn test_integer_literal() {
    let cpg = js_cpg("const n = 42;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Integer))
        .expect("expected Integer Literal");
}

#[test]
fn test_null_literal() {
    let cpg = js_cpg("const x = null;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Null))
        .expect("expected Null Literal for 'null'");
}

#[test]
fn test_undefined_literal() {
    let cpg = js_cpg("const x = undefined;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Null))
        .expect("expected Null Literal for 'undefined'");
}

#[test]
fn test_boolean_literal() {
    let cpg = js_cpg("const a = true; const b = false;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let bool_lits: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Bool))
        .collect();
    assert_eq!(bool_lits.len(), 2, "expected 2 Bool Literals");
}

#[test]
fn test_regex_literal() {
    let cpg = js_cpg("const re = /^[a-z]+$/i;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Regex))
        .expect("expected Regex Literal for '/.../'");
}

#[test]
fn test_destructuring_assignment_array() {
    let cpg = js_cpg("const [a, b] = [1, 2];");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let a_def = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("a"))
        .expect("expected LocalDef for destructured 'a'");
    let b_def = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("b"))
        .expect("expected LocalDef for destructured 'b'");
    let _ = (a_def, b_def);
}

#[test]
fn test_destructuring_assignment_object() {
    let cpg = js_cpg("const { x, y } = point;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("x"))
        .expect("expected LocalDef for destructured 'x'");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("y"))
        .expect("expected LocalDef for destructured 'y'");
}

#[test]
fn test_comment_not_in_ast() {
    let cpg = js_cpg("// This is a comment\nconst x = 1;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let comment_in_ast = cpg.ast.values().any(|n| n.node_type == "comment");
    assert!(!comment_in_ast, "comment nodes should not appear in cpg.ast");
    assert!(!cpg.comments.is_empty(), "comment should be stored in cpg.comments");
}

// ── CFG Tests ─────────────────────────────────────────────────────────────────

#[test]
fn test_cfg_try_catch_branches() {
    let cpg = js_cpg("function f() { try { return 1; } catch (e) { return 0; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let return_nodes: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::Return).collect();
    assert_eq!(return_nodes.len(), 2, "expected 2 Return nodes");
}

#[test]
fn test_cfg_async_await_chain() {
    let cpg = js_cpg("async function f() { const a = await step1(); const b = await step2(a); return b; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let await_nodes: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::AwaitExpr).collect();
    assert_eq!(await_nodes.len(), 2, "expected 2 AwaitExpr nodes");
}

// ── DFG Tests ─────────────────────────────────────────────────────────────────

#[test]
fn test_dfg_var_declaration_defines() {
    let cpg = js_cpg("const x = 42; console.log(x);");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_x_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "x");
    assert!(has_x_def, "expected DataflowDef for 'x'");
    let has_x_use = cpg.dataflow.uses.iter().any(|u| u.variable == "x");
    assert!(has_x_use, "expected DataflowUse for 'x' at console.log(x)");
}

#[test]
fn test_dfg_closure_capture() {
    let cpg = js_cpg("function outer() { const x = 10; return function() { return x; }; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let x_uses: Vec<_> = cpg.dataflow.uses.iter().filter(|u| u.variable == "x").collect();
    assert!(!x_uses.is_empty(), "expected DataflowUse for 'x' in closure");
}

// ── Call Graph Tests ──────────────────────────────────────────────────────────

#[test]
fn test_callgraph_function_call() {
    let cpg = js_cpg("function foo() {} function bar() { foo(); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let bar_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "bar")
        .expect("expected CallGraphEntry for 'bar'");
    let calls_foo = bar_entry.calls.iter().any(|cs| cs.callee == "foo");
    assert!(calls_foo, "bar should call 'foo' in call graph");
}

#[test]
fn test_callgraph_constructor_new() {
    let cpg = js_cpg("class Foo {} function f() { const foo = new Foo(); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let f_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "f")
        .expect("expected CallGraphEntry for 'f'");
    let calls_foo = f_entry.calls.iter().any(|cs| cs.callee == "Foo");
    assert!(calls_foo, "f should call 'Foo' constructor in call graph");
}

// ── Incremental Tests ─────────────────────────────────────────────────────────

#[test]
fn test_incremental_add_function() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "function a() {}";
    let modified = "function a() {} function b() { a(); }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::JavaScript, GraphBuildOptions::default())
        .expect("JS incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_b = updated
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("b"));
    assert!(has_b, "after adding 'function b', MethodDef for 'b' should exist");
}

#[test]
fn test_incremental_remove_function() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "function a() {} function b() { a(); }";
    let modified = "function a() {}";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::JavaScript, GraphBuildOptions::default())
        .expect("JS incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_b = updated
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("b"));
    assert!(!has_b, "after removing function b, MethodDef for 'b' should be gone");
}

// ── Parity Tests ──────────────────────────────────────────────────────────────

#[test]
fn test_parity_add_function() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "function a() {}";
    let modified = "function a() {} function b() { a(); }";

    let full_cpg = CpgGenerator::new_for_language(SourceLanguage::JavaScript)
        .expect("JS parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::JavaScript, GraphBuildOptions::default())
        .expect("JS incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");
    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let inc_cpg = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let full_method_names: HashSet<_> = full_cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .filter_map(|n| n.name.as_deref())
        .collect();
    let inc_method_names: HashSet<_> = inc_cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .filter_map(|n| n.name.as_deref())
        .collect();
    assert_eq!(
        full_method_names, inc_method_names,
        "incremental CPG should have same MethodDef names as full rebuild"
    );
}

#[test]
fn test_incremental_replace_body_updates_dfg() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "function f() { var x = 1; return x; }\n";
    let modified = "function f() { var x = 99; return x; }\n";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::JavaScript, GraphBuildOptions::default())
        .expect("JS incremental init");
    inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edit = compute_edit(base.as_bytes(), modified.as_bytes())
        .expect("expected a Replace edit");
    assert_eq!(edit.change_type, web_sitter::ChangeType::Replace, "editing a literal should be a Replace");

    let updated = inc.apply_edit(&edit, modified.as_bytes()).expect("apply_edit");

    assert!(!updated.ast.is_empty(), "CPG must not be empty after replace");
    let has_f = updated.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("f"));
    assert!(has_f, "MethodDef 'f' must survive a body replace");
    let has_x_def = updated.dataflow.definitions.iter().any(|d| d.variable == "x");
    assert!(has_x_def, "DFG definition for 'x' must exist after replace");
    let has_x_use = updated.dataflow.uses.iter().any(|u| u.variable == "x");
    assert!(has_x_use, "DFG use of 'x' must exist after replace");
    assert_cfg_valid(updated);
}

#[test]
fn test_incremental_sequential_edits_js() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let src0 = "function a() {}\n";
    let src1 = "function a() {} function b() { a(); }\n";
    let src2 = "function a() {} function b() { a(); } function c() { b(); }\n";
    let src3 = "function a() {} function c() { a(); }\n";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::JavaScript, GraphBuildOptions::default())
        .expect("JS incremental init");
    inc.parse_initial(src0.as_bytes()).expect("initial");

    let e1 = compute_edit(src0.as_bytes(), src1.as_bytes()).expect("edit1");
    inc.apply_edit(&e1, src1.as_bytes()).expect("edit1");

    let e2 = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit2");
    inc.apply_edit(&e2, src2.as_bytes()).expect("edit2");

    let e3 = compute_edit(src2.as_bytes(), src3.as_bytes()).expect("edit3");
    let final_inc = inc.apply_edit(&e3, src3.as_bytes()).expect("edit3");

    let full = CpgGenerator::new_for_language(SourceLanguage::JavaScript)
        .expect("JS parser")
        .generate_from_source_with_options(src3.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let full_names: HashSet<_> = full.ast.values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .filter_map(|n| n.name.as_deref()).collect();
    let inc_names: HashSet<_> = final_inc.ast.values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .filter_map(|n| n.name.as_deref()).collect();
    assert_eq!(full_names, inc_names, "after 3 sequential edits, MethodDef names must match fresh parse");

    let full_cg: HashSet<_> = full.call_graph.values().map(|e| e.name.as_str()).collect();
    let inc_cg: HashSet<_> = final_inc.call_graph.values().map(|e| e.name.as_str()).collect();
    assert_eq!(full_cg, inc_cg, "call graph must match fresh parse after sequential edits");

    assert_cfg_valid(final_inc);
}

#[test]
fn test_parity_dfg_and_callgraph_js() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "function a() {}\n";
    let modified = "function a() { var x = 1; return x; } function b() { a(); }\n";

    let full = CpgGenerator::new_for_language(SourceLanguage::JavaScript)
        .expect("JS parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::JavaScript, GraphBuildOptions::default())
        .expect("JS incremental init");
    inc.parse_initial(base.as_bytes()).expect("initial");
    let edit = compute_edit(base.as_bytes(), modified.as_bytes()).expect("edit");
    let inc_cpg = inc.apply_edit(&edit, modified.as_bytes()).expect("apply_edit");

    let full_cg: HashSet<_> = full.call_graph.values().map(|e| e.name.as_str()).collect();
    let inc_cg: HashSet<_> = inc_cpg.call_graph.values().map(|e| e.name.as_str()).collect();
    assert_eq!(full_cg, inc_cg, "call graph function names must match between full and incremental");

    let full_defs: HashSet<_> = full.dataflow.definitions.iter().map(|d| d.variable.as_str()).collect();
    let inc_defs: HashSet<_> = inc_cpg.dataflow.definitions.iter().map(|d| d.variable.as_str()).collect();
    assert_eq!(full_defs, inc_defs, "DFG definition variable names must match between full and incremental");

    assert_cfg_valid(inc_cpg);
}
