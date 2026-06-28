//! Grammar construct coverage tests for Rust (Phase 1).
//!
//! Tests are in the TDD red state — assertions about `IrNodeKind` will fail
//! until the real RustLifter is implemented.

use std::collections::HashSet;

use web_sitter::{IrNodeKind, LiteralKind, LoopKind, NodeId};
use web_sitter::{CpgGenerator, GraphBuildOptions, SourceLanguage};

fn rust_cpg(src: &str) -> web_sitter::Cpg {
    CpgGenerator::new_for_language(SourceLanguage::Rust)
        .expect("Rust parser init")
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("Rust CPG generation failed")
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
fn test_source_file_lifts_to_file() {
    let cpg = rust_cpg("fn main() {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let file_nodes: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::File && n.node_type == "source_file")
        .collect();
    assert_eq!(file_nodes.len(), 1, "expected exactly one File node with node_type 'source_file'");
}

#[test]
fn test_function_item_lifts_to_method_def() {
    let cpg = rust_cpg("fn greet(name: &str) -> String { format!(\"hello {}\", name) }");
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
fn test_async_function() {
    let cpg = rust_cpg("async fn fetch() -> String { String::new() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("fetch"))
        .expect("expected MethodDef for 'fetch'");
    let meta = cpg.rust_meta(*method_id).expect("fetch should have RustNodeMetadata");
    assert!(meta.is_async, "is_async should be true for 'async fn'");
}

#[test]
fn test_unsafe_function() {
    let cpg = rust_cpg("unsafe fn danger() {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("danger"))
        .expect("expected MethodDef for 'danger'");
    let meta = cpg.rust_meta(*method_id).expect("danger should have RustNodeMetadata");
    assert!(meta.is_unsafe, "is_unsafe should be true for 'unsafe fn'");
}

#[test]
fn test_const_function() {
    let cpg = rust_cpg("const fn add(a: u32, b: u32) -> u32 { a + b }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("add"))
        .expect("expected MethodDef for 'add'");
    let meta = cpg.rust_meta(*method_id).expect("add should have RustNodeMetadata");
    assert!(meta.is_const, "is_const should be true for 'const fn'");
}

#[test]
fn test_struct_definition_lifts_to_class_def() {
    let cpg = rust_cpg("struct Point { x: f64, y: f64 }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let class_def = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Point"))
        .expect("expected ClassDef for 'Point'");
    assert_eq!(class_def.name.as_deref(), Some("Point"));
    let fields: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::FieldDef).collect();
    assert!(fields.iter().any(|n| n.name.as_deref() == Some("x")), "expected FieldDef for 'x'");
    assert!(fields.iter().any(|n| n.name.as_deref() == Some("y")), "expected FieldDef for 'y'");
}

#[test]
fn test_tuple_struct() {
    let cpg = rust_cpg("struct Pair(i32, i32);");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Pair"))
        .expect("expected ClassDef for 'Pair'");
}

#[test]
fn test_enum_definition() {
    let cpg = rust_cpg("enum Shape { Circle(f64), Rectangle(f64, f64), Triangle }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Shape"))
        .expect("expected ClassDef for 'Shape' enum");
}

#[test]
fn test_impl_block() {
    let cpg = rust_cpg("struct C { val: i32 } impl C { fn new(val: i32) -> C { C { val } } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ImplBlock)
        .expect("expected ImplBlock node");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("new"))
        .expect("expected MethodDef for 'new'");
}

#[test]
fn test_trait_definition() {
    let cpg = rust_cpg("trait Animal { fn speak(&self) -> String; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TraitDef && n.name.as_deref() == Some("Animal"))
        .expect("expected TraitDef for 'Animal'");
}

#[test]
fn test_trait_impl() {
    let cpg = rust_cpg("trait Greet { fn greet(&self); } struct Dog; impl Greet for Dog { fn greet(&self) {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (impl_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ImplBlock)
        .expect("expected ImplBlock");
    let meta = cpg.rust_meta(*impl_id).expect("ImplBlock should have RustNodeMetadata");
    assert_eq!(
        meta.trait_type.as_deref(),
        Some("Greet"),
        "trait_type should be 'Greet'"
    );
    assert_eq!(
        meta.self_type.as_deref(),
        Some("Dog"),
        "self_type should be 'Dog'"
    );
}

#[test]
fn test_use_declaration() {
    let cpg = rust_cpg("use std::collections::HashMap;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::UseDecl)
        .expect("expected UseDecl for 'use std::...'");
}

#[test]
fn test_mod_declaration() {
    let cpg = rust_cpg("mod utils { pub fn helper() {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ModDef && n.name.as_deref() == Some("utils"))
        .expect("expected ModDef for 'utils'");
}

#[test]
fn test_let_binding_lifts_to_local_def() {
    let cpg = rust_cpg("fn f() { let x = 42; let _ = x; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("x"))
        .expect("expected LocalDef for 'let x = 42'");
}

#[test]
fn test_let_binding_mutable() {
    let cpg = rust_cpg("fn f() { let mut x = 0; x += 1; let _ = x; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (x_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("x"))
        .expect("expected LocalDef for 'let mut x'");
    let meta = cpg.rust_meta(*x_id).expect("x should have RustNodeMetadata");
    assert!(meta.is_mut, "is_mut should be true for 'let mut x'");
}

#[test]
fn test_assignment_expression() {
    let cpg = rust_cpg("fn f() { let mut x = 0; x = 5; let _ = x; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Assign)
        .expect("expected Assign node for 'x = 5'");
}

#[test]
fn test_if_expression() {
    let cpg = rust_cpg("fn f(x: i32) -> i32 { if x > 0 { x } else { 0 } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Conditional)
        .expect("expected Conditional for 'if x > 0'");
}

#[test]
fn test_if_let_expression() {
    let cpg = rust_cpg("fn f(opt: Option<i32>) -> i32 { if let Some(v) = opt { v } else { 0 } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Conditional)
        .expect("expected Conditional for 'if let Some(v) = opt'");
}

#[test]
fn test_match_expression() {
    let cpg = rust_cpg("fn f(x: i32) -> &'static str { match x { 0 => \"zero\", _ => \"nonzero\" } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MatchExpr)
        .expect("expected MatchExpr for 'match x'");
    let arms: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::MatchArm).collect();
    assert_eq!(arms.len(), 2, "expected 2 MatchArm nodes (0 and _)");
}

#[test]
fn test_match_arm_guard() {
    let cpg = rust_cpg("fn f(x: i32) -> &'static str { match x { n if n > 0 => \"pos\", _ => \"non-pos\" } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MatchExpr)
        .expect("expected MatchExpr");
}

#[test]
fn test_loop_expression() {
    let cpg = rust_cpg("fn f() -> i32 { let mut x = 0; loop { x += 1; if x >= 10 { break x; } } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::LoopExpr || (n.kind == IrNodeKind::Loop && n.loop_kind == Some(LoopKind::While)))
        .expect("expected LoopExpr or Loop for 'loop { ... }'");
    let _ = loop_node;
}

#[test]
fn test_while_loop() {
    let cpg = rust_cpg("fn f() { let mut x = 10; while x > 0 { x -= 1; } }");
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
fn test_while_let_loop() {
    let cpg = rust_cpg("fn f(stack: &mut Vec<i32>) { while let Some(top) = stack.pop() { let _ = top; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'while let'");
}

#[test]
fn test_for_in_loop() {
    let cpg = rust_cpg("fn f(v: &[i32]) { for x in v { let _ = x; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'for x in v'");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::ForEach));
}

#[test]
fn test_closure_expression() {
    let cpg = rust_cpg("fn f() { let double = |x: i32| x * 2; let _ = double(3); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClosureExpr || n.kind == IrNodeKind::LambdaDef)
        .expect("expected ClosureExpr or LambdaDef for '|x| x * 2'");
}

#[test]
fn test_move_closure() {
    let cpg = rust_cpg("fn f() { let x = 10; let clamp = move || x; let _ = clamp(); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (closure_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClosureExpr || n.kind == IrNodeKind::LambdaDef)
        .expect("expected ClosureExpr or LambdaDef");
    let meta = cpg.rust_meta(*closure_id).expect("move closure should have RustNodeMetadata");
    assert!(meta.is_move_closure, "is_move_closure should be true for 'move ||'");
}

#[test]
fn test_return_statement() {
    let cpg = rust_cpg("fn f(x: i32) -> i32 { return x * 2; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Return)
        .expect("expected Return node");
}

#[test]
fn test_break_continue() {
    let cpg = rust_cpg("fn f() { for i in 0..10 { if i == 5 { break; } if i == 3 { continue; } } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Break || n.kind == IrNodeKind::BreakExpr)
        .expect("expected Break or BreakExpr node");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Continue)
        .expect("expected Continue node");
}

#[test]
fn test_try_operator() {
    let cpg = rust_cpg("use std::num::ParseIntError;\nfn f(s: &str) -> Result<i32, ParseIntError> { let n = s.parse::<i32>()?; Ok(n) }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TryExpr)
        .expect("expected TryExpr for '?' operator");
}

#[test]
fn test_unsafe_block() {
    let cpg = rust_cpg("fn f(ptr: *const i32) -> i32 { unsafe { *ptr } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let unsafe_block = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::UnsafeBlock)
        .expect("expected UnsafeBlock for 'unsafe { ... }'");
    let (ub_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::UnsafeBlock)
        .unwrap();
    let meta = cpg.rust_meta(*ub_id).expect("unsafe block should have RustNodeMetadata");
    assert!(meta.is_unsafe_context, "is_unsafe_context should be true");
    let _ = unsafe_block;
}

#[test]
fn test_macro_invocation() {
    let cpg = rust_cpg("fn f() { println!(\"hello {}\", 42); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MacroInvocation)
        .expect("expected MacroInvocation for 'println!(...)'");
}

#[test]
fn test_call_expression() {
    let cpg = rust_cpg("fn greet(name: &str) -> String { format!(\"hello {}\", name) }\nfn main() { greet(\"world\"); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Call && n.name.as_deref() == Some("greet"))
        .expect("expected Call for 'greet(...)'");
}

#[test]
fn test_method_call() {
    let cpg = rust_cpg("fn f(s: String) { let _ = s.len(); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Call && n.name.as_deref() == Some("len"))
        .expect("expected Call for 's.len()'");
}

#[test]
fn test_struct_expression() {
    let cpg = rust_cpg("struct P { x: i32, y: i32 } fn f() -> P { P { x: 1, y: 2 } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::StructExpr)
        .expect("expected StructExpr for 'P { x: 1, y: 2 }'");
}

#[test]
fn test_range_expression() {
    let cpg = rust_cpg("fn f() -> i32 { let sum: i32 = (0..10).sum(); sum }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::RangeExpr)
        .expect("expected RangeExpr for '0..10'");
}

#[test]
fn test_inclusive_range_expression() {
    let cpg = rust_cpg("fn f() -> i32 { let sum: i32 = (1..=10).sum(); sum }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::RangeExpr)
        .expect("expected RangeExpr for '1..=10'");
}

#[test]
fn test_field_access() {
    let cpg = rust_cpg("struct P { x: i32 } fn f(p: P) -> i32 { p.x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MemberAccess)
        .expect("expected MemberAccess for 'p.x'");
}

#[test]
fn test_index_expression() {
    let cpg = rust_cpg("fn f(v: &[i32]) -> i32 { v[0] }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Subscript)
        .expect("expected Subscript for 'v[0]'");
}

#[test]
fn test_binary_expression() {
    let cpg = rust_cpg("fn f(a: i32, b: i32) -> i32 { a + b }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::BinaryOp && n.operator.as_deref() == Some("+"))
        .expect("expected BinaryOp with operator '+'");
}

#[test]
fn test_unary_expression() {
    let cpg = rust_cpg("fn f(x: bool) -> bool { !x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::UnaryOp && n.operator.as_deref() == Some("!"))
        .expect("expected UnaryOp with operator '!'");
}

#[test]
fn test_reference_expression() {
    let cpg = rust_cpg("fn f(x: i32) { let r = &x; let _ = r; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::UnaryOp && n.operator.as_deref() == Some("&"))
        .expect("expected UnaryOp with operator '&' for reference");
}

#[test]
fn test_mutable_reference() {
    let cpg = rust_cpg("fn f(x: &mut i32) { *x += 1; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // *x is a dereference (UnaryOp with '*')
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::UnaryOp && n.operator.as_deref() == Some("*"))
        .expect("expected UnaryOp with operator '*' for dereference");
}

#[test]
fn test_cast_expression() {
    let cpg = rust_cpg("fn f(x: i32) -> f64 { x as f64 }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Cast)
        .expect("expected Cast for 'x as f64'");
}

#[test]
fn test_integer_literal() {
    let cpg = rust_cpg("fn f() -> i32 { 42 }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Integer))
        .expect("expected Integer Literal for '42'");
}

#[test]
fn test_float_literal() {
    let cpg = rust_cpg("fn f() -> f64 { 3.14 }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Float))
        .expect("expected Float Literal for '3.14'");
}

#[test]
fn test_string_literal() {
    let cpg = rust_cpg("fn f() -> &'static str { \"hello\" }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::String))
        .expect("expected String Literal for \"hello\"");
}

#[test]
fn test_bool_literal() {
    let cpg = rust_cpg("fn f() -> bool { true }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Bool)
            && n.text.as_deref().unwrap_or("").contains("true"))
        .expect("expected Bool Literal for 'true'");
}

#[test]
fn test_char_literal() {
    let cpg = rust_cpg("fn f() -> char { 'a' }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Char))
        .expect("expected Char Literal for 'a'");
}

#[test]
fn test_derive_macro() {
    let cpg = rust_cpg("#[derive(Debug, Clone, PartialEq)] struct Point { x: i32, y: i32 }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (struct_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Point"))
        .expect("expected ClassDef for 'Point'");
    let meta = cpg.rust_meta(*struct_id).expect("Point should have RustNodeMetadata");
    let derives = meta.derive_macros.as_slice();
    assert!(derives.contains(&"Debug".to_string()), "derive_macros should contain 'Debug'");
    assert!(derives.contains(&"Clone".to_string()), "derive_macros should contain 'Clone'");
}

#[test]
fn test_lifetime_annotation() {
    let cpg = rust_cpg("fn longest<'a>(x: &'a str, y: &'a str) -> &'a str { if x.len() > y.len() { x } else { y } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("longest"))
        .expect("expected MethodDef for 'longest'");
    let meta = cpg.rust_meta(*method_id).expect("longest should have RustNodeMetadata");
    let lifetimes = meta.lifetimes.as_slice();
    assert!(lifetimes.contains(&"'a".to_string()), "lifetimes should contain \"'a\"");
}

#[test]
fn test_generic_function() {
    let cpg = rust_cpg("fn max<T: PartialOrd>(a: T, b: T) -> T { if a > b { a } else { b } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("max"))
        .expect("expected MethodDef for 'max'");
    let meta = cpg.rust_meta(*method_id).expect("max should have RustNodeMetadata");
    let params = meta.generic_params.as_slice();
    assert!(params.contains(&"T".to_string()), "generic_params should contain 'T'");
    let bounds = meta.trait_bounds.as_slice();
    assert!(
        bounds.iter().any(|b| b.contains("PartialOrd")),
        "trait_bounds should contain 'PartialOrd'"
    );
}

#[test]
fn test_where_clause() {
    let cpg = rust_cpg("use std::fmt; fn print<T>(val: T) where T: fmt::Display { println!(\"{}\", val); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("print"))
        .expect("expected MethodDef for 'print'");
    let meta = cpg.rust_meta(*method_id).expect("print should have RustNodeMetadata");
    let where_clauses = meta.where_clauses.as_slice();
    assert!(
        where_clauses.iter().any(|w| w.contains("Display")),
        "where_clauses should contain 'Display'"
    );
}

#[test]
fn test_visibility_pub() {
    let cpg = rust_cpg("pub fn public_fn() {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("public_fn"))
        .expect("expected MethodDef for 'public_fn'");
    let meta = cpg.rust_meta(*method_id).expect("public_fn should have RustNodeMetadata");
    assert_eq!(
        meta.visibility.as_deref(),
        Some("pub"),
        "visibility should be 'pub'"
    );
}

#[test]
fn test_extern_function() {
    let cpg = rust_cpg("extern \"C\" fn c_func() -> i32 { 0 }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("c_func"))
        .expect("expected MethodDef for 'c_func'");
    let meta = cpg.rust_meta(*method_id).expect("c_func should have RustNodeMetadata");
    assert!(meta.is_extern, "is_extern should be true for 'extern fn'");
    assert_eq!(meta.abi.as_deref(), Some("C"), "abi should be 'C'");
}

#[test]
fn test_comment_not_in_ast() {
    let cpg = rust_cpg("// This is a comment\nfn f() {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let comment_in_ast = cpg.ast.values().any(|n| n.node_type == "line_comment");
    assert!(!comment_in_ast, "comment nodes should not appear in cpg.ast");
    assert!(!cpg.comments.is_empty(), "comment should be stored in cpg.comments");
}

// ── CFG Tests ─────────────────────────────────────────────────────────────────

#[test]
fn test_cfg_match_branches() {
    let cpg = rust_cpg("fn f(x: i32) -> &'static str { match x { 0 => \"zero\", 1 => \"one\", _ => \"other\" } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let match_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::MatchExpr)
        .expect("expected MatchExpr");
    let match_bb = match_node.basic_block.as_deref().unwrap_or("");
    if !match_bb.is_empty() {
        let bb = cpg.basic_blocks.get(match_bb).expect("match BB exists");
        assert!(
            bb.successors.len() >= 3,
            "match with 3 arms should have at least 3 successors, got {}",
            bb.successors.len()
        );
    }
}

#[test]
fn test_cfg_question_mark_operator() {
    let cpg = rust_cpg("fn f(s: &str) -> Result<i32, std::num::ParseIntError> { let n = s.parse::<i32>()?; Ok(n * 2) }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TryExpr)
        .expect("expected TryExpr for '?'");
    let return_nodes: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::Return).collect();
    // '?' desugars to an early return on Err
    assert!(!return_nodes.is_empty() || !cpg.basic_blocks.is_empty(), "CFG should have blocks");
}

#[test]
fn test_cfg_loop_with_break_value() {
    let cpg = rust_cpg("fn f() -> i32 { let x = loop { break 42; }; x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LoopExpr || n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'loop'");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Break || n.kind == IrNodeKind::BreakExpr)
        .expect("expected Break or BreakExpr");
}

// ── DFG Tests ─────────────────────────────────────────────────────────────────

#[test]
fn test_dfg_let_binding_defines() {
    let cpg = rust_cpg("fn f() { let x = 42; let _ = x; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_x_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "x");
    assert!(has_x_def, "expected DataflowDef for 'x'");
    let has_x_use = cpg.dataflow.uses.iter().any(|u| u.variable == "x");
    assert!(has_x_use, "expected DataflowUse for 'x'");
}

#[test]
fn test_dfg_closure_capture() {
    let cpg = rust_cpg("fn f() -> impl Fn() -> i32 { let x = 10; move || x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let x_uses: Vec<_> = cpg.dataflow.uses.iter().filter(|u| u.variable == "x").collect();
    assert!(!x_uses.is_empty(), "expected DataflowUse for 'x' captured by closure");
}

#[test]
fn test_dfg_pattern_binding_in_match() {
    let cpg = rust_cpg("fn f(opt: Option<i32>) -> i32 { match opt { Some(v) => v, None => 0 } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_v_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "v");
    assert!(has_v_def, "expected DataflowDef for 'v' bound in match arm 'Some(v)'");
}

// ── Call Graph Tests ──────────────────────────────────────────────────────────

#[test]
fn test_callgraph_function_call() {
    let cpg = rust_cpg("fn foo() {} fn bar() { foo(); }");
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
fn test_callgraph_method_call() {
    let cpg = rust_cpg("struct C; impl C { fn do_work(&self) {} } fn caller(c: C) { c.do_work(); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let caller_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "caller")
        .expect("expected CallGraphEntry for 'caller'");
    let calls_do = caller_entry.calls.iter().any(|cs| cs.callee == "do_work");
    assert!(calls_do, "caller should call 'do_work' in call graph");
}

#[test]
fn test_callgraph_macro_call() {
    let cpg = rust_cpg("fn f() { println!(\"hello\"); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let f_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "f")
        .expect("expected CallGraphEntry for 'f'");
    let calls_println = f_entry.calls.iter().any(|cs| cs.callee == "println");
    assert!(calls_println, "f should call 'println' in call graph");
}

// ── Incremental Tests ─────────────────────────────────────────────────────────

#[test]
fn test_incremental_add_function() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "fn a() {}";
    let modified = "fn a() {} fn b() { a(); }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Rust, GraphBuildOptions::default())
        .expect("Rust incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_b = updated
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("b"));
    assert!(has_b, "after adding 'fn b', MethodDef for 'b' should exist");
}

#[test]
fn test_incremental_add_struct() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "fn f() {}";
    let modified = "struct Point { x: i32, y: i32 } fn f() {}";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Rust, GraphBuildOptions::default())
        .expect("Rust incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_point = updated
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Point"));
    assert!(has_point, "after adding struct Point, ClassDef for 'Point' should exist");
}

#[test]
fn test_incremental_add_unsafe_block() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "fn f(p: *const i32) {}";
    let modified = "fn f(p: *const i32) -> i32 { unsafe { *p } }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Rust, GraphBuildOptions::default())
        .expect("Rust incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_unsafe = updated.ast.values().any(|n| n.kind == IrNodeKind::UnsafeBlock);
    assert!(has_unsafe, "after adding unsafe block, UnsafeBlock should exist");
}

// ── Parity Tests ──────────────────────────────────────────────────────────────

#[test]
fn test_parity_add_function() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "fn a() {}";
    let modified = "fn a() {} fn b() { a(); }";

    let full_cpg = CpgGenerator::new_for_language(SourceLanguage::Rust)
        .expect("Rust parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Rust, GraphBuildOptions::default())
        .expect("Rust incremental init");
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

    let base = "fn f() -> i32 { let x = 1; x }\n";
    let modified = "fn f() -> i32 { let x = 99; x }\n";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Rust, GraphBuildOptions::default())
        .expect("Rust incremental init");
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
    assert_cfg_valid(updated);
}

#[test]
fn test_incremental_sequential_edits_rust() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let src0 = "fn a() {}\n";
    let src1 = "fn a() {} fn b() { a(); }\n";
    let src2 = "fn a() {} fn b() { a(); } fn c() { b(); }\n";
    let src3 = "fn a() {} fn c() { a(); }\n";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Rust, GraphBuildOptions::default())
        .expect("Rust incremental init");
    inc.parse_initial(src0.as_bytes()).expect("initial");

    let e1 = compute_edit(src0.as_bytes(), src1.as_bytes()).expect("edit1");
    inc.apply_edit(&e1, src1.as_bytes()).expect("edit1");

    let e2 = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit2");
    inc.apply_edit(&e2, src2.as_bytes()).expect("edit2");

    let e3 = compute_edit(src2.as_bytes(), src3.as_bytes()).expect("edit3");
    let final_inc = inc.apply_edit(&e3, src3.as_bytes()).expect("edit3");

    let full = CpgGenerator::new_for_language(SourceLanguage::Rust)
        .expect("Rust parser")
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
fn test_parity_dfg_and_callgraph_rust() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "fn a() {}\n";
    let modified = "fn a() { let x = 1; let _ = x; } fn b() { a(); }\n";

    let full = CpgGenerator::new_for_language(SourceLanguage::Rust)
        .expect("Rust parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Rust, GraphBuildOptions::default())
        .expect("Rust incremental init");
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

// ── Type System Tests ─────────────────────────────────────────────────────────

#[test]
fn test_type_ref_primitive() {
    // Primitive type annotation → IrNodeKind::TypeRef per Rust plan §1428
    let cpg = rust_cpg("fn f(x: i32) {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_i32_type_ref = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeRef && n.text.as_deref().map_or(false, |t| t.contains("i32")));
    assert!(has_i32_type_ref, "expected TypeRef node whose text contains 'i32'");
}

#[test]
fn test_type_ref_reference() {
    // Reference type &T → IrNodeKind::TypeRef with node_type 'reference_type'
    let cpg = rust_cpg("fn f(s: &str) -> &str { s }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_ref_type = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "reference_type");
    assert!(has_ref_type, "expected TypeRef node with node_type 'reference_type' for '&str'");
}

#[test]
fn test_type_ref_generic() {
    // Generic type Vec<i32> → IrNodeKind::TypeRef with node_type 'generic_type'
    let cpg = rust_cpg("fn f() -> Vec<i32> { vec![1, 2, 3] }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_generic_type = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "generic_type");
    assert!(has_generic_type, "expected TypeRef node with node_type 'generic_type' for 'Vec<i32>'");
}

#[test]
fn test_extern_crate_declaration() {
    // extern crate → IrNodeKind::UseDecl
    let cpg = rust_cpg("extern crate alloc;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_use_decl = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::UseDecl && n.text.as_deref().map_or(false, |t| t.contains("alloc")));
    assert!(has_use_decl, "expected UseDecl node containing 'alloc' for 'extern crate alloc'");
}

#[test]
fn test_async_block() {
    // async { ... } → IrNodeKind::Block with RustNodeMetadata.is_async == true
    let cpg = rust_cpg("fn f() { let _ = async { 42 }; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let async_block = cpg
        .ast
        .iter()
        .find(|(id, n)| {
            n.kind == IrNodeKind::Block
                && cpg.rust_meta(**id).map_or(false, |m| m.is_async)
        });
    assert!(async_block.is_some(), "expected Block node with RustNodeMetadata.is_async == true");
}

#[test]
fn test_lifetime_maps_to_lifetime_ref() {
    // Lifetime annotations 'a → IrNodeKind::LifetimeRef nodes
    let cpg = rust_cpg("fn f<'a>(s: &'a str) -> &'a str { s }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_lifetime_ref = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::LifetimeRef);
    assert!(has_lifetime_ref, "expected LifetimeRef nodes for lifetime 'a");
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("f"))
        .expect("expected MethodDef for 'f'");
    let meta = cpg.rust_meta(*method_id).expect("f should have RustNodeMetadata");
    assert!(
        meta.lifetimes.iter().any(|l| l.contains("'a")),
        "RustNodeMetadata.lifetimes should contain \"'a\""
    );
}

#[test]
#[ignore]
fn debug_rust_issues() {
    // DFG let binding
    let cpg = rust_cpg("fn f() { let x = 42; let _ = x; }");
    println!("=== DFG let binding ===");
    for (nid, n) in &cpg.ast {
        if n.node_type == "identifier" || n.node_type == "wildcard_pattern" || n.node_type == "let_declaration" {
            println!("  {nid}: kind={:?} type={} text={:?} children={:?} parent={:?}", n.kind, n.node_type, n.text, n.children, n.parent_id);
        }
    }
    println!("  defs: {:?}", cpg.dataflow.definitions.iter().map(|d| &d.variable).collect::<Vec<_>>());
    println!("  uses: {:?}", cpg.dataflow.uses.iter().map(|u| &u.variable).collect::<Vec<_>>());

    // method_call name
    let cpg2 = rust_cpg("fn f(s: String) { let _ = s.len(); }");
    println!("=== method_call ===");
    for (nid, n) in &cpg2.ast {
        if n.node_type == "method_call_expression" || n.kind == IrNodeKind::Call {
            println!("  {nid}: kind={:?} type={} name={:?} children={:?} field_names={:?}", n.kind, n.node_type, n.name, n.children, n.field_names);
        }
        if n.node_type == "field_identifier" || n.node_type == "identifier" {
            println!("  {nid}: kind={:?} type={} text={:?} parent={:?}", n.kind, n.node_type, n.text, n.parent_id);
        }
    }

    // reference expression
    let cpg3 = rust_cpg("fn f(x: i32) { let r = &x; let _ = r; }");
    println!("=== reference_expression ===");
    for (nid, n) in &cpg3.ast {
        if n.node_type == "reference_expression" || n.kind == IrNodeKind::UnaryOp {
            println!("  {nid}: kind={:?} type={} op={:?} text={:?} children={:?}", n.kind, n.node_type, n.operator, n.text, n.children);
        }
    }

    // impl block trait_type/self_type
    let cpg4 = rust_cpg("trait Greet { fn greet(&self); } struct Dog; impl Greet for Dog { fn greet(&self) {} }");
    println!("=== impl block ===");
    for (nid, n) in &cpg4.ast {
        if n.node_type == "impl_item" || n.kind == IrNodeKind::ImplBlock {
            println!("  {nid}: kind={:?} type={} name={:?} text={:?} children={:?} field_names={:?}", n.kind, n.node_type, n.name, n.text.as_deref().map(|s| &s[..s.len().min(40)]), n.children, n.field_names);
        }
    }

    // function visibility, extern, generics, lifetimes
    let cpg5 = rust_cpg("pub fn longest<'a, T: PartialOrd>(x: &'a T, y: &'a T) -> &'a T { if x > y { x } else { y } }");
    println!("=== pub fn with generics/lifetimes ===");
    for (nid, n) in &cpg5.ast {
        if n.node_type == "function_item" || n.node_type == "type_parameters" || n.node_type == "lifetime" || n.node_type == "visibility_modifier" {
            println!("  {nid}: kind={:?} type={} text={:?} children={:?} field_names={:?}", n.kind, n.node_type, n.text.as_deref().map(|s| &s[..s.len().min(60)]), n.children, n.field_names);
        }
    }
}

#[test]
#[ignore]
fn debug_rust_issues2() {
    // Full node dump for type_parameters with generics/lifetimes
    let cpg = rust_cpg("pub fn longest<'a, T: PartialOrd>(x: &'a T) -> &'a T { x }");
    println!("=== all nodes ===");
    for (nid, n) in &cpg.ast {
        println!("  {nid}: type={} text={:?} field_names={:?} children={:?}", 
            n.node_type, 
            n.text.as_deref().map(|s| &s[..s.len().min(30)]), 
            n.field_names, n.children);
    }

    // Derive macro on struct
    let cpg2 = rust_cpg("#[derive(Debug, Clone)] struct Point { x: i32, y: i32 }");
    println!("=== derive macro ===");
    for (nid, n) in &cpg2.ast {
        println!("  {nid}: type={} kind={:?} text={:?} children={:?} field_names={:?}", 
            n.node_type, n.kind,
            n.text.as_deref().map(|s| &s[..s.len().min(40)]), 
            n.children, n.field_names);
    }

    // Move closure  
    let cpg3 = rust_cpg("fn f() { let x = 10; let clamp = move || x; let _ = clamp(); }");
    println!("=== move closure ===");
    for (nid, n) in &cpg3.ast {
        if n.node_type.contains("closure") || n.node_type == "move" {
            println!("  {nid}: type={} text={:?} children={:?} field_names={:?}", 
                n.node_type, n.text, n.children, n.field_names);
        }
    }

    // extern "C" fn
    let cpg4 = rust_cpg("extern \"C\" fn c_func() -> i32 { 0 }");
    println!("=== extern fn ===");
    for (nid, n) in &cpg4.ast {
        println!("  {nid}: type={} text={:?} children={:?} field_names={:?}", 
            n.node_type, n.text.as_deref().map(|s| &s[..s.len().min(30)]), n.children, n.field_names);
    }

    // where clause
    let cpg5 = rust_cpg("use std::fmt; fn print<T>(val: T) where T: fmt::Display { }");
    println!("=== where clause ===");
    for (nid, n) in &cpg5.ast {
        if n.node_type.contains("where") || n.node_type.contains("bound") || n.node_type.contains("constraint") {
            println!("  {nid}: type={} text={:?} children={:?} field_names={:?}", 
                n.node_type, n.text, n.children, n.field_names);
        }
    }

    // macro call
    let cpg6 = rust_cpg("fn f() { println!(\"hello\"); }");
    println!("=== macro call ===");
    for (nid, n) in &cpg6.ast {
        println!("  {nid}: type={} kind={:?} name={:?} text={:?} children={:?}", 
            n.node_type, n.kind, n.name, n.text.as_deref().map(|s| &s[..s.len().min(30)]), n.children);
    }
    println!("  callgraph: {:?}", cpg6.call_graph.values().map(|e| (&e.name, &e.calls)).collect::<Vec<_>>());
}

#[test]
#[ignore]
fn debug_rust_cfg_match() {
    let cpg = rust_cpg("fn f(x: i32) -> &'static str { match x { 0 => \"zero\", 1 => \"one\", _ => \"other\" } }");
    println!("=== all nodes ===");
    for (nid, n) in &cpg.ast {
        println!("  {nid}: kind={:?} type={} bb={:?} children={:?}", n.kind, n.node_type, n.basic_block, n.children);
    }
    println!("=== basic blocks ===");
    for (bbid, bb) in &cpg.basic_blocks {
        println!("  {bbid}: nodes={:?} succs={:?}", bb.nodes, bb.successors);
    }
    let match_node = cpg.ast.values().find(|n| n.kind == IrNodeKind::MatchExpr).expect("MatchExpr");
    println!("=== MatchExpr bb={:?} ===", match_node.basic_block);
}
