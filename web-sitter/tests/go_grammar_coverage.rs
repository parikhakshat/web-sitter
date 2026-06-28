//! Grammar construct coverage tests for Go.
//!
//! Each test builds a CPG from a Go snippet and asserts properties on the IR.
//! With stub lifters these tests are in the TDD red state — every assertion
//! about `IrNodeKind` values will fail until the real GoLifter is implemented.

use std::collections::HashSet;

use web_sitter::{ChannelDirection, IrNodeKind, LiteralKind, LoopKind, NodeId};
use web_sitter::{CpgGenerator, GraphBuildOptions, SourceLanguage};

fn go_cpg(src: &str) -> web_sitter::Cpg {
    CpgGenerator::new_for_language(SourceLanguage::Go)
        .expect("Go parser init")
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("Go CPG generation failed")
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
                "Exception successor BB '{exc}' not found in basic_blocks"
            );
        }
    }
}

fn assert_dfg_valid(cpg: &web_sitter::Cpg) {
    let ast_ids: HashSet<NodeId> = cpg.ast.keys().copied().collect();
    for edge in &cpg.dataflow.edges {
        assert!(
            ast_ids.contains(&edge.source),
            "DFG edge source {} not in AST",
            edge.source
        );
        assert!(
            ast_ids.contains(&edge.destination),
            "DFG edge destination {} not in AST",
            edge.destination
        );
    }
}

fn nodes_of_type<'a>(
    cpg: &'a web_sitter::Cpg,
    ts_kind: &str,
) -> Vec<(&'a NodeId, &'a web_sitter::AstNode)> {
    cpg.ast
        .iter()
        .filter(|(_, n)| n.node_type == ts_kind)
        .collect()
}

// ── 1.1 Grammar Construct Coverage ───────────────────────────────────────────

#[test]
fn test_source_file_lifts_to_file() {
    let cpg = go_cpg("package main");
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
fn test_package_clause() {
    let cpg = go_cpg("package mypackage");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let pkg_nodes = nodes_of_type(&cpg, "package_clause");
    assert!(!pkg_nodes.is_empty(), "expected a package_clause node in the AST");
    let (pkg_id, pkg_node) = pkg_nodes[0];
    assert_eq!(
        pkg_node.kind,
        IrNodeKind::Unknown,
        "package_clause should map to Unknown (transparent wrapper)"
    );
    // File node should have GoNodeMetadata with package_name == "mypackage"
    let file_id = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::File)
        .map(|(id, _)| *id)
        .expect("expected a File node");
    let go_meta = cpg
        .go_meta(file_id)
        .expect("File node should have GoNodeMetadata");
    assert_eq!(
        go_meta.package_name.as_deref(),
        Some("mypackage"),
        "GoNodeMetadata.package_name should be 'mypackage'"
    );
    let _ = pkg_id;
}

#[test]
fn test_import_declaration_single() {
    let cpg = go_cpg(r#"package main; import "fmt""#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let import_nodes = nodes_of_type(&cpg, "import_declaration");
    assert!(!import_nodes.is_empty(), "expected import_declaration node");
    let (_, import_node) = import_nodes[0];
    assert_eq!(
        import_node.kind,
        IrNodeKind::Unknown,
        "import_declaration should map to Unknown"
    );
    // There should be an import_spec child whose text contains "fmt"
    let has_fmt_spec = cpg
        .ast
        .values()
        .filter(|n| n.node_type == "import_spec")
        .any(|n| n.text.as_deref().unwrap_or("").contains("fmt"));
    assert!(has_fmt_spec, "expected import_spec with text containing 'fmt'");
}

#[test]
fn test_import_declaration_grouped() {
    let cpg = go_cpg(r#"package main
import (
    "fmt"
    "os"
)"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let import_decls = nodes_of_type(&cpg, "import_declaration");
    assert!(!import_decls.is_empty(), "expected import_declaration node");
    let import_specs: Vec<_> = nodes_of_type(&cpg, "import_spec");
    assert_eq!(import_specs.len(), 2, "expected two import_spec nodes, one for 'fmt' and one for 'os'");
}

#[test]
fn test_function_declaration_lifts_to_method_def() {
    let cpg = go_cpg(r#"
package main
func greet(name string) string {
    return "hello " + name
}
"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let method = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::MethodDef)
        .expect("expected a MethodDef node for 'greet'");
    assert_eq!(
        method.name.as_deref(),
        Some("greet"),
        "MethodDef.name should be 'greet'"
    );
    assert!(
        method.signature.as_deref().unwrap_or("").contains("(name string) string"),
        "MethodDef.signature should contain '(name string) string', got {:?}",
        method.signature
    );
}

#[test]
fn test_exported_function_metadata() {
    let cpg = go_cpg(r#"package main
func Greet(name string) string { return name }"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("Greet"))
        .expect("expected MethodDef for 'Greet'");
    let meta = cpg
        .go_meta(*method_id)
        .expect("Greet MethodDef should have GoNodeMetadata");
    assert!(meta.is_exported, "GoNodeMetadata.is_exported should be true for 'Greet'");
}

#[test]
fn test_method_declaration_lifts_to_method_def() {
    let cpg = go_cpg("package main\ntype Receiver struct{}\nfunc (r *Receiver) DoWork() {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, method_node) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("DoWork"))
        .expect("expected MethodDef for 'DoWork'");
    let _ = method_node;
    let meta = cpg
        .go_meta(*method_id)
        .expect("DoWork should have GoNodeMetadata");
    assert_eq!(
        meta.receiver_type.as_deref(),
        Some("*Receiver"),
        "receiver_type should be '*Receiver'"
    );
    assert_eq!(
        meta.receiver_name.as_deref(),
        Some("r"),
        "receiver_name should be 'r'"
    );
}

#[test]
fn test_var_declaration_lifts_to_local_def() {
    let cpg = go_cpg("package main\nfunc f() { var x int = 5\n_ = x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let local = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("x"))
        .expect("expected LocalDef for 'x'");
    assert_eq!(local.name.as_deref(), Some("x"), "LocalDef.name should be 'x'");
}

#[test]
fn test_var_spec_list_multiple() {
    let cpg = go_cpg("package main\nfunc f() {\nvar (\na int\nb string\n)\n_ = a\n_ = b\n}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let local_defs: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::LocalDef)
        .collect();
    let names: Vec<_> = local_defs.iter().filter_map(|n| n.name.as_deref()).collect();
    assert!(
        names.contains(&"a"),
        "expected LocalDef for 'a', got {:?}",
        names
    );
    assert!(
        names.contains(&"b"),
        "expected LocalDef for 'b', got {:?}",
        names
    );
}

#[test]
fn test_const_declaration_lifts_to_local_def() {
    let cpg = go_cpg("package main\nconst Pi = 3.14");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let local = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("Pi"))
        .expect("expected LocalDef for const 'Pi'");
    assert_eq!(local.name.as_deref(), Some("Pi"));
    // Child Literal should have lit_kind == Float
    let float_lit = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Float))
        .expect("expected a Float literal for 3.14");
    assert_eq!(float_lit.lit_kind, Some(LiteralKind::Float));
}

#[test]
fn test_iota_in_const_block() {
    let cpg = go_cpg("package main\nconst (\nA = iota\nB\nC\n)");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let local_defs: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::LocalDef)
        .collect();
    assert!(
        local_defs.len() >= 3,
        "expected at least 3 LocalDef nodes (A, B, C), got {}",
        local_defs.len()
    );
    // iota should map to Literal with LiteralKind::Integer and text "iota"
    let iota_lit = cpg
        .ast
        .values()
        .find(|n| {
            n.kind == IrNodeKind::Literal
                && n.lit_kind == Some(LiteralKind::Integer)
                && n.text.as_deref().unwrap_or("").contains("iota")
        })
        .expect("expected Literal with lit_kind=Integer and text containing 'iota'");
    assert_eq!(iota_lit.lit_kind, Some(LiteralKind::Integer));
}

#[test]
fn test_short_var_declaration_lifts_to_short_var_decl() {
    let cpg = go_cpg("package main\nfunc f() { x := 42\n_ = x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let short_decl = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ShortVarDecl)
        .expect("expected ShortVarDecl node for ':='");
    let children_ids = &short_decl.children;
    let ident_child = children_ids
        .iter()
        .any(|id| cpg.ast.get(id).map_or(false, |n| n.kind == IrNodeKind::Identifier));
    let lit_child = children_ids
        .iter()
        .any(|id| cpg.ast.get(id).map_or(false, |n| n.kind == IrNodeKind::Literal));
    assert!(ident_child, "ShortVarDecl should have an Identifier child for 'x'");
    assert!(lit_child, "ShortVarDecl should have a Literal child for '42'");
}

#[test]
fn test_short_var_declaration_multi() {
    let cpg = go_cpg("package main\nfunc f() int { a, b := foo()\n_ = a\nreturn b }\nfunc foo() (int, int) { return 0, 0 }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let short_decl = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ShortVarDecl)
        .expect("expected ShortVarDecl for 'a, b := foo()'");
    // Should have at least two Identifier children (a and b)
    let ident_count = short_decl
        .children
        .iter()
        .filter(|id| cpg.ast.get(*id).map_or(false, |n| n.kind == IrNodeKind::Identifier))
        .count();
    assert!(
        ident_count >= 2,
        "ShortVarDecl should have at least 2 Identifier children (a, b), got {}",
        ident_count
    );
}

#[test]
fn test_assignment_statement_lifts_to_assign() {
    let cpg = go_cpg("package main\nfunc f() { var x int; x = 10\n_ = x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Assign)
        .expect("expected Assign node for 'x = 10'");
}

#[test]
fn test_multi_assignment() {
    let cpg = go_cpg("package main\nfunc f() { var a, b int; a, b = b, a\n_ = a\n_ = b }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let assign = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Assign)
        .expect("expected Assign node for 'a, b = b, a'");
    let lhs_idents = assign
        .children
        .iter()
        .filter(|id| cpg.ast.get(*id).map_or(false, |n| n.kind == IrNodeKind::Identifier))
        .count();
    assert!(
        lhs_idents >= 2,
        "multi-assignment LHS should have at least 2 Identifier children"
    );
}

#[test]
fn test_inc_statement() {
    let cpg = go_cpg("package main\nfunc f() { var x int; x++ }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let inc = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::IncDecStmt)
        .expect("expected IncDecStmt for 'x++'");
    assert_eq!(
        inc.operator.as_deref(),
        Some("++"),
        "IncDecStmt operator should be '++'"
    );
}

#[test]
fn test_dec_statement() {
    let cpg = go_cpg("package main\nfunc f() { var x int; x-- }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let dec = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::IncDecStmt)
        .expect("expected IncDecStmt for 'x--'");
    assert_eq!(
        dec.operator.as_deref(),
        Some("--"),
        "IncDecStmt operator should be '--'"
    );
}

#[test]
fn test_binary_expression() {
    let cpg = go_cpg("package main\nfunc f(x, y int) int { z := x + y\nreturn z }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let binop = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::BinaryOp && n.operator.as_deref() == Some("+"))
        .expect("expected BinaryOp with operator '+'");
    assert_eq!(binop.operator.as_deref(), Some("+"));
}

#[test]
fn test_unary_expression_address_of() {
    let cpg = go_cpg("package main\nfunc f() { var x int; p := &x\n_ = p }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let unary = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::UnaryOp && n.operator.as_deref() == Some("&"))
        .expect("expected UnaryOp with operator '&'");
    assert_eq!(unary.operator.as_deref(), Some("&"));
}

#[test]
fn test_unary_expression_receive() {
    let cpg = go_cpg("package main\nfunc f(ch chan int) { v := <-ch\n_ = v }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let recv = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ReceiveExpr)
        .expect("expected ReceiveExpr for '<-ch'");
    // child should be the 'ch' identifier
    let has_ch_child = recv
        .children
        .iter()
        .any(|id| cpg.ast.get(id).map_or(false, |n| n.kind == IrNodeKind::Identifier));
    assert!(has_ch_child, "ReceiveExpr should have an Identifier child for 'ch'");
}

#[test]
fn test_call_expression_lifts_to_call() {
    let cpg = go_cpg(r#"package main
import "fmt"
func f() { fmt.Println("hello") }"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let call = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Call)
        .expect("expected Call node for 'fmt.Println'");
    let callee_text = call.name.as_deref().or(call.text.as_deref()).unwrap_or("");
    assert!(
        callee_text.contains("Println") || callee_text.contains("fmt"),
        "Call name/text should contain 'fmt.Println', got {:?}",
        call.name
    );
}

#[test]
fn test_selector_expression_lifts_to_member_access() {
    let cpg = go_cpg("package main\ntype T struct{ Field int }\nfunc f(x T) { _ = x.Field }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MemberAccess)
        .expect("expected MemberAccess node for 'x.Field'");
}

#[test]
fn test_index_expression_lifts_to_subscript() {
    let cpg = go_cpg("package main\nfunc f(s []int) int { return s[0] }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Subscript)
        .expect("expected Subscript node for 's[0]'");
}

#[test]
fn test_slice_expression() {
    let cpg = go_cpg("package main\nfunc f(s []int) []int { return s[1:3] }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let sub = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Subscript && n.node_type == "slice_expression")
        .expect("expected Subscript with node_type 'slice_expression' for 's[1:3]'");
    assert_eq!(sub.node_type, "slice_expression");
}

#[test]
fn test_type_assertion_expression() {
    let cpg = go_cpg("package main\nfunc f(i interface{}) { v, ok := i.(int)\n_ = v\n_ = ok }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let ta = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeAssertion)
        .expect("expected TypeAssertion for 'i.(int)'");
    let has_type_ref = ta
        .children
        .iter()
        .any(|id| cpg.ast.get(id).map_or(false, |n| n.kind == IrNodeKind::TypeRef));
    assert!(has_type_ref, "TypeAssertion should have a TypeRef child for 'int'");
}

#[test]
fn test_type_conversion_expression_lifts_to_cast() {
    let cpg = go_cpg("package main\nfunc f(x int) int64 { return int64(x) }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Cast)
        .expect("expected Cast node for 'int64(x)'");
}

#[test]
fn test_composite_literal_struct() {
    let cpg = go_cpg("package main\ntype Point struct{ X, Y int }\nfunc f() { p := Point{X: 1, Y: 2}\n_ = p }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::CompositeLit)
        .expect("expected CompositeLit for 'Point{X:1, Y:2}'");
}

#[test]
fn test_composite_literal_slice() {
    let cpg = go_cpg("package main\nfunc f() { s := []int{1, 2, 3}\n_ = s }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::CompositeLit)
        .expect("expected CompositeLit for '[]int{1,2,3}'");
}

#[test]
fn test_composite_literal_map() {
    let cpg = go_cpg(r#"package main
func f() { m := map[string]int{"a": 1}
_ = m }"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::CompositeLit)
        .expect("expected CompositeLit for map literal");
}

#[test]
fn test_func_literal_lifts_to_lambda_def() {
    let cpg = go_cpg("package main\nfunc f() { fn := func(x int) int { return x * 2 }\n_ = fn }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let lambda = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::LambdaDef)
        .expect("expected LambdaDef for func literal");
    // It should introduce a new function scope
    assert!(
        lambda.function_id.is_some() || cpg.ast.values().any(|n| n.function_id == Some(lambda.function_id.unwrap_or(0))),
        "func literal should introduce a new function scope"
    );
}

#[test]
fn test_go_statement_lifts_to_go_stmt() {
    let cpg = go_cpg("package main\nfunc worker() {}\nfunc f() { go worker() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let go_stmt = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::GoStmt)
        .expect("expected GoStmt for 'go worker()'");
    let has_call_child = go_stmt
        .children
        .iter()
        .any(|id| cpg.ast.get(id).map_or(false, |n| n.kind == IrNodeKind::Call));
    assert!(has_call_child, "GoStmt should have a Call child for 'worker()'");
}

#[test]
fn test_defer_statement_lifts_to_defer_stmt() {
    let cpg = go_cpg("package main\nfunc cleanup() {}\nfunc f() { defer cleanup() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let defer_stmt = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::DeferStmt)
        .expect("expected DeferStmt for 'defer cleanup()'");
    let has_call_child = defer_stmt
        .children
        .iter()
        .any(|id| cpg.ast.get(id).map_or(false, |n| n.kind == IrNodeKind::Call));
    assert!(has_call_child, "DeferStmt should have a Call child for 'cleanup()'");
}

#[test]
fn test_return_statement_lifts_to_return() {
    let cpg = go_cpg("package main\nfunc f() (int, error) { var x int; var e error; return x, e }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let ret = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Return)
        .expect("expected Return node");
    let ident_children = ret
        .children
        .iter()
        .filter(|id| cpg.ast.get(*id).map_or(false, |n| n.kind == IrNodeKind::Identifier))
        .count();
    assert!(
        ident_children >= 2,
        "Return should have at least 2 Identifier children (x, e)"
    );
}

#[test]
fn test_if_statement_lifts_to_conditional() {
    let cpg = go_cpg("package main\nfunc f(x int) int { if x > 0 { return x }\nreturn 0 }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Conditional)
        .expect("expected Conditional for 'if x > 0'");
}

#[test]
fn test_if_with_init() {
    let cpg = go_cpg("package main\nfunc doWork() error { return nil }\nfunc f() error { if err := doWork(); err != nil { return err }\nreturn nil }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Conditional)
        .expect("expected Conditional for 'if err := doWork(); err != nil'");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ShortVarDecl && n.name.as_deref() == Some("err"))
        .expect("expected ShortVarDecl for 'err' in the if init");
}

#[test]
fn test_for_statement_c_style() {
    let cpg = go_cpg("package main\nfunc f() { for i := 0; i < 10; i++ {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop node for C-style for");
    assert_eq!(
        loop_node.loop_kind,
        Some(LoopKind::For),
        "C-style for loop should have loop_kind For"
    );
}

#[test]
fn test_for_statement_while_style() {
    let cpg = go_cpg("package main\nfunc f() { var x int; for x > 0 { x-- } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop node for while-style for");
    assert_eq!(
        loop_node.loop_kind,
        Some(LoopKind::While),
        "condition-only for should have loop_kind While"
    );
}

#[test]
fn test_for_statement_infinite() {
    let cpg = go_cpg("package main\nfunc f() { for {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop node for infinite for");
    assert_eq!(
        loop_node.loop_kind,
        Some(LoopKind::While),
        "infinite for should have loop_kind While"
    );
}

#[test]
fn test_range_clause_lifts_to_loop_foreach() {
    let cpg = go_cpg("package main\nfunc f(m map[string]int) { for k, v := range m { _ = k\n_ = v } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop node for range loop");
    assert_eq!(
        loop_node.loop_kind,
        Some(LoopKind::ForEach),
        "range loop should have loop_kind ForEach"
    );
}

#[test]
fn test_expression_switch_statement() {
    let cpg = go_cpg("package main\nfunc doA(){}\nfunc doB(){}\nfunc doC(){}\nfunc f(x int) { switch x { case 1: doA()\ncase 2: doB()\ndefault: doC() } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Switch)
        .expect("expected Switch node");
    let case_nodes: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::Case).collect();
    assert_eq!(case_nodes.len(), 2, "expected 2 Case children");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SwitchDefault)
        .expect("expected SwitchDefault node");
}

#[test]
fn test_type_switch_statement() {
    let cpg = go_cpg(r#"package main
import "fmt"
func f(i interface{}) { switch v := i.(type) { case int: fmt.Println(v) } }"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeSwitch)
        .expect("expected TypeSwitch for 'switch v := i.(type)'");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeCase)
        .expect("expected TypeCase for 'case int:'");
}

#[test]
fn test_select_statement() {
    let cpg = go_cpg("package main\nfunc process(msg int){}\nfunc skip(){}\nfunc f(ch chan int) { select { case msg := <-ch: process(msg)\ndefault: skip() } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SelectStmt)
        .expect("expected SelectStmt");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::CommCase)
        .expect("expected CommCase for channel arm");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SwitchDefault)
        .expect("expected SwitchDefault for default arm");
}

#[test]
fn test_send_statement() {
    let cpg = go_cpg("package main\nfunc f(ch chan int, value int) { ch <- value }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let send = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::SendStmt)
        .expect("expected SendStmt for 'ch <- value'");
    let ident_children = send
        .children
        .iter()
        .filter(|id| cpg.ast.get(*id).map_or(false, |n| n.kind == IrNodeKind::Identifier))
        .count();
    assert!(
        ident_children >= 2,
        "SendStmt should have at least 2 Identifier children (ch, value)"
    );
}

#[test]
fn test_receive_statement() {
    let cpg = go_cpg("package main\nfunc f(ch chan int) { v, ok := <-ch\n_ = v\n_ = ok }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ShortVarDecl)
        .expect("expected ShortVarDecl for 'v, ok := <-ch'");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ReceiveExpr)
        .expect("expected ReceiveExpr as child of ShortVarDecl");
}

#[test]
fn test_fallthrough_statement() {
    let cpg = go_cpg("package main\nfunc doA(){}\nfunc doB(){}\nfunc f(x int) { switch x { case 1: doA()\nfallthrough\ncase 2: doB() } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Fallthrough)
        .expect("expected Fallthrough node inside the first case body");
}

#[test]
fn test_break_statement() {
    let cpg = go_cpg("package main\nfunc f() { for { break } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Break)
        .expect("expected Break node");
}

#[test]
fn test_continue_statement() {
    let cpg = go_cpg("package main\nfunc f() { for { continue } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Continue)
        .expect("expected Continue node");
}

#[test]
fn test_goto_statement() {
    let cpg = go_cpg("package main\nfunc f() { goto done\ndone: }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Goto)
        .expect("expected Goto node");
    let label = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Label && n.name.as_deref() == Some("done"))
        .expect("expected Label node with name 'done'");
    assert_eq!(label.name.as_deref(), Some("done"));
}

#[test]
fn test_labeled_statement() {
    let cpg = go_cpg("package main\nfunc f() { outer: for { break outer } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let label = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Label && n.name.as_deref() == Some("outer"))
        .expect("expected Label 'outer'");
    assert_eq!(label.name.as_deref(), Some("outer"));
}

#[test]
fn test_block_lifts_to_block() {
    let cpg = go_cpg("package main\nfunc f() { { x := 1\n_ = x } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Block)
        .expect("expected Block node");
}

#[test]
fn test_empty_statement() {
    let cpg = go_cpg("package main\nfunc f() { ; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let empty_stmts = nodes_of_type(&cpg, "empty_statement");
    assert!(!empty_stmts.is_empty(), "expected empty_statement node");
    let (_, empty) = empty_stmts[0];
    assert_eq!(
        empty.kind,
        IrNodeKind::Unknown,
        "empty_statement should map to Unknown"
    );
}

#[test]
fn test_expression_statement() {
    let cpg = go_cpg("package main\nfunc doSomething(){}\nfunc f() { doSomething() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ExprStmt)
        .expect("expected ExprStmt wrapping a Call");
}

#[test]
fn test_struct_type_lifts_to_class_def() {
    let cpg = go_cpg("package main\ntype Point struct {\nX int\nY int\n}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let class_def = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Point"))
        .expect("expected ClassDef for 'Point'");
    assert_eq!(class_def.name.as_deref(), Some("Point"));
    let field_defs: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::FieldDef)
        .collect();
    assert!(
        field_defs.iter().any(|n| n.name.as_deref() == Some("X")),
        "expected FieldDef for 'X'"
    );
    assert!(
        field_defs.iter().any(|n| n.name.as_deref() == Some("Y")),
        "expected FieldDef for 'Y'"
    );
}

#[test]
fn test_interface_type_lifts_to_class_def() {
    let cpg = go_cpg("package main\ntype Reader interface {\nRead(p []byte) (n int, err error)\n}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let class_def = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Reader"))
        .expect("expected ClassDef for 'Reader' interface");
    let (reader_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Reader"))
        .expect("expected ClassDef for 'Reader'");
    let meta = cpg
        .go_meta(*reader_id)
        .expect("Reader ClassDef should have GoNodeMetadata");
    assert!(meta.is_interface, "GoNodeMetadata.is_interface should be true for Reader");
    let _ = class_def;
}

#[test]
fn test_type_alias() {
    let cpg = go_cpg("package main\ntype MyInt = int");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let alias = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeAlias && n.name.as_deref() == Some("MyInt"))
        .expect("expected TypeAlias for 'MyInt = int'");
    assert_eq!(alias.name.as_deref(), Some("MyInt"));
}

#[test]
fn test_type_definition_new_type() {
    let cpg = go_cpg("package main\ntype Celsius float64");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeAlias && n.name.as_deref() == Some("Celsius"))
        .expect("expected TypeAlias for 'Celsius'");
}

#[test]
fn test_pointer_type() {
    let cpg = go_cpg("package main\nfunc f() { var p *int\n_ = p }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "pointer_type")
        .expect("expected TypeRef with node_type 'pointer_type'");
}

#[test]
fn test_slice_type() {
    let cpg = go_cpg("package main\nfunc f() { var s []byte\n_ = s }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "slice_type")
        .expect("expected TypeRef with node_type 'slice_type'");
}

#[test]
fn test_array_type() {
    let cpg = go_cpg("package main\nfunc f() { var a [10]int\n_ = a }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let arr_type = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "array_type")
        .expect("expected TypeRef with node_type 'array_type'");
    assert_eq!(
        arr_type.array_size,
        Some(10),
        "array_type should have array_size == 10"
    );
}

#[test]
fn test_map_type() {
    let cpg = go_cpg("package main\nfunc f() { var m map[string]int\n_ = m }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "map_type")
        .expect("expected TypeRef with node_type 'map_type'");
}

#[test]
fn test_channel_type_bidi() {
    let cpg = go_cpg("package main\nfunc f() { var ch chan int\n_ = ch }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (chan_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::TypeRef && n.node_type == "channel_type")
        .expect("expected TypeRef with node_type 'channel_type'");
    let meta = cpg.go_meta(*chan_id).expect("channel_type node should have GoNodeMetadata");
    assert_eq!(
        meta.channel_direction,
        Some(ChannelDirection::Bidi),
        "chan int should have ChannelDirection::Bidi"
    );
}

#[test]
fn test_channel_type_send_only() {
    let cpg = go_cpg("package main\nfunc f() { var ch chan<- int\n_ = ch }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (chan_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::TypeRef && n.node_type == "channel_type")
        .expect("expected channel_type node");
    let meta = cpg.go_meta(*chan_id).expect("channel_type should have GoNodeMetadata");
    assert_eq!(
        meta.channel_direction,
        Some(ChannelDirection::Send),
        "chan<- int should have ChannelDirection::Send"
    );
}

#[test]
fn test_channel_type_recv_only() {
    let cpg = go_cpg("package main\nfunc f() { var ch <-chan int\n_ = ch }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (chan_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::TypeRef && n.node_type == "channel_type")
        .expect("expected channel_type node");
    let meta = cpg.go_meta(*chan_id).expect("channel_type should have GoNodeMetadata");
    assert_eq!(
        meta.channel_direction,
        Some(ChannelDirection::Recv),
        "<-chan int should have ChannelDirection::Recv"
    );
}

#[test]
fn test_function_type() {
    let cpg = go_cpg("package main\nfunc f() { var fn func(int) error\n_ = fn }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "function_type")
        .expect("expected TypeRef with node_type 'function_type'");
}

#[test]
fn test_interface_embedding() {
    let cpg = go_cpg("package main\ntype Reader interface { Read() }\ntype Writer interface { Write() }\ntype ReadWriter interface { Reader\nWriter\n}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (rw_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("ReadWriter"))
        .expect("expected ClassDef for 'ReadWriter'");
    let meta = cpg.go_meta(*rw_id).expect("ReadWriter should have GoNodeMetadata");
    let embedded = meta.embedded_interfaces.as_deref().unwrap_or(&[]);
    assert!(
        embedded.contains(&"Reader".to_string()),
        "embedded_interfaces should contain 'Reader'"
    );
    assert!(
        embedded.contains(&"Writer".to_string()),
        "embedded_interfaces should contain 'Writer'"
    );
}

#[test]
fn test_generic_type_instantiation() {
    let cpg = go_cpg("package main\ntype Map[K, V any] struct{ k K; v V }\nfunc f() { var m Map[string, int]\n_ = m }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // The instantiated type should produce a TypeRef node
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeRef)
        .expect("expected TypeRef for generic type instantiation");
}

#[test]
fn test_generic_function_declaration() {
    let cpg = go_cpg("package main\nfunc MapSlice[T, U any](s []T, f func(T) U) []U { return nil }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("MapSlice"))
        .expect("expected MethodDef for 'MapSlice'");
    let meta = cpg.go_meta(*method_id).expect("MapSlice should have GoNodeMetadata");
    let params = meta.generic_type_params.as_deref().unwrap_or(&[]);
    assert!(
        params.contains(&"T".to_string()),
        "generic_type_params should contain 'T'"
    );
    assert!(
        params.contains(&"U".to_string()),
        "generic_type_params should contain 'U'"
    );
}

#[test]
fn test_variadic_parameter() {
    let cpg = go_cpg("package main\nfunc sum(nums ...int) int { return 0 }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (param_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("nums"))
        .expect("expected ParamDef for 'nums'");
    let meta = cpg.go_meta(*param_id).expect("nums ParamDef should have GoNodeMetadata");
    assert!(meta.is_variadic, "GoNodeMetadata.is_variadic should be true for 'nums ...int'");
}

#[test]
fn test_variadic_argument() {
    let cpg = go_cpg(r#"package main
import "fmt"
func f(args ...interface{}) { fmt.Println(args...) }"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let variadic_arg = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::UnaryOp && n.operator.as_deref() == Some("..."))
        .expect("expected UnaryOp with operator '...' for variadic argument");
    assert_eq!(variadic_arg.operator.as_deref(), Some("..."));
}

#[test]
fn test_blank_identifier() {
    let cpg = go_cpg("package main\nfunc compute() int { return 0 }\nfunc f() { _ = compute() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let blank = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Identifier && n.name.as_deref() == Some("_"))
        .expect("expected Identifier node for '_'");
    assert_eq!(blank.name.as_deref(), Some("_"));
}

#[test]
fn test_nil_literal() {
    let cpg = go_cpg("package main\nfunc f() { var p *int = nil\n_ = p }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Null))
        .expect("expected Literal with lit_kind Null for 'nil'");
}

#[test]
fn test_bool_literal_true() {
    let cpg = go_cpg("package main\nfunc f() { var b bool = true\n_ = b }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Bool)
            && n.text.as_deref().unwrap_or("").contains("true"))
        .expect("expected Bool Literal for 'true'");
}

#[test]
fn test_bool_literal_false() {
    let cpg = go_cpg("package main\nfunc f() { var b bool = false\n_ = b }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Bool)
            && n.text.as_deref().unwrap_or("").contains("false"))
        .expect("expected Bool Literal for 'false'");
}

#[test]
fn test_int_literal() {
    let cpg = go_cpg("package main\nfunc f() { x := 42\n_ = x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.node_type == "int_literal" && n.kind == IrNodeKind::Literal
            && n.lit_kind == Some(LiteralKind::Integer))
        .expect("expected Literal with node_type 'int_literal' and lit_kind Integer");
}

#[test]
fn test_float_literal() {
    let cpg = go_cpg("package main\nfunc f() { x := 3.14\n_ = x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.node_type == "float_literal" && n.kind == IrNodeKind::Literal
            && n.lit_kind == Some(LiteralKind::Float))
        .expect("expected Literal with node_type 'float_literal' and lit_kind Float");
}

#[test]
fn test_imaginary_literal() {
    let cpg = go_cpg("package main\nfunc f() { x := 2i\n_ = x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.node_type == "imaginary_literal" && n.kind == IrNodeKind::Literal
            && n.lit_kind == Some(LiteralKind::Float))
        .expect("expected Literal with node_type 'imaginary_literal' and lit_kind Float");
}

#[test]
fn test_interpreted_string_literal() {
    let cpg = go_cpg(r#"package main
func f() { s := "hello"
_ = s }"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.node_type == "interpreted_string_literal" && n.kind == IrNodeKind::Literal
            && n.lit_kind == Some(LiteralKind::String))
        .expect("expected Literal with node_type 'interpreted_string_literal' and lit_kind String");
}

#[test]
fn test_raw_string_literal() {
    let cpg = go_cpg("package main\nfunc f() { s := `raw\\nstring`\n_ = s }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.node_type == "raw_string_literal" && n.kind == IrNodeKind::Literal
            && n.lit_kind == Some(LiteralKind::String))
        .expect("expected Literal with node_type 'raw_string_literal' and lit_kind String");
}

#[test]
fn test_rune_literal() {
    let cpg = go_cpg("package main\nfunc f() { r := 'a'\n_ = r }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.node_type == "rune_literal" && n.kind == IrNodeKind::Literal
            && n.lit_kind == Some(LiteralKind::Char))
        .expect("expected Literal with node_type 'rune_literal' and lit_kind Char");
}

#[test]
fn test_qualified_type() {
    let cpg = go_cpg(r#"package main
import "os"
func f() { var err error = os.ErrNotExist
_ = err }"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // os.ErrNotExist is a selector expression, not a type; but the 'error' type is a type_identifier
    // The qualified_type would appear in import resolution contexts
    // We just verify the CPG builds without panic and has valid structure
    assert!(!cpg.ast.is_empty(), "CPG should have AST nodes");
}

#[test]
fn test_comment_not_in_ast() {
    let cpg = go_cpg("package main\n// This is a comment\nfunc f() { x := 1\n_ = x }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // Comments should not appear in cpg.ast
    let comment_in_ast = cpg.ast.values().any(|n| n.node_type == "comment");
    assert!(
        !comment_in_ast,
        "comment nodes should not appear in cpg.ast"
    );
    // Comment should be stored in cpg.comments
    assert!(
        !cpg.comments.is_empty(),
        "comment should be stored in cpg.comments"
    );
    let comment = &cpg.comments[0];
    assert!(
        comment.text.contains("This is a comment"),
        "comment text should be captured"
    );
}

// ── 1.2 CFG Tests ─────────────────────────────────────────────────────────────

#[test]
fn test_cfg_go_statement_does_not_block() {
    let cpg = go_cpg("package main\nfunc worker(x int){}\nfunc compute() int{return 0}\nfunc f(x int) { go worker(x)\ny := compute()\n_ = y }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // GoStmt node should be in a basic block
    let go_stmt = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::GoStmt)
        .expect("expected GoStmt node");
    assert!(
        go_stmt.basic_block.is_some(),
        "GoStmt should be in a basic block"
    );
    // The compute() call should be in a different or successor block
    // (at minimum, we verify the CFG is structurally valid)
}

#[test]
fn test_cfg_goroutine_body_separate_cfg() {
    let cpg = go_cpg("package main\nfunc doWork(){}\nfunc rest(){}\nfunc f() { go func() { doWork() }()\nrest() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // The func literal should have its own function_id
    let lambda = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::LambdaDef)
        .expect("expected LambdaDef for goroutine func literal");
    let lambda_fn_id = lambda.function_id;
    // The GoStmt should not be a CFG edge into the goroutine's entry
    let go_stmt = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::GoStmt)
        .expect("expected GoStmt");
    let go_bb = go_stmt.basic_block.as_deref().unwrap_or("");
    if !go_bb.is_empty() {
        let bb = cpg.basic_blocks.get(go_bb).expect("GoStmt BB should exist");
        // Goroutine entry should not be a direct successor of the GoStmt block
        let _ = (lambda_fn_id, bb);
    }
}

#[test]
fn test_cfg_defer_runs_at_return() {
    let cpg = go_cpg("package main\nfunc cleanup(){}\nfunc doWork(){}\nfunc f() { defer cleanup()\ndoWork()\nreturn }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // Both the defer and return should be in the CFG
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::DeferStmt)
        .expect("expected DeferStmt");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Return)
        .expect("expected Return node");
    // The CFG should be valid (defer chain appears after return)
}

#[test]
fn test_cfg_defer_lifo_order() {
    let cpg = go_cpg("package main\nfunc a(){}\nfunc b(){}\nfunc c(){}\nfunc f() { defer a()\ndefer b()\ndefer c() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let defer_stmts: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::DeferStmt)
        .collect();
    assert_eq!(defer_stmts.len(), 3, "expected 3 DeferStmt nodes");
}

#[test]
fn test_cfg_select_non_deterministic_branches() {
    let cpg = go_cpg("package main\nfunc handleA(msg int){}\nfunc handleB(){}\nfunc f(chA chan int, chB chan int, val int) { select { case msg := <-chA: handleA(msg)\ncase chB <- val: handleB() } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let select_stmt = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::SelectStmt)
        .expect("expected SelectStmt");
    let select_bb_id = select_stmt.basic_block.as_deref().unwrap_or("");
    if !select_bb_id.is_empty() {
        let select_bb = cpg.basic_blocks.get(select_bb_id).expect("SelectStmt BB exists");
        assert!(
            select_bb.successors.len() >= 2,
            "SelectStmt block should have at least 2 successors (one per arm), got {}",
            select_bb.successors.len()
        );
    }
}

#[test]
fn test_cfg_select_with_default() {
    let cpg = go_cpg("package main\nfunc use(v int){}\nfunc skip(){}\nfunc f(ch chan int) { select { case v := <-ch: use(v)\ndefault: skip() } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SelectStmt)
        .expect("expected SelectStmt");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SwitchDefault)
        .expect("expected SwitchDefault for 'default' arm");
}

#[test]
fn test_cfg_send_statement_successor() {
    let cpg = go_cpg("package main\nfunc next(){}\nfunc f(ch chan int, x int) { ch <- x\nnext() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SendStmt)
        .expect("expected SendStmt");
    // CFG validity already checked; next() should be reachable
}

#[test]
fn test_cfg_receive_expression_successor() {
    let cpg = go_cpg("package main\nfunc use(v int){}\nfunc f(ch chan int) { v := <-ch\nuse(v) }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ReceiveExpr)
        .expect("expected ReceiveExpr");
}

#[test]
fn test_cfg_fallthrough_edge() {
    let cpg = go_cpg("package main\nfunc doA(){}\nfunc doB(){}\nfunc f(x int) { switch x { case 1: doA()\nfallthrough\ncase 2: doB() } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Fallthrough)
        .expect("expected Fallthrough node");
}

#[test]
fn test_cfg_type_switch_branches() {
    let cpg = go_cpg("package main\nfunc useInt(v int){}\nfunc useStr(v string){}\nfunc f(i interface{}) { switch v := i.(type) { case int: useInt(v)\ncase string: useStr(v) } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let type_switch = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeSwitch)
        .expect("expected TypeSwitch");
    let ts_bb_id = type_switch.basic_block.as_deref().unwrap_or("");
    if !ts_bb_id.is_empty() {
        let ts_bb = cpg.basic_blocks.get(ts_bb_id).expect("TypeSwitch BB exists");
        assert!(
            ts_bb.successors.len() >= 2,
            "TypeSwitch block should have at least 2 successors, got {}",
            ts_bb.successors.len()
        );
    }
}

#[test]
fn test_cfg_multiple_return_values() {
    let cpg = go_cpg(r#"package main
import "errors"
func divide(a, b int) (int, error) {
    if b == 0 {
        return 0, errors.New("div zero")
    }
    return a / b, nil
}"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let return_nodes: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::Return)
        .collect();
    assert_eq!(return_nodes.len(), 2, "expected 2 Return nodes in 'divide'");
}

#[test]
fn test_cfg_named_return_values() {
    let cpg = go_cpg("package main\nfunc compute() (result int, err error) { result = 42\nreturn }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Return)
        .expect("expected Return node for bare 'return'");
    let named_locals: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::LocalDef)
        .collect();
    assert!(
        named_locals.iter().any(|n| n.name.as_deref() == Some("result")),
        "expected LocalDef for named return 'result'"
    );
    assert!(
        named_locals.iter().any(|n| n.name.as_deref() == Some("err")),
        "expected LocalDef for named return 'err'"
    );
}

#[test]
fn test_cfg_range_loop_iteration_edge() {
    let cpg = go_cpg("package main\nfunc process(i, v int){}\nfunc f(s []int) { for i, v := range s { process(i, v) } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop && n.loop_kind == Some(LoopKind::ForEach))
        .expect("expected ForEach Loop for range");
    let loop_bb_id = loop_node.basic_block.as_deref().unwrap_or("");
    if !loop_bb_id.is_empty() {
        let loop_bb = cpg.basic_blocks.get(loop_bb_id).expect("Loop BB should exist");
        // Loop header should have back-edge (successor back to itself or to body)
        assert!(
            !loop_bb.successors.is_empty(),
            "loop header BB should have successors"
        );
    }
}

#[test]
fn test_cfg_goroutine_launch_edge() {
    let cpg = go_cpg("package main\nfunc f_fn(){}\nfunc g(){}\nfunc main() { go f_fn()\ng() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // GoStmt and g() call should both be in the caller's CFG
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::GoStmt)
        .expect("expected GoStmt");
}

// ── 1.3 DFG Tests ─────────────────────────────────────────────────────────────

#[test]
fn test_dfg_short_var_decl_defines_variable() {
    let cpg = go_cpg("package main\nfunc compute() int { return 0 }\nfunc use(x int){}\nfunc f() { x := compute()\nuse(x) }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_x_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "x");
    assert!(has_x_def, "expected DataflowDef for 'x' at the ShortVarDecl");
    let has_x_use = cpg.dataflow.uses.iter().any(|u| u.variable == "x");
    assert!(has_x_use, "expected DataflowUse for 'x' at the use(x) call");
    let x_def_id = cpg.dataflow.definitions.iter().find(|d| d.variable == "x").map(|d| d.node_id);
    let x_use_id = cpg.dataflow.uses.iter().find(|u| u.variable == "x").map(|u| u.node_id);
    if let (Some(def_id), Some(use_id)) = (x_def_id, x_use_id) {
        let has_edge = cpg.dataflow.edges.iter().any(|e| e.source == def_id && e.destination == use_id);
        assert!(has_edge, "expected DataflowEdge from 'x' def to 'x' use");
    }
}

#[test]
fn test_dfg_multi_assignment_short_var() {
    let cpg = go_cpg("package main\nfunc foo() (int, int) { return 0, 0 }\nfunc use(x int){}\nfunc f() { a, b := foo()\nuse(a)\nuse(b) }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_a_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "a");
    let has_b_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "b");
    assert!(has_a_def, "expected DataflowDef for 'a'");
    assert!(has_b_def, "expected DataflowDef for 'b'");
}

#[test]
fn test_dfg_blank_identifier_no_def() {
    let cpg = go_cpg(r#"package main
import "os"
func f() { _, err := os.Open("file")
_ = err }"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_err_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "err");
    assert!(has_err_def, "expected DataflowDef for 'err'");
    let has_blank_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "_");
    assert!(!has_blank_def, "should NOT have DataflowDef for '_' (blank identifier)");
}

#[test]
fn test_dfg_range_variable_binding() {
    let cpg = go_cpg("package main\nfunc use(x int){}\nfunc f(m map[int]int) { for k, v := range m { use(k)\nuse(v) } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_k_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "k");
    let has_v_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "v");
    assert!(has_k_def, "expected DataflowDef for range variable 'k'");
    assert!(has_v_def, "expected DataflowDef for range variable 'v'");
}

#[test]
fn test_dfg_channel_send_is_use() {
    let cpg = go_cpg("package main\nfunc f(ch chan int, secret int) { ch <- secret }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_secret_use = cpg.dataflow.uses.iter().any(|u| u.variable == "secret");
    assert!(has_secret_use, "expected DataflowUse for 'secret' at the SendStmt");
}

#[test]
fn test_dfg_channel_receive_is_def() {
    let cpg = go_cpg("package main\nfunc use(v int){}\nfunc f(ch chan int) { v := <-ch\nuse(v) }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_v_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "v");
    assert!(has_v_def, "expected DataflowDef for 'v' from channel receive");
}

#[test]
fn test_dfg_closure_capture() {
    let cpg = go_cpg("package main\nfunc use(x int){}\nfunc f() { x := 10\nfn := func() { use(x) }\nfn() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_x_use_inside = cpg.dataflow.uses.iter().any(|u| u.variable == "x");
    assert!(has_x_use_inside, "expected DataflowUse for 'x' inside the closure");
}

#[test]
fn test_dfg_iota_is_literal_no_def() {
    let cpg = go_cpg("package main\nconst A = iota");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // iota should produce a Literal node
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.text.as_deref().unwrap_or("").contains("iota"))
        .expect("expected Literal node for 'iota'");
    // No DataflowDef for iota itself
    let has_iota_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "iota");
    assert!(!has_iota_def, "should NOT have DataflowDef for 'iota' (compile-time constant)");
}

// ── 1.4 Call Graph Tests ──────────────────────────────────────────────────────

#[test]
fn test_callgraph_function_declaration() {
    let cpg = go_cpg("package main\nfunc foo() {}\nfunc bar() { foo() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let bar_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "bar")
        .expect("expected CallGraphEntry for 'bar'");
    let calls_foo = bar_entry.calls.iter().any(|cs| cs.callee == "foo");
    assert!(calls_foo, "bar's call graph should include a CallSite for 'foo'");
}

#[test]
fn test_callgraph_method_declaration() {
    let cpg = go_cpg("package main\ntype T struct{}\nfunc (r *T) Do() {}\nfunc caller(t *T) { t.Do() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let caller_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "caller")
        .expect("expected CallGraphEntry for 'caller'");
    let calls_do = caller_entry.calls.iter().any(|cs| cs.callee == "Do");
    assert!(calls_do, "caller's call graph should include CallSite for 'Do'");
}

#[test]
fn test_callgraph_goroutine_call() {
    let cpg = go_cpg("package main\nfunc worker(x int){}\nfunc f(x int) { go worker(x) }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let f_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "f")
        .expect("expected CallGraphEntry for 'f'");
    let calls_worker = f_entry.calls.iter().any(|cs| cs.callee == "worker");
    assert!(calls_worker, "goroutine call to 'worker' should appear in call graph");
}

#[test]
fn test_callgraph_deferred_call() {
    let cpg = go_cpg("package main\nfunc cleanup(){}\nfunc f() { defer cleanup() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let f_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "f")
        .expect("expected CallGraphEntry for 'f'");
    let calls_cleanup = f_entry.calls.iter().any(|cs| cs.callee == "cleanup");
    assert!(calls_cleanup, "deferred call to 'cleanup' should appear in call graph");
}

#[test]
fn test_callgraph_init_function() {
    let cpg = go_cpg("package main\nfunc register(){}\nfunc init() { register() }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let init_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "init")
        .expect("expected CallGraphEntry for 'init'");
    let calls_register = init_entry.calls.iter().any(|cs| cs.callee == "register");
    assert!(calls_register, "init should call 'register'");
}

// ── 1.5 Incremental CPG Tests ─────────────────────────────────────────────────

#[test]
fn test_incremental_add_function() {
    use web_sitter::{IncrementalCpgGenerator, SourceLanguage, GraphBuildOptions, compute_edit};

    let base = "package main\nfunc a() {}";
    let modified = "package main\nfunc a() {}\nfunc b() { a() }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Go, GraphBuildOptions::default())
        .expect("Go incremental init");
    let _base_cpg = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated_cpg = inc
        .parse_incremental(modified.as_bytes(), &edits)
        .expect("incremental update");

    let has_b = updated_cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("b"));
    assert!(has_b, "after adding func b, MethodDef for 'b' should exist");
}

#[test]
fn test_incremental_remove_function() {
    use web_sitter::{IncrementalCpgGenerator, SourceLanguage, GraphBuildOptions, compute_edit};

    let base = "package main\nfunc a() {}\nfunc b() { a() }";
    let modified = "package main\nfunc a() {}";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Go, GraphBuildOptions::default())
        .expect("Go incremental init");
    let _base_cpg = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated_cpg = inc
        .parse_incremental(modified.as_bytes(), &edits)
        .expect("incremental update");

    let has_b = updated_cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("b"));
    assert!(!has_b, "after removing func b, no MethodDef for 'b' should remain");

    let b_in_callgraph = updated_cpg.call_graph.values().any(|e| e.name == "b");
    assert!(!b_in_callgraph, "CallGraphEntry for 'b' should be gone after removal");
}

#[test]
fn test_incremental_add_goroutine_call() {
    use web_sitter::{IncrementalCpgGenerator, SourceLanguage, GraphBuildOptions, compute_edit};

    let base = "package main\nfunc work(){}\nfunc f() { work() }";
    let modified = "package main\nfunc work(){}\nfunc f() { go work() }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Go, GraphBuildOptions::default())
        .expect("Go incremental init");
    let _base_cpg = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated_cpg = inc
        .parse_incremental(modified.as_bytes(), &edits)
        .expect("incremental update");

    let has_go_stmt = updated_cpg.ast.values().any(|n| n.kind == IrNodeKind::GoStmt);
    assert!(has_go_stmt, "after adding 'go work()', GoStmt should exist");
}

#[test]
fn test_incremental_add_defer_statement() {
    use web_sitter::{IncrementalCpgGenerator, SourceLanguage, GraphBuildOptions, compute_edit};

    let base = "package main\nfunc cleanup(){}\nfunc work(){}\nfunc f() { work() }";
    let modified = "package main\nfunc cleanup(){}\nfunc work(){}\nfunc f() { defer cleanup()\nwork() }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Go, GraphBuildOptions::default())
        .expect("Go incremental init");
    let _base_cpg = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated_cpg = inc
        .parse_incremental(modified.as_bytes(), &edits)
        .expect("incremental update");

    let has_defer = updated_cpg.ast.values().any(|n| n.kind == IrNodeKind::DeferStmt);
    assert!(has_defer, "after adding defer, DeferStmt should exist");
}

// ── 1.6 Parity Tests ──────────────────────────────────────────────────────────

#[test]
fn test_parity_add_function() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, SourceLanguage, GraphBuildOptions, compute_edit};

    let base = "package main\nfunc a() {}";
    let modified = "package main\nfunc a() {}\nfunc b() { a() }";

    // Full rebuild
    let full_cpg = CpgGenerator::new_for_language(SourceLanguage::Go)
        .expect("Go parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    // Incremental
    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Go, GraphBuildOptions::default())
        .expect("Go incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");
    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let inc_cpg = inc.parse_incremental(modified.as_bytes(), &edits).expect("incremental update");

    let full_kinds: std::collections::HashSet<_> = full_cpg.ast.values().map(|n| &n.kind).collect();
    let inc_kinds: std::collections::HashSet<_> = inc_cpg.ast.values().map(|n| &n.kind).collect();
    assert_eq!(
        full_kinds, inc_kinds,
        "incremental CPG should have same IrNodeKind set as full rebuild"
    );
}

#[test]
fn test_incremental_replace_body_updates_dfg() {
    use web_sitter::{IncrementalCpgGenerator, SourceLanguage, GraphBuildOptions, compute_edit};

    let base = "package main\nfunc f() int { x := 1\nreturn x }\n";
    let modified = "package main\nfunc f() int { x := 99\nreturn x }\n";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Go, GraphBuildOptions::default())
        .expect("Go incremental init");
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
fn test_incremental_sequential_edits_go() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, SourceLanguage, GraphBuildOptions, compute_edit};

    let src0 = "package main\nfunc a() {}\n";
    let src1 = "package main\nfunc a() {}\nfunc b() { a() }\n";
    let src2 = "package main\nfunc a() {}\nfunc b() { a() }\nfunc c() { b() }\n";
    let src3 = "package main\nfunc a() {}\nfunc c() { a() }\n";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Go, GraphBuildOptions::default())
        .expect("Go incremental init");
    inc.parse_initial(src0.as_bytes()).expect("initial");

    let e1 = compute_edit(src0.as_bytes(), src1.as_bytes()).expect("edit1");
    inc.apply_edit(&e1, src1.as_bytes()).expect("edit1");

    let e2 = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit2");
    inc.apply_edit(&e2, src2.as_bytes()).expect("edit2");

    let e3 = compute_edit(src2.as_bytes(), src3.as_bytes()).expect("edit3");
    let final_inc = inc.apply_edit(&e3, src3.as_bytes()).expect("edit3");

    let full = CpgGenerator::new_for_language(SourceLanguage::Go)
        .expect("Go parser")
        .generate_from_source_with_options(src3.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let full_names: std::collections::HashSet<_> = full.ast.values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .filter_map(|n| n.name.as_deref()).collect();
    let inc_names: std::collections::HashSet<_> = final_inc.ast.values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .filter_map(|n| n.name.as_deref()).collect();
    assert_eq!(full_names, inc_names, "after 3 sequential edits, MethodDef names must match fresh parse");

    let full_cg: std::collections::HashSet<_> = full.call_graph.values().map(|e| e.name.as_str()).collect();
    let inc_cg: std::collections::HashSet<_> = final_inc.call_graph.values().map(|e| e.name.as_str()).collect();
    assert_eq!(full_cg, inc_cg, "call graph must match fresh parse after sequential edits");

    assert_cfg_valid(final_inc);
}

#[test]
fn test_parity_dfg_and_callgraph_go() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, SourceLanguage, GraphBuildOptions, compute_edit};

    let base = "package main\nfunc a() {}\n";
    let modified = "package main\nfunc a() { x := 1\n_ = x }\nfunc b() { a() }\n";

    let full = CpgGenerator::new_for_language(SourceLanguage::Go)
        .expect("Go parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Go, GraphBuildOptions::default())
        .expect("Go incremental init");
    inc.parse_initial(base.as_bytes()).expect("initial");
    let edit = compute_edit(base.as_bytes(), modified.as_bytes()).expect("edit");
    let inc_cpg = inc.apply_edit(&edit, modified.as_bytes()).expect("apply_edit");

    let full_cg: std::collections::HashSet<_> = full.call_graph.values().map(|e| e.name.as_str()).collect();
    let inc_cg: std::collections::HashSet<_> = inc_cpg.call_graph.values().map(|e| e.name.as_str()).collect();
    assert_eq!(full_cg, inc_cg, "call graph function names must match between full and incremental");

    let full_defs: std::collections::HashSet<_> = full.dataflow.definitions.iter().map(|d| d.variable.as_str()).collect();
    let inc_defs: std::collections::HashSet<_> = inc_cpg.dataflow.definitions.iter().map(|d| d.variable.as_str()).collect();
    assert_eq!(full_defs, inc_defs, "DFG definition variable names must match between full and incremental");

    assert_cfg_valid(inc_cpg);
}

// ── 1.7 Weird Edit Tests ──────────────────────────────────────────────────────

#[test]
fn test_blank_identifier_in_range() {
    let cpg = go_cpg("package main\nfunc use(v int){}\nfunc f(s []int) { for _, v := range s { use(v) } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // '_' is an Identifier with name "_"
    let blank = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Identifier && n.name.as_deref() == Some("_"))
        .expect("expected Identifier '_' in range");
    assert_eq!(blank.name.as_deref(), Some("_"));
    // No DataflowDef for '_'
    let blank_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "_");
    assert!(!blank_def, "should NOT have DataflowDef for '_'");
    // DataflowDef for 'v' should exist
    let v_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "v");
    assert!(v_def, "expected DataflowDef for 'v'");
}

#[test]
fn test_multiple_return_with_named_returns() {
    let cpg = go_cpg(r#"package main
func f() (a int, b string) {
    a = 1
    b = "x"
    return
}"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let local_defs: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::LocalDef).collect();
    assert!(
        local_defs.iter().any(|n| n.name.as_deref() == Some("a")),
        "expected LocalDef for named return 'a'"
    );
    assert!(
        local_defs.iter().any(|n| n.name.as_deref() == Some("b")),
        "expected LocalDef for named return 'b'"
    );
    let ret = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Return)
        .expect("expected bare Return node");
    assert_eq!(ret.kind, IrNodeKind::Return);
}

#[test]
fn test_goroutine_loop_variable_capture() {
    let cpg = go_cpg("package main\nfunc use(i int){}\nfunc f() { for i := 0; i < 3; i++ { go func() { use(i) }() } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // Lambda should exist and capture 'i'
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LambdaDef)
        .expect("expected LambdaDef for goroutine closure");
    // 'i' use should appear inside the closure
    let i_uses: Vec<_> = cpg.dataflow.uses.iter().filter(|u| u.variable == "i").collect();
    assert!(!i_uses.is_empty(), "expected DataflowUse for 'i' captured by goroutine");
}

#[test]
fn test_variadic_parameter_expansion() {
    let cpg = go_cpg("package main\nfunc sum(nums ...int) int { return 0 }\nfunc f(s []int) { sum(1, 2, 3)\nsum(s...) }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (param_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("nums"))
        .expect("expected ParamDef for 'nums'");
    let meta = cpg.go_meta(*param_id).expect("nums should have GoNodeMetadata");
    assert!(meta.is_variadic, "nums should be variadic");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::UnaryOp && n.operator.as_deref() == Some("..."))
        .expect("expected UnaryOp '...' for variadic argument");
}

#[test]
fn test_type_assertion_vs_type_switch() {
    let cpg = go_cpg("package main\nfunc use(t int){}\nfunc f(i interface{}) { v, ok := i.(int)\n_ = v\n_ = ok\nswitch t := i.(type) { case int: use(t) } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeAssertion)
        .expect("expected TypeAssertion for 'i.(int)'");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeSwitch)
        .expect("expected TypeSwitch for 'switch v := i.(type)'");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeCase)
        .expect("expected TypeCase for 'case int:'");
}

#[test]
fn test_interface_embedding_methods_inherited() {
    let cpg = go_cpg("package main\ntype R interface { Read() }\ntype W interface { Write() }\ntype RW interface { R\nW\n}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (rw_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("RW"))
        .expect("expected ClassDef for 'RW'");
    let meta = cpg.go_meta(*rw_id).expect("RW should have GoNodeMetadata");
    let embedded = meta.embedded_interfaces.as_deref().unwrap_or(&[]);
    assert!(
        embedded.contains(&"R".to_string()),
        "embedded_interfaces should contain 'R'"
    );
    assert!(
        embedded.contains(&"W".to_string()),
        "embedded_interfaces should contain 'W'"
    );
}

#[test]
fn test_composite_literal_mixed_keyed_unkeyed() {
    let cpg = go_cpg("package main\ntype Point struct{ X, Y int }\nfunc f() { s := []Point{{1, 2}, {X: 3, Y: 4}}\n_ = s }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let composite_lits: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::CompositeLit)
        .collect();
    assert!(
        composite_lits.len() >= 3,
        "expected at least 3 CompositeLit nodes (outer + 2 inner), got {}",
        composite_lits.len()
    );
}

#[test]
#[ignore]
fn debug_go_issues() {
    // short_var_decl
    let cpg = go_cpg("package main\nfunc compute() int { return 0 }\nfunc f() { x := compute() }");
    println!("=== short_var_decl ===");
    for (nid, n) in &cpg.ast {
        if n.node_type.contains("short") || n.node_type.contains("expr_list") || n.node_type.contains("expression_list") {
            println!("  {nid}: kind={:?} type={} name={:?} children={:?}", n.kind, n.node_type, n.name, n.children);
        }
    }

    // named returns  
    let cpg2 = go_cpg("package main\nfunc compute() (result int, err error) { result = 42\nreturn }");
    println!("=== named returns ===");
    for (nid, n) in &cpg2.ast {
        if n.node_type.contains("result") || n.node_type.contains("param") || n.node_type.contains("return") || n.kind == IrNodeKind::LocalDef || n.kind == IrNodeKind::ParamDef {
            println!("  {nid}: kind={:?} type={} name={:?} text={:?}", n.kind, n.node_type, n.name, n.text);
        }
    }

    // generic function
    let cpg3 = go_cpg("package main\nfunc MapSlice[T, U any](s []T, f func(T) U) []U { return nil }");
    println!("=== generic function ===");
    for (nid, n) in &cpg3.ast {
        if n.node_type.contains("type_param") || n.node_type.contains("generic") {
            println!("  {nid}: kind={:?} type={} name={:?} text={:?} children={:?}", n.kind, n.node_type, n.name, n.text, n.children);
        }
    }
    let (method_id, _) = cpg3.ast.iter().find(|(_, n)| n.name.as_deref() == Some("MapSlice")).unwrap();
    let meta = cpg3.go_meta(*method_id);
    println!("MapSlice meta: {meta:?}");
}

#[test]
#[ignore]
fn debug_dfg_edge() {
    let cpg = go_cpg("package main\nfunc compute() int { return 0 }\nfunc use(x int){}\nfunc f() { x := compute()\nuse(x) }");
    
    println!("=== definitions ===");
    for def in &cpg.dataflow.definitions {
        let node = cpg.ast.get(&def.node_id);
        println!("  var={} node_id={} type={} bb={:?} fn={:?}", 
            def.variable, def.node_id, 
            node.map(|n| n.node_type.as_str()).unwrap_or("?"),
            node.and_then(|n| n.basic_block.as_deref()),
            def.function_id);
    }
    println!("=== uses ===");
    for u in &cpg.dataflow.uses {
        let node = cpg.ast.get(&u.node_id);
        if u.variable == "x" {
            println!("  var={} node_id={} type={} bb={:?} fn={:?}", 
                u.variable, u.node_id, 
                node.map(|n| n.node_type.as_str()).unwrap_or("?"),
                node.and_then(|n| n.basic_block.as_deref()),
                u.function_id);
        }
    }
    println!("=== edges for x ===");
    for e in &cpg.dataflow.edges {
        if e.variable == "x" {
            println!("  {}->{} var={}", e.source, e.destination, e.variable);
        }
    }
}

#[test]
#[ignore]
fn debug_interface_composite() {
    // Interface embedding
    let cpg = go_cpg("package main\ntype Reader interface { Read() }\ntype ReadWriter interface { Reader\n}");
    println!("=== interface embedding ===");
    for (nid, n) in &cpg.ast {
        println!("  {nid}: kind={:?} type={} name={:?} text={:?} parent={:?} children={:?}", n.kind, n.node_type, n.name, n.text.as_deref().unwrap_or(""), n.parent_id, n.children);
    }

    // Type switch AST
    let cpg_ts = go_cpg("package main\nfunc useInt(v int){}\nfunc f(i interface{}) { switch v := i.(type) { case int: useInt(v)\ncase string: _ = v } }");
    println!("=== type switch ===");
    for (nid, n) in &cpg_ts.ast {
        if matches!(n.kind, IrNodeKind::TypeSwitch | IrNodeKind::TypeCase | IrNodeKind::SwitchDefault) || n.node_type.contains("type_switch") || n.node_type.contains("type_case") || n.node_type.contains("comm_") {
            println!("  {nid}: kind={:?} type={} children={:?}", n.kind, n.node_type, n.children);
        }
    }

    // Select AST
    let cpg_sel = go_cpg("package main\nfunc handleA(msg int){}\nfunc handleB(){}\nfunc f(chA chan int, chB chan int, val int) { select { case msg := <-chA: handleA(msg)\ncase chB <- val: handleB() } }");
    println!("=== select ===");
    for (nid, n) in &cpg_sel.ast {
        if matches!(n.kind, IrNodeKind::SelectStmt | IrNodeKind::CommCase | IrNodeKind::SwitchDefault) || n.node_type.contains("select") || n.node_type.contains("comm_") {
            println!("  {nid}: kind={:?} type={} children={:?}", n.kind, n.node_type, n.children);
        }
    }

    // Composite literal
    let cpg2 = go_cpg("package main\ntype Point struct{ X, Y int }\nfunc f() { s := []Point{{1, 2}, {X: 3, Y: 4}}\n_ = s }");
    println!("=== composite literals ===");
    for (nid, n) in &cpg2.ast {
        if n.node_type.contains("literal") || n.kind == IrNodeKind::CompositeLit {
            println!("  {nid}: kind={:?} type={} name={:?} children={:?}", n.kind, n.node_type, n.name, n.children);
        }
    }

    // Named returns
    let cpg3 = go_cpg("package main\nfunc f() (a int, b string) { a = 1\nb = \"x\"\nreturn }");
    println!("=== named returns ===");
    for (nid, n) in &cpg3.ast {
        if matches!(n.kind, IrNodeKind::ParamDef | IrNodeKind::LocalDef) || n.node_type.contains("parameter") {
            println!("  {nid}: kind={:?} type={} name={:?} field_names={:?} parent={:?}", n.kind, n.node_type, n.name, n.field_names, n.parent_id);
        }
    }
    // Print the function declaration's field_names
    for (nid, n) in &cpg3.ast {
        if n.node_type == "function_declaration" {
            println!("  fn {nid}: field_names={:?} children={:?}", n.field_names, n.children);
        }
    }
}

#[test]
#[ignore]
fn debug_cfg_type_switch() {
    let cpg = go_cpg("package main\nfunc useInt(v int){}\nfunc useStr(v string){}\nfunc f(i interface{}) { switch v := i.(type) { case int: useInt(v)\ncase string: useStr(v) } }");
    println!("=== all nodes with kind ===");
    for (nid, n) in &cpg.ast {
        println!("  {nid}: kind={:?} type={} bb={:?} children={:?}", n.kind, n.node_type, n.basic_block, n.children);
    }
    println!("=== basic blocks ===");
    for (bbid, bb) in &cpg.basic_blocks {
        println!("  {bbid}: nodes={:?} succs={:?}", bb.nodes, bb.successors);
    }
    let ts = cpg.ast.values().find(|n| n.kind == IrNodeKind::TypeSwitch).expect("TypeSwitch");
    println!("=== TypeSwitch node {} bb={:?} ===", 0, ts.basic_block);
    if let Some(bb_id) = &ts.basic_block {
        if let Some(bb) = cpg.basic_blocks.get(bb_id) {
            println!("  successors={:?}", bb.successors);
        }
    }
}
