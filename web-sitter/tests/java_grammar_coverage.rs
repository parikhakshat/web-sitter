//! Grammar construct coverage tests for Java (Phase 1).
//!
//! Tests are in the TDD red state — assertions about `IrNodeKind` will fail
//! until the real JavaLifter is implemented.

use std::collections::HashSet;

use web_sitter::{IrNodeKind, LiteralKind, LoopKind, NodeId, TryKind};
use web_sitter::{CpgGenerator, GraphBuildOptions, SourceLanguage};

fn java_cpg(src: &str) -> web_sitter::Cpg {
    CpgGenerator::new_for_language(SourceLanguage::Java)
        .expect("Java parser init")
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("Java CPG generation failed")
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
fn test_compilation_unit_lifts_to_file() {
    let cpg = java_cpg("public class Hello { }");
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
fn test_class_declaration_lifts_to_class_def() {
    let cpg = java_cpg("public class Animal { }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let class_def = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Animal"))
        .expect("expected ClassDef for 'Animal'");
    assert_eq!(class_def.name.as_deref(), Some("Animal"));
    let (class_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Animal"))
        .unwrap();
    let meta = cpg.java_meta(*class_id).expect("Animal should have JavaNodeMetadata");
    assert_eq!(
        meta.access_modifiers.as_slice(),
        &["public".to_string()],
        "access_modifiers should contain 'public'"
    );
}

#[test]
fn test_interface_declaration() {
    let cpg = java_cpg("public interface Drawable { void draw(); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (iface_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Drawable"))
        .expect("expected ClassDef for 'Drawable' interface");
    let meta = cpg.java_meta(*iface_id).expect("Drawable should have JavaNodeMetadata");
    assert!(meta.is_interface, "is_interface should be true for 'Drawable'");
}

#[test]
fn test_enum_declaration() {
    let cpg = java_cpg("public enum Color { RED, GREEN, BLUE }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let enum_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::EnumDef && n.name.as_deref() == Some("Color"))
        .expect("expected EnumDef for 'Color'");
    assert_eq!(enum_node.name.as_deref(), Some("Color"));
    let enum_constants: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::EnumConstant)
        .collect();
    assert_eq!(enum_constants.len(), 3, "expected 3 EnumConstant nodes (RED, GREEN, BLUE)");
}

#[test]
fn test_record_declaration() {
    let cpg = java_cpg("public record Point(int x, int y) { }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (record_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Point"))
        .expect("expected ClassDef for 'Point' record");
    let meta = cpg.java_meta(*record_id).expect("Point record should have JavaNodeMetadata");
    assert!(meta.is_record, "is_record should be true for record 'Point'");
}

#[test]
fn test_method_declaration() {
    let cpg = java_cpg("class C { public int add(int a, int b) { return a + b; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let method = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("add"))
        .expect("expected MethodDef for 'add'");
    assert_eq!(method.name.as_deref(), Some("add"));
    let params: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::ParamDef)
        .collect();
    assert_eq!(params.len(), 2, "expected 2 ParamDef nodes (a, b)");
}

#[test]
fn test_constructor_declaration() {
    let cpg = java_cpg("class Person { String name; Person(String name) { this.name = name; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (ctor_id, ctor_node) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("Person"))
        .expect("expected MethodDef for constructor 'Person'");
    assert_eq!(ctor_node.is_constructor, Some(true), "constructor MethodDef should have is_constructor=Some(true)");
    let _ = ctor_id;
}

#[test]
fn test_field_declaration() {
    let cpg = java_cpg("class C { private int x; private String name; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let fields: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::FieldDef)
        .collect();
    assert_eq!(fields.len(), 2, "expected 2 FieldDef nodes");
    assert!(
        fields.iter().any(|n| n.name.as_deref() == Some("x")),
        "expected FieldDef for 'x'"
    );
    assert!(
        fields.iter().any(|n| n.name.as_deref() == Some("name")),
        "expected FieldDef for 'name'"
    );
}

#[test]
fn test_local_variable_declaration() {
    let cpg = java_cpg("class C { void f() { int x = 5; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("x"))
        .expect("expected LocalDef for 'x'");
}

#[test]
fn test_assignment_statement() {
    let cpg = java_cpg("class C { void f() { int x = 0; x = 5; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Assign)
        .expect("expected Assign node for 'x = 5'");
}

#[test]
fn test_if_statement() {
    let cpg = java_cpg("class C { void f(int x) { if (x > 0) { return; } } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Conditional)
        .expect("expected Conditional for 'if (x > 0)'");
}

#[test]
fn test_for_loop() {
    let cpg = java_cpg("class C { void f() { for (int i = 0; i < 10; i++) {} } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for C-style for");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::For));
}

#[test]
fn test_enhanced_for_loop() {
    let cpg = java_cpg("class C { void f(int[] arr) { for (int x : arr) {} } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for enhanced for");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::ForEach));
}

#[test]
fn test_while_loop() {
    let cpg = java_cpg("class C { void f(int x) { while (x > 0) { x--; } } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for while");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::While));
}

#[test]
fn test_do_while_loop() {
    let cpg = java_cpg("class C { void f() { int x = 0; do { x++; } while (x < 10); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for do-while");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::DoWhile));
}

#[test]
fn test_switch_statement() {
    let cpg = java_cpg("class C { void f(int x) { switch (x) { case 1: break; case 2: break; default: break; } } }");
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
fn test_switch_expression() {
    let cpg = java_cpg("class C { int f(int x) { return switch (x) { case 1 -> 10; case 2 -> 20; default -> 0; }; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SwitchExpr)
        .expect("expected SwitchExpr for switch expression");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SwitchRule)
        .expect("expected SwitchRule for '->' arm");
}

#[test]
fn test_try_catch() {
    let cpg = java_cpg("class C { void f() { try { int x = 1/0; } catch (ArithmeticException e) { } } }");
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
    let (catch_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Catch)
        .unwrap();
    let meta = cpg.java_meta(*catch_id).expect("Catch should have JavaNodeMetadata");
    let catch_types = meta.catch_types.as_slice();
    assert!(
        catch_types.contains(&"ArithmeticException".to_string()),
        "catch_types should contain 'ArithmeticException'"
    );
}

#[test]
fn test_try_with_resources() {
    let cpg = java_cpg(r#"class C {
    void f() {
        try (java.io.InputStream is = getStream()) {
            is.read();
        }
    }
    java.io.InputStream getStream() { return null; }
}"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let try_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Try)
        .expect("expected Try node for try-with-resources");
    assert_eq!(
        try_node.try_kind,
        Some(TryKind::WithResources),
        "try-with-resources should have TryKind::WithResources"
    );
}

#[test]
fn test_throw_statement() {
    let cpg = java_cpg("class C { void f() { throw new RuntimeException(\"error\"); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Throw)
        .expect("expected Throw node");
}

#[test]
fn test_synchronized_block() {
    let cpg = java_cpg("class C { Object lock = new Object(); void f() { synchronized (lock) { } } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Synchronized)
        .expect("expected Synchronized node");
}

#[test]
fn test_lambda_expression() {
    let cpg = java_cpg("import java.util.function.Function; class C { Function<Integer,Integer> f = x -> x * 2; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LambdaDef)
        .expect("expected LambdaDef for lambda '-> x * 2'");
}

#[test]
fn test_method_reference() {
    let cpg = java_cpg("import java.util.function.Consumer; class C { Consumer<String> f = System.out::println; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MethodRef)
        .expect("expected MethodRef for 'System.out::println'");
}

#[test]
fn test_instanceof_expression() {
    let cpg = java_cpg("class C { boolean f(Object o) { return o instanceof String; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::InstanceofExpr)
        .expect("expected InstanceofExpr for 'o instanceof String'");
}

#[test]
fn test_pattern_matching_instanceof() {
    let cpg = java_cpg("class C { void f(Object o) { if (o instanceof String s) { System.out.println(s.length()); } } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::InstanceofExpr)
        .expect("expected InstanceofExpr for pattern-matching instanceof");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("s"))
        .expect("expected LocalDef for pattern variable 's'");
}

#[test]
fn test_new_object_expression() {
    let cpg = java_cpg("class C { void f() { Object o = new Object(); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::NewExpr)
        .expect("expected NewExpr for 'new Object()'");
}

#[test]
fn test_new_array_expression() {
    let cpg = java_cpg("class C { void f() { int[] arr = new int[10]; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::NewArray)
        .expect("expected NewArray for 'new int[10]'");
}

#[test]
fn test_array_initializer() {
    let cpg = java_cpg("class C { int[] arr = {1, 2, 3}; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ArrayInit)
        .expect("expected ArrayInit for '{1, 2, 3}'");
}

#[test]
fn test_call_expression() {
    let cpg = java_cpg("class C { void greet(String name) {} void f() { greet(\"Alice\"); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let call = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Call && n.name.as_deref() == Some("greet"))
        .expect("expected Call for 'greet(\"Alice\")'");
    assert_eq!(call.name.as_deref(), Some("greet"));
}

#[test]
fn test_method_invocation_on_object() {
    let cpg = java_cpg("class C { void f(String s) { int len = s.length(); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let call = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Call && n.name.as_deref() == Some("length"))
        .expect("expected Call for 's.length()'");
    assert_eq!(call.name.as_deref(), Some("length"));
}

#[test]
fn test_this_expression() {
    let cpg = java_cpg("class C { int x; void f(int x) { this.x = x; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::ThisExpr)
        .expect("expected ThisExpr for 'this'");
}

#[test]
fn test_super_call() {
    let cpg = java_cpg("class Parent { Parent(int x) {} } class Child extends Parent { Child() { super(0); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (ctor_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("Child"))
        .expect("expected MethodDef for 'Child' constructor");
    let meta = cpg.java_meta(*ctor_id).expect("Child ctor should have JavaNodeMetadata");
    assert!(meta.is_super_call, "is_super_call should be true for constructor with super()");
}

#[test]
fn test_ternary_operator() {
    let cpg = java_cpg("class C { int f(int x) { return x > 0 ? x : 0; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TernaryOp)
        .expect("expected TernaryOp for '? :' expression");
}

#[test]
fn test_cast_expression() {
    let cpg = java_cpg("class C { long f(int x) { return (long) x; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Cast)
        .expect("expected Cast for '(long) x'");
}

#[test]
fn test_binary_operations() {
    let cpg = java_cpg("class C { int f(int a, int b) { return a + b; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::BinaryOp && n.operator.as_deref() == Some("+"))
        .expect("expected BinaryOp with operator '+'");
}

#[test]
fn test_array_access() {
    let cpg = java_cpg("class C { int f(int[] arr) { return arr[0]; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Subscript)
        .expect("expected Subscript for 'arr[0]'");
}

#[test]
fn test_field_access() {
    let cpg = java_cpg("class C { String f(String s) { return s.length() + \"\"; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MemberAccess || n.kind == IrNodeKind::Call)
        .expect("expected MemberAccess or Call for 's.length()'");
}

#[test]
fn test_integer_literal() {
    let cpg = java_cpg("class C { int x = 42; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Integer))
        .expect("expected Integer Literal for '42'");
}

#[test]
fn test_string_literal() {
    let cpg = java_cpg(r#"class C { String s = "hello"; }"#);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::String))
        .expect("expected String Literal");
}

#[test]
fn test_null_literal() {
    let cpg = java_cpg("class C { Object o = null; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Null))
        .expect("expected Null Literal for 'null'");
}

#[test]
fn test_boolean_literal() {
    let cpg = java_cpg("class C { boolean a = true; boolean b = false; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let bool_lits: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Bool))
        .collect();
    assert_eq!(bool_lits.len(), 2, "expected 2 Bool Literals (true, false)");
}

#[test]
fn test_annotation() {
    let cpg = java_cpg("class C { @Override public String toString() { return \"\"; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("toString"))
        .expect("expected MethodDef for 'toString'");
    let meta = cpg.java_meta(*method_id).expect("toString should have JavaNodeMetadata");
    let annotations = meta.annotations.as_slice();
    assert!(
        annotations.contains(&"Override".to_string()),
        "annotations should contain 'Override'"
    );
}

#[test]
fn test_generic_class() {
    let cpg = java_cpg("class Box<T> { T value; Box(T value) { this.value = value; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (class_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Box"))
        .expect("expected ClassDef for 'Box'");
    let meta = cpg.java_meta(*class_id).expect("Box should have JavaNodeMetadata");
    let params = meta.generic_type_params.as_slice();
    assert!(params.contains(&"T".to_string()), "generic_type_params should contain 'T'");
}

#[test]
fn test_varargs_parameter() {
    let cpg = java_cpg("class C { int sum(int... nums) { return 0; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (param_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("nums"))
        .expect("expected ParamDef for 'nums'");
    let meta = cpg.java_meta(*param_id).expect("nums should have JavaNodeMetadata");
    assert!(meta.is_varargs, "is_varargs should be true for 'int... nums'");
}

#[test]
fn test_static_method() {
    let cpg = java_cpg("class C { static int square(int x) { return x * x; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("square"))
        .expect("expected MethodDef for 'square'");
    let meta = cpg.java_meta(*method_id).expect("square should have JavaNodeMetadata");
    assert!(meta.is_static, "is_static should be true for static 'square'");
}

#[test]
fn test_class_extends() {
    let cpg = java_cpg("class Animal {} class Dog extends Animal {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (dog_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Dog"))
        .expect("expected ClassDef for 'Dog'");
    let meta = cpg.java_meta(*dog_id).expect("Dog should have JavaNodeMetadata");
    assert_eq!(
        meta.extends_type.as_deref(),
        Some("Animal"),
        "extends_type should be 'Animal'"
    );
}

#[test]
fn test_class_implements() {
    let cpg = java_cpg("interface Runnable { void run(); } class MyTask implements Runnable { public void run() {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (task_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("MyTask"))
        .expect("expected ClassDef for 'MyTask'");
    let meta = cpg.java_meta(*task_id).expect("MyTask should have JavaNodeMetadata");
    let impls = meta.implements_types.as_slice();
    assert!(
        impls.contains(&"Runnable".to_string()),
        "implements_types should contain 'Runnable'"
    );
}

#[test]
fn test_return_statement() {
    let cpg = java_cpg("class C { int f(int x) { return x * 2; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Return)
        .expect("expected Return node");
}

#[test]
fn test_break_and_continue() {
    let cpg = java_cpg("class C { void f() { for (int i = 0; i < 10; i++) { if (i == 5) break; if (i == 3) continue; } } }");
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

// ── CFG Tests ─────────────────────────────────────────────────────────────────

#[test]
fn test_cfg_try_catch_branches() {
    let cpg = java_cpg("class C { void f() { try { int x = 1/0; } catch (Exception e) { } } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let try_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Try)
        .expect("expected Try node");
    let try_bb = try_node.basic_block.as_deref().unwrap_or("");
    if !try_bb.is_empty() {
        let bb = cpg.basic_blocks.get(try_bb).expect("Try BB should exist");
        assert!(
            !bb.exception_successors.is_empty() || !bb.successors.is_empty(),
            "Try block should have successors"
        );
    }
}

#[test]
fn test_cfg_finally_always_runs() {
    let cpg = java_cpg("class C { void f() { try { return; } finally { cleanup(); } } void cleanup() {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Try)
        .expect("expected Try node");
    let (try_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Try)
        .unwrap();
    let meta = cpg.java_meta(*try_id).expect("Try should have JavaNodeMetadata");
    assert!(meta.has_finally, "has_finally should be true");
}

// ── DFG Tests ─────────────────────────────────────────────────────────────────

#[test]
fn test_dfg_variable_declaration_defines() {
    let cpg = java_cpg("class C { void f() { int x = 5; System.out.println(x); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_x_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "x");
    assert!(has_x_def, "expected DataflowDef for 'x'");
    let has_x_use = cpg.dataflow.uses.iter().any(|u| u.variable == "x");
    assert!(has_x_use, "expected DataflowUse for 'x' at println");
}

#[test]
fn test_dfg_field_taint() {
    let cpg = java_cpg("class C { String name; void f(String input) { name = input; System.out.println(name); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_input_use = cpg.dataflow.uses.iter().any(|u| u.variable == "input");
    assert!(has_input_use, "expected DataflowUse for 'input'");
    let has_name_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "name");
    assert!(has_name_def, "expected DataflowDef for 'name'");
}

// ── Call Graph Tests ──────────────────────────────────────────────────────────

#[test]
fn test_callgraph_method_call() {
    let cpg = java_cpg("class C { void foo() {} void bar() { foo(); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let bar_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "bar")
        .expect("expected CallGraphEntry for 'bar'");
    let calls_foo = bar_entry.calls.iter().any(|cs| cs.callee == "foo");
    assert!(calls_foo, "bar should call 'foo' in the call graph");
}

#[test]
fn test_callgraph_constructor_call() {
    let cpg = java_cpg("class Person { String name; Person(String n) { name = n; } } class C { void f() { Person p = new Person(\"Alice\"); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let f_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "f")
        .expect("expected CallGraphEntry for 'f'");
    let calls_person = f_entry.calls.iter().any(|cs| cs.callee == "Person");
    assert!(calls_person, "f should call 'Person' constructor in call graph");
}

// ── Type System Tests ─────────────────────────────────────────────────────────

#[test]
fn test_type_ref_integral() {
    // integral_type (int, long, etc.) → IrNodeKind::TypeRef per Java plan §1628
    let cpg = java_cpg("class C { void f() { int x = 5; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_int_type_ref = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "integral_type");
    assert!(has_int_type_ref, "expected TypeRef node with node_type 'integral_type' for 'int'");
}

#[test]
fn test_scoped_identifier() {
    // scoped_type_identifier → IrNodeKind::TypeRef with qualified name
    let cpg = java_cpg("class C { java.util.List l; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_scoped = cpg
        .ast
        .values()
        .any(|n| {
            n.kind == IrNodeKind::TypeRef
                && n.text.as_deref().map_or(false, |t| t.contains("java.util.List"))
        });
    assert!(has_scoped, "expected TypeRef node with text containing 'java.util.List'");
}

#[test]
fn test_import_declaration() {
    let cpg = java_cpg("import java.util.List;\nclass C { }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_import = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::Import && n.name.as_deref().map_or(false, |nm| nm.contains("java.util.List")));
    assert!(has_import, "expected Import node for 'java.util.List'");
}

#[test]
fn test_type_ref_boolean() {
    let cpg = java_cpg("class C { boolean f() { return true; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_bool_type = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "boolean_type");
    assert!(has_bool_type, "expected TypeRef node with node_type 'boolean_type'");
}

#[test]
fn test_type_ref_void() {
    let cpg = java_cpg("class C { void f() {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_void_type = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "void_type");
    assert!(has_void_type, "expected TypeRef node with node_type 'void_type'");
}

#[test]
fn test_type_ref_array() {
    let cpg = java_cpg("class C { void f() { int[] arr = new int[3]; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_array_type = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "array_type");
    assert!(has_array_type, "expected TypeRef node with node_type 'array_type'");
}

// ── Incremental Tests ─────────────────────────────────────────────────────────

#[test]
fn test_incremental_add_method() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "class C { void a() {} }";
    let modified = "class C { void a() {} void b() { a(); } }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Java, GraphBuildOptions::default())
        .expect("Java incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_b = updated
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("b"));
    assert!(has_b, "after adding method b, MethodDef for 'b' should exist");
}

#[test]
fn test_incremental_add_try_catch() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "class C { void f() { int x = 1; } }";
    let modified = "class C { void f() { try { int x = 1/0; } catch (Exception e) {} } }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Java, GraphBuildOptions::default())
        .expect("Java incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_try = updated.ast.values().any(|n| n.kind == IrNodeKind::Try);
    assert!(has_try, "after adding try-catch, Try node should exist");
}

#[test]
fn test_incremental_replace_body_updates_dfg() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "class C { int f() { int x = 1; return x; } }";
    let modified = "class C { int f() { int x = 99; return x; } }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Java, GraphBuildOptions::default())
        .expect("Java incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

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
fn test_incremental_sequential_edits_java() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let src0 = "class C { void a() {} }";
    let src1 = "class C { void a() {} void b() { a(); } }";
    let src2 = "class C { void a() {} void b() { a(); } void c() { b(); } }";
    let src3 = "class C { void a() {} void c() { a(); } }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Java, GraphBuildOptions::default())
        .expect("Java incremental init");
    inc.parse_initial(src0.as_bytes()).expect("initial");

    let e1 = compute_edit(src0.as_bytes(), src1.as_bytes()).expect("edit1");
    inc.apply_edit(&e1, src1.as_bytes()).expect("edit1");

    let e2 = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit2");
    inc.apply_edit(&e2, src2.as_bytes()).expect("edit2");

    let e3 = compute_edit(src2.as_bytes(), src3.as_bytes()).expect("edit3");
    let final_inc = inc.apply_edit(&e3, src3.as_bytes()).expect("edit3");

    let full = CpgGenerator::new_for_language(SourceLanguage::Java)
        .expect("Java parser")
        .generate_from_source_with_options(src3.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let full_names: HashSet<_> = full.ast.values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .filter_map(|n| n.name.as_deref()).collect();
    let inc_names: HashSet<_> = final_inc.ast.values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .filter_map(|n| n.name.as_deref()).collect();
    assert_eq!(full_names, inc_names, "after 3 sequential edits, MethodDef names must match fresh parse");

    assert_cfg_valid(final_inc);
}

#[test]
fn test_parity_dfg_and_callgraph_java() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "class C { void a() {} }";
    let modified = "class C { void a() { int x = 1; } void b() { a(); } }";

    let full = CpgGenerator::new_for_language(SourceLanguage::Java)
        .expect("Java parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Java, GraphBuildOptions::default())
        .expect("Java incremental init");
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

#[test]
#[ignore]
fn debug_switch_ast() {
    let cpg = java_cpg("class C { void f(int x) { switch (x) { case 1: break; case 2: break; default: break; } } }");
    for (nid, n) in &cpg.ast {
        if n.node_type.contains("switch") || n.node_type.contains("case") || n.node_type.contains("default") || n.node_type.contains("label") {
            println!("  {nid}: kind={:?} type={}", n.kind, n.node_type);
        }
    }
}

#[test]
#[ignore]
fn debug_modifiers_ast() {
    let cpg = java_cpg("public class Animal { public static void greet(String name) {} }");
    for (nid, n) in &cpg.ast {
        if n.node_type.contains("modifier") || n.node_type == "public" || n.node_type == "static" || n.node_type == "modifiers" {
            println!("  {nid}: kind={:?} type={} text={:?}", n.kind, n.node_type, n.text);
        }
    }
}

#[test]
#[ignore]
fn debug_misc_ast() {
    // method invocation
    let cpg = java_cpg("class C { void f(String s) { int len = s.length(); greet(\"Alice\"); } void greet(String n) {} }");
    println!("=== method invocation ===");
    for (nid, n) in &cpg.ast {
        if n.kind == IrNodeKind::Call || n.node_type.contains("invocation") || n.node_type.contains("method_inv") {
            println!("  {nid}: kind={:?} type={} name={:?} text={:?}", n.kind, n.node_type, n.name, n.text);
        }
    }

    // pattern matching instanceof
    let cpg2 = java_cpg("class C { void f(Object o) { if (o instanceof String s) { } } }");
    println!("=== instanceof pattern ===");
    for (nid, n) in &cpg2.ast {
        if n.node_type.contains("instance") || n.node_type.contains("pattern") || n.node_type.contains("type_pattern") {
            println!("  {nid}: kind={:?} type={} name={:?} text={:?} children={:?}", n.kind, n.node_type, n.name, n.text, n.children);
        }
    }

    // class extends/implements
    let cpg3 = java_cpg("class Animal {} class Dog extends Animal implements Runnable { public void run() {} }");
    println!("=== class extends/implements ===");
    for (nid, n) in &cpg3.ast {
        if n.node_type.contains("class_dec") || n.node_type.contains("super") || n.node_type.contains("implement") || n.node_type.contains("interface_type") {
            println!("  {nid}: kind={:?} type={} name={:?} text={:?}", n.kind, n.node_type, n.name, n.text);
        }
    }

    // try/catch/finally  
    let cpg4 = java_cpg("class C { void f() { try { return; } catch (Exception e) { } finally { cleanup(); } } void cleanup() {} }");
    println!("=== try/catch/finally ===");
    for (nid, n) in &cpg4.ast {
        if n.node_type.contains("try") || n.node_type.contains("catch") || n.node_type.contains("finally") || n.node_type.contains("exception") {
            println!("  {nid}: kind={:?} type={} name={:?} text={:?}", n.kind, n.node_type, n.name, n.text);
        }
    }
}

#[test]
#[ignore]
fn debug_more_ast() {
    // generic class
    let cpg = java_cpg("class Box<T> { T value; }");
    println!("=== generic class ===");
    for (nid, n) in &cpg.ast {
        if n.node_type.contains("type_param") || n.node_type.contains("generic") {
            println!("  {nid}: type={} text={:?} children={:?}", n.node_type, n.text, n.children);
        }
    }
    
    // super_interfaces children
    let cpg2 = java_cpg("class Dog extends Animal implements Runnable, Serializable { }");
    println!("=== super_interfaces ===");
    for (nid, n) in &cpg2.ast {
        if n.node_type.contains("super") || n.node_type.contains("implement") || n.node_type.contains("type_list") || n.node_type.contains("type_identifier") {
            println!("  {nid}: type={} text={:?} children={:?}", n.node_type, n.text, n.children);
        }
    }
    
    // annotation methods
    let cpg3 = java_cpg("class C { @Override public String toString() { return \"\"; } }");
    println!("=== annotations ===");
    for (nid, n) in &cpg3.ast {
        if n.node_type.contains("modifier") || n.node_type.contains("annotation") {
            println!("  {nid}: type={} text={:?} children={:?}", n.node_type, n.text, n.children);
        }
    }
    
    // varargs, super call, constructor invocation
    let cpg4 = java_cpg("class C { int sum(int... nums) { return 0; } } class B extends C { B() { super(); } }");
    println!("=== varargs + super call ===");
    for (nid, n) in &cpg4.ast {
        if n.node_type.contains("spread") || n.node_type.contains("invocation") || n.node_type.contains("constructor") {
            println!("  {nid}: type={} text={:?} children={:?}", n.node_type, n.text, n.children);
        }
    }
}

#[test]
#[ignore]
fn debug_final_issues() {
    // switch expression
    let cpg = java_cpg("class C { int f(int x) { return switch (x) { case 1 -> 10; case 2 -> 20; default -> 0; }; } }");
    println!("=== switch expression ===");
    for (nid, n) in &cpg.ast {
        if n.node_type.contains("switch") || n.node_type.contains("rule") {
            println!("  {nid}: kind={:?} type={}", n.kind, n.node_type);
        }
    }
    
    // instanceof pattern
    let cpg2 = java_cpg("class C { void f(Object o) { if (o instanceof String s) { } } }");
    println!("=== instanceof pattern ===");
    for (nid, n) in &cpg2.ast {
        println!("  {nid}: kind={:?} type={} name={:?}", n.kind, n.node_type, n.name);
    }
    
    // varargs
    let cpg3 = java_cpg("class C { int sum(int... nums) { return 0; } }");
    println!("=== varargs ===");
    for (nid, n) in &cpg3.ast {
        if n.node_type.contains("spread") || n.node_type.contains("param") || n.kind == IrNodeKind::ParamDef {
            println!("  {nid}: kind={:?} type={} name={:?} children={:?}", n.kind, n.node_type, n.name, n.children);
        }
    }
}

#[test]
#[ignore]
fn debug_varargs_detail() {
    let cpg = java_cpg("class C { int sum(int... nums) { return 0; } }");
    for (nid, n) in &cpg.ast {
        println!("  {nid}: kind={:?} type={} name={:?} text={:?}", n.kind, n.node_type, n.name, n.text);
    }
}
