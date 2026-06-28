//! Grammar construct coverage tests for TypeScript (Phase 1).
//!
//! Tests are in the TDD red state — assertions about `IrNodeKind` will fail
//! until the real TsLifter is implemented.

use std::collections::HashSet;

use web_sitter::{IrNodeKind, LiteralKind, LoopKind, NodeId, TryKind};
use web_sitter::{CpgGenerator, GraphBuildOptions, SourceLanguage};

fn ts_cpg(src: &str) -> web_sitter::Cpg {
    CpgGenerator::new_for_language(SourceLanguage::TypeScript)
        .expect("TypeScript parser init")
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("TypeScript CPG generation failed")
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
    let cpg = ts_cpg("const x: number = 1;");
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
fn test_typed_variable_declaration() {
    let cpg = ts_cpg("const x: number = 42;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let local = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("x"))
        .expect("expected LocalDef for 'x'");
    let (local_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::LocalDef && n.name.as_deref() == Some("x"))
        .unwrap();
    let meta = cpg.ts_meta(*local_id).expect("x should have TsNodeMetadata");
    assert!(
        meta.type_annotation.as_deref().unwrap_or("").contains("number"),
        "type_annotation should contain 'number'"
    );
    let _ = local;
}

#[test]
fn test_interface_declaration() {
    let cpg = ts_cpg("interface Shape { area(): number; perimeter(): number; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let iface = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::InterfaceDecl && n.name.as_deref() == Some("Shape"))
        .expect("expected InterfaceDecl for 'Shape'");
    assert_eq!(iface.name.as_deref(), Some("Shape"));
}

#[test]
fn test_enum_declaration() {
    let cpg = ts_cpg("enum Direction { Up, Down, Left, Right }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let enum_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::EnumDecl && n.name.as_deref() == Some("Direction"))
        .expect("expected EnumDecl for 'Direction'");
    assert_eq!(enum_node.name.as_deref(), Some("Direction"));
}

#[test]
fn test_const_enum() {
    let cpg = ts_cpg("const enum Color { Red, Green, Blue }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (enum_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::EnumDecl && n.name.as_deref() == Some("Color"))
        .expect("expected EnumDecl for 'Color'");
    let meta = cpg.ts_meta(*enum_id).expect("Color should have TsNodeMetadata");
    assert!(meta.enum_is_const, "enum_is_const should be true for 'const enum'");
}

#[test]
fn test_class_with_typed_members() {
    let cpg = ts_cpg("class Person { name: string; age: number; constructor(name: string, age: number) { this.name = name; this.age = age; } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let class_def = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Person"))
        .expect("expected ClassDef for 'Person'");
    assert_eq!(class_def.name.as_deref(), Some("Person"));
    let fields: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::FieldDef).collect();
    assert!(fields.iter().any(|n| n.name.as_deref() == Some("name")), "expected FieldDef for 'name'");
    assert!(fields.iter().any(|n| n.name.as_deref() == Some("age")), "expected FieldDef for 'age'");
}

#[test]
fn test_abstract_class() {
    let cpg = ts_cpg("abstract class Animal { abstract speak(): void; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (class_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Animal"))
        .expect("expected ClassDef for 'Animal'");
    let meta = cpg.ts_meta(*class_id).expect("Animal should have TsNodeMetadata");
    assert!(meta.is_abstract, "is_abstract should be true for 'abstract class'");
}

#[test]
fn test_readonly_field() {
    let cpg = ts_cpg("class C { readonly id: number = 0; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (field_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::FieldDef && n.name.as_deref() == Some("id"))
        .expect("expected FieldDef for 'id'");
    let meta = cpg.ts_meta(*field_id).expect("id should have TsNodeMetadata");
    assert!(meta.is_readonly, "is_readonly should be true for 'readonly id'");
}

#[test]
fn test_optional_member() {
    let cpg = ts_cpg("interface Config { host: string; port?: number; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (port_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| (n.kind == IrNodeKind::FieldDef || n.kind == IrNodeKind::ParamDef)
            && n.name.as_deref() == Some("port"))
        .expect("expected field/param for optional 'port?'");
    let meta = cpg.ts_meta(*port_id).expect("port should have TsNodeMetadata");
    assert!(meta.is_optional, "is_optional should be true for 'port?'");
}

#[test]
fn test_access_modifier_public_private() {
    let cpg = ts_cpg("class C { public name: string = ''; private secret: number = 0; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (name_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::FieldDef && n.name.as_deref() == Some("name"))
        .expect("expected FieldDef for 'name'");
    let name_meta = cpg.ts_meta(*name_id).expect("name should have TsNodeMetadata");
    assert_eq!(
        name_meta.access_modifier.as_deref(),
        Some("public"),
        "access_modifier should be 'public'"
    );

    let (secret_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::FieldDef && n.name.as_deref() == Some("secret"))
        .expect("expected FieldDef for 'secret'");
    let secret_meta = cpg.ts_meta(*secret_id).expect("secret should have TsNodeMetadata");
    assert_eq!(
        secret_meta.access_modifier.as_deref(),
        Some("private"),
        "access_modifier should be 'private'"
    );
}

#[test]
fn test_generic_function() {
    let cpg = ts_cpg("function identity<T>(arg: T): T { return arg; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("identity"))
        .expect("expected MethodDef for 'identity'");
    let meta = cpg.ts_meta(*method_id).expect("identity should have TsNodeMetadata");
    let has_t = meta.generic_constraints.iter().any(|(name, _)| name == "T");
    assert!(has_t, "generic_constraints should contain 'T'");
}

#[test]
fn test_type_alias() {
    let cpg = ts_cpg("type StringOrNumber = string | number;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TypeAlias && n.name.as_deref() == Some("StringOrNumber"))
        .expect("expected TypeAlias for 'StringOrNumber'");
}

#[test]
fn test_as_expression() {
    let cpg = ts_cpg("const x: any = 'hello'; const s = x as string;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::AsExpr)
        .expect("expected AsExpr for 'x as string'");
}

#[test]
fn test_non_null_assertion() {
    let cpg = ts_cpg("function f(x: string | null) { return x!.length; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::NonNullExpr)
        .expect("expected NonNullExpr for 'x!' non-null assertion");
}

#[test]
fn test_satisfies_expression() {
    let cpg = ts_cpg("type Shape = { area(): number }; const c = { area() { return 1; } } satisfies Shape;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::SatisfiesExpr)
        .expect("expected SatisfiesExpr for '... satisfies Shape'");
}

#[test]
fn test_ambient_declaration() {
    let cpg = ts_cpg("declare const process: { env: { NODE_ENV: string } };");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (decl_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::AmbientDecl)
        .expect("expected AmbientDecl for 'declare ...'");
    let meta = cpg.ts_meta(*decl_id).expect("AmbientDecl should have TsNodeMetadata");
    assert!(meta.is_ambient, "is_ambient should be true for 'declare ...'");
}

#[test]
fn test_namespace_module() {
    let cpg = ts_cpg("namespace MyLib { export function fn() {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Namespace && n.name.as_deref() == Some("MyLib"))
        .expect("expected Namespace for 'MyLib'");
}

#[test]
fn test_decorator_on_class() {
    let cpg = ts_cpg("function sealed(cls: any) {} @sealed class C {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Decorator)
        .expect("expected Decorator node for '@sealed'");
    let (class_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("C"))
        .expect("expected ClassDef for 'C'");
    let meta = cpg.ts_meta(*class_id).expect("C should have TsNodeMetadata");
    let decorators = meta.decorator_names.as_slice();
    assert!(
        decorators.contains(&"sealed".to_string()),
        "decorator_names should contain 'sealed'"
    );
}

#[test]
fn test_function_with_typed_params() {
    let cpg = ts_cpg("function add(a: number, b: number): number { return a + b; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let params: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::ParamDef).collect();
    assert_eq!(params.len(), 2, "expected 2 ParamDef nodes");
    let (a_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("a"))
        .expect("expected ParamDef for 'a'");
    let meta = cpg.ts_meta(*a_id).expect("a should have TsNodeMetadata");
    assert!(
        meta.type_annotation.as_deref().unwrap_or("").contains("number"),
        "type_annotation for 'a' should contain 'number'"
    );
}

#[test]
fn test_interface_extends() {
    let cpg = ts_cpg("interface Base { id: number; } interface Extended extends Base { name: string; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (ext_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::InterfaceDecl && n.name.as_deref() == Some("Extended"))
        .expect("expected InterfaceDecl for 'Extended'");
    let meta = cpg.ts_meta(*ext_id).expect("Extended should have TsNodeMetadata");
    assert_eq!(
        meta.extends_type.as_deref(),
        Some("Base"),
        "extends_type should be 'Base'"
    );
}

#[test]
fn test_class_implements_interface() {
    let cpg = ts_cpg("interface Printable { print(): void; } class Document implements Printable { print() {} }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (class_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Document"))
        .expect("expected ClassDef for 'Document'");
    let meta = cpg.ts_meta(*class_id).expect("Document should have TsNodeMetadata");
    let implements = meta.implements_types.as_slice();
    assert!(
        implements.contains(&"Printable".to_string()),
        "implements_types should contain 'Printable'"
    );
}

#[test]
fn test_for_loop() {
    let cpg = ts_cpg("for (let i = 0; i < 10; i++) {}");
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
fn test_for_of_loop() {
    let cpg = ts_cpg("const arr: number[] = [1,2,3]; for (const x of arr) {}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'for...of'");
    assert_eq!(loop_node.loop_kind, Some(LoopKind::ForEach));
}

#[test]
fn test_try_catch() {
    let cpg = ts_cpg("try { throw new Error(); } catch (e: unknown) { console.log(e); }");
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
fn test_async_await() {
    let cpg = ts_cpg("async function f(): Promise<void> { await doWork(); }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("f"))
        .expect("expected MethodDef for 'f'");
    let meta = cpg.ts_meta(*method_id).expect("f should have TsNodeMetadata");
    assert!(meta.is_async, "is_async should be true for 'async function'");
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::AwaitExpr)
        .expect("expected AwaitExpr for 'await doWork()'");
}

#[test]
fn test_call_expression() {
    let cpg = ts_cpg("console.log('hello');");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Call)
        .expect("expected Call node");
}

#[test]
fn test_string_literal() {
    let cpg = ts_cpg("const s: string = 'hello';");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::String))
        .expect("expected String Literal");
}

#[test]
fn test_number_literal() {
    let cpg = ts_cpg("const n: number = 42;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Integer))
        .expect("expected Integer Literal");
}

#[test]
fn test_arrow_function_typed() {
    let cpg = ts_cpg("const add = (a: number, b: number): number => a + b;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let lambda = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::LambdaDef)
        .expect("expected LambdaDef for typed arrow function");
    let (lambda_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::LambdaDef)
        .unwrap();
    let meta = cpg.ts_meta(*lambda_id).expect("arrow should have TsNodeMetadata");
    assert!(meta.is_async || !meta.is_async, "lambda should have TsNodeMetadata (always true)");
    let _ = lambda;
}

#[test]
fn test_template_literal() {
    let cpg = ts_cpg("const name = 'world'; const s = `hello ${name}`;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TemplateStr)
        .expect("expected TemplateStr for template literal");
}

#[test]
fn test_type_predicate() {
    let cpg = ts_cpg("function isString(x: any): x is string { return typeof x === 'string'; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("isString"))
        .expect("expected MethodDef for 'isString'");
    let meta = cpg.ts_meta(*method_id).expect("isString should have TsNodeMetadata");
    let ret_type = meta.type_annotation.as_deref().unwrap_or("");
    assert!(
        ret_type.contains("is string") || ret_type.contains("TypePredicate"),
        "return type annotation should reflect 'x is string'"
    );
}

#[test]
fn test_import_statement() {
    let cpg = ts_cpg("import { Component } from '@angular/core';");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Import)
        .expect("expected Import node");
}

#[test]
fn test_export_declaration() {
    let cpg = ts_cpg("export function greet(name: string): string { return name; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Export)
        .expect("expected Export node");
}

#[test]
fn test_comment_not_in_ast() {
    let cpg = ts_cpg("// TypeScript comment\nconst x: number = 1;");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let comment_in_ast = cpg.ast.values().any(|n| n.node_type == "comment");
    assert!(!comment_in_ast, "comment nodes should not appear in cpg.ast");
    assert!(!cpg.comments.is_empty(), "comment should be stored in cpg.comments");
}

// ── DFG Tests ─────────────────────────────────────────────────────────────────

#[test]
fn test_dfg_typed_variable_defines() {
    let cpg = ts_cpg("const x: number = 42; console.log(x);");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_x_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "x");
    assert!(has_x_def, "expected DataflowDef for 'x'");
    let has_x_use = cpg.dataflow.uses.iter().any(|u| u.variable == "x");
    assert!(has_x_use, "expected DataflowUse for 'x'");
}

#[test]
fn test_dfg_type_narrowing_does_not_break_flow() {
    let cpg = ts_cpg("function f(x: string | null) { if (x !== null) { console.log(x.length); } }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_x_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "x");
    assert!(has_x_def, "expected DataflowDef for 'x'");
}

// ── Type System Tests ─────────────────────────────────────────────────────────

#[test]
fn test_type_annotation_on_param_produces_type_ref() {
    // Per TS plan §34: ParamDef for typed param should have a TypeRef child
    let cpg = ts_cpg("function greet(name: string): void { }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (param_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("name"))
        .expect("expected ParamDef for 'name'");
    let param_meta = cpg.ts_meta(*param_id).expect("'name' param should have TsNodeMetadata");
    assert!(
        param_meta.type_annotation.as_deref().unwrap_or("").contains("string"),
        "type_annotation for 'name' should contain 'string'"
    );
    let has_string_type_ref = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeRef && n.text.as_deref().map_or(false, |t| t.contains("string")));
    assert!(has_string_type_ref, "expected TypeRef node with text 'string' for parameter type annotation");
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("greet"))
        .expect("expected MethodDef for 'greet'");
    let method_meta = cpg.ts_meta(*method_id).expect("'greet' should have TsNodeMetadata");
    assert!(
        method_meta.type_annotation.as_deref().unwrap_or("").contains("void"),
        "type_annotation for 'greet' return type should contain 'void'"
    );
}

#[test]
fn test_optional_property_annotation() {
    // Per TS plan §51: FieldDef with optional marker has is_optional == true in TsNodeMetadata
    let cpg = ts_cpg("interface I { name?: string; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let iface = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::InterfaceDecl && n.name.as_deref() == Some("I"))
        .expect("expected InterfaceDecl for 'I'");
    let _ = iface;
    let (field_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::FieldDef && n.name.as_deref() == Some("name"))
        .expect("expected FieldDef for 'name'");
    let meta = cpg.ts_meta(*field_id).expect("'name' field should have TsNodeMetadata");
    assert!(meta.is_optional, "is_optional should be true for 'name?: string'");
    assert!(
        meta.type_annotation.as_deref().unwrap_or("").contains("string"),
        "type_annotation for optional 'name' should contain 'string'"
    );
}

#[test]
fn test_readonly_property() {
    // Per TS plan §59: readonly modifier → TsNodeMetadata.is_readonly == true
    let cpg = ts_cpg("class Foo { readonly count: number = 0; }");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (field_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::FieldDef && n.name.as_deref() == Some("count"))
        .expect("expected FieldDef for 'count'");
    let meta = cpg.ts_meta(*field_id).expect("'count' field should have TsNodeMetadata");
    assert!(meta.is_readonly, "is_readonly should be true for 'readonly count'");
}

// ── Call Graph Tests ──────────────────────────────────────────────────────────

#[test]
fn test_callgraph_typed_function() {
    let cpg = ts_cpg("function foo(): void {} function bar(): void { foo(); }");
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

// ── Incremental Tests ─────────────────────────────────────────────────────────

#[test]
fn test_incremental_add_interface() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "class A {}";
    let modified = "class A {} interface I { method(): void; }";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::TypeScript, GraphBuildOptions::default())
        .expect("TS incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_iface = updated
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::InterfaceDecl && n.name.as_deref() == Some("I"));
    assert!(has_iface, "after adding interface I, InterfaceDecl for 'I' should exist");
}

#[test]
fn test_incremental_add_type_alias() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "const x = 1;";
    let modified = "const x = 1; type Num = number;";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::TypeScript, GraphBuildOptions::default())
        .expect("TS incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_alias = updated
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeAlias && n.name.as_deref() == Some("Num"));
    assert!(has_alias, "after adding 'type Num = number', TypeAlias for 'Num' should exist");
}

// ── Parity Tests ──────────────────────────────────────────────────────────────

#[test]
fn test_parity_add_function() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "function a(): void {}";
    let modified = "function a(): void {} function b(): void { a(); }";

    let full_cpg = CpgGenerator::new_for_language(SourceLanguage::TypeScript)
        .expect("TS parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::TypeScript, GraphBuildOptions::default())
        .expect("TS incremental init");
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

    let base = "function f(): number { let x = 1; return x; }\n";
    let modified = "function f(): number { let x = 99; return x; }\n";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::TypeScript, GraphBuildOptions::default())
        .expect("TS incremental init");
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
fn test_incremental_sequential_edits_ts() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let src0 = "function a(): void {}\n";
    let src1 = "function a(): void {} function b(): void { a(); }\n";
    let src2 = "function a(): void {} function b(): void { a(); } function c(): void { b(); }\n";
    let src3 = "function a(): void {} function c(): void { a(); }\n";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::TypeScript, GraphBuildOptions::default())
        .expect("TS incremental init");
    inc.parse_initial(src0.as_bytes()).expect("initial");

    let e1 = compute_edit(src0.as_bytes(), src1.as_bytes()).expect("edit1");
    inc.apply_edit(&e1, src1.as_bytes()).expect("edit1");

    let e2 = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit2");
    inc.apply_edit(&e2, src2.as_bytes()).expect("edit2");

    let e3 = compute_edit(src2.as_bytes(), src3.as_bytes()).expect("edit3");
    let final_inc = inc.apply_edit(&e3, src3.as_bytes()).expect("edit3");

    let full = CpgGenerator::new_for_language(SourceLanguage::TypeScript)
        .expect("TS parser")
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
fn test_parity_dfg_and_callgraph_ts() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "function a(): void {}\n";
    let modified = "function a(): void { let x = 1; return x; } function b(): void { a(); }\n";

    let full = CpgGenerator::new_for_language(SourceLanguage::TypeScript)
        .expect("TS parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::TypeScript, GraphBuildOptions::default())
        .expect("TS incremental init");
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
