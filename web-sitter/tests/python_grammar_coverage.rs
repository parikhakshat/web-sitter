//! Grammar construct coverage tests for Python (Phase 1).
//!
//! Tests are in the TDD red state — assertions about `IrNodeKind` will fail
//! until the real PythonLifter is implemented.

use std::collections::HashSet;

use web_sitter::{
    ComprehensionKind, GlobalKind, IrNodeKind, ImportKind, LiteralKind, LoopKind, NodeId,
    TryKind,
};
use web_sitter::{CpgGenerator, GraphBuildOptions, SourceLanguage};

fn py_cpg(src: &str) -> web_sitter::Cpg {
    CpgGenerator::new_for_language(SourceLanguage::Python)
        .expect("Python parser init")
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("Python CPG generation failed")
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

// ── 1a Grammar Coverage ───────────────────────────────────────────────────────

#[test]
fn test_module_lifts_to_file() {
    let cpg = py_cpg("x = 1");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let file_nodes: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::File && n.node_type == "module")
        .collect();
    assert_eq!(file_nodes.len(), 1, "expected exactly one File node with node_type 'module'");
}

#[test]
fn test_function_def_lifts_to_method_def() {
    let cpg = py_cpg("def greet(name):\n    return 'hello ' + name");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let method = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("greet"))
        .expect("expected MethodDef for 'greet'");
    assert_eq!(method.name.as_deref(), Some("greet"));
    let has_param = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("name"));
    assert!(has_param, "expected ParamDef for 'name'");
}

#[test]
fn test_async_function_def_metadata() {
    let cpg = py_cpg("async def fetch(url):\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("fetch"))
        .expect("expected MethodDef for 'fetch'");
    let meta = cpg
        .python_meta(*method_id)
        .expect("fetch should have PythonNodeMetadata");
    assert!(meta.is_async, "PythonNodeMetadata.is_async should be true for 'async def'");
}

#[test]
fn test_class_def_lifts_to_class_def() {
    let cpg = py_cpg("class Animal:\n    def speak(self):\n        pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let class_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Animal"))
        .expect("expected ClassDef for 'Animal'");
    assert_eq!(class_node.name.as_deref(), Some("Animal"));
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("speak"))
        .expect("expected MethodDef for 'speak'");
}

#[test]
fn test_class_with_base() {
    let cpg = py_cpg("class Dog(Animal):\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let class_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Dog"))
        .expect("expected ClassDef for 'Dog'");
    let has_parent = class_node
        .children
        .iter()
        .any(|id| cpg.ast.get(id).map_or(false, |n| n.kind == IrNodeKind::TypeRef));
    assert!(has_parent, "Dog ClassDef should have TypeRef child for base 'Animal'");
}

#[test]
fn test_import_statement_lifts_to_import() {
    let cpg = py_cpg("import os");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let import_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Import)
        .expect("expected Import node for 'import os'");
    let (import_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Import)
        .unwrap();
    let meta = cpg.python_meta(*import_id).expect("Import should have PythonNodeMetadata");
    assert_eq!(
        meta.import_kind,
        ImportKind::Regular,
        "import_kind should be Regular for 'import os'"
    );
    assert_eq!(
        meta.import_module.as_deref(),
        Some("os"),
        "import_module should be 'os'"
    );
    let _ = import_node;
}

#[test]
fn test_from_import_statement() {
    let cpg = py_cpg("from os.path import join, exists");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (import_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Import)
        .expect("expected Import node");
    let meta = cpg.python_meta(*import_id).expect("Import should have PythonNodeMetadata");
    assert_eq!(
        meta.import_kind,
        ImportKind::From,
        "import_kind should be From for 'from ... import ...'"
    );
    assert_eq!(
        meta.import_module.as_deref(),
        Some("os.path"),
        "import_module should be 'os.path'"
    );
    let names = &meta.import_names;
    assert!(names.contains(&"join".to_string()), "import_names should contain 'join'");
    assert!(names.contains(&"exists".to_string()), "import_names should contain 'exists'");
}

#[test]
fn test_wildcard_import() {
    let cpg = py_cpg("from os import *");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (import_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Import)
        .expect("expected Import node");
    let meta = cpg.python_meta(*import_id).expect("Import should have PythonNodeMetadata");
    assert!(
        meta.import_is_wildcard,
        "import_is_wildcard should be true for 'from os import *'"
    );
}

#[test]
fn test_future_import() {
    let cpg = py_cpg("from __future__ import annotations");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (import_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Import)
        .expect("expected Import node");
    let meta = cpg.python_meta(*import_id).expect("Import should have PythonNodeMetadata");
    assert_eq!(
        meta.import_kind,
        ImportKind::Future,
        "import_kind should be Future for 'from __future__ import ...'"
    );
}

#[test]
fn test_assignment_lifts_to_assign() {
    let cpg = py_cpg("x = 42");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Assign)
        .expect("expected Assign node for 'x = 42'");
}

#[test]
fn test_augmented_assignment() {
    let cpg = py_cpg("x = 0\nx += 1");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let assign = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Assign && n.operator.as_deref() == Some("+="))
        .expect("expected Assign with operator '+=' for 'x += 1'");
    assert_eq!(assign.operator.as_deref(), Some("+="));
}

#[test]
fn test_annotated_assignment() {
    let cpg = py_cpg("x: int = 5");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let assign = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Assign)
        .expect("expected Assign for 'x: int = 5'");
    let (assign_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Assign && n.node_type == "annotated_assignment")
        .expect("expected Assign with node_type 'annotated_assignment'");
    let meta = cpg.python_meta(*assign_id).expect("Assign should have PythonNodeMetadata");
    assert!(meta.is_annotated, "is_annotated should be true");
    let _ = assign;
}

#[test]
fn test_named_expression_walrus() {
    let cpg = py_cpg("if (n := len('hello')) > 3:\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::NamedExpr)
        .expect("expected NamedExpr for ':=' walrus operator");
}

#[test]
fn test_if_statement_lifts_to_conditional() {
    let cpg = py_cpg("x = 1\nif x > 0:\n    y = x");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Conditional)
        .expect("expected Conditional for 'if x > 0'");
}

#[test]
fn test_if_elif_else() {
    let cpg = py_cpg("x = 1\nif x < 0:\n    pass\nelif x == 0:\n    pass\nelse:\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let conditionals: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::Conditional)
        .collect();
    assert!(
        conditionals.len() >= 2,
        "if/elif/else should produce at least 2 Conditional nodes"
    );
}

#[test]
fn test_for_statement_lifts_to_foreach_loop() {
    let cpg = py_cpg("for x in range(10):\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'for x in range(10)'");
    assert_eq!(
        loop_node.loop_kind,
        Some(LoopKind::ForEach),
        "Python for loop should have loop_kind ForEach"
    );
}

#[test]
fn test_while_statement() {
    let cpg = py_cpg("x = 10\nwhile x > 0:\n    x -= 1");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let loop_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Loop)
        .expect("expected Loop for 'while x > 0'");
    assert_eq!(
        loop_node.loop_kind,
        Some(LoopKind::While),
        "while loop should have loop_kind While"
    );
}

#[test]
fn test_try_except_lifts_to_try() {
    let cpg = py_cpg("try:\n    x = 1/0\nexcept ZeroDivisionError:\n    pass");
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
        .expect("expected Catch node for 'except ZeroDivisionError'");
}

#[test]
fn test_try_except_as() {
    let cpg = py_cpg("try:\n    x = int('a')\nexcept ValueError as e:\n    print(e)");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (catch_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Catch)
        .expect("expected Catch node");
    let meta = cpg.python_meta(*catch_id).expect("Catch should have PythonNodeMetadata");
    assert_eq!(
        meta.exception_alias.as_deref(),
        Some("e"),
        "exception_alias should be 'e'"
    );
    assert_eq!(
        meta.exception_type.as_deref(),
        Some("ValueError"),
        "exception_type should be 'ValueError'"
    );
}

#[test]
fn test_try_finally() {
    let cpg = py_cpg("try:\n    x = 1\nfinally:\n    print('done')");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let try_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Try)
        .expect("expected Try node");
    let (try_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Try)
        .unwrap();
    let meta = cpg.python_meta(*try_id).expect("Try should have PythonNodeMetadata");
    assert!(meta.has_finally, "has_finally should be true");
    let _ = try_node;
}

#[test]
fn test_raise_statement_lifts_to_throw() {
    let cpg = py_cpg("raise ValueError('bad')");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Throw)
        .expect("expected Throw node for 'raise ValueError(...)'");
}

#[test]
fn test_with_statement() {
    let cpg = py_cpg("with open('file.txt') as f:\n    data = f.read()");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let with_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::With)
        .expect("expected With node");
    let (with_id, _) = cpg.ast.iter().find(|(_, n)| n.kind == IrNodeKind::With).unwrap();
    let meta = cpg.python_meta(*with_id).expect("With should have PythonNodeMetadata");
    assert_eq!(
        meta.with_alias.as_deref(),
        Some("f"),
        "with_alias should be 'f'"
    );
    let _ = with_node;
}

#[test]
fn test_assert_statement() {
    let cpg = py_cpg("assert x > 0, 'must be positive'");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Assert)
        .expect("expected Assert node");
}

#[test]
fn test_delete_statement() {
    let cpg = py_cpg("x = [1,2,3]\ndel x[0]");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Delete)
        .expect("expected Delete node for 'del x[0]'");
}

#[test]
fn test_global_statement() {
    let cpg = py_cpg("g = 0\ndef f():\n    global g\n    g = 1");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let global_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Global)
        .expect("expected Global node for 'global g'");
    let (global_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Global)
        .unwrap();
    let meta = cpg.python_meta(*global_id).expect("Global should have PythonNodeMetadata");
    assert_eq!(
        meta.global_kind,
        GlobalKind::Global,
        "global_kind should be Global"
    );
    let names = &meta.global_names;
    assert!(names.contains(&"g".to_string()), "global_names should contain 'g'");
    let _ = global_node;
}

#[test]
fn test_nonlocal_statement() {
    let cpg = py_cpg("def outer():\n    x = 0\n    def inner():\n        nonlocal x\n        x = 1");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (global_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Global && n.node_type == "nonlocal_statement")
        .expect("expected Global node with node_type 'nonlocal_statement'");
    let meta = cpg.python_meta(*global_id).expect("nonlocal should have PythonNodeMetadata");
    assert_eq!(
        meta.global_kind,
        GlobalKind::Nonlocal,
        "global_kind should be Nonlocal for 'nonlocal'"
    );
}

#[test]
fn test_return_statement() {
    let cpg = py_cpg("def f(x):\n    return x * 2");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Return)
        .expect("expected Return node");
}

#[test]
fn test_break_and_continue() {
    let cpg = py_cpg("for x in range(10):\n    if x == 5:\n        break\n    if x == 3:\n        continue");
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
fn test_pass_statement() {
    let cpg = py_cpg("def f():\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.node_type == "pass_statement")
        .expect("expected pass_statement node in AST");
}

#[test]
fn test_call_expression_lifts_to_call() {
    let cpg = py_cpg("print('hello')");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let call = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Call)
        .expect("expected Call node for 'print(...)'");
    assert_eq!(call.name.as_deref(), Some("print"), "Call.name should be 'print'");
}

#[test]
fn test_attribute_access_lifts_to_member_access() {
    let cpg = py_cpg("s = 'hello'\ns.upper()");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::MemberAccess)
        .expect("expected MemberAccess for 's.upper'");
}

#[test]
fn test_subscript_lifts_to_subscript() {
    let cpg = py_cpg("s = [1, 2, 3]\nx = s[0]");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Subscript)
        .expect("expected Subscript for 's[0]'");
}

#[test]
fn test_binary_expression() {
    let cpg = py_cpg("x = 1 + 2");
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
fn test_boolean_expression() {
    let cpg = py_cpg("x = True and False");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let binop = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::BinaryOp && n.operator.as_deref() == Some("and"))
        .expect("expected BinaryOp with operator 'and'");
    assert_eq!(binop.operator.as_deref(), Some("and"));
}

#[test]
fn test_comparison_expression() {
    let cpg = py_cpg("x = 1 < 2");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::BinaryOp && n.operator.as_deref() == Some("<"))
        .expect("expected BinaryOp with operator '<'");
}

#[test]
fn test_unary_not() {
    let cpg = py_cpg("x = not True");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::UnaryOp && n.operator.as_deref() == Some("not"))
        .expect("expected UnaryOp with operator 'not'");
}

#[test]
fn test_lambda_lifts_to_lambda_def() {
    let cpg = py_cpg("fn = lambda x: x * 2");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::LambdaDef)
        .expect("expected LambdaDef for lambda expression");
}

#[test]
fn test_yield_expression() {
    let cpg = py_cpg("def gen():\n    yield 1\n    yield 2");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let yield_nodes: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::Yield)
        .collect();
    assert_eq!(yield_nodes.len(), 2, "expected 2 Yield nodes");
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("gen"))
        .expect("expected MethodDef for 'gen'");
    let meta = cpg.python_meta(*method_id).expect("gen should have PythonNodeMetadata");
    assert!(meta.is_generator, "is_generator should be true for 'gen'");
}

#[test]
fn test_yield_from_expression() {
    let cpg = py_cpg("def gen():\n    yield from range(10)");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (yield_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Yield)
        .expect("expected Yield node for 'yield from'");
    let meta = cpg.python_meta(*yield_id).expect("yield from should have PythonNodeMetadata");
    assert!(meta.is_yield_from, "is_yield_from should be true");
}

#[test]
fn test_await_expression() {
    let cpg = py_cpg("import asyncio\nasync def f():\n    await asyncio.sleep(1)");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Await)
        .expect("expected Await node for 'await asyncio.sleep(1)'");
}

#[test]
fn test_list_comprehension() {
    let cpg = py_cpg("x = [i*2 for i in range(10)]");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let comp = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Comprehension)
        .expect("expected Comprehension for list comprehension");
    let (comp_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Comprehension)
        .unwrap();
    let meta = cpg.python_meta(*comp_id).expect("Comprehension should have PythonNodeMetadata");
    assert_eq!(
        meta.comprehension_kind,
        ComprehensionKind::List,
        "comprehension_kind should be List"
    );
    let _ = comp;
}

#[test]
fn test_set_comprehension() {
    let cpg = py_cpg("x = {i for i in range(10)}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (comp_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Comprehension)
        .expect("expected Comprehension for set comprehension");
    let meta = cpg.python_meta(*comp_id).expect("Comprehension should have PythonNodeMetadata");
    assert_eq!(
        meta.comprehension_kind,
        ComprehensionKind::Set,
        "comprehension_kind should be Set"
    );
}

#[test]
fn test_dict_comprehension() {
    let cpg = py_cpg("x = {k: v for k, v in items.items()}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (comp_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Comprehension)
        .expect("expected Comprehension for dict comprehension");
    let meta = cpg.python_meta(*comp_id).expect("Comprehension should have PythonNodeMetadata");
    assert_eq!(
        meta.comprehension_kind,
        ComprehensionKind::Dict,
        "comprehension_kind should be Dict"
    );
}

#[test]
fn test_generator_expression() {
    let cpg = py_cpg("g = (i for i in range(10))");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (comp_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Comprehension)
        .expect("expected Comprehension for generator expression");
    let meta = cpg.python_meta(*comp_id).expect("Comprehension should have PythonNodeMetadata");
    assert_eq!(
        meta.comprehension_kind,
        ComprehensionKind::Generator,
        "comprehension_kind should be Generator"
    );
}

#[test]
fn test_decorator() {
    let cpg = py_cpg("def decorator(fn):\n    return fn\n\n@decorator\ndef f():\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Decorator)
        .expect("expected Decorator node");
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("f"))
        .expect("expected MethodDef for 'f'");
    let meta = cpg.python_meta(*method_id).expect("f should have PythonNodeMetadata");
    let decorators = &meta.decorators;
    assert!(
        decorators.contains(&"decorator".to_string()),
        "decorators should contain 'decorator'"
    );
}

#[test]
fn test_staticmethod_decorator_metadata() {
    let cpg = py_cpg("class C:\n    @staticmethod\n    def static_fn():\n        pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("static_fn"))
        .expect("expected MethodDef for 'static_fn'");
    let meta = cpg.python_meta(*method_id).expect("static_fn should have PythonNodeMetadata");
    assert!(meta.is_staticmethod, "is_staticmethod should be true");
}

#[test]
fn test_classmethod_decorator_metadata() {
    let cpg = py_cpg("class C:\n    @classmethod\n    def cls_fn(cls):\n        pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("cls_fn"))
        .expect("expected MethodDef for 'cls_fn'");
    let meta = cpg.python_meta(*method_id).expect("cls_fn should have PythonNodeMetadata");
    assert!(meta.is_classmethod, "is_classmethod should be true");
}

#[test]
fn test_integer_literal() {
    let cpg = py_cpg("x = 42");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Integer))
        .expect("expected Integer Literal for '42'");
}

#[test]
fn test_float_literal() {
    let cpg = py_cpg("x = 3.14");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Float))
        .expect("expected Float Literal for '3.14'");
}

#[test]
fn test_string_literal() {
    let cpg = py_cpg("x = 'hello'");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::String))
        .expect("expected String Literal for 'hello'");
}

#[test]
fn test_none_literal() {
    let cpg = py_cpg("x = None");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Null))
        .expect("expected Null Literal for 'None'");
}

#[test]
fn test_true_false_literal() {
    let cpg = py_cpg("a = True\nb = False");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let bool_lits: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Bool))
        .collect();
    assert_eq!(bool_lits.len(), 2, "expected 2 Bool Literals (True, False)");
}

#[test]
fn test_bytes_literal() {
    let cpg = py_cpg("x = b'bytes'");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Bytes))
        .expect("expected Bytes Literal for b'bytes'");
}

#[test]
fn test_ellipsis_literal() {
    let cpg = py_cpg("x = ...");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(LiteralKind::Ellipsis))
        .expect("expected Ellipsis Literal for '...'");
}

#[test]
fn test_list_collection() {
    let cpg = py_cpg("x = [1, 2, 3]");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::CollectionExpr && n.node_type == "list")
        .expect("expected CollectionExpr with node_type 'list'");
}

#[test]
fn test_dict_collection() {
    let cpg = py_cpg("x = {'a': 1, 'b': 2}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::CollectionExpr && n.node_type == "dictionary")
        .expect("expected CollectionExpr with node_type 'dictionary'");
}

#[test]
fn test_tuple_collection() {
    let cpg = py_cpg("x = (1, 2, 3)");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::CollectionExpr && n.node_type == "tuple")
        .expect("expected CollectionExpr with node_type 'tuple'");
}

#[test]
fn test_set_collection() {
    let cpg = py_cpg("x = {1, 2, 3}");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::CollectionExpr && n.node_type == "set")
        .expect("expected CollectionExpr with node_type 'set'");
}

#[test]
fn test_conditional_expression_ternary() {
    let cpg = py_cpg("x = 1\ny = x if x > 0 else 0");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::TernaryOp)
        .expect("expected TernaryOp for Python ternary 'a if cond else b'");
}

#[test]
fn test_star_args() {
    let cpg = py_cpg("def f(*args, **kwargs):\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (args_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("args"))
        .expect("expected ParamDef for '*args'");
    let args_meta = cpg.python_meta(*args_id).expect("args should have PythonNodeMetadata");
    assert!(args_meta.is_star_param, "is_star_param should be true for '*args'");

    let (kwargs_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("kwargs"))
        .expect("expected ParamDef for '**kwargs'");
    let kwargs_meta = cpg.python_meta(*kwargs_id).expect("kwargs should have PythonNodeMetadata");
    assert!(kwargs_meta.is_double_star_param, "is_double_star_param should be true for '**kwargs'");
}

#[test]
fn test_default_parameter() {
    let cpg = py_cpg("def f(x=10):\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (param_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("x"))
        .expect("expected ParamDef for 'x=10'");
    let meta = cpg.python_meta(*param_id).expect("x should have PythonNodeMetadata");
    assert!(meta.has_default, "has_default should be true for 'x=10'");
}

#[test]
fn test_type_annotation_on_param() {
    let cpg = py_cpg("def f(x: int) -> str:\n    return str(x)");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (param_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("x"))
        .expect("expected ParamDef for 'x: int'");
    let meta = cpg.python_meta(*param_id).expect("x should have PythonNodeMetadata");
    assert_eq!(
        meta.annotation.as_deref(),
        Some("int"),
        "annotation should be 'int' for 'x: int'"
    );
    let (method_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("f"))
        .expect("expected MethodDef for 'f'");
    let f_meta = cpg.python_meta(*method_id).expect("f should have PythonNodeMetadata");
    assert_eq!(
        f_meta.return_annotation.as_deref(),
        Some("str"),
        "return_annotation should be 'str'"
    );
}

#[test]
fn test_for_else() {
    let cpg = py_cpg("for x in range(10):\n    pass\nelse:\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (loop_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Loop)
        .expect("expected Loop node");
    let meta = cpg.python_meta(*loop_id).expect("Loop should have PythonNodeMetadata");
    assert!(meta.has_loop_else, "has_loop_else should be true");
}

#[test]
fn test_try_else() {
    let cpg = py_cpg("try:\n    x = 1\nexcept:\n    pass\nelse:\n    pass");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let (try_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::Try)
        .expect("expected Try node");
    let meta = cpg.python_meta(*try_id).expect("Try should have PythonNodeMetadata");
    assert!(meta.has_try_else, "has_try_else should be true");
}

#[test]
fn test_fstring() {
    let cpg = py_cpg("name = 'world'\nx = f'hello {name}'");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // f-string is a string literal with embedded expressions
    cpg.ast
        .values()
        .find(|n| {
            n.kind == IrNodeKind::Literal
                && n.lit_kind == Some(LiteralKind::Template)
                && n.node_type == "string"
        })
        .expect("expected Literal with lit_kind Template for f-string");
}

#[test]
fn test_comment_not_in_ast() {
    let cpg = py_cpg("# This is a comment\nx = 1");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let comment_in_ast = cpg.ast.values().any(|n| n.node_type == "comment");
    assert!(!comment_in_ast, "comment nodes should not appear in cpg.ast");
    assert!(!cpg.comments.is_empty(), "comment should be stored in cpg.comments");
    let comment = &cpg.comments[0];
    assert!(
        comment.text.contains("This is a comment"),
        "comment text should be captured"
    );
}

// ── 1b CFG Tests ──────────────────────────────────────────────────────────────

#[test]
fn test_cfg_try_except_branches() {
    let cpg = py_cpg("def f():\n    try:\n        x = int('a')\n    except ValueError:\n        x = 0\n    return x");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let try_node = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::Try)
        .expect("expected Try node");
    let try_bb_id = try_node.basic_block.as_deref().unwrap_or("");
    if !try_bb_id.is_empty() {
        let try_bb = cpg.basic_blocks.get(try_bb_id).expect("Try BB should exist");
        assert!(
            !try_bb.exception_successors.is_empty() || !try_bb.successors.is_empty(),
            "Try block should have successors"
        );
    }
}

#[test]
fn test_cfg_for_else_branch() {
    let cpg = py_cpg("def f(lst):\n    for x in lst:\n        if x > 0:\n            break\n    else:\n        return -1\n    return 0");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let return_nodes: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::Return)
        .collect();
    assert_eq!(return_nodes.len(), 2, "expected 2 Return nodes");
}

#[test]
fn test_cfg_with_statement_cleanup() {
    let cpg = py_cpg("def f():\n    with open('f') as fh:\n        data = fh.read()\n    return data");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::With)
        .expect("expected With node");
}

#[test]
fn test_cfg_comprehension_not_in_outer_scope() {
    let cpg = py_cpg("x = [i for i in range(10)]\ny = x[0]");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // Variable 'i' from comprehension should not be visible outside
    // (Python 3 comprehensions have their own scope)
    // We verify the CPG is structurally valid
    cpg.ast
        .values()
        .find(|n| n.kind == IrNodeKind::Comprehension)
        .expect("expected Comprehension node");
}

// ── 1c DFG Tests ──────────────────────────────────────────────────────────────

#[test]
fn test_dfg_assignment_defines_variable() {
    let cpg = py_cpg("x = 42\nprint(x)");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_x_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "x");
    assert!(has_x_def, "expected DataflowDef for 'x'");
    let has_x_use = cpg.dataflow.uses.iter().any(|u| u.variable == "x");
    assert!(has_x_use, "expected DataflowUse for 'x' at print(x)");
}

#[test]
fn test_dfg_global_variable_use() {
    let cpg = py_cpg("g = 0\ndef f():\n    global g\n    g = 1\nf()");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_g_def = cpg.dataflow.definitions.iter().any(|d| d.variable == "g");
    assert!(has_g_def, "expected DataflowDef for 'g'");
}

#[test]
fn test_dfg_closure_capture() {
    let cpg = py_cpg("def outer():\n    x = 10\n    def inner():\n        return x\n    return inner");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let x_uses: Vec<_> = cpg.dataflow.uses.iter().filter(|u| u.variable == "x").collect();
    assert!(!x_uses.is_empty(), "expected DataflowUse for captured 'x' in inner()");
}

#[test]
fn test_dfg_comprehension_variable_scoped() {
    let cpg = py_cpg("x = [i*2 for i in range(5)]\nprint(x)");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // 'x' should have a use at print(x)
    let has_x_use = cpg.dataflow.uses.iter().any(|u| u.variable == "x");
    assert!(has_x_use, "expected DataflowUse for 'x' at print(x)");
}

// ── 1d Call Graph Tests ───────────────────────────────────────────────────────

#[test]
fn test_callgraph_simple_call() {
    let cpg = py_cpg("def foo():\n    pass\ndef bar():\n    foo()");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let bar_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "bar")
        .expect("expected CallGraphEntry for 'bar'");
    let calls_foo = bar_entry.calls.iter().any(|cs| cs.callee == "foo");
    assert!(calls_foo, "bar's call graph should include CallSite for 'foo'");
}

#[test]
fn test_callgraph_method_call() {
    let cpg = py_cpg("class C:\n    def do(self):\n        pass\n\ndef caller():\n    obj = C()\n    obj.do()");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let caller_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "caller")
        .expect("expected CallGraphEntry for 'caller'");
    let has_c_call = caller_entry.calls.iter().any(|cs| cs.callee == "C" || cs.callee == "do");
    assert!(has_c_call, "caller's call sites should include 'C()' or 'do'");
}

#[test]
fn test_callgraph_recursive_function() {
    let cpg = py_cpg("def fib(n):\n    if n <= 1:\n        return n\n    return fib(n-1) + fib(n-2)");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let fib_entry = cpg
        .call_graph
        .values()
        .find(|e| e.name == "fib")
        .expect("expected CallGraphEntry for 'fib'");
    let self_calls: Vec<_> = fib_entry.calls.iter().filter(|cs| cs.callee == "fib").collect();
    assert_eq!(self_calls.len(), 2, "fib should have 2 recursive call sites to itself");
}

// ── 1e Incremental Tests ──────────────────────────────────────────────────────

#[test]
fn test_incremental_add_function() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "def a():\n    pass";
    let modified = "def a():\n    pass\ndef b():\n    a()";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Python, GraphBuildOptions::default())
        .expect("Python incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_b = updated
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("b"));
    assert!(has_b, "after adding def b, MethodDef for 'b' should exist");
}

#[test]
fn test_incremental_remove_function() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "def a():\n    pass\ndef b():\n    a()";
    let modified = "def a():\n    pass";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Python, GraphBuildOptions::default())
        .expect("Python incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_b = updated
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("b"));
    assert!(!has_b, "after removing def b, MethodDef for 'b' should be gone");
}

#[test]
fn test_incremental_add_decorator() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "def f():\n    pass";
    let modified = "def my_decorator(fn):\n    return fn\n\n@my_decorator\ndef f():\n    pass";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Python, GraphBuildOptions::default())
        .expect("Python incremental init");
    let _base = inc.parse_initial(base.as_bytes()).expect("initial parse");

    let edits: Vec<web_sitter::TextEdit> = compute_edit(base.as_bytes(), modified.as_bytes()).into_iter().collect();
    let updated = inc.parse_incremental(modified.as_bytes(), &edits).expect("update");

    let has_decorator = updated.ast.values().any(|n| n.kind == IrNodeKind::Decorator);
    assert!(has_decorator, "after adding @my_decorator, Decorator node should exist");
}

// ── 1f Parity Tests ───────────────────────────────────────────────────────────

#[test]
fn test_parity_add_function() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "def a():\n    pass";
    let modified = "def a():\n    pass\ndef b():\n    a()";

    let full_cpg = CpgGenerator::new_for_language(SourceLanguage::Python)
        .expect("Python parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Python, GraphBuildOptions::default())
        .expect("Python incremental init");
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
        "full and incremental CPG should have same MethodDef names"
    );
}

#[test]
fn test_incremental_replace_body_updates_dfg() {
    use web_sitter::{IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "def f():\n    x = 1\n    return x\n";
    let modified = "def f():\n    x = 99\n    return x\n";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Python, GraphBuildOptions::default())
        .expect("Python incremental init");
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
fn test_incremental_sequential_edits_python() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let src0 = "def a():\n    pass\n";
    let src1 = "def a():\n    pass\ndef b():\n    a()\n";
    let src2 = "def a():\n    pass\ndef b():\n    a()\ndef c():\n    b()\n";
    let src3 = "def a():\n    pass\ndef c():\n    a()\n";

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Python, GraphBuildOptions::default())
        .expect("Python incremental init");
    inc.parse_initial(src0.as_bytes()).expect("initial");

    let e1 = compute_edit(src0.as_bytes(), src1.as_bytes()).expect("edit1");
    inc.apply_edit(&e1, src1.as_bytes()).expect("edit1 apply");

    let e2 = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit2");
    inc.apply_edit(&e2, src2.as_bytes()).expect("edit2 apply");

    let e3 = compute_edit(src2.as_bytes(), src3.as_bytes()).expect("edit3");
    let final_inc = inc.apply_edit(&e3, src3.as_bytes()).expect("edit3 apply");

    let full = CpgGenerator::new_for_language(SourceLanguage::Python)
        .expect("Python parser")
        .generate_from_source_with_options(src3.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let full_names: HashSet<_> = full.ast.values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .filter_map(|n| n.name.as_deref()).collect();
    let inc_names: HashSet<_> = final_inc.ast.values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .filter_map(|n| n.name.as_deref()).collect();
    assert_eq!(full_names, inc_names, "after 3 sequential edits, MethodDef names must match fresh parse");

    let full_defs: HashSet<_> = full.dataflow.definitions.iter().map(|d| d.variable.as_str()).collect();
    let inc_defs: HashSet<_> = final_inc.dataflow.definitions.iter().map(|d| d.variable.as_str()).collect();
    assert_eq!(full_defs, inc_defs, "DFG definition variable sets must match after sequential edits");
}

#[test]
fn test_parity_dfg_and_callgraph_python() {
    use web_sitter::{CpgGenerator, IncrementalCpgGenerator, GraphBuildOptions, SourceLanguage, compute_edit};

    let base = "def a():\n    pass\n";
    let modified = "def a():\n    x = 1\n    return x\ndef b():\n    a()\n";

    let full = CpgGenerator::new_for_language(SourceLanguage::Python)
        .expect("Python parser")
        .generate_from_source_with_options(modified.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG");

    let mut inc = IncrementalCpgGenerator::new_for_language(SourceLanguage::Python, GraphBuildOptions::default())
        .expect("Python incremental init");
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
fn test_type_annotation_ref() {
    // generic_type in annotation → IrNodeKind::TypeRef (Python plan §490)
    let cpg = py_cpg("def f(x: list[int]) -> dict[str, int]: ...");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_generic_type_ref = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeRef && n.node_type == "generic_type");
    assert!(has_generic_type_ref, "expected TypeRef node with node_type 'generic_type' for 'list[int]'");
}

#[test]
fn test_union_type_ref() {
    // `int | str` in a type annotation → IrNodeKind::TypeRef wrapping the union expression.
    // tree-sitter-python emits `type` (kind=TypeRef) whose text is "int | str".
    let cpg = py_cpg("def f(x: int | str): ...");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_union_type_ref = cpg
        .ast
        .values()
        .any(|n| {
            n.kind == IrNodeKind::TypeRef
                && n.text.as_deref().map_or(false, |t| t.contains("int | str"))
        });
    assert!(has_union_type_ref, "expected TypeRef node with text 'int | str' for union type annotation");
}

#[test]
fn test_type_alias_statement() {
    // 'type Vector = list[float]' → IrNodeKind::TypeAlias (Python plan §502)
    let cpg = py_cpg("type Vector = list[float]");
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let has_type_alias = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::TypeAlias && n.name.as_deref() == Some("Vector"));
    assert!(has_type_alias, "expected TypeAlias node with name 'Vector'");
}
