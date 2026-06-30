//! Incremental CPG tests — verify structural equivalence between main and incremental parsers.

use web_sitter::Cpg;
use web_sitter::{
    CpgGenerator, GraphBuildOptions, IncrementalCpgGenerator, IrNodeKind, SourceLanguage,
    compute_edit, generate_cpg_from_code,
};
use std::collections::HashSet;

fn generate_cpg_for_language(language: SourceLanguage, src: &str) -> Cpg {
    CpgGenerator::new_for_language(language)
        .expect("parser init")
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("full CPG generation failed")
}

fn node_types(cpg: &Cpg) -> HashSet<String> {
    cpg.ast.values().map(|n| n.node_type.clone()).collect()
}

fn call_names(cpg: &Cpg) -> HashSet<String> {
    cpg.call_graph.values().map(|e| e.name.clone()).collect()
}

fn new_incremental() -> IncrementalCpgGenerator {
    IncrementalCpgGenerator::new(GraphBuildOptions::default())
        .expect("failed to create IncrementalCpgGenerator")
}

fn new_incremental_for(language: SourceLanguage) -> IncrementalCpgGenerator {
    IncrementalCpgGenerator::new_for_language(language, GraphBuildOptions::default())
        .expect("failed to create IncrementalCpgGenerator")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn incremental_full_parse_matches_main_cpg() {
    let src = r#"
        void bar(int x) { x = x * 2; }
        void foo() { bar(3); }
    "#;

    let main_cpg = generate_cpg_from_code(src).expect("main CPG failed");
    let mut inc_gen = new_incremental();
    let inc_cpg = inc_gen
        .parse_initial(src.as_bytes())
        .expect("incremental initial parse failed");

    let main_types = node_types(&main_cpg);
    let inc_types = node_types(inc_cpg);

    // Both should have the same set of node types (structural equivalence).
    let in_main_not_inc: Vec<_> = main_types.difference(&inc_types).collect();
    let in_inc_not_main: Vec<_> = inc_types.difference(&main_types).collect();
    assert!(
        in_main_not_inc.is_empty() && in_inc_not_main.is_empty(),
        "node type sets differ:\n  only in main: {:?}\n  only in incremental: {:?}",
        in_main_not_inc,
        in_inc_not_main
    );

    // Call graphs should identify the same functions.
    assert_eq!(
        call_names(&main_cpg),
        call_names(inc_cpg),
        "call_graph function names differ between main and incremental CPG"
    );
}

#[test]
fn incremental_update_produces_valid_cpg() {
    let src1 = "void f() { int x = 5; }";
    let src2 = "void f() { int x = 10; }";

    let mut inc_gen = new_incremental();
    inc_gen
        .parse_initial(src1.as_bytes())
        .expect("initial parse");

    let edit = compute_edit(src1.as_bytes(), src2.as_bytes())
        .expect("compute_edit returned None for differing sources");
    let updated = inc_gen
        .apply_edit(&edit, src2.as_bytes())
        .expect("apply_edit failed");

    assert!(!updated.ast.is_empty(), "CPG after edit must not be empty");
    for (id, node) in &updated.ast {
        assert!(
            !node.node_type.is_empty(),
            "node {id} has empty node_type after edit"
        );
        for child_id in &node.children {
            assert!(
                updated.ast.contains_key(child_id),
                "child {child_id} of node {id} not in AST after edit"
            );
        }
    }
}

#[test]
fn incremental_update_preserves_unchanged_node_types() {
    // Changing `y`'s value should not affect the node types for `x`.
    let src1 = "void f() { int x = 5; int y = 10; }";
    let src2 = "void f() { int x = 5; int y = 99; }";

    let main_for_src2 = generate_cpg_from_code(src2).expect("main CPG for src2");

    let mut inc_gen = new_incremental();
    inc_gen
        .parse_initial(src1.as_bytes())
        .expect("initial parse");
    let edit = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit should exist");
    let inc_updated = inc_gen
        .apply_edit(&edit, src2.as_bytes())
        .expect("apply_edit");

    // The set of node types should match a fresh full parse.
    let main_types: HashSet<String> = node_types(&main_for_src2);
    let inc_types: HashSet<String> = node_types(inc_updated);
    assert_eq!(
        main_types, inc_types,
        "node type sets should match after edit"
    );
}

#[test]
fn incremental_dfg_equivalent_after_edit() {
    // Edit one function body; the unchanged function's DFG should be equivalent
    // to a fresh parse of the updated source.
    let src1 = "void foo(int x) { x = x + 1; } void bar(int y) { y = y * 2; }";
    let src2 = "void foo(int x) { x = x + 99; } void bar(int y) { y = y * 2; }";

    let main_for_src2 = generate_cpg_from_code(src2).expect("main CPG for src2");

    let mut inc_gen = new_incremental();
    inc_gen
        .parse_initial(src1.as_bytes())
        .expect("initial parse");
    let edit = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit should exist");
    let inc_updated = inc_gen
        .apply_edit(&edit, src2.as_bytes())
        .expect("apply_edit");

    // `bar` is unchanged: its definitions should be the same in both.
    let main_bar_defs: Vec<_> = main_for_src2
        .dataflow
        .definitions
        .iter()
        .filter(|d| {
            d.function_id
                .and_then(|fid| main_for_src2.call_graph.get(&fid))
                .map(|e| e.name == "bar")
                .unwrap_or(false)
        })
        .map(|d| d.variable.clone())
        .collect();

    let inc_bar_defs: Vec<_> = inc_updated
        .dataflow
        .definitions
        .iter()
        .filter(|d| {
            d.function_id
                .and_then(|fid| inc_updated.call_graph.get(&fid))
                .map(|e| e.name == "bar")
                .unwrap_or(false)
        })
        .map(|d| d.variable.clone())
        .collect();

    let mut main_sorted = main_bar_defs.clone();
    let mut inc_sorted = inc_bar_defs.clone();
    main_sorted.sort();
    inc_sorted.sort();
    assert_eq!(
        main_sorted, inc_sorted,
        "bar's DFG definitions should be the same after editing foo"
    );
}

#[test]
fn incremental_multiple_edits_matches_fresh_parse() {
    let src0 = "void f() { int a = 1; }";
    let src1 = "void f() { int a = 2; }";
    let src2 = "void f() { int a = 2; int b = 3; }";
    let src3 = "void f() { int a = 2; int b = 4; }";

    let mut inc_gen = new_incremental();
    inc_gen
        .parse_initial(src0.as_bytes())
        .expect("initial parse");

    let edit1 = compute_edit(src0.as_bytes(), src1.as_bytes()).expect("edit1");
    inc_gen
        .apply_edit(&edit1, src1.as_bytes())
        .expect("edit1 apply");

    let edit2 = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit2");
    inc_gen
        .apply_edit(&edit2, src2.as_bytes())
        .expect("edit2 apply");

    let edit3 = compute_edit(src2.as_bytes(), src3.as_bytes()).expect("edit3");
    let final_inc = inc_gen
        .apply_edit(&edit3, src3.as_bytes())
        .expect("edit3 apply");

    let main_final = generate_cpg_from_code(src3).expect("main CPG for src3");

    assert_eq!(
        node_types(&main_final),
        node_types(final_inc),
        "after 3 sequential edits, node type set should match fresh parse"
    );
}

#[test]
fn incremental_replace_edit_preserves_dfg() {
    // Modifying a literal value is a Replace edit; DFG structure must survive.
    let src1 = "void f() { int x = 1; int y = x * 2; }";
    let src2 = "void f() { int x = 99; int y = x * 2; }";

    let main_for_src2 = generate_cpg_from_code(src2).expect("main CPG for src2");

    let mut inc_gen = new_incremental();
    inc_gen.parse_initial(src1.as_bytes()).expect("initial parse");

    let edit = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit should exist");
    use web_sitter::ChangeType;
    assert_eq!(edit.change_type, ChangeType::Replace, "changing a literal value should produce a Replace edit");

    let inc_updated = inc_gen.apply_edit(&edit, src2.as_bytes()).expect("apply_edit");

    // Both full and incremental should define x and y.
    let full_def_vars: HashSet<String> = main_for_src2
        .dataflow.definitions.iter().map(|d| d.variable.clone()).collect();
    let inc_def_vars: HashSet<String> = inc_updated
        .dataflow.definitions.iter().map(|d| d.variable.clone()).collect();
    assert_eq!(full_def_vars, inc_def_vars,
        "DFG definition variable sets must match after Replace edit");

    let full_use_vars: HashSet<String> = main_for_src2
        .dataflow.uses.iter().map(|u| u.variable.clone()).collect();
    let inc_use_vars: HashSet<String> = inc_updated
        .dataflow.uses.iter().map(|u| u.variable.clone()).collect();
    assert_eq!(full_use_vars, inc_use_vars,
        "DFG use variable sets must match after Replace edit");
}

#[test]
fn incremental_parity_callgraph_and_dfg() {
    // Stronger parity: after an add-function edit, call graph and DFG must
    // match a fresh full parse — not just node type sets.
    let src_base = "void helper(int v) { v = v + 1; }";
    let src_full = "void helper(int v) { v = v + 1; } void caller() { int x = 5; helper(x); }";

    let main_cpg = generate_cpg_from_code(src_full).expect("main CPG");

    let mut inc_gen = new_incremental();
    inc_gen.parse_initial(src_base.as_bytes()).expect("initial parse");
    let edit = compute_edit(src_base.as_bytes(), src_full.as_bytes()).expect("edit");
    let inc_cpg = inc_gen.apply_edit(&edit, src_full.as_bytes()).expect("apply_edit");

    // Call graph function names must match.
    assert_eq!(
        call_names(&main_cpg),
        call_names(inc_cpg),
        "call graph names must match between full and incremental after insert"
    );

    // DFG definition variable sets must match.
    let main_defs: HashSet<String> = main_cpg.dataflow.definitions.iter()
        .map(|d| d.variable.clone()).collect();
    let inc_defs: HashSet<String> = inc_cpg.dataflow.definitions.iter()
        .map(|d| d.variable.clone()).collect();
    assert_eq!(main_defs, inc_defs,
        "DFG definition variables must match between full and incremental");

    // DFG use variable sets must match.
    let main_uses: HashSet<String> = main_cpg.dataflow.uses.iter()
        .map(|u| u.variable.clone()).collect();
    let inc_uses: HashSet<String> = inc_cpg.dataflow.uses.iter()
        .map(|u| u.variable.clone()).collect();
    assert_eq!(main_uses, inc_uses,
        "DFG use variables must match between full and incremental");
}

#[test]
fn incremental_cpp_base_classes_and_hierarchy_update_after_edit() {
    // Editing a class to add a base class must update cpp_metadata.base_classes
    // and workspace.class_hierarchy on the incremental path, not just on a full parse.
    let src1 = "class Base { public: void greet(); }; class Foo { public: void bar(); };";
    let src2 = "class Base { public: void greet(); }; class Foo : public Base { public: void bar(); };";

    let main_for_src2 = generate_cpg_for_language(SourceLanguage::Cpp, src2);

    let mut inc_gen = new_incremental_for(SourceLanguage::Cpp);
    inc_gen.parse_initial(src1.as_bytes()).expect("initial parse");
    let edit = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit should exist");
    let inc_updated = inc_gen.apply_edit(&edit, src2.as_bytes()).expect("apply_edit");

    let find_foo_base_classes = |cpg: &Cpg| -> Vec<String> {
        cpg.ast
            .values()
            .find(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Foo"))
            .and_then(|n| n.base_classes.clone())
            .unwrap_or_default()
    };

    assert_eq!(
        find_foo_base_classes(&main_for_src2),
        vec!["Base".to_string()],
        "sanity check: full parse should report Foo's base class"
    );
    assert_eq!(
        find_foo_base_classes(inc_updated),
        vec!["Base".to_string()],
        "incremental update must refresh cpp_metadata.base_classes for the edited class, \
         not silently carry forward the pre-edit (empty) value"
    );

    assert_eq!(
        main_for_src2.workspace.class_hierarchy.get("Foo").cloned().unwrap_or_default(),
        vec!["Base".to_string()],
        "sanity check: full parse should populate class_hierarchy for Foo"
    );
    assert_eq!(
        inc_updated.workspace.class_hierarchy.get("Foo").cloned().unwrap_or_default(),
        vec!["Base".to_string()],
        "incremental update must recompute workspace.class_hierarchy, not carry forward \
         the pre-edit (empty) value"
    );
}

#[test]
fn incremental_java_package_name_survives_unrelated_class_edit() {
    // package_name is derived from a sibling package_declaration node, outside any single
    // edited class's subtree. Editing the class must not lose it.
    let src1 = "package com.example; class Foo { void bar() {} }";
    let src2 = "package com.example; class Foo { void bar() { int x = 1; } }";

    let main_for_src2 = generate_cpg_for_language(SourceLanguage::Java, src2);

    let mut inc_gen = new_incremental_for(SourceLanguage::Java);
    inc_gen.parse_initial(src1.as_bytes()).expect("initial parse");
    let edit = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit should exist");
    let inc_updated = inc_gen.apply_edit(&edit, src2.as_bytes()).expect("apply_edit");

    let find_foo_package = |cpg: &Cpg| -> Option<String> {
        cpg.ast
            .iter()
            .find(|(_, n)| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some("Foo"))
            .and_then(|(id, _)| cpg.java_metadata.get(id))
            .and_then(|m| m.package_name.clone())
    };

    assert_eq!(
        find_foo_package(&main_for_src2),
        Some("com.example".to_string()),
        "sanity check: full parse should report Foo's package_name"
    );
    assert_eq!(
        find_foo_package(inc_updated),
        Some("com.example".to_string()),
        "incremental update must keep package_name correct even though the edited \
         subtree (the method body) doesn't itself contain the package_declaration"
    );
}

#[test]
fn incremental_cpp_virtual_dispatch_recomputed_after_edit() {
    // is_virtual_dispatch is set by enrich_call_graph_cpp, which the incremental path used
    // to skip entirely — verify it now matches a full parse after an incremental edit.
    // `call_it` is a method of `Sub`, itself a derived class (a key in class_hierarchy),
    // so enrich_call_graph_cpp flags the b->speak() call site as virtual-dispatch.
    let src1 = r#"
        class Base { public: virtual void speak(); };
        class Sub : public Base {
        public:
            void speak();
            void call_it(Base* b) { b->speak(); }
        };
    "#;
    let src2 = r#"
        class Base { public: virtual void speak(); };
        class Sub : public Base {
        public:
            void speak();
            void call_it(Base* b) { b->speak(); b->speak(); }
        };
    "#;

    let main_for_src2 = generate_cpg_for_language(SourceLanguage::Cpp, src2);

    let mut inc_gen = new_incremental_for(SourceLanguage::Cpp);
    inc_gen.parse_initial(src1.as_bytes()).expect("initial parse");
    let edit = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit should exist");
    let inc_updated = inc_gen.apply_edit(&edit, src2.as_bytes()).expect("apply_edit");

    let virtual_dispatch_call_count = |cpg: &Cpg| -> usize {
        cpg.cpp_metadata.values().filter(|m| m.is_virtual_dispatch).count()
    };

    let main_count = virtual_dispatch_call_count(&main_for_src2);
    assert!(main_count > 0, "sanity check: full parse should flag virtual dispatch calls");
    assert_eq!(
        virtual_dispatch_call_count(inc_updated),
        main_count,
        "incremental update must recompute is_virtual_dispatch flags, not leave the \
         call-graph enrichment pass entirely unrun"
    );
}

#[test]
fn incremental_edit_inside_one_method_preserves_unrelated_class_members() {
    // Regression test: editing inside one method body of a multi-member class must not
    // delete unrelated sibling members (fields/methods) of that same class from the AST.
    // The top-level diff treats the whole class as one unit; when the class's structural
    // key is reused (because only a nested method body changed), the now-unused
    // pre-edit AST snapshot must not be allowed to clobber the reused sibling node ids.
    let src1 = r#"
        class Widget {
        public:
            int width;
            int height;
            void resize(int w) { width = w; }
            void describe() { int x = width; }
        };
    "#;
    let src2 = r#"
        class Widget {
        public:
            int width;
            int height;
            void resize(int w) { width = w; width = width + 1; }
            void describe() { int x = width; }
        };
    "#;

    let main_for_src2 = generate_cpg_for_language(SourceLanguage::Cpp, src2);

    let mut inc_gen = new_incremental_for(SourceLanguage::Cpp);
    inc_gen.parse_initial(src1.as_bytes()).expect("initial parse");
    let edit = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("edit should exist");
    let inc_updated = inc_gen.apply_edit(&edit, src2.as_bytes()).expect("apply_edit");

    let method_names = |cpg: &Cpg| -> HashSet<String> {
        cpg.ast
            .values()
            .filter(|n| n.kind == IrNodeKind::MethodDef)
            .filter_map(|n| n.name.clone())
            .collect()
    };
    let field_count = |cpg: &Cpg| -> usize {
        cpg.ast.values().filter(|n| n.kind == IrNodeKind::FieldDef).count()
    };

    let main_members = method_names(&main_for_src2);
    assert!(
        main_members.contains("resize") && main_members.contains("describe"),
        "sanity check: full parse should retain both Widget methods: {main_members:?}"
    );
    let main_field_count = field_count(&main_for_src2);
    assert_eq!(main_field_count, 2, "sanity check: full parse should retain both Widget fields");

    let inc_members = method_names(inc_updated);
    assert_eq!(
        inc_members, main_members,
        "editing resize() must not delete the unrelated sibling method (describe) \
         from the incremental AST"
    );
    assert_eq!(
        field_count(inc_updated),
        main_field_count,
        "editing resize() must not delete unrelated sibling fields (width/height) \
         from the incremental AST"
    );

    // `describe`, which was never touched, should still reference `width` in its DFG uses.
    let describe_uses_width = inc_updated
        .dataflow
        .uses
        .iter()
        .any(|u| u.variable == "width");
    assert!(
        describe_uses_width,
        "DFG uses for the unaffected `describe` method must survive the edit"
    );
}
