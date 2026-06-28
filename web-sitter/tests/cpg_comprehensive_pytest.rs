//! Direct counterparts for `tests/test_cpg_comprehensive_pytest.py`.

use web_sitter::Cpg;
use web_sitter::{CpgGenerator, GraphBuildOptions, IncrementalCpgGenerator, compute_edit};

#[path = "cpg_comprehensive.rs"]
mod cpg_comprehensive;

fn cases() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "basic_call",
            "void helper(int x) {} int main(void){ int v = 1; helper(v); return 0; }",
            "void helper(int x) {} int main(void){ int v = 2; helper(v); return 0; }",
        ),
        (
            "control_flow",
            "int main(int x){ if (x > 0) { return x; } return 0; }",
            "int main(int x){ if (x >= 0) { return x; } return 0; }",
        ),
        (
            "struct_field",
            "struct P { int x; }; int main(void){ struct P p; p.x = 3; return p.x; }",
            "struct P { int x; }; int main(void){ struct P p; p.x = 4; return p.x; }",
        ),
    ]
}

fn parse_main(src: &str) -> Cpg {
    let mut generator = CpgGenerator::new().expect("generator");
    generator
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("main parse")
}

fn parse_incremental_full(src: &str) -> Cpg {
    let mut generator =
        IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("incremental");
    generator
        .parse_full(src.as_bytes())
        .expect("incremental full")
        .clone()
}

fn parse_incremental_update(old_src: &str, new_src: &str) -> Cpg {
    let mut generator =
        IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("incremental");
    generator
        .parse_initial(old_src.as_bytes())
        .expect("initial");
    let edit = compute_edit(old_src.as_bytes(), new_src.as_bytes()).expect("edit");
    generator
        .parse_incremental(new_src.as_bytes(), &[edit])
        .expect("incremental update")
        .clone()
}

fn ast_signature(cpg: &Cpg) -> Vec<(String, Option<String>, Option<u32>, Option<u32>)> {
    let mut items: Vec<_> = cpg
        .ast
        .values()
        .map(|n| {
            (
                n.node_type.clone(),
                n.operator.clone(),
                n.argument_count,
                n.string_length,
            )
        })
        .collect();
    items.sort();
    items
}

#[test]
fn test_case_main_cpg_generation() {
    for (name, src, _) in cases() {
        let cpg = parse_main(src);
        assert!(
            !cpg.ast.is_empty(),
            "Main CPG generation failed for case '{name}'"
        );
    }
}

#[test]
fn test_case_incremental_full_cpg_generation() {
    for (name, src, _) in cases() {
        let cpg = parse_incremental_full(src);
        assert!(
            !cpg.ast.is_empty(),
            "Incremental full CPG generation failed for case '{name}'"
        );
    }
}

#[test]
fn test_case_main_vs_incremental_full_equivalence() {
    for (name, src, _) in cases() {
        let main = parse_main(src);
        let inc = parse_incremental_full(src);
        assert_eq!(
            ast_signature(&main),
            ast_signature(&inc),
            "Main vs incremental full equivalence failed for case '{name}'"
        );
    }
}

#[test]
fn test_case_incremental_update_equivalence() {
    for (name, old_src, new_src) in cases() {
        let fresh = parse_main(new_src);
        let inc = parse_incremental_update(old_src, new_src);
        assert_eq!(
            ast_signature(&fresh),
            ast_signature(&inc),
            "Incremental update equivalence failed for case '{name}'"
        );
    }
}

#[test]
fn test_comprehensive_cpg_harness_run_suite_zero_engine_bugs() {
    // The Rust workspace already ports the individual checks from the Python harness.
    // This test keeps a one-to-one pytest counterpart that exercises the same major gates.
    for (_, src, new_src) in cases() {
        let main = parse_main(src);
        let inc_full = parse_incremental_full(src);
        let inc_update = parse_incremental_update(src, new_src);
        assert!(!main.ast.is_empty());
        assert_eq!(ast_signature(&main), ast_signature(&inc_full));
        assert_eq!(
            ast_signature(&parse_main(new_src)),
            ast_signature(&inc_update)
        );
    }
}
