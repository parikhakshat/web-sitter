//! Direct counterparts for `test_identifier_flag.py`.

use web_sitter::{CpgGenerator, GraphBuildOptions, IncrementalCpgGenerator, SymbolAnonymizer};

const TEST_CODE: &str = r#"
int main(int argc, char **argv) {
    int x = 5;
    int y = x + 10;
    printf("Hello, World%s!\n", y);
    return y;
}
"#;

fn count_identifiers(cpg: &web_sitter::Cpg) -> usize {
    cpg.ast
        .values()
        .filter(|node| node.node_type == "identifier")
        .count()
}

#[test]
fn test_cpg_generator() {
    let mut generator = CpgGenerator::new().expect("generator");
    let with_ids = generator
        .generate_from_source_with_options(
            TEST_CODE.as_bytes(),
            GraphBuildOptions {
                minimal_text: false,
                remove_identifiers: false,
                ..GraphBuildOptions::default()
            },
        )
        .expect("with identifiers");
    assert!(count_identifiers(&with_ids) > 0);
    assert!(!with_ids.dataflow.edges.is_empty());

    let without_ids = generator
        .generate_from_source_with_options(
            TEST_CODE.as_bytes(),
            GraphBuildOptions {
                minimal_text: false,
                remove_identifiers: true,
                ..GraphBuildOptions::default()
            },
        )
        .expect("without identifiers");
    assert_eq!(count_identifiers(&without_ids), 0);
    assert!(!without_ids.dataflow.edges.is_empty());
}

#[test]
fn test_incremental_cpg() {
    let mut with_ids = IncrementalCpgGenerator::new(GraphBuildOptions {
        minimal_text: false,
        remove_identifiers: false,
        ..GraphBuildOptions::default()
    })
    .expect("incremental");
    let cpg_with_ids = with_ids
        .parse_full(TEST_CODE.as_bytes())
        .expect("full")
        .clone();
    assert!(count_identifiers(&cpg_with_ids) > 0);
    assert!(!cpg_with_ids.dataflow.edges.is_empty());

    let mut without_ids = IncrementalCpgGenerator::new(GraphBuildOptions {
        minimal_text: false,
        remove_identifiers: true,
        ..GraphBuildOptions::default()
    })
    .expect("incremental");
    let cpg_without_ids = without_ids
        .parse_full(TEST_CODE.as_bytes())
        .expect("full")
        .clone();
    assert_eq!(count_identifiers(&cpg_without_ids), 0);
    assert!(!cpg_without_ids.dataflow.edges.is_empty());
}

#[test]
fn test_symbol_table() {
    let mut generator = CpgGenerator::new().expect("generator");
    let cpg = generator
        .generate_from_source_with_options(
            TEST_CODE.as_bytes(),
            GraphBuildOptions {
                minimal_text: false,
                remove_identifiers: false,
                ..GraphBuildOptions::default()
            },
        )
        .expect("cpg");

    let mut anonymizer = SymbolAnonymizer::new();
    let anonymized = anonymizer.anonymize(&cpg);
    assert!(
        !anonymized.symbol_table.is_empty(),
        "symbol table should contain anonymized mappings"
    );

    let mut generator = CpgGenerator::new().expect("generator");
    let pruned = generator
        .generate_from_source_with_options(
            TEST_CODE.as_bytes(),
            GraphBuildOptions {
                minimal_text: false,
                remove_identifiers: true,
                ..GraphBuildOptions::default()
            },
        )
        .expect("pruned cpg");
    let mut anonymizer = SymbolAnonymizer::new();
    let _anonymized_pruned = anonymizer.anonymize(&pruned);
    // With remove_identifiers=true all identifiers are already stripped,
    // so the symbol table is empty — the important thing is it doesn't panic.
}
