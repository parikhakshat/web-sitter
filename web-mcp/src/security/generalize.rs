//! Query-by-example generalization: turn one known bug instance (a `Finding`'s matched
//! nodes, or any explicit `NodeId` set) into a runnable ScuzzQL rule that finds
//! structurally similar instances elsewhere in the codebase.
//!
//! Structural-only first pass (per the design doc — dataflow-aware generalization is a
//! later refinement): the CWE rule corpus's dominant pattern is already
//! `find n: Call where n.callee_name() in [...]` (see `web-ql-queries/`), so the anchor
//! this module extracts is exactly that — every `Call` node among the example's matched
//! nodes, generalized to "any call to one of these callee names," dropping the specific
//! argument/variable identifiers the same way `symbol_anonymizer.rs` preserves function
//! names while anonymizing user variables. An example with no `Call` node among its
//! matched nodes can't be generalized this way yet — `generalize_call_pattern` returns
//! `None` rather than emitting a rule that would match nothing (or everything).

use std::collections::BTreeSet;

use web_ql::kind_index::KindIndex;
use web_sitter::{Cpg, IrNodeKind, NodeId};

#[derive(Debug, Clone, PartialEq)]
pub struct GeneralizedRule {
    /// A fresh rule id derived from `base_rule_id` (never reuses it — this is a distinct,
    /// derived rule, not a redefinition of the original).
    pub rule_id: String,
    /// Compilable ScuzzQL rule source — pass straight to `web_ql::compile_rules`.
    pub rule_source: String,
    /// The callee names the generalized rule anchors on, for display/debugging without
    /// re-parsing `rule_source`.
    pub anchor_callees: Vec<String>,
}

/// Escape a callee name for embedding in a ScuzzQL string literal. Callee names are
/// identifiers/paths in practice (`system`, `os.system`, `Runtime.exec`) and never
/// contain a `"`, but this is cheap insurance against a pathological identifier breaking
/// the generated rule's syntax.
fn escape_string_literal(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Extract every `Call` node's callee name among `matched_nodes` and emit a rule matching
/// calls to any of them. Returns `None` when no matched node is a `Call` (nothing to
/// anchor a structural-only generalization on) — a caller shouldn't fall back to a rule
/// that matches too broadly.
pub fn generalize_call_pattern(
    cpg: &Cpg,
    kind_index: &KindIndex,
    matched_nodes: &[NodeId],
    base_rule_id: &str,
    severity: &str,
    message: &str,
) -> Option<GeneralizedRule> {
    let mut callees: BTreeSet<String> = BTreeSet::new();
    for &node_id in matched_nodes {
        let Some(node) = cpg.ast.get(&node_id) else {
            continue;
        };
        if node.kind != IrNodeKind::Call {
            continue;
        }
        if let Some(call_site) = kind_index.call_site_for_node(node_id) {
            callees.insert(call_site.callee.clone());
        }
    }
    if callees.is_empty() {
        return None;
    }

    let rule_id = format!("{base_rule_id}-variant");
    let callee_list = callees
        .iter()
        .map(|c| format!("\"{}\"", escape_string_literal(c)))
        .collect::<Vec<_>>()
        .join(", ");
    let escaped_message = escape_string_literal(message);
    let rule_source = format!(
        "rule \"{rule_id}\" {{\n    \
         severity: {severity}\n    \
         languages: [{language}]\n    \
         message: \"{escaped_message}\"\n    \
         find n: Call where n.callee_name() in [{callee_list}]\n\
         }}\n",
        language = cpg.language,
    );

    Some(GeneralizedRule {
        rule_id,
        rule_source,
        anchor_callees: callees.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use web_ql::workspace::Workspace;
    use web_sitter::cpg_generator::{GraphBuildOptions, SourceLanguage};
    use web_sitter::incremental::IncrementalCpgGenerator;

    fn parse(lang: SourceLanguage, src: &str) -> Cpg {
        let mut generator =
            IncrementalCpgGenerator::new_for_language(lang, GraphBuildOptions::default())
                .expect("generator");
        generator.parse_full(src.as_bytes()).expect("parse").clone()
    }

    fn call_node_id(cpg: &Cpg) -> NodeId {
        cpg.ast
            .iter()
            .find(|(_, n)| n.kind == IrNodeKind::Call)
            .map(|(id, _)| *id)
            .expect("a Call node in the fixture")
    }

    /// Index `cpg` into a real `Workspace` the same way the live server does, so the test
    /// exercises `call_site_for_node` against a genuinely populated `KindIndex` rather
    /// than a stub — callers then borrow `.cpg`/`.kind_index` straight off the returned
    /// `FileIndex` (neither is `Clone`, by design: they're meant to be shared by
    /// reference, not copied).
    fn indexed(cpg: Cpg) -> Workspace {
        let registry = web_ql::security_patterns::builtin_endpoint_registry();
        let mut workspace = Workspace::new(registry);
        workspace.upsert_file(std::path::PathBuf::from("a.cpp"), cpg, 0);
        workspace
    }

    #[test]
    fn generalizes_a_single_call_into_a_callee_name_rule() {
        let cpg = parse(
            SourceLanguage::Cpp,
            "void run(const char* cmd) { system(cmd); }",
        );
        let call_id = call_node_id(&cpg);
        let workspace = indexed(cpg);
        let idx = workspace.files.get(std::path::Path::new("a.cpp")).unwrap();

        let generalized = generalize_call_pattern(
            &idx.cpg,
            &idx.kind_index,
            &[call_id],
            "cwe-78-c-command-injection",
            "critical",
            "call to system()",
        )
        .expect("must generalize a Call node");

        assert_eq!(generalized.rule_id, "cwe-78-c-command-injection-variant");
        assert_eq!(generalized.anchor_callees, vec!["system".to_string()]);
        assert!(
            generalized
                .rule_source
                .contains("n.callee_name() in [\"system\"]")
        );
        assert!(generalized.rule_source.contains("severity: critical"));
        assert!(generalized.rule_source.contains("languages: [cpp]"));

        // The generated rule must actually compile.
        web_ql::compile_rules(&generalized.rule_source).expect("generated rule must compile");
    }

    #[test]
    fn the_generated_rule_actually_matches_other_instances_of_the_same_call() {
        let example_cpg = parse(
            SourceLanguage::Cpp,
            "void a(const char* cmd) { system(cmd); }",
        );
        let call_id = call_node_id(&example_cpg);
        let example_workspace = indexed(example_cpg);
        let idx = example_workspace
            .files
            .get(std::path::Path::new("a.cpp"))
            .unwrap();
        let generalized = generalize_call_pattern(
            &idx.cpg,
            &idx.kind_index,
            &[call_id],
            "cwe-78",
            "critical",
            "call to system()",
        )
        .unwrap();
        let rule_set = web_ql::compile_rules(&generalized.rule_source).unwrap();

        // A different file with a differently-named variable calling the same function —
        // the whole point of generalizing past the specific identifiers.
        let other_cpg = parse(
            SourceLanguage::Cpp,
            "void b(const char* user_input) { system(user_input); }",
        );
        let registry = web_ql::security_patterns::builtin_endpoint_registry();
        let mut other_workspace = Workspace::new(registry);
        other_workspace.upsert_file(std::path::PathBuf::from("other.cpp"), other_cpg, 0);
        let findings = other_workspace.scan(&rule_set);
        assert_eq!(findings.len(), 1, "{findings:#?}");
    }

    #[test]
    fn returns_none_when_no_matched_node_is_a_call() {
        let cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let return_node_id = cpg
            .ast
            .iter()
            .find(|(_, n)| n.kind == IrNodeKind::Return)
            .map(|(id, _)| *id)
            .expect("a Return node in the fixture");
        let workspace = indexed(cpg);
        let idx = workspace.files.get(std::path::Path::new("a.cpp")).unwrap();

        let generalized = generalize_call_pattern(
            &idx.cpg,
            &idx.kind_index,
            &[return_node_id],
            "some-rule",
            "medium",
            "not a call pattern",
        );
        assert!(generalized.is_none());
    }

    #[test]
    fn multiple_call_nodes_generalize_into_a_deduplicated_sorted_list() {
        let cpg = parse(
            SourceLanguage::Cpp,
            "void run(const char* cmd) { system(cmd); popen(cmd, \"r\"); system(cmd); }",
        );
        let call_ids: Vec<NodeId> = cpg
            .ast
            .iter()
            .filter(|(_, n)| n.kind == IrNodeKind::Call)
            .map(|(id, _)| *id)
            .collect();
        let workspace = indexed(cpg);
        let idx = workspace.files.get(std::path::Path::new("a.cpp")).unwrap();

        let generalized = generalize_call_pattern(
            &idx.cpg,
            &idx.kind_index,
            &call_ids,
            "cwe-78",
            "critical",
            "multiple dangerous calls",
        )
        .unwrap();

        assert_eq!(
            generalized.anchor_callees,
            vec!["popen".to_string(), "system".to_string()],
            "must dedupe the repeated system() call and sort deterministically"
        );
    }

    #[test]
    fn escapes_quotes_in_callee_names_and_message() {
        // Not realistically producible by a real parse, but the escaping logic itself
        // must be correct in isolation regardless of how exotic the input is.
        assert_eq!(escape_string_literal("a\"b"), "a\\\"b");
        assert_eq!(escape_string_literal("a\\b"), "a\\\\b");
    }
}
