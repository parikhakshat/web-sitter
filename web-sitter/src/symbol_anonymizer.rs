use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{Cpg, NodeId};

/// Maps original variable names to anonymized names (var0, var1, ...) while
/// preserving function names, stdlib identifiers, field names, and type names.
pub struct SymbolAnonymizer {
    var_counter: u32,
    idx_counter: u32,
    tmp_counter: u32,
    var_table: HashMap<String, String>,
    reversed: HashMap<String, String>,
}

pub struct AnonymizedCpg {
    pub cpg: Cpg,
    /// Maps anonymized name → original name
    pub symbol_table: HashMap<String, String>,
}

impl Default for SymbolAnonymizer {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolAnonymizer {
    pub fn new() -> Self {
        Self {
            var_counter: 0,
            idx_counter: 0,
            tmp_counter: 0,
            var_table: HashMap::new(),
            reversed: HashMap::new(),
        }
    }

    /// Anonymize all user-defined variable/parameter names in a CPG.
    /// Stdlib function names, field names, and type names are preserved.
    pub fn anonymize(&mut self, cpg: &Cpg) -> AnonymizedCpg {
        let mut out = cpg.clone();
        let function_names = collect_function_names(&out);
        let node_ids: Vec<NodeId> = out.ast.keys().copied().collect();

        for &node_id in &node_ids {
            let Some(node) = out.ast.get(&node_id) else {
                continue;
            };
            if !node.is_identifier() {
                continue;
            }
            let Some(original) = node.text.clone() else {
                continue;
            };

            if should_preserve_identifier(&out.ast, node_id, &original, &function_names) {
                continue;
            }

            let anonymized = if let Some(existing) = self.var_table.get(&original) {
                existing.clone()
            } else {
                let fresh = self.next_name(&original, &out.ast, node_id);
                self.var_table.insert(original.clone(), fresh.clone());
                self.reversed.insert(fresh.clone(), original.clone());
                fresh
            };

            if let Some(target) = out.ast.get_mut(&node_id) {
                target.text = Some(anonymized);
            }
        }

        // Second pass: update shadow nodes (init_declarator, declarator, etc.)
        // whose text was set to the bare variable name by first_identifier_text().
        for &node_id in &node_ids {
            let Some(node) = out.ast.get(&node_id) else {
                continue;
            };
            if node.is_identifier() {
                continue; // already handled
            }
            let Some(text) = node.text.clone() else {
                continue;
            };
            if let Some(anonymized) = self.var_table.get(&text) {
                let anonymized = anonymized.clone();
                if let Some(target) = out.ast.get_mut(&node_id) {
                    target.text = Some(anonymized);
                }
            }
        }

        AnonymizedCpg {
            cpg: out,
            symbol_table: self.reversed.clone(),
        }
    }

    /// Return the current forward mapping (original → anonymized).
    pub fn var_table(&self) -> &HashMap<String, String> {
        &self.var_table
    }

    /// Return the reverse mapping (anonymized → original).
    pub fn reversed(&self) -> &HashMap<String, String> {
        &self.reversed
    }

    fn next_name(
        &mut self,
        original: &str,
        ast: &BTreeMap<NodeId, crate::AstNode>,
        node_id: NodeId,
    ) -> String {
        if is_loop_index_name(original, ast, node_id) {
            let name = format!("idx{}", self.idx_counter);
            self.idx_counter += 1;
            return name;
        }
        if original.starts_with("tmp") {
            let name = format!("tmp{}", self.tmp_counter);
            self.tmp_counter += 1;
            return name;
        }
        let name = format!("var{}", self.var_counter);
        self.var_counter += 1;
        name
    }
}

fn collect_function_names(cpg: &Cpg) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for entry in cpg.call_graph.values() {
        if !entry.name.is_empty() {
            names.insert(entry.name.clone());
        }
    }
    names
}

fn should_preserve_identifier(
    ast: &BTreeMap<NodeId, crate::AstNode>,
    node_id: NodeId,
    name: &str,
    function_names: &BTreeSet<String>,
) -> bool {
    if is_known_stdlib(name) || function_names.contains(name) {
        return true;
    }

    let Some(node) = ast.get(&node_id) else {
        return true;
    };
    let Some(parent_id) = node.parent_id else {
        return true;
    };
    let Some(parent) = ast.get(&parent_id) else {
        return true;
    };

    // Preserve function declarator identifiers.
    if parent.node_type == "function_declarator"
        && parent.children.first().copied() == Some(node_id)
    {
        return true;
    }
    // Preserve field accesses and field declaration names.
    if parent.is_member_access() || parent.is_field_def() || parent.is_class_def() {
        return true;
    }
    false
}

fn is_loop_index_name(
    name: &str,
    ast: &BTreeMap<NodeId, crate::AstNode>,
    node_id: NodeId,
) -> bool {
    if !matches!(name, "i" | "j" | "k" | "idx") {
        return false;
    }
    let mut current = ast.get(&node_id).and_then(|n| n.parent_id);
    while let Some(pid) = current {
        let Some(parent) = ast.get(&pid) else {
            break;
        };
        if parent.is_loop() {
            return true;
        }
        current = parent.parent_id;
    }
    false
}

fn is_known_stdlib(name: &str) -> bool {
    crate::security_patterns::is_known_stdlib(name)
}
