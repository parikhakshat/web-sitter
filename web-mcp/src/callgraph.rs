//! `SymbolCallGraph`: a workspace-wide caller<->callee graph over `SymbolId`s, built once
//! at startup (Phase 1 scope — no incremental maintenance yet) from every file's
//! `cpg.call_graph`. Backs `get_callers`/`get_callees`/`call_path_exists`.
//!
//! Precomputing this (rather than re-deriving edges per tool call) is what makes
//! transitive traversal cheap: `get_callers`/`get_callees` are BFS over an adjacency map,
//! not a rescan of every file's call sites at every hop.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use web_ql::Workspace;
use web_ql::symbol_index::ReverseSymbolIndex;
use web_sitter::symbol_id::SymbolId;

use crate::symbol_query::call_site_matches_symbol;

pub struct SymbolCallGraph {
    callees: HashMap<SymbolId, BTreeSet<SymbolId>>,
    callers: HashMap<SymbolId, BTreeSet<SymbolId>>,
}

impl SymbolCallGraph {
    pub fn build(workspace: &Workspace, reverse_index: &ReverseSymbolIndex) -> Self {
        // (file, node_id) -> SymbolId, for resolving a call_graph entry's caller (keyed by
        // NodeId) and a CallSite's local `callee_id` (when the callee is defined in the
        // same file) back to a stable SymbolId.
        let mut node_to_symbol: HashMap<(&std::path::Path, web_sitter::NodeId), &SymbolId> =
            HashMap::new();
        for (symbol_id, def) in reverse_index.definitions() {
            node_to_symbol.insert((def.file.as_path(), def.node_id), symbol_id);
        }

        let mut callees: HashMap<SymbolId, BTreeSet<SymbolId>> = HashMap::new();
        let mut callers: HashMap<SymbolId, BTreeSet<SymbolId>> = HashMap::new();

        for (path, idx) in &workspace.files {
            for (&caller_node, entry) in &idx.cpg.call_graph {
                let Some(&caller_symbol) = node_to_symbol.get(&(path.as_path(), caller_node))
                else {
                    continue;
                };
                for call_site in &entry.calls {
                    let resolved = call_site
                        .callee_id
                        .and_then(|id| node_to_symbol.get(&(path.as_path(), id)))
                        .copied()
                        .or_else(|| {
                            // Cross-file (or same-file-but-unresolved-locally) callee:
                            // match by name against every known definition. O(symbols)
                            // per call site — fine at Phase 1's batch/single-shard scale;
                            // revisit if profiling shows this dominates large-repo indexing.
                            reverse_index.definitions().map(|(id, _)| id).find(|id| {
                                call_site_matches_symbol(
                                    call_site.qualified_callee.as_deref(),
                                    &call_site.callee,
                                    id,
                                )
                            })
                        });
                    if let Some(callee_symbol) = resolved {
                        callees
                            .entry(caller_symbol.clone())
                            .or_default()
                            .insert(callee_symbol.clone());
                        callers
                            .entry(callee_symbol.clone())
                            .or_default()
                            .insert(caller_symbol.clone());
                    }
                }
            }
        }

        Self { callees, callers }
    }

    /// BFS out to `max_depth` hops along callee edges, returning each reached symbol
    /// paired with its shortest distance from `start`. `start` itself is not included.
    pub fn transitive_callees(&self, start: &SymbolId, max_depth: usize) -> Vec<(SymbolId, u32)> {
        self.transitive(start, max_depth, &self.callees)
    }

    /// BFS out to `max_depth` hops along caller edges (i.e. "who eventually calls this,
    /// transitively"), returning each reached symbol paired with its shortest distance
    /// from `start`. `start` itself is not included.
    pub fn transitive_callers(&self, start: &SymbolId, max_depth: usize) -> Vec<(SymbolId, u32)> {
        self.transitive(start, max_depth, &self.callers)
    }

    fn transitive(
        &self,
        start: &SymbolId,
        max_depth: usize,
        adjacency: &HashMap<SymbolId, BTreeSet<SymbolId>>,
    ) -> Vec<(SymbolId, u32)> {
        let mut visited: HashSet<SymbolId> = HashSet::new();
        visited.insert(start.clone());
        let mut queue: VecDeque<(SymbolId, u32)> = VecDeque::new();
        queue.push_back((start.clone(), 0));
        let mut result = Vec::new();

        while let Some((current, depth)) = queue.pop_front() {
            if depth as usize >= max_depth {
                continue;
            }
            let Some(neighbors) = adjacency.get(&current) else {
                continue;
            };
            for neighbor in neighbors {
                if visited.insert(neighbor.clone()) {
                    result.push((neighbor.clone(), depth + 1));
                    queue.push_back((neighbor.clone(), depth + 1));
                }
            }
        }
        result
    }

    /// BFS along callee edges for the shortest call path `from -> ... -> to`, up to
    /// `max_depth` hops. Returns the full path (including both endpoints) if one exists
    /// within the depth bound, `None` otherwise — a caller-facing `false` for
    /// `call_path_exists` and a witness trace for `true` are the same computation.
    pub fn shortest_path(
        &self,
        from: &SymbolId,
        to: &SymbolId,
        max_depth: usize,
    ) -> Option<Vec<SymbolId>> {
        if from == to {
            return Some(vec![from.clone()]);
        }
        let mut visited: HashSet<SymbolId> = HashSet::new();
        visited.insert(from.clone());
        let mut queue: VecDeque<(SymbolId, u32)> = VecDeque::new();
        queue.push_back((from.clone(), 0));
        let mut predecessor: HashMap<SymbolId, SymbolId> = HashMap::new();

        while let Some((current, depth)) = queue.pop_front() {
            if depth as usize >= max_depth {
                continue;
            }
            let Some(neighbors) = self.callees.get(&current) else {
                continue;
            };
            for neighbor in neighbors {
                if !visited.insert(neighbor.clone()) {
                    continue;
                }
                predecessor.insert(neighbor.clone(), current.clone());
                if neighbor == to {
                    let mut path = vec![to.clone()];
                    let mut cursor = to.clone();
                    while let Some(pred) = predecessor.get(&cursor) {
                        path.push(pred.clone());
                        cursor = pred.clone();
                    }
                    path.reverse();
                    return Some(path);
                }
                queue.push_back((neighbor.clone(), depth + 1));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use web_ql::taint::EndpointRegistry;
    use web_sitter::{CpgGenerator, SourceLanguage};

    /// Build a small workspace out of (path, source) pairs, mirroring `crate::index`'s
    /// real pipeline (parse -> upsert_file -> build_cross_file_edges) minus the
    /// filesystem walk, so `SymbolCallGraph::build` sees real `cross_file_calls`.
    fn build(files: &[(&str, &str)]) -> (Workspace, ReverseSymbolIndex) {
        let mut workspace = Workspace::new(EndpointRegistry::new());
        for (name, src) in files {
            let mut generator =
                CpgGenerator::new_for_language(SourceLanguage::Cpp).expect("generator");
            let cpg = generator
                .generate_from_source_with_options(
                    src.as_bytes(),
                    web_sitter::GraphBuildOptions::default(),
                )
                .expect("parse");
            workspace.upsert_file(PathBuf::from(name), cpg, 0);
        }
        workspace.build_cross_file_edges();
        let reverse_index = ReverseSymbolIndex::build(
            workspace
                .files
                .iter()
                .map(|(p, idx)| (p.as_path(), idx.cpg.as_ref())),
        );
        (workspace, reverse_index)
    }

    fn find_symbol<'a>(reverse_index: &'a ReverseSymbolIndex, simple: &str) -> &'a SymbolId {
        reverse_index
            .definitions()
            .map(|(id, _)| id)
            .find(|id| crate::symbol_query::simple_name(id) == simple)
            .unwrap_or_else(|| panic!("no symbol named {simple}"))
    }

    #[test]
    fn direct_edges_cover_a_three_level_chain() {
        // a -> b -> c, all in separate files.
        let (workspace, reverse_index) = build(&[
            ("c.cpp", "int c_fn() { return 1; }"),
            ("b.cpp", "int c_fn(); int b_fn() { return c_fn(); }"),
            ("a.cpp", "int b_fn(); int a_fn() { return b_fn(); }"),
        ]);
        let graph = SymbolCallGraph::build(&workspace, &reverse_index);

        let a = find_symbol(&reverse_index, "a_fn").clone();
        let b = find_symbol(&reverse_index, "b_fn").clone();
        let c = find_symbol(&reverse_index, "c_fn").clone();

        assert_eq!(
            graph.transitive_callees(&a, 1),
            vec![(b.clone(), 1)],
            "depth-1 callees of a_fn is exactly its direct callee, b_fn"
        );
        assert_eq!(
            graph.transitive_callers(&b, 1),
            vec![(a, 1)],
            "depth-1 callers of b_fn is exactly its direct caller, a_fn"
        );
        assert_eq!(
            graph.transitive_callees(&b, 1),
            vec![(c, 1)],
            "depth-1 callees of b_fn is exactly its direct callee, c_fn"
        );
    }

    #[test]
    fn transitive_callees_respects_max_depth() {
        let (workspace, reverse_index) = build(&[
            ("c.cpp", "int c_fn() { return 1; }"),
            ("b.cpp", "int c_fn(); int b_fn() { return c_fn(); }"),
            ("a.cpp", "int b_fn(); int a_fn() { return b_fn(); }"),
        ]);
        let graph = SymbolCallGraph::build(&workspace, &reverse_index);
        let a = find_symbol(&reverse_index, "a_fn").clone();
        let b = find_symbol(&reverse_index, "b_fn").clone();
        let c = find_symbol(&reverse_index, "c_fn").clone();

        let depth_1: Vec<SymbolId> = graph
            .transitive_callees(&a, 1)
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        assert_eq!(depth_1, vec![b.clone()], "depth 1 must not reach c_fn");

        let depth_2: HashSet<SymbolId> = graph
            .transitive_callees(&a, 2)
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        assert_eq!(depth_2, HashSet::from([b, c]));
    }

    #[test]
    fn shortest_path_finds_the_transitive_chain() {
        let (workspace, reverse_index) = build(&[
            ("c.cpp", "int c_fn() { return 1; }"),
            ("b.cpp", "int c_fn(); int b_fn() { return c_fn(); }"),
            ("a.cpp", "int b_fn(); int a_fn() { return b_fn(); }"),
        ]);
        let graph = SymbolCallGraph::build(&workspace, &reverse_index);
        let a = find_symbol(&reverse_index, "a_fn").clone();
        let b = find_symbol(&reverse_index, "b_fn").clone();
        let c = find_symbol(&reverse_index, "c_fn").clone();

        let path = graph.shortest_path(&a, &c, 5).expect("path must exist");
        assert_eq!(path, vec![a.clone(), b, c.clone()]);

        assert!(
            graph.shortest_path(&c, &a, 5).is_none(),
            "no path in reverse direction"
        );
        assert!(
            graph.shortest_path(&a, &c, 1).is_none(),
            "depth 1 must be too shallow to reach c_fn from a_fn"
        );
    }

    #[test]
    fn shortest_path_from_symbol_to_itself_is_trivial() {
        let (workspace, reverse_index) = build(&[("a.cpp", "int a_fn() { return 1; }")]);
        let graph = SymbolCallGraph::build(&workspace, &reverse_index);
        let a = find_symbol(&reverse_index, "a_fn").clone();
        assert_eq!(graph.shortest_path(&a, &a, 5), Some(vec![a]));
    }
}
