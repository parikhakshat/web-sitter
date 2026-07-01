use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rustc_hash::{FxHashMap, FxHashSet};
use crate::{
    AstNode, BasicBlock, CallGraphEntry, CallSite, Cpg, DataflowDef, DataflowEdge, DataflowGraph,
    DataflowUse, IrNodeKind, NodeId,
};

pub type PreprocessingMaps = (
    BTreeMap<NodeId, NodeId>,
    BTreeMap<NodeId, NodeId>,
    BTreeMap<String, Vec<NodeId>>,
);

pub fn build_preprocessing_maps(graph: &BTreeMap<NodeId, AstNode>) -> PreprocessingMaps {
    let mut parent_map = BTreeMap::new();
    let mut function_map = BTreeMap::new();
    let mut type_index: BTreeMap<String, Vec<NodeId>> = BTreeMap::new();

    for (id, node) in graph {
        type_index
            .entry(node.node_type.clone())
            .or_default()
            .push(*id);
        if let Some(parent) = node.parent_id {
            parent_map.insert(*id, parent);
        }
    }

    let function_nodes: Vec<NodeId> = graph
        .iter()
        .filter_map(|(id, node)| node.is_method_def().then_some(*id))
        .collect();

    for func_id in function_nodes {
        let mut stack = vec![func_id];
        let mut seen = BTreeSet::new();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            function_map.insert(cur, func_id);
            if let Some(node) = graph.get(&cur) {
                stack.extend(node.children.iter().copied());
            }
        }
    }

    (parent_map, function_map, type_index)
}

/// Extract the *unqualified* function name from a function_definition node.
/// For `void Foo::bar() {}`, returns `"bar"`.
/// For `void ns::helper() {}`, returns `"helper"`.
/// Also returns the fully-qualified name (for registration under both keys) via
/// the second return value.
pub fn get_func_def_name(
    graph: &BTreeMap<NodeId, AstNode>,
    func_node_id: NodeId,
) -> Option<String> {
    let node = graph.get(&func_node_id)?;
    if node.is_lambda_def() {
        return Some("<lambda>".to_string());
    }
    // If enrichment already populated the name (non-C/C++ languages), use it directly.
    if let Some(name) = &node.name {
        if !name.is_empty() {
            return Some(name.clone());
        }
    }

    fn find_name(
        graph: &BTreeMap<NodeId, AstNode>,
        node_id: NodeId,
        depth: usize,
    ) -> Option<String> {
        if depth > 8 {
            return None;
        }
        let node = graph.get(&node_id)?;
        match node.node_type.as_str() {
            "identifier" => node.text.clone(),
            // operator_name nodes contain text like "operator+" or "operator[]"
            "operator_name" => node.text.clone(),
            // operator_cast: "operator T()" — use the type as the name
            "operator_cast" => node.text.clone(),
            // Destructor declarations: `~Foo` — include the tilde.
            "destructor_name" => node.text.clone(),
            // Qualified names like `Foo::bar` or `ns::helper`:
            // return just the last component (unqualified name).
            "qualified_identifier" | "scoped_namespace_identifier" => {
                // Last identifier/operator_name/destructor_name child is the unqualified part.
                node.children.iter().rev().find_map(|cid| {
                    let c = graph.get(cid)?;
                    match c.node_type.as_str() {
                        "identifier" | "operator_name" | "operator_cast" | "destructor_name" => {
                            c.text.clone()
                        }
                        _ => None,
                    }
                })
            }
            "function_declarator"
            | "pointer_declarator"
            | "parenthesized_declarator"
            | "reference_declarator"
            | "abstract_reference_declarator"
            | "abstract_pointer_declarator" => node
                .children
                .iter()
                .find_map(|child_id| find_name(graph, *child_id, depth + 1)),
            _ => None,
        }
    }

    for child_id in &node.children {
        let child = graph.get(child_id)?;
        if matches!(
            child.node_type.as_str(),
            "function_declarator" | "pointer_declarator" | "parenthesized_declarator"
        ) {
            if let Some(name) = find_name(graph, *child_id, 0) {
                return Some(name);
            }
        }
    }

    node.text.as_ref().and_then(|text| {
        text.find('(').and_then(|open| {
            let prefix = &text[..open];
            prefix
                .split_whitespace()
                .last()
                .map(|v| v.trim_matches('*').to_string())
                .filter(|v| !v.is_empty())
        })
    })
}

/// Extract the fully-qualified name of a function definition when its declarator
/// contains a `qualified_identifier` (e.g. `Foo::bar` or `ns::helper`).
/// Returns `None` for top-level unqualified functions.
pub fn get_func_def_qualified_name(
    graph: &BTreeMap<NodeId, AstNode>,
    func_node_id: NodeId,
) -> Option<String> {
    let node = graph.get(&func_node_id)?;

    fn find_qualified(
        graph: &BTreeMap<NodeId, AstNode>,
        node_id: NodeId,
        depth: usize,
    ) -> Option<String> {
        if depth > 8 {
            return None;
        }
        let node = graph.get(&node_id)?;
        match node.node_type.as_str() {
            "qualified_identifier" | "scoped_namespace_identifier" => {
                // Reconstruct `A::B::C` from the node text (most reliable).
                node.text
                    .as_ref()
                    .map(|t| t.split('(').next().unwrap_or(t).trim().to_string())
                    .filter(|s| s.contains("::"))
            }
            "function_declarator"
            | "pointer_declarator"
            | "parenthesized_declarator"
            | "reference_declarator" => node
                .children
                .iter()
                .find_map(|cid| find_qualified(graph, *cid, depth + 1)),
            _ => None,
        }
    }

    for child_id in &node.children {
        let child = graph.get(child_id)?;
        if matches!(
            child.node_type.as_str(),
            "function_declarator" | "pointer_declarator" | "parenthesized_declarator"
        ) {
            if let Some(qname) = find_qualified(graph, *child_id, 0) {
                return Some(qname);
            }
        }
    }
    None
}

pub fn build_call_graph(
    graph: &BTreeMap<NodeId, AstNode>,
    preprocessing_maps: Option<&PreprocessingMaps>,
    macro_aliases: Option<&BTreeMap<String, String>>,
) -> BTreeMap<NodeId, CallGraphEntry> {
    build_call_graph_impl(graph, preprocessing_maps, macro_aliases, None)
}

pub fn build_call_graph_for_functions(
    graph: &BTreeMap<NodeId, AstNode>,
    previous: Option<&BTreeMap<NodeId, CallGraphEntry>>,
    affected_function_ids: &BTreeSet<NodeId>,
    preprocessing_maps: Option<&PreprocessingMaps>,
    macro_aliases: Option<&BTreeMap<String, String>>,
) -> BTreeMap<NodeId, CallGraphEntry> {
    if previous.is_none() || affected_function_ids.is_empty() {
        return build_call_graph(graph, preprocessing_maps, macro_aliases);
    }
    let fresh = build_call_graph_impl(
        graph,
        preprocessing_maps,
        macro_aliases,
        Some(affected_function_ids),
    );
    let previous = previous.expect("checked is_some");
    let mut merged = previous
        .iter()
        .filter(|(func_id, _)| !affected_function_ids.contains(func_id))
        .map(|(func_id, entry)| (*func_id, entry.clone()))
        .collect::<BTreeMap<_, _>>();
    merged.extend(fresh);

    let live_ids = merged.keys().copied().collect::<BTreeSet<_>>();
    for entry in merged.values_mut() {
        entry
            .called_by
            .retain(|caller_id| live_ids.contains(caller_id));
    }
    let caller_to_callees = merged
        .iter()
        .map(|(func_id, entry)| {
            (
                *func_id,
                entry
                    .calls
                    .iter()
                    .filter_map(|call| call.callee_id)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    for entry in merged.values_mut() {
        entry.called_by.clear();
    }
    for (caller_id, callees) in caller_to_callees {
        for callee_id in callees {
            if let Some(callee) = merged.get_mut(&callee_id) {
                if !callee.called_by.contains(&caller_id) {
                    callee.called_by.push(caller_id);
                }
            }
        }
    }
    merged
}

fn build_call_graph_impl(
    graph: &BTreeMap<NodeId, AstNode>,
    preprocessing_maps: Option<&PreprocessingMaps>,
    macro_aliases: Option<&BTreeMap<String, String>>,
    scoped_function_ids: Option<&BTreeSet<NodeId>>,
) -> BTreeMap<NodeId, CallGraphEntry> {
    let (_, function_map, type_index) = preprocessing_maps
        .cloned()
        .unwrap_or_else(|| build_preprocessing_maps(graph));
    let mut call_graph: BTreeMap<NodeId, CallGraphEntry> = BTreeMap::new();
    let mut function_name_to_id: BTreeMap<String, NodeId> = BTreeMap::new();
    let mut func_ptr_aliases: BTreeMap<String, String> = BTreeMap::new();
    // Maps array variable name → list of function names stored in that array.
    // Populated from `{ foo, bar }` style initializer lists.
    let mut array_dispatch: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Maps struct field name → list of function names assigned to that field in
    // initializers (e.g. `.handler = my_func`).  Used to resolve indirect calls
    // through struct function pointer dispatch tables.
    let mut field_dispatch: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // Collect all function definition node IDs: C/C++ "function_definition" plus
    // all other languages' MethodDef nodes (Go function_declaration, Python
    // function_definition, Java method_declaration, JS/TS function_declaration,
    // Rust function_item, etc.).
    let mut all_func_node_ids: BTreeSet<NodeId> = type_index
        .get("function_definition")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();
    // Add all nodes with IrNodeKind::MethodDef (covers all languages after enrichment).
    for (&node_id, node) in graph.iter() {
        if node.kind == crate::IrNodeKind::MethodDef {
            all_func_node_ids.insert(node_id);
        }
    }

    for node_id in all_func_node_ids {
        if scoped_function_ids.is_some_and(|ids| !ids.contains(&node_id)) {
            continue;
        }
        if let Some(name) = get_func_def_name(graph, node_id) {
            // Register under the short (unqualified) name.
            function_name_to_id.entry(name.clone()).or_insert(node_id);

            // Also register under the fully-qualified name when available so
            // calls like `ns::foo()` or `Foo::bar()` resolve correctly.
            if let Some(qname) = get_func_def_qualified_name(graph, node_id) {
                function_name_to_id.entry(qname).or_insert(node_id);
            }

            // Register under any enclosing namespace/class context so
            // `ClassName::method` calls can be resolved even when the call
            // only uses the short name.
            if let Some(class_ctx) = graph.get(&node_id).and_then(|n| n.class_context.clone()) {
                let qualified = format!("{}::{}", class_ctx, name);
                function_name_to_id.entry(qualified).or_insert(node_id);
            }

            call_graph.entry(node_id).or_insert_with(|| CallGraphEntry {
                name,
                calls: vec![],
                called_by: vec![],
            });
        }
    }

    // Also register any function whose type_index entry is a class/struct member
    // definition that the tree-sitter grammar surfaces as `function_definition`
    // inside a `class_specifier`. The unqualified name is already registered;
    // this ensures the full `ClassName::name` variant is present for callers
    // that use qualified names.
    for node_id in type_index
        .get("class_specifier")
        .into_iter()
        .flatten()
        .chain(type_index.get("struct_specifier").into_iter().flatten())
    {
        if let Some(class_node) = graph.get(node_id) {
            let class_name = class_node.children.iter().find_map(|cid| {
                let c = graph.get(cid)?;
                if c.is_type_ref() || c.is_identifier() {
                    c.text.clone()
                } else {
                    None
                }
            });
            if let Some(cname) = class_name {
                let mut stack = class_node.children.clone();
                while let Some(child_id) = stack.pop() {
                    let Some(child) = graph.get(&child_id) else {
                        continue;
                    };
                    if child.is_method_def() {
                        if let Some(fname) = get_func_def_name(graph, child_id) {
                            let qkey = format!("{}::{}", cname, fname);
                            function_name_to_id.entry(qkey).or_insert(child_id);
                        }
                    }
                    stack.extend(child.children.iter().copied());
                }
            }
        }
    }

    for init_id in type_index
        .get("init_declarator")
        .cloned()
        .unwrap_or_default()
    {
        if let Some(init) = graph.get(&init_id) {
            if init.children.len() >= 2 {
                let lhs_id = init.children[0];
                let rhs_id = *init.children.last().unwrap_or(&init.children[0]);
                record_func_ptr_alias(
                    graph,
                    lhs_id,
                    rhs_id,
                    &function_name_to_id,
                    &mut func_ptr_aliases,
                );
                // Array of function pointers: `void (*handlers[])(int) = {foo, bar}`
                record_array_dispatch(
                    graph,
                    lhs_id,
                    rhs_id,
                    &function_name_to_id,
                    &mut array_dispatch,
                );
            }
        }
    }

    for assign_id in type_index
        .get("assignment_expression")
        .cloned()
        .unwrap_or_default()
    {
        if let Some(assign) = graph.get(&assign_id) {
            if assign.children.len() >= 2 {
                let lhs_id = assign.children[0];
                let rhs_id = *assign.children.last().unwrap_or(&assign.children[0]);
                record_func_ptr_alias(
                    graph,
                    lhs_id,
                    rhs_id,
                    &function_name_to_id,
                    &mut func_ptr_aliases,
                );
                record_array_dispatch(
                    graph,
                    lhs_id,
                    rhs_id,
                    &function_name_to_id,
                    &mut array_dispatch,
                );
            }
        }
    }

    // Scan `initializer_pair` nodes for `.field = function_name` patterns.
    for pair_id in type_index
        .get("initializer_pair")
        .cloned()
        .unwrap_or_default()
    {
        let Some(pair) = graph.get(&pair_id) else {
            continue;
        };
        // initializer_pair children: [field_designator, value]
        if pair.children.len() < 2 {
            continue;
        }
        let designator_id = pair.children[0];
        let value_id = *pair.children.last().unwrap_or(&designator_id);

        // Extract the field name from the designator
        let field_name = graph.get(&designator_id).and_then(|d| {
            if d.node_type == "field_designator" {
                d.children.iter().find_map(|cid| {
                    let c = graph.get(cid)?;
                    if c.node_type == "field_identifier" {
                        c.text.clone()
                    } else {
                        None
                    }
                })
            } else if d.node_type == "field_identifier" {
                d.text.clone()
            } else {
                None
            }
        });
        let Some(field_name) = field_name else {
            continue;
        };

        // Value must be a known function name (possibly &func)
        let Some(value_node) = graph.get(&value_id) else {
            continue;
        };
        let fn_name = if value_node.node_type == "identifier" {
            value_node.text.clone()
        } else if value_node.node_type == "pointer_expression" {
            value_node.children.iter().find_map(|cid| {
                let c = graph.get(cid)?;
                if c.node_type == "identifier" {
                    c.text.clone()
                } else {
                    None
                }
            })
        } else {
            None
        };
        if let Some(name) = fn_name {
            if function_name_to_id.contains_key(&name) {
                field_dispatch.entry(field_name).or_default().push(name);
            }
        }
    }

    // Per-function sets for O(1) duplicate detection instead of O(n) linear scans.
    // Key: "callee_name@call_node_id" so multiple call sites to same function are each recorded.
    let mut seen_callees: HashMap<u32, HashSet<String>> = HashMap::new();
    let mut seen_called_by: HashMap<u32, HashSet<u32>> = HashMap::new();

    for (node_id, node) in graph {
        if !node.is_call() {
            continue;
        }
        let Some(caller_func_id) = function_map.get(node_id).copied() else {
            continue;
        };
        if scoped_function_ids.is_some_and(|ids| !ids.contains(&caller_func_id)) {
            continue;
        }

        let raw_callee = extract_called_function_name(graph, *node_id, macro_aliases)
            .and_then(|name| func_ptr_aliases.get(&name).cloned().or(Some(name)))
            .unwrap_or_default();
        if raw_callee.is_empty() {
            continue;
        }

        // Determine if this call uses subscript or field dispatch.
        let is_indirect_dispatch = node.children.iter().any(|cid| {
            graph
                .get(cid)
                .map(|c| {
                    matches!(
                        c.node_type.as_str(),
                        "subscript_expression" | "field_expression"
                    )
                })
                .unwrap_or(false)
        });

        // Array dispatch: `handlers[n](x)` — add all possible targets.
        // Field dispatch: `ops->handler(x)` — add all functions assigned to that field.
        let callee_names: Vec<String> = if let Some(targets) = array_dispatch.get(&raw_callee) {
            targets.clone()
        } else if is_indirect_dispatch {
            if let Some(targets) = field_dispatch.get(&raw_callee) {
                targets.clone()
            } else {
                vec![raw_callee.clone()]
            }
        } else {
            vec![raw_callee.clone()]
        };

        let qualified_callee = extract_qualified_callee(graph, *node_id);

        for callee_name in callee_names {
            let callee_id = function_name_to_id.get(&callee_name).copied();
            let callee_kind = if callee_id.is_some() {
                crate::FunctionKind::Internal
            } else {
                crate::FunctionKind::ExternalDecl
            };
            let caller_seen = seen_callees.entry(caller_func_id).or_default();
            // Include node_id so multiple call sites to same callee are each recorded
            let seen_key = format!("{}@{}", callee_name, node_id);
            if caller_seen.insert(seen_key) {
                if let Some(entry) = call_graph.get_mut(&caller_func_id) {
                    entry.calls.push(CallSite {
                        callee: callee_name.clone(),
                        callee_id,
                        call_site: Some(*node_id),
                        qualified_callee: qualified_callee.clone(),
                        callee_kind,
                    });
                }
            }
            if let Some(cid) = callee_id {
                if seen_called_by
                    .entry(cid)
                    .or_default()
                    .insert(caller_func_id)
                {
                    if let Some(callee) = call_graph.get_mut(&cid) {
                        callee.called_by.push(caller_func_id);
                    }
                }
            }
        }

        for callback_name in extract_callback_argument_names(graph, *node_id, &function_name_to_id)
        {
            let caller_seen = seen_callees.entry(caller_func_id).or_default();
            if !caller_seen.insert(callback_name.clone()) {
                continue;
            }
            let callback_id = function_name_to_id.get(&callback_name).copied();
            let callback_kind = if callback_id.is_some() {
                crate::FunctionKind::Internal
            } else {
                crate::FunctionKind::ExternalDecl
            };
            if let Some(entry) = call_graph.get_mut(&caller_func_id) {
                entry.calls.push(CallSite {
                    callee: callback_name.clone(),
                    callee_id: callback_id,
                    call_site: Some(*node_id),
                    qualified_callee: None,
                    callee_kind: callback_kind,
                });
            }
            if let Some(cid) = callback_id {
                if seen_called_by
                    .entry(cid)
                    .or_default()
                    .insert(caller_func_id)
                {
                    if let Some(callee) = call_graph.get_mut(&cid) {
                        callee.called_by.push(caller_func_id);
                    }
                }
            }
        }
    }

    // ── Constructor calls via `new_expression` ────────────────────────────────
    // `new Foo(args)` and `new Foo[n]` are constructor invocations.  The type
    // name becomes the callee; `Foo::Foo` (constructor) or just `Foo` is looked up.
    for node_id in type_index
        .get("new_expression")
        .cloned()
        .unwrap_or_default()
    {
        let Some(caller_func_id) = function_map.get(&node_id).copied() else {
            continue;
        };
        if scoped_function_ids.is_some_and(|ids| !ids.contains(&caller_func_id)) {
            continue;
        }
        let Some(new_node) = graph.get(&node_id) else {
            continue;
        };
        // Find the type name (type_identifier or qualified_identifier child).
        let type_name: Option<String> = new_node.children.iter().find_map(|cid| {
            let c = graph.get(cid)?;
            match c.node_type.as_str() {
                "type_identifier" => c.text.clone(),
                "qualified_identifier" | "scoped_namespace_identifier" => c
                    .text
                    .as_ref()
                    .map(|t| t.split('(').next().unwrap_or(t).trim().to_string()),
                _ => None,
            }
        });
        if let Some(tname) = type_name {
            // Try `Foo::Foo` (constructor) then plain `Foo`.
            let ctor_name = format!("{}::{}", tname, tname.rsplit("::").next().unwrap_or(&tname));
            let callee_name = if function_name_to_id.contains_key(&ctor_name) {
                ctor_name
            } else {
                tname
            };
            let callee_id = function_name_to_id.get(&callee_name).copied();
            let callee_kind = if callee_id.is_some() {
                crate::FunctionKind::Internal
            } else {
                crate::FunctionKind::ExternalDecl
            };
            let caller_seen = seen_callees.entry(caller_func_id).or_default();
            if caller_seen.insert(callee_name.clone()) {
                if let Some(entry) = call_graph.get_mut(&caller_func_id) {
                    entry.calls.push(CallSite {
                        callee: callee_name.clone(),
                        callee_id,
                        call_site: Some(node_id),
                        qualified_callee: None,
                        callee_kind,
                    });
                }
            }
            if let Some(cid) = callee_id {
                if seen_called_by
                    .entry(cid)
                    .or_default()
                    .insert(caller_func_id)
                {
                    if let Some(callee) = call_graph.get_mut(&cid) {
                        callee.called_by.push(caller_func_id);
                    }
                }
            }
        }
    }

    call_graph
}

/// Returns both the dataflow graph and any cross-file call edges discovered.
/// The cross-file edges are collected into `Cpg::cross_file_calls` by the caller.
pub fn build_dataflow(
    graph: &BTreeMap<NodeId, AstNode>,
    basic_blocks: Option<&BTreeMap<String, BasicBlock>>,
    preprocessing_maps: Option<&PreprocessingMaps>,
    macro_aliases: Option<&BTreeMap<String, String>>,
) -> (DataflowGraph, Vec<crate::CrossFileCallEdge>) {
    build_dataflow_impl(
        graph,
        basic_blocks,
        preprocessing_maps,
        macro_aliases,
        None,
        false,
        true,
    )
}

fn build_dataflow_impl(
    graph: &BTreeMap<NodeId, AstNode>,
    basic_blocks: Option<&BTreeMap<String, BasicBlock>>,
    preprocessing_maps: Option<&PreprocessingMaps>,
    macro_aliases: Option<&BTreeMap<String, String>>,
    affected_function_ids: Option<&BTreeSet<NodeId>>,
    include_globals: bool,
    include_interprocedural: bool,
) -> (DataflowGraph, Vec<crate::CrossFileCallEdge>) {
    // Build preprocessing maps once and keep the owned tuple so we can pass a
    // reference into add_interprocedural_edges, avoiding a second O(n) rebuild.
    let owned_maps: PreprocessingMaps = preprocessing_maps
        .cloned()
        .unwrap_or_else(|| build_preprocessing_maps(graph));
    let (parent_map, function_map, type_index) = &owned_maps;

    // Pre-compute CFG reachability per BB when basic_blocks are available.
    // This enables loop-carried def-use detection (back-edge reachability).
    let bb_reachability: FxHashMap<String, FxHashSet<String>> = if let Some(bbs) = basic_blocks {
        let function_bbs = reachable_basic_blocks_from_function_entries(bbs);
        build_bb_reachability(bbs, &function_bbs)
    } else {
        FxHashMap::default()
    };

    let mut definitions_lvalue: Vec<DataflowDef> = Vec::new();
    let mut definitions_param: Vec<DataflowDef> = Vec::new();
    let mut uses = Vec::new();
    let mut edges = Vec::new();
    let mut cross_file_calls: Vec<crate::CrossFileCallEdge> = Vec::new();
    let mut defs_by_var: BTreeMap<(Option<NodeId>, String), Vec<NodeId>> = BTreeMap::new();
    let mut global_defs: BTreeMap<String, Vec<NodeId>> = BTreeMap::new();
    // (function_id, base_path, field_name) — base_path is `"*"` when unresolvable.
    let mut field_defs: BTreeMap<(Option<NodeId>, String, String), Vec<NodeId>> = BTreeMap::new();
    let mut lambda_writebacks: Vec<(Option<NodeId>, NodeId, String)> = Vec::new();
    let mut field_expr_by_func_name: BTreeMap<(Option<NodeId>, String), Vec<NodeId>> =
        BTreeMap::new();

    for node_id in type_index
        .get("field_expression")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(
            node_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        if let Some(field_name) = field_expression_field_name(graph, node_id) {
            field_expr_by_func_name
                .entry((function_map.get(&node_id).copied(), field_name))
                .or_default()
                .push(node_id);
        }
    }

    for id_type in ["identifier", "field_identifier"] {
        for node_id in type_index.get(id_type).cloned().unwrap_or_default() {
            if !node_in_scope(
                node_id,
                &function_map,
                affected_function_ids,
                include_globals,
            ) {
                continue;
            }
            let Some(node) = graph.get(&node_id) else {
                continue;
            };
            let Some(var) = node.text.clone() else {
                continue;
            };
            let function_id = function_map.get(&node_id).copied();

            if node.node_type == "field_identifier" {
                if is_field_declaration_name(graph, node_id) {
                    definitions_lvalue.push(DataflowDef {
                        node_id,
                        variable: var.clone(),
                        function_id: None,
                    });
                    let base = enclosing_struct_name(graph, &parent_map, node_id)
                        .unwrap_or_else(|| "*".to_string());
                    field_defs
                        .entry((function_id, base, var))
                        .or_default()
                        .push(node_id);
                }
                continue;
            }

            if is_call_callee_identifier(graph, node_id) {
                continue;
            }

            let is_lvalue = is_lvalue_context(graph, &parent_map, node_id);
            let is_param = !is_lvalue && is_parameter_name(graph, node_id);
            if is_lvalue || is_param {
                // Skip blank identifier — it is never a meaningful def
                if var == "_" {
                    continue;
                }
                let def = DataflowDef {
                    node_id,
                    variable: var.clone(),
                    function_id,
                };
                if is_lvalue {
                    definitions_lvalue.push(def);
                } else {
                    definitions_param.push(def);
                }
                if function_id.is_some() {
                    defs_by_var
                        .entry((function_id, var))
                        .or_default()
                        .push(node_id);
                } else {
                    global_defs.entry(var).or_default().push(node_id);
                }
            } else {
                uses.push(DataflowUse {
                    node_id,
                    variable: var.clone(),
                    function_id,
                });
                if let Some(parent_id) = parent_map.get(&node_id).copied() {
                    if is_expression_like(graph, parent_id) {
                        push_edge(&mut edges, node_id, parent_id, var, "REACHING_DEF");
                    }
                }
            }
        }
    }

    for update_type in [
        "update_expression",
        "preincrement_expression",
        "predecrement_expression",
        "postincrement_expression",
        "postdecrement_expression",
    ] {
        for node_id in type_index.get(update_type).cloned().unwrap_or_default() {
            if !node_in_scope(
                node_id,
                &function_map,
                affected_function_ids,
                include_globals,
            ) {
                continue;
            }
            let function_id = function_map.get(&node_id).copied();
            for var in collect_identifiers_in_expr(graph, node_id, Some(&parent_map)) {
                uses.push(DataflowUse {
                    node_id: var.node_id,
                    variable: var.name.clone(),
                    function_id,
                });
                definitions_lvalue.push(DataflowDef {
                    node_id: var.node_id,
                    variable: var.name.clone(),
                    function_id,
                });
                defs_by_var
                    .entry((function_id, var.name.clone()))
                    .or_default()
                    .push(var.node_id);
                push_edge(&mut edges, node_id, var.node_id, var.name, "REACHING_DEF");
            }
        }
    }

    for node_id in type_index
        .get("assignment_expression")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(
            node_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(node) = graph.get(&node_id) else {
            continue;
        };
        if node.children.len() < 2 {
            continue;
        }
        let lhs_expr_id = node.children[0];
        let lhs_vars = collect_identifiers_in_expr(graph, lhs_expr_id, Some(&parent_map));

        // For subscript/pointer LHS like `arr[i] = x` or `*ptr = x`, lhs_vars is empty
        // because is_lvalue_context filters the identifiers. Emit USE edges for the
        // pointer/array/index operands so they register as reads even in write context.
        if lhs_vars.is_empty() {
            if let Some(lhs_node) = graph.get(&lhs_expr_id) {
                let function_id = function_map.get(&lhs_expr_id).copied();
                match lhs_node.node_type.as_str() {
                    "subscript_expression" => {
                        // arr[i] = x  →  USE arr, USE i
                        // Also emit REACHING_DEF from rhs identifiers to the base array so
                        // taint written through arr[i] flows to subsequent arr reads.
                        let mut base_array_var: Option<(u32, String)> = None;
                        for child_id in &lhs_node.children {
                            let Some(child) = graph.get(child_id) else {
                                continue;
                            };
                            if child.is_identifier() {
                                if let Some(name) = child.text.clone() {
                                    if base_array_var.is_none() {
                                        // first identifier child is the array base
                                        base_array_var = Some((*child_id, name.clone()));
                                    }
                                    uses.push(DataflowUse {
                                        node_id: *child_id,
                                        variable: name,
                                        function_id,
                                    });
                                }
                            }
                        }
                        if let Some((arr_id, arr_name)) = base_array_var {
                            for rhs_child_id in node.children.iter().skip(1) {
                                for var in collect_identifiers_in_expr(
                                    graph,
                                    *rhs_child_id,
                                    Some(&parent_map),
                                ) {
                                    push_edge(
                                        &mut edges,
                                        var.node_id,
                                        arr_id,
                                        arr_name.clone(),
                                        "REACHING_DEF",
                                    );
                                }
                            }
                        }
                    }
                    "pointer_expression" => {
                        // *ptr = x  →  USE ptr, and propagate taint from RHS to ptr
                        // so that `*buf = tainted; sink(*buf)` is visible.
                        let mut base_ptr_var: Option<(u32, String)> = None;
                        for child_id in &lhs_node.children {
                            let Some(child) = graph.get(child_id) else {
                                continue;
                            };
                            if child.is_identifier() {
                                if let Some(name) = child.text.clone() {
                                    if base_ptr_var.is_none() {
                                        base_ptr_var = Some((*child_id, name.clone()));
                                    }
                                    uses.push(DataflowUse {
                                        node_id: *child_id,
                                        variable: name,
                                        function_id,
                                    });
                                }
                            }
                        }
                        if let Some((ptr_id, ptr_name)) = base_ptr_var {
                            definitions_lvalue.push(DataflowDef {
                                node_id: ptr_id,
                                variable: ptr_name.clone(),
                                function_id,
                            });
                            for rhs_child_id in node.children.iter().skip(1) {
                                for var in collect_identifiers_in_expr(
                                    graph,
                                    *rhs_child_id,
                                    Some(&parent_map),
                                ) {
                                    push_edge(
                                        &mut edges,
                                        var.node_id,
                                        ptr_id,
                                        ptr_name.clone(),
                                        "REACHING_DEF",
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // When the LHS is a plain identifier, collect_identifiers_in_expr returns []
        // because is_lvalue_context returns true for the first child of
        // assignment_expression. Fall back to reading the identifier directly.
        let lhs_var_owned;
        let lhs_var = if let Some(v) = lhs_vars.first() {
            v
        } else if graph.get(&lhs_expr_id).map(|n| n.is_identifier()).unwrap_or(false) {
            if let Some(name) = graph.get(&lhs_expr_id).and_then(|n| n.text.clone()) {
                lhs_var_owned = VarRef { name, node_id: lhs_expr_id };
                &lhs_var_owned
            } else {
                continue;
            }
        } else {
            continue;
        };

        let rhs_children = &node.children[1..];
        if let Some(rhs_call) = rhs_children
            .iter()
            .find_map(|child_id| find_call_expression_in_tree(graph, *child_id))
        {
            push_edge(
                &mut edges,
                rhs_call,
                lhs_var.node_id,
                lhs_var.name.clone(),
                "REACHING_DEF",
            );
        }

        for rhs_child_id in rhs_children {
            if graph
                .get(rhs_child_id)
                .map(|n| n.kind == IrNodeKind::TernaryOp)
                .unwrap_or(false)
            {
                let branches = graph
                    .get(rhs_child_id)
                    .map(|n| n.children.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default();
                for branch_id in branches {
                    for var in collect_identifiers_in_expr(graph, branch_id, Some(&parent_map)) {
                        push_edge(
                            &mut edges,
                            var.node_id,
                            lhs_var.node_id,
                            lhs_var.name.clone(),
                            "REACHING_DEF",
                        );
                    }
                }
            } else {
                for var in collect_identifiers_in_expr(graph, *rhs_child_id, Some(&parent_map)) {
                    push_edge(
                        &mut edges,
                        var.node_id,
                        lhs_var.node_id,
                        lhs_var.name.clone(),
                        "REACHING_DEF",
                    );
                }
            }
        }
    }

    for node_id in type_index
        .get("init_declarator")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(
            node_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(node) = graph.get(&node_id) else {
            continue;
        };
        if node.children.len() < 2 {
            continue;
        }
        let Some(lhs) = get_declared_variable(graph, node.children[0]) else {
            continue;
        };
        for init_child_id in node.children.iter().skip(1).copied() {
            if init_child_id == lhs.node_id {
                continue;
            }
            if graph
                .get(&init_child_id)
                .map(|n| n.kind == IrNodeKind::TernaryOp)
                .unwrap_or(false)
            {
                let branches = graph
                    .get(&init_child_id)
                    .map(|n| n.children.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default();
                for branch_id in branches {
                    push_edge(
                        &mut edges,
                        branch_id,
                        lhs.node_id,
                        lhs.name.clone(),
                        "REACHING_DEF",
                    );
                }
            } else {
                push_edge(
                    &mut edges,
                    init_child_id,
                    lhs.node_id,
                    lhs.name.clone(),
                    "REACHING_DEF",
                );
                for var in collect_identifiers_in_expr(graph, init_child_id, Some(&parent_map)) {
                    push_edge(
                        &mut edges,
                        var.node_id,
                        lhs.node_id,
                        lhs.name.clone(),
                        "REACHING_DEF",
                    );
                }
            }
        }
    }

    // ── C++17 structured bindings: auto [a, b, c] = expr ────────────────────
    for node_id in type_index
        .get("structured_binding_declaration")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(
            node_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(node) = graph.get(&node_id) else {
            continue;
        };
        // Collect bound identifiers and the initializer expression.
        let mut bound_ids: Vec<NodeId> = Vec::new();
        let mut init_expr_id: Option<NodeId> = None;
        let mut past_eq = false;
        for child_id in &node.children {
            let Some(child) = graph.get(child_id) else {
                continue;
            };
            if child.text.as_deref() == Some("=") {
                past_eq = true;
                continue;
            }
            if past_eq {
                init_expr_id = Some(*child_id);
            } else if child.is_identifier()
                || child.node_type == "structured_binding_list"
            {
                if child.node_type == "structured_binding_list" {
                    for inner_id in &child.children {
                        if let Some(inner) = graph.get(inner_id) {
                            if inner.is_identifier() {
                                bound_ids.push(*inner_id);
                            }
                        }
                    }
                } else {
                    bound_ids.push(*child_id);
                }
            }
        }
        if let Some(expr_id) = init_expr_id {
            for bound_id in &bound_ids {
                push_edge(
                    &mut edges,
                    expr_id,
                    *bound_id,
                    "<binding>".to_string(),
                    "REACHING_DEF",
                );
                for var in collect_identifiers_in_expr(graph, expr_id, Some(&parent_map)) {
                    push_edge(&mut edges, var.node_id, *bound_id, var.name, "REACHING_DEF");
                }
            }
        }
    }

    // ── C++ member initializer list: ctor(T x) : field(x) {} ────────────────────
    // Create REACHING_DEF edges from constructor argument expressions to the
    // field being initialized so taint flows from a constructor parameter into
    // the class field.
    for fi_id in type_index
        .get("field_initializer")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(fi_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let Some(fi) = graph.get(&fi_id) else {
            continue;
        };
        // field_initializer children: [field_identifier, argument_list] (or similar)
        // First identifier child is the field name (def); remaining children are
        // the initializer arguments (uses).
        let mut field_id: Option<NodeId> = None;
        let mut arg_ids: Vec<NodeId> = Vec::new();
        for child_id in &fi.children {
            let Some(child) = graph.get(child_id) else {
                continue;
            };
            if field_id.is_none() && child.is_identifier() {
                field_id = Some(*child_id);
            } else if child.node_type == "argument_list" {
                arg_ids.extend(child.children.iter().copied());
            }
        }
        if let Some(fid) = field_id {
            let function_id = function_map.get(&fi_id).copied();
            // Record the field as a definition within the constructor scope.
            if let Some(var) = graph.get(&fid).and_then(|n| n.text.clone()) {
                definitions_lvalue.push(DataflowDef {
                    node_id: fid,
                    variable: var.clone(),
                    function_id,
                });
                defs_by_var
                    .entry((function_id, var.clone()))
                    .or_default()
                    .push(fid);
                // Draw REACHING_DEF from each argument identifier to the field node.
                for arg_id in &arg_ids {
                    push_edge(&mut edges, *arg_id, fid, var.clone(), "REACHING_DEF");
                    for var_ref in collect_identifiers_in_expr(graph, *arg_id, Some(&parent_map)) {
                        push_edge(
                            &mut edges,
                            var_ref.node_id,
                            fid,
                            var.clone(),
                            "REACHING_DEF",
                        );
                    }
                }
            }
        }
    }

    // ── C++17 fold expressions: (args + ...) / (... + args) ─────────────────────
    // Taint propagates from the pack operand(s) to the fold expression result.
    for fold_id in type_index
        .get("fold_expression")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(
            fold_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        // Collect all identifier operands within the fold expression and draw
        // REACHING_DEF edges from each to the fold expression node itself.
        for var_ref in collect_identifiers_in_expr(graph, fold_id, Some(&parent_map)) {
            push_edge(
                &mut edges,
                var_ref.node_id,
                fold_id,
                var_ref.name,
                "REACHING_DEF",
            );
        }
    }

    // ── C++ lambda capture analysis ────────────────────────────────────────────
    for node_id in type_index
        .get("lambda_expression")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(
            node_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(node) = graph.get(&node_id) else {
            continue;
        };
        // Find lambda_capture_specifier and body.
        let mut by_ref_all = false;
        let mut by_val_all = false;
        let mut explicit_captures: Vec<(String, bool)> = Vec::new(); // (name, by_ref)
        let mut lambda_body_id: Option<NodeId> = None;
        for child_id in &node.children {
            let Some(child) = graph.get(child_id) else {
                continue;
            };
            match child.node_type.as_str() {
                "lambda_capture_specifier" => {
                    for cap_id in &child.children {
                        let Some(cap) = graph.get(cap_id) else {
                            continue;
                        };
                        match cap.text.as_deref() {
                            Some("&") => by_ref_all = true,
                            Some("=") => by_val_all = true,
                            Some(name) if !matches!(name, "[" | "]" | ",") => {
                                let by_ref = child.children.iter().any(|oid| {
                                    graph.get(oid).and_then(|n| n.text.as_deref()) == Some("&")
                                });
                                explicit_captures.push((name.to_string(), by_ref));
                            }
                            _ => {}
                        }
                    }
                }
                "compound_statement" => lambda_body_id = Some(*child_id),
                _ => {}
            }
        }
        let lambda_func_id = function_map.get(&node_id).copied();
        let outer_func_id = parent_map
            .get(&node_id)
            .and_then(|p| function_map.get(p))
            .copied();
        if let (Some(body_id), Some(outer_fn)) = (lambda_body_id, outer_func_id) {
            // Collect identifiers used inside the lambda body.
            let body_uses = collect_identifiers_in_expr(graph, body_id, Some(&parent_map));
            for var in &body_uses {
                let is_captured_by_ref = by_ref_all
                    || explicit_captures
                        .iter()
                        .any(|(name, by_ref)| name == &var.name && *by_ref);
                let is_captured_by_val = by_val_all
                    || explicit_captures
                        .iter()
                        .any(|(name, by_ref)| name == &var.name && !*by_ref);
                if !is_captured_by_ref && !is_captured_by_val {
                    continue;
                }
                // Emit REACHING_DEF from outer-scope definitions to the lambda use.
                for def_id in defs_by_var
                    .get(&(Some(outer_fn), var.name.clone()))
                    .into_iter()
                    .flatten()
                    .copied()
                {
                    push_edge(
                        &mut edges,
                        def_id,
                        var.node_id,
                        var.name.clone(),
                        "REACHING_DEF",
                    );
                }
                // By-ref write-back is deferred until defs_by_var is fully populated.
                if is_captured_by_ref {
                    lambda_writebacks.push((lambda_func_id, outer_fn, var.name.clone()));
                }
            }
        }
    }

    for node_id in type_index
        .get("initializer_pair")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(
            node_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(parent_id) = parent_map.get(&node_id).copied() else {
            continue;
        };
        if graph
            .get(&parent_id)
            .map(|n| n.node_type != "initializer_list")
            .unwrap_or(true)
        {
            continue;
        }
        let Some(node) = graph.get(&node_id) else {
            continue;
        };
        if let Some(value_id) = node.children.last().copied() {
            for var in collect_identifiers_in_expr(graph, value_id, Some(&parent_map)) {
                push_edge(&mut edges, var.node_id, node_id, var.name, "REACHING_DEF");
            }
        }
        if let Some(field_name) = initializer_pair_field_name(graph, node_id) {
            push_edge(&mut edges, node_id, parent_id, field_name, "REACHING_DEF");
        }
    }

    for node_id in type_index
        .get("compound_literal_expression")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(
            node_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(node) = graph.get(&node_id) else {
            continue;
        };
        for child_id in &node.children {
            let Some(child) = graph.get(child_id) else {
                continue;
            };
            if child.node_type != "initializer_list" {
                continue;
            }
            for pair_id in &child.children {
                let Some(pair_node) = graph.get(pair_id) else {
                    continue;
                };
                match pair_node.node_type.as_str() {
                    "initializer_pair" => {
                        if let Some(value_id) = pair_node.children.last().copied() {
                            for var in
                                collect_identifiers_in_expr(graph, value_id, Some(&parent_map))
                            {
                                let name = var.name.clone();
                                push_edge(
                                    &mut edges,
                                    var.node_id,
                                    *pair_id,
                                    name.clone(),
                                    "REACHING_DEF",
                                );
                                push_edge(&mut edges, *pair_id, node_id, name, "REACHING_DEF");
                            }
                        }
                    }
                    "identifier" => {
                        if let Some(name) = pair_node.text.clone() {
                            push_edge(&mut edges, *pair_id, node_id, name, "REACHING_DEF");
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    for node_id in type_index
        .get("array_declarator")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(
            node_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(node) = graph.get(&node_id) else {
            continue;
        };
        let Some(array_var) = get_declared_variable(graph, node_id) else {
            continue;
        };
        for size_expr_id in node.children.iter().skip(1).copied() {
            let Some(size_node) = graph.get(&size_expr_id) else {
                continue;
            };
            if matches!(size_node.node_type.as_str(), "[" | "]" | "number_literal") {
                continue;
            }
            if size_node.is_identifier() {
                push_edge(
                    &mut edges,
                    size_expr_id,
                    array_var.node_id,
                    array_var.name.clone(),
                    "SIZE_FLOW",
                );
            } else {
                for var in collect_identifiers_in_expr(graph, size_expr_id, Some(&parent_map)) {
                    push_edge(
                        &mut edges,
                        var.node_id,
                        array_var.node_id,
                        array_var.name.clone(),
                        "SIZE_FLOW",
                    );
                }
            }
        }
    }

    for node_id in type_index
        .get("field_expression")
        .cloned()
        .unwrap_or_default()
    {
        if !node_in_scope(
            node_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(field_name) = field_expression_field_name(graph, node_id) else {
            continue;
        };
        let function_id = function_map.get(&node_id).copied();
        let object_vars = field_expression_object_vars(graph, &parent_map, node_id);
        let is_assignment = is_lvalue_context(graph, &parent_map, node_id);

        if is_assignment {
            if let Some(field_id) = field_expression_field_identifier_id(graph, node_id) {
                definitions_lvalue.push(DataflowDef {
                    node_id: field_id,
                    variable: field_name.clone(),
                    function_id,
                });
                let bases: Vec<String> = if object_vars.is_empty() {
                    vec!["*".to_string()]
                } else {
                    object_vars.iter().map(|v| v.name.clone()).collect()
                };
                for base in &bases {
                    field_defs
                        .entry((function_id, base.clone(), field_name.clone()))
                        .or_default()
                        .push(field_id);
                }
                defs_by_var
                    .entry((function_id, field_name.clone()))
                    .or_default()
                    .push(field_id);
                for other_fe_id in field_expr_by_func_name
                    .get(&(function_id, field_name.clone()))
                    .into_iter()
                    .flatten()
                    .copied()
                {
                    if other_fe_id == node_id {
                        continue;
                    }
                    let Some(other_parent_id) = parent_map.get(&other_fe_id).copied() else {
                        continue;
                    };
                    let Some(other_parent) = graph.get(&other_parent_id) else {
                        continue;
                    };
                    if matches!(
                        other_parent.node_type.as_str(),
                        "pointer_expression" | "subscript_expression"
                    ) {
                        push_edge(
                            &mut edges,
                            field_id,
                            other_parent_id,
                            field_name.clone(),
                            "REACHING_DEF",
                        );
                    }
                }
            }
        }

        let fp = vec![field_name.clone()];

        for obj_var in &object_vars {
            uses.push(DataflowUse {
                node_id: obj_var.node_id,
                variable: obj_var.name.clone(),
                function_id,
            });
            push_edge_field(
                &mut edges,
                obj_var.node_id,
                node_id,
                obj_var.name.clone(),
                "REACHING_DEF",
                fp.clone(),
            );
        }

        if !is_assignment {
            if let Some(parent_id) = parent_map.get(&node_id).copied() {
                if is_expression_like(graph, parent_id) {
                    if let Some(field_id) = field_expression_field_identifier_id(graph, node_id) {
                        push_edge_field(
                            &mut edges,
                            field_id,
                            parent_id,
                            field_name.clone(),
                            "REACHING_DEF",
                            fp.clone(),
                        );
                    }
                }
            }
        }
    }

    for node_id in type_index.get("enumerator").cloned().unwrap_or_default() {
        if !node_in_scope(
            node_id,
            &function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(node) = graph.get(&node_id) else {
            continue;
        };
        let Some(first_child_id) = node.children.first().copied() else {
            continue;
        };
        let Some(first_child) = graph.get(&first_child_id) else {
            continue;
        };
        if first_child.node_type == "identifier" {
            if let Some(name) = first_child.text.clone() {
                definitions_lvalue.push(DataflowDef {
                    node_id: first_child_id,
                    variable: name.clone(),
                    function_id: None,
                });
                global_defs.entry(name).or_default().push(first_child_id);
            }
        }
    }

    // ── Go: channel send/receive dataflow ────────────────────────────────────
    // `ch <- v` : v flows into ch. `v := <-ch` : ch flows into v.
    for node_id in type_index.get("send_statement").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let function_id = function_map.get(&node_id).copied();
        // send_statement children: [channel_expr, "<-", value_expr]
        let Some(node) = graph.get(&node_id) else { continue; };
        let children: Vec<NodeId> = node.children.clone();
        if children.len() >= 2 {
            let chan_child = children[0];
            let val_child = children.last().copied().unwrap_or(children[0]);
            // value identifiers → channel use (value flows into channel)
            for var in collect_identifiers_in_expr(graph, val_child, Some(&parent_map)) {
                push_edge(&mut edges, var.node_id, node_id, var.name, "REACHING_DEF");
            }
            // channel identifier is a use
            for var in collect_identifiers_in_expr(graph, chan_child, Some(&parent_map)) {
                uses.push(DataflowUse { node_id: var.node_id, variable: var.name.clone(), function_id });
            }
        }
    }

    // Go: range clause — bind loop variables as defs, iterable as use.
    // range_clause children: [var_list, ":=", "range", iterable_expr]
    for node_id in type_index.get("range_clause").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let function_id = function_map.get(&node_id).copied();
        let Some(node) = graph.get(&node_id) else { continue; };
        let mut past_range = false;
        let mut lhs_ids: Vec<NodeId> = Vec::new();
        for &child_id in &node.children {
            let Some(child) = graph.get(&child_id) else { continue; };
            if child.text.as_deref() == Some("range") {
                past_range = true;
                continue;
            }
            if child.text.as_deref() == Some(":=") || child.text.as_deref() == Some("=") {
                continue;
            }
            if past_range {
                // iterable expression — its identifiers are uses
                for var in collect_identifiers_in_expr(graph, child_id, Some(&parent_map)) {
                    uses.push(DataflowUse { node_id: var.node_id, variable: var.name.clone(), function_id });
                    push_edge(&mut edges, var.node_id, node_id, var.name, "REACHING_DEF");
                }
            } else {
                // LHS variable list — each non-blank identifier is a def
                if child.is_identifier() {
                    if child.text.as_deref() != Some("_") {
                        if let Some(name) = child.text.clone() {
                            definitions_lvalue.push(DataflowDef { node_id: child_id, variable: name.clone(), function_id });
                            defs_by_var.entry((function_id, name)).or_default().push(child_id);
                            lhs_ids.push(child_id);
                        }
                    }
                } else if child.node_type == "expression_list" {
                    for &inner_id in &child.children {
                        let Some(inner) = graph.get(&inner_id) else { continue; };
                        if inner.is_identifier() && inner.text.as_deref() != Some("_") {
                            if let Some(name) = inner.text.clone() {
                                definitions_lvalue.push(DataflowDef { node_id: inner_id, variable: name.clone(), function_id });
                                defs_by_var.entry((function_id, name)).or_default().push(inner_id);
                            }
                        }
                    }
                }
            }
        }
    }

    // Go: composite literal — field uses flow into the composite literal node.
    // composite_literal children include field: value pairs.
    for node_id in type_index.get("composite_literal").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let function_id = function_map.get(&node_id).copied();
        let Some(node) = graph.get(&node_id) else { continue; };
        for &child_id in &node.children {
            let Some(child) = graph.get(&child_id) else { continue; };
            if child.node_type == "literal_value" || child.node_type == "keyed_element" {
                for var in collect_identifiers_in_expr(graph, child_id, Some(&parent_map)) {
                    uses.push(DataflowUse { node_id: var.node_id, variable: var.name.clone(), function_id });
                    push_edge(&mut edges, var.node_id, node_id, var.name, "REACHING_DEF");
                }
            }
        }
    }

    // ── Python: walrus operator `:=` — NamedExpr defines in outer scope ──────
    // named_expression: [identifier, ":=", value_expr]
    // The identifier is a def; value flows into it; also visible in outer scope.
    for node_id in type_index.get("named_expression").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let function_id = function_map.get(&node_id).copied();
        let Some(node) = graph.get(&node_id) else { continue; };
        if let Some(&name_id) = node.children.first() {
            let Some(name_node) = graph.get(&name_id) else { continue; };
            if name_node.is_identifier() {
                if let Some(name) = name_node.text.clone() {
                    definitions_lvalue.push(DataflowDef { node_id: name_id, variable: name.clone(), function_id });
                    defs_by_var.entry((function_id, name.clone())).or_default().push(name_id);
                    // Value expression → name def
                    if let Some(&val_id) = node.children.last() {
                        if val_id != name_id {
                            for var in collect_identifiers_in_expr(graph, val_id, Some(&parent_map)) {
                                push_edge(&mut edges, var.node_id, name_id, name.clone(), "REACHING_DEF");
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Python: assignment / augmented-assignment statements ─────────────────
    // assignment:           [lhs, "=",  rhs]
    // augmented_assignment: [lhs, "+=", rhs]  (and similar)
    //
    // The identifier loop above already classifies the LHS identifier as a DEF
    // (via is_lvalue_context recognising "assignment"/"augmented_assignment").
    // What is missing is a cross-variable REACHING_DEF edge from each RHS
    // identifier → the LHS identifier so that taint flows between variables
    // (e.g. `x = data` should give data→x flow, not just same-variable flow).
    for assign_type in ["assignment", "augmented_assignment"] {
        for node_id in type_index.get(assign_type).cloned().unwrap_or_default() {
            if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
                continue;
            }
            let Some(node) = graph.get(&node_id) else { continue; };
            if node.children.len() < 2 { continue; }
            let lhs_expr_id = node.children[0];
            // collect_identifiers_in_expr skips lvalue-context nodes, but here we
            // specifically want the LHS identifier, so look up it directly.
            let Some(lhs_node) = graph.get(&lhs_expr_id) else { continue; };
            let lhs_name = lhs_node.text.clone().or_else(|| {
                // tuple / attribute LHS — skip for now
                None
            });
            let Some(lhs_name) = lhs_name else { continue; };
            if !lhs_node.is_identifier() { continue; }
            let rhs_children: Vec<NodeId> = node.children[1..].to_vec();
            for rhs_child_id in rhs_children {
                for var in collect_identifiers_in_expr(graph, rhs_child_id, Some(&parent_map)) {
                    push_edge(
                        &mut edges,
                        var.node_id,
                        lhs_expr_id,
                        lhs_name.clone(),
                        "REACHING_DEF",
                    );
                }
            }
        }
    }

    // ── Go: short_var_declaration / assignment_statement ────────────────────
    // short_var_declaration: [lhs_identifier, ":=", rhs_expr]
    //   or (multi-assign): [expression_list_lhs, ":=", expression_list_rhs]
    // assignment_statement:  similar structure with "="
    //
    // The identifier loop above already classifies LHS identifiers as DEFs.
    // This pass adds the missing cross-variable REACHING_DEF edge from each
    // RHS identifier to the LHS identifier.
    for assign_type in ["short_var_declaration", "assignment_statement"] {
        for node_id in type_index.get(assign_type).cloned().unwrap_or_default() {
            if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
                continue;
            }
            let Some(node) = graph.get(&node_id) else { continue; };
            if node.children.len() < 2 { continue; }
            // Collect LHS identifier(s): first child (identifier) or first child's children
            // if it's an expression_list.
            let lhs_child_id = node.children[0];
            let lhs_ids: Vec<(NodeId, String)> = {
                match graph.get(&lhs_child_id) {
                    Some(lhs) if lhs.is_identifier() => {
                        lhs.text.as_ref().map(|t| vec![(lhs_child_id, t.clone())]).unwrap_or_default()
                    }
                    Some(lhs) if lhs.node_type == "expression_list" => {
                        lhs.children.iter().filter_map(|&cid| {
                            let c = graph.get(&cid)?;
                            if c.is_identifier() {
                                Some((cid, c.text.clone()?))
                            } else {
                                None
                            }
                        }).collect()
                    }
                    _ => vec![],
                }
            };
            for (lhs_id, lhs_name) in lhs_ids {
                for &rhs_child_id in node.children.iter().skip(1) {
                    for var in collect_identifiers_in_expr(graph, rhs_child_id, Some(&parent_map)) {
                        push_edge(&mut edges, var.node_id, lhs_id, lhs_name.clone(), "REACHING_DEF");
                    }
                }
            }
        }
    }

    // ── Java / JS / TS: variable_declarator ─────────────────────────────────
    // variable_declarator: [name_identifier, "=", rhs_expr]
    // The identifier loop classifies name_identifier as a DEF.
    // This pass creates the cross-variable edge: rhs_identifier → name_identifier.
    for node_id in type_index.get("variable_declarator").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let Some(node) = graph.get(&node_id) else { continue; };
        if node.children.len() < 2 { continue; }
        let lhs_id = node.children[0];
        let Some(lhs_node) = graph.get(&lhs_id) else { continue; };
        let Some(lhs_name) = lhs_node.text.clone() else { continue; };
        if !lhs_node.is_identifier() { continue; }
        for &rhs_child_id in node.children.iter().skip(1) {
            for var in collect_identifiers_in_expr(graph, rhs_child_id, Some(&parent_map)) {
                push_edge(&mut edges, var.node_id, lhs_id, lhs_name.clone(), "REACHING_DEF");
            }
        }
    }

    // ── Rust: let_declaration ────────────────────────────────────────────────
    // let_declaration children have field names: "pattern" (lhs) and "value" (rhs).
    // The identifier loop classifies the pattern identifier as a DEF.
    // This pass creates the cross-variable edge: rhs_identifier → pattern_identifier.
    for node_id in type_index.get("let_declaration").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let Some(node) = graph.get(&node_id) else { continue; };
        let mut lhs_id_opt: Option<NodeId> = None;
        let mut rhs_ids: Vec<NodeId> = Vec::new();
        let mut past_eq = false;
        for (&cid, fname) in node.children.iter().zip(node.field_names.iter()) {
            match fname.as_deref() {
                Some("pattern") => lhs_id_opt = Some(cid),
                Some("value") => rhs_ids.push(cid),
                _ => {
                    // Fallback: split on "=" token for let declarations without field names
                    if graph.get(&cid).and_then(|c| c.text.as_deref()).map(|t| t == "=") == Some(true) {
                        past_eq = true;
                    } else if past_eq {
                        rhs_ids.push(cid);
                    }
                }
            }
        }
        // If no pattern field found, assume first non-keyword child is the pattern
        if lhs_id_opt.is_none() {
            past_eq = false;
            for (&cid, fname) in node.children.iter().zip(node.field_names.iter()) {
                if graph.get(&cid).and_then(|c| c.text.as_deref()).map(|t| t == "let") == Some(true) {
                    continue;
                }
                if graph.get(&cid).and_then(|c| c.text.as_deref()).map(|t| t == "=") == Some(true) {
                    past_eq = true;
                    continue;
                }
                if !past_eq && lhs_id_opt.is_none() {
                    lhs_id_opt = Some(cid);
                } else if past_eq {
                    rhs_ids.push(cid);
                }
            }
        }
        let Some(lhs_id) = lhs_id_opt else { continue; };
        let Some(lhs_node) = graph.get(&lhs_id) else { continue; };
        if !lhs_node.is_identifier() { continue; }
        let Some(lhs_name) = lhs_node.text.clone() else { continue; };
        for &rhs_child_id in &rhs_ids {
            for var in collect_identifiers_in_expr(graph, rhs_child_id, Some(&parent_map)) {
                push_edge(&mut edges, var.node_id, lhs_id, lhs_name.clone(), "REACHING_DEF");
            }
        }
    }

    // Python: for-in comprehension iteration variable — isolated scope def.
    // for_in_clause: [identifier, "in", iterable]
    for node_id in type_index.get("for_in_clause").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let function_id = function_map.get(&node_id).copied();
        let Some(node) = graph.get(&node_id) else { continue; };
        let mut past_in = false;
        for &child_id in &node.children {
            let Some(child) = graph.get(&child_id) else { continue; };
            if child.text.as_deref() == Some("in") { past_in = true; continue; }
            if past_in {
                for var in collect_identifiers_in_expr(graph, child_id, Some(&parent_map)) {
                    uses.push(DataflowUse { node_id: var.node_id, variable: var.name.clone(), function_id });
                }
            } else if child.is_identifier() {
                if let Some(name) = child.text.clone() {
                    definitions_lvalue.push(DataflowDef { node_id: child_id, variable: name.clone(), function_id });
                    defs_by_var.entry((function_id, name)).or_default().push(child_id);
                }
            }
        }
    }

    // ── Java: enhanced-for iteration variable def ─────────────────────────────
    // enhanced_for_statement: [type, name, ":", iterable, body]
    for node_id in type_index.get("enhanced_for_statement").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let function_id = function_map.get(&node_id).copied();
        let Some(node) = graph.get(&node_id) else { continue; };
        let mut seen_colon = false;
        let mut var_id: Option<NodeId> = None;
        for &child_id in &node.children {
            let Some(child) = graph.get(&child_id) else { continue; };
            if child.text.as_deref() == Some(":") { seen_colon = true; continue; }
            if !seen_colon {
                if child.is_identifier() && var_id.is_none() {
                    // Skip type annotations; the second identifier is the variable name.
                    // Actually: first identifier without a matching type_ref parent is the var.
                    if child.node_type == "identifier" {
                        var_id = Some(child_id);
                    }
                }
            } else {
                // iterable expr identifiers are uses
                for var in collect_identifiers_in_expr(graph, child_id, Some(&parent_map)) {
                    uses.push(DataflowUse { node_id: var.node_id, variable: var.name.clone(), function_id });
                }
            }
        }
        if let Some(vid) = var_id {
            if let Some(name) = graph.get(&vid).and_then(|n| n.text.clone()) {
                definitions_lvalue.push(DataflowDef { node_id: vid, variable: name.clone(), function_id });
                defs_by_var.entry((function_id, name)).or_default().push(vid);
            }
        }
    }

    // Java: instanceof pattern binding — `expr instanceof Type name` defines `name`.
    // pattern_expression / type_pattern children: [type_identifier, identifier]
    for node_id in type_index.get("type_pattern").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let function_id = function_map.get(&node_id).copied();
        let Some(node) = graph.get(&node_id) else { continue; };
        // last child is the pattern variable name
        if let Some(&last_id) = node.children.last() {
            let Some(last) = graph.get(&last_id) else { continue; };
            if last.is_identifier() {
                if let Some(name) = last.text.clone() {
                    definitions_lvalue.push(DataflowDef { node_id: last_id, variable: name.clone(), function_id });
                    defs_by_var.entry((function_id, name)).or_default().push(last_id);
                }
            }
        }
    }

    // ── JS/TS: var-hoisting — var declarations hoist to function entry ────────
    // This creates a synthetic REACHING_DEF from all var_declarator name nodes
    // to every identifier use of the same name in the enclosing function.
    // We record them as definitions (is_lvalue already captures this via
    // variable_declarator), so no additional pass is needed here;
    // the main identifier loop above already processes them. The `var`-specific
    // behavior (same-name re-declarations within a function are merged) is
    // handled implicitly because defs_by_var accumulates all defs by (fn, name).

    // JS/TS: yield data-flow — yield_expression identifier operands flow into the expression.
    for node_id in type_index.get("yield_expression").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let function_id = function_map.get(&node_id).copied();
        let Some(node) = graph.get(&node_id) else { continue; };
        for &child_id in &node.children {
            let Some(child) = graph.get(&child_id) else { continue; };
            if child.text.as_deref() == Some("yield") || child.text.as_deref() == Some("*") { continue; }
            for var in collect_identifiers_in_expr(graph, child_id, Some(&parent_map)) {
                uses.push(DataflowUse { node_id: var.node_id, variable: var.name.clone(), function_id });
                push_edge(&mut edges, var.node_id, node_id, var.name, "REACHING_DEF");
            }
        }
    }

    // ── Rust: try_expression `expr?` — success-path def flows through ─────────
    // try_expression: [inner_expr, "?"]
    // The inner expression's identifiers are uses; the expression itself is a use
    // (value passes through on Ok path). No new defs; error path early-returns.
    for node_id in type_index.get("try_expression").cloned().unwrap_or_default() {
        if !node_in_scope(node_id, &function_map, affected_function_ids, include_globals) {
            continue;
        }
        let Some(node) = graph.get(&node_id) else { continue; };
        for &child_id in &node.children {
            let Some(child) = graph.get(&child_id) else { continue; };
            if child.text.as_deref() == Some("?") { continue; }
            for var in collect_identifiers_in_expr(graph, child_id, Some(&parent_map)) {
                push_edge(&mut edges, var.node_id, node_id, var.name, "REACHING_DEF");
            }
        }
    }

    // Rust: closure captures — identifiers used inside a closure that are
    // defined in the enclosing scope flow in via REACHING_DEF.
    // (Already handled by the main def/use loop through defs_by_var since
    // function_map maps nodes inside closures to the closure's function_id.
    // Cross-function reaching_def from outer scope: the lambda_writeback
    // mechanism above handles the C++ case; same pattern applies to Rust
    // closure_expression. No additional pass needed.)

    // Combine: lvalue defs first so callers find local vars before parameters
    // when searching by variable name (e.g. `definitions.iter().find`).
    let mut definitions = definitions_lvalue;
    definitions.extend(definitions_param);

    for def in &definitions {
        if def.function_id.is_some() {
            defs_by_var
                .entry((def.function_id, def.variable.clone()))
                .or_default()
                .push(def.node_id);
        } else {
            global_defs
                .entry(def.variable.clone())
                .or_default()
                .push(def.node_id);
        }
    }

    for (lambda_func_id, outer_fn, var_name) in &lambda_writebacks {
        for def_id in defs_by_var
            .get(&(*lambda_func_id, var_name.clone()))
            .into_iter()
            .flatten()
            .copied()
        {
            for outer_use_id in uses
                .iter()
                .filter(|u| u.function_id == Some(*outer_fn) && u.variable == *var_name)
                .map(|u| u.node_id)
            {
                push_edge(
                    &mut edges,
                    def_id,
                    outer_use_id,
                    var_name.clone(),
                    "REACHING_DEF",
                );
            }
        }
    }

    for use_item in &uses {
        let key = (use_item.function_id, use_item.variable.clone());
        for def_id in defs_by_var.get(&key).into_iter().flatten().copied() {
            // CFG-primary gating: when BB reachability data is available, trust the
            // CFG rather than source order.  Source order produces false positives for
            // goto-past-def and switch-fallthrough patterns.  Fall back to source order
            // only when no BB data exists (e.g. synthetic/header nodes).
            let reaches_via_order = def_precedes_use(graph, def_id, use_item.node_id);
            let reaches_via_cfg = !bb_reachability.is_empty()
                && def_reaches_use(graph, &bb_reachability, def_id, use_item.node_id);

            let can_reach = if bb_reachability.is_empty() {
                reaches_via_order
            } else {
                reaches_via_cfg
            };

            if can_reach {
                // Loop-carried: CFG back-edge reaches use but source order does not
                // (def appears after use in source, e.g. loop body re-defs header var).
                let edge_type = if reaches_via_cfg && !reaches_via_order {
                    "LOOP_CARRY"
                } else {
                    "REACHING_DEF"
                };
                push_edge(
                    &mut edges,
                    def_id,
                    use_item.node_id,
                    use_item.variable.clone(),
                    edge_type,
                );
            }
        }
        for def_id in global_defs
            .get(&use_item.variable)
            .into_iter()
            .flatten()
            .copied()
        {
            push_edge(
                &mut edges,
                def_id,
                use_item.node_id,
                use_item.variable.clone(),
                "REACHING_DEF",
            );
        }
        let field_context = field_use_context(graph, &parent_map, use_item.node_id);
        let field_name = field_context
            .as_ref()
            .map(|(f, _, _)| f.clone())
            .unwrap_or_else(|| use_item.variable.clone());
        let base_paths: Vec<String> = field_context
            .as_ref()
            .map(|(_, bases, _)| bases.clone())
            .unwrap_or_else(|| vec!["*".to_string()]);
        let func_id = field_context
            .as_ref()
            .and_then(|(_, _, fid)| *fid)
            .or(use_item.function_id);
        let field_use_struct =
            resolve_field_access_struct_type(graph, &parent_map, use_item.node_id)
                .or_else(|| enclosing_struct_name(graph, &parent_map, use_item.node_id));
        for def_id in lookup_field_def_ids(
            &field_defs,
            func_id,
            &base_paths,
            &field_name,
            field_use_struct.as_deref(),
            graph,
            &parent_map,
        ) {
            push_edge(
                &mut edges,
                def_id,
                use_item.node_id,
                field_name.clone(),
                "REACHING_DEF",
            );
        }
    }

    add_points_to_edges(
        graph,
        &mut edges,
        affected_function_ids,
        include_globals,
        &function_map,
    );
    add_return_flow_edges(
        graph,
        &mut edges,
        &parent_map,
        &function_map,
        &type_index,
        affected_function_ids,
        include_globals,
    );
    add_call_return_edges(
        graph,
        &mut edges,
        &type_index,
        &function_map,
        affected_function_ids,
        include_globals,
    );
    add_taint_propagator_edges(
        graph,
        &mut edges,
        &type_index,
        &parent_map,
        &function_map,
        affected_function_ids,
        include_globals,
        macro_aliases,
    );
    if include_interprocedural {
        add_interprocedural_edges(
            graph,
            &mut edges,
            &mut cross_file_calls,
            macro_aliases,
            affected_function_ids,
            include_globals,
            &owned_maps,
        );
    }

    // Deduplicate edges once at the end instead of per-push (O(E) vs O(E²)).
    {
        use std::collections::HashSet;
        let mut seen = HashSet::with_capacity(edges.len());
        edges.retain(|e| {
            seen.insert((
                e.source,
                e.destination,
                e.variable.clone(),
                e.edge_type.clone(),
            ))
        });
    }

    (
        DataflowGraph {
            definitions,
            uses,
            edges,
        },
        cross_file_calls,
    )
}

pub fn build_dataflow_for_functions(
    graph: &BTreeMap<NodeId, AstNode>,
    basic_blocks: Option<&BTreeMap<String, BasicBlock>>,
    previous: Option<&DataflowGraph>,
    affected_function_ids: &BTreeSet<NodeId>,
    include_globals: bool,
    preprocessing_maps: Option<&PreprocessingMaps>,
    macro_aliases: Option<&BTreeMap<String, String>>,
) -> (DataflowGraph, Vec<crate::CrossFileCallEdge>) {
    if previous.is_none() || (affected_function_ids.is_empty() && !include_globals) {
        return build_dataflow(graph, basic_blocks, preprocessing_maps, macro_aliases);
    }

    // Build preprocessing maps once; share them with build_dataflow_impl and
    // the subsequent edge-merge step so neither has to rebuild.
    let owned_maps: PreprocessingMaps = preprocessing_maps
        .cloned()
        .unwrap_or_else(|| build_preprocessing_maps(graph));
    let function_map = &owned_maps.1;
    let (fresh, new_xfile_calls) = build_dataflow_impl(
        graph,
        basic_blocks,
        Some(&owned_maps),
        macro_aliases,
        Some(affected_function_ids),
        include_globals,
        false,
    );
    let previous = previous.expect("checked is_some");

    let definitions = previous
        .definitions
        .iter()
        .filter(|def| {
            !dataflow_item_in_scope(def.function_id, affected_function_ids, include_globals)
        })
        .cloned()
        .chain(
            fresh
                .definitions
                .iter()
                .filter(|def| {
                    dataflow_item_in_scope(def.function_id, affected_function_ids, include_globals)
                })
                .cloned(),
        )
        .collect();

    let uses = previous
        .uses
        .iter()
        .filter(|use_item| {
            !dataflow_item_in_scope(use_item.function_id, affected_function_ids, include_globals)
        })
        .cloned()
        .chain(
            fresh
                .uses
                .iter()
                .filter(|use_item| {
                    dataflow_item_in_scope(
                        use_item.function_id,
                        affected_function_ids,
                        include_globals,
                    )
                })
                .cloned(),
        )
        .collect();

    let merged_edges: Vec<DataflowEdge> = previous
        .edges
        .iter()
        .filter(|edge| {
            !edge_touches_functions(edge, &function_map, affected_function_ids, include_globals)
        })
        .cloned()
        .chain(
            fresh
                .edges
                .iter()
                .filter(|edge| {
                    edge_touches_functions(
                        edge,
                        &function_map,
                        affected_function_ids,
                        include_globals,
                    )
                })
                .cloned(),
        )
        .collect();

    // Remove edges whose source or destination no longer exists in the AST.
    // This cleans up stale edges left over when node IDs are recycled or
    // removed during incremental updates.
    let edges = merged_edges
        .into_iter()
        .filter(|edge| graph.contains_key(&edge.source) && graph.contains_key(&edge.destination))
        .collect();

    (
        DataflowGraph {
            definitions,
            uses,
            edges,
        },
        new_xfile_calls,
    )
}

pub fn enrich_cpg_with_flow(cpg: &mut Cpg) {
    let maps = build_preprocessing_maps(&cpg.ast);
    cpg.call_graph = build_call_graph(&cpg.ast, Some(&maps), None);
    let (dataflow, xfile) = build_dataflow(&cpg.ast, Some(&cpg.basic_blocks), Some(&maps), None);
    cpg.dataflow = dataflow;
    cpg.workspace.cross_file_calls = xfile;
}

#[derive(Clone)]
struct VarRef {
    name: String,
    node_id: NodeId,
}

fn is_inside_node(
    parent_map: &BTreeMap<NodeId, NodeId>,
    child_id: NodeId,
    container_id: NodeId,
) -> bool {
    let mut current = Some(child_id);
    while let Some(id) = current {
        if id == container_id {
            return true;
        }
        current = parent_map.get(&id).copied();
    }
    false
}

fn is_lvalue_context(
    graph: &BTreeMap<NodeId, AstNode>,
    parent_map: &BTreeMap<NodeId, NodeId>,
    node_id: NodeId,
) -> bool {
    let Some(parent_id) = parent_map.get(&node_id).copied() else {
        return false;
    };
    let Some(parent) = graph.get(&parent_id) else {
        return false;
    };

    match parent.node_type.as_str() {
        "pointer_declarator"
        | "array_declarator"
        | "parenthesized_declarator"
        | "function_declarator"
        | "reference_declarator" => {
            parent.children.first().copied() == Some(node_id)
                && is_lvalue_context(graph, parent_map, parent_id)
        }
        "parameter_declaration" => parent.children.first().copied() != Some(node_id),
        // C/C++, Python, JS/TS
        "function_definition" => true,
        // Go: function/method declarations, func literals
        // Java: method/constructor declarations
        // JS/TS: function declarations, arrow functions
        // Rust: function items
        "function_declaration"
        | "method_declaration"
        | "func_literal"
        | "function_item"
        | "constructor_declaration" => true,
        // Go: var_spec and const_spec — the name identifier (first child) is the def
        "var_spec" | "const_spec" => parent.children.first().copied() == Some(node_id),
        // Go: short_var_declaration — ALL LHS identifiers are defs.
        // After Pass 1.6 flattening, expression_list nodes are removed from
        // short_var_declaration.children but still exist in the AST with their
        // original children. The first child of short_var_declaration is always
        // a LHS identifier (fast path). For multi-assignment (a, b := foo()),
        // find the original LHS expression_list (lowest node_id with parent_id
        // = this short_var_declaration) and check if node_id is in its children.
        "short_var_declaration" => {
            if parent.children.first().copied() == Some(node_id) {
                return true;
            }
            // Find the original LHS expression_list and check membership
            graph
                .iter()
                .filter(|(eid, en)| {
                    en.node_type == "expression_list" && en.parent_id == Some(parent_id)
                })
                .min_by_key(|(eid, _)| *eid)
                .map_or(false, |(_, lhs)| lhs.children.contains(&node_id))
        }
        // Go: assignment_statement — first expression_list (LHS) is def context
        "assignment_statement" => {
            parent.children.first().copied() == Some(node_id)
                || (!parent.children.is_empty()
                    && is_inside_node(parent_map, node_id, parent.children[0]))
        }
        // Go: expression_list as LHS of short_var_declaration, assignment_statement,
        // or range_clause (for k, v := range m)
        "expression_list" => {
            if let Some(&grandparent_id) = parent_map.get(&parent_id) {
                if let Some(gp) = graph.get(&grandparent_id) {
                    if matches!(
                        gp.node_type.as_str(),
                        "short_var_declaration" | "assignment_statement" | "range_clause"
                    ) {
                        return gp.children.first().copied() == Some(parent_id);
                    }
                }
            }
            false
        }
        // Python/Java/Rust: local variable declarations
        "local_variable_declaration" => true,
        // Rust: let_declaration — only the "pattern" field child is the lvalue.
        // Use field_names to detect pattern field; wildcard `_` is an unnamed node
        // so the value identifier may otherwise appear as the first named child.
        "let_declaration" => {
            parent.children.iter().zip(parent.field_names.iter())
                .any(|(&cid, fname)| cid == node_id && fname.as_deref() == Some("pattern"))
        }
        // JS/TS: variable_declarator — the name (first child) is the lvalue
        "variable_declarator" => parent.children.first().copied() == Some(node_id),
        // Python: assignment — first child (left side) is the lvalue
        "assignment" | "augmented_assignment" => {
            parent.children.first().copied() == Some(node_id)
        }
        // Rust: match arm patterns — identifiers in patterns are bindings (defs)
        "match_arm" | "tuple_struct_pattern" | "struct_pattern" | "tuple_pattern"
        | "slice_pattern" | "capture_pattern" | "or_pattern" | "ref_pattern"
        | "mut_pattern" => true,
        // JS/TS: destructuring patterns — identifiers in array/object patterns are defs
        "array_pattern" | "object_pattern" => true,
        "assignment_expression" | "init_declarator" => {
            if parent.children.first().copied() == Some(node_id) {
                return true;
            }
            parent
                .children
                .first()
                .copied()
                .map(|lhs_id| {
                    graph
                        .get(&lhs_id)
                        .map(|lhs| {
                            matches!(
                                lhs.node_type.as_str(),
                                "pointer_expression"
                                    | "subscript_expression"
                                    | "field_expression"
                                    | "cast_expression"
                                    | "parenthesized_expression"
                            ) && is_inside_node(parent_map, node_id, lhs_id)
                        })
                        .unwrap_or(false)
                })
                .unwrap_or(false)
        }
        "declarator"
        | "update_expression"
        | "preincrement_expression"
        | "predecrement_expression"
        | "postincrement_expression"
        | "postdecrement_expression" => true,
        "pointer_expression"
        | "subscript_expression"
        | "field_expression"
        | "cast_expression"
        | "parenthesized_expression" => is_lvalue_context(graph, parent_map, parent_id),
        "for_statement" => parent
            .children
            .first()
            .copied()
            .map(|first| first == node_id || is_inside_node(parent_map, node_id, first))
            .unwrap_or(false),
        _ => false,
    }
}

fn is_field_declaration_name(graph: &BTreeMap<NodeId, AstNode>, node_id: NodeId) -> bool {
    let Some(node) = graph.get(&node_id) else {
        return false;
    };
    if node.node_type != "field_identifier" {
        return false;
    }
    let Some(parent_id) = node.parent_id else {
        return false;
    };
    graph
        .get(&parent_id)
        .map(|parent| parent.is_field_def() || parent.node_type == "field_designator")
        .unwrap_or(false)
}

fn is_call_callee_identifier(graph: &BTreeMap<NodeId, AstNode>, node_id: NodeId) -> bool {
    let Some(node) = graph.get(&node_id) else {
        return false;
    };
    if !node.is_identifier() {
        return false;
    }
    let Some(parent_id) = node.parent_id else {
        return false;
    };
    graph
        .get(&parent_id)
        .map(|parent| {
            parent.is_call()
                && parent.children.first().copied() == Some(node_id)
        })
        .unwrap_or(false)
}

fn is_parameter_name(graph: &BTreeMap<NodeId, AstNode>, node_id: NodeId) -> bool {
    let Some(node) = graph.get(&node_id) else {
        return false;
    };
    // Python: parameters are lifted to ParamDef kind directly (not wrapped in an Identifier child)
    if node.is_param_def() {
        return true;
    }
    if !node.is_identifier() {
        return false;
    }

    let mut current = node.parent_id;
    while let Some(pid) = current {
        let Some(parent) = graph.get(&pid) else {
            return false;
        };
        if parent.is_param_def() {
            return true;
        }
        if parent.is_method_def() {
            return false;
        }
        current = parent.parent_id;
    }
    false
}

fn get_declared_var_name(
    graph: &BTreeMap<NodeId, AstNode>,
    node_id: NodeId,
    depth: usize,
) -> Option<String> {
    if depth > 8 {
        return None;
    }
    let node = graph.get(&node_id)?;
    match node.node_type.as_str() {
        "identifier" => node.text.clone(),
        "pointer_declarator"
        | "array_declarator"
        | "parenthesized_declarator"
        | "function_declarator"
        | "reference_declarator"
        | "declarator"
        | "init_declarator" => node
            .children
            .iter()
            .find_map(|child_id| get_declared_var_name(graph, *child_id, depth + 1)),
        _ => None,
    }
}

fn get_declared_variable(graph: &BTreeMap<NodeId, AstNode>, node_id: NodeId) -> Option<VarRef> {
    let node = graph.get(&node_id)?;
    match node.node_type.as_str() {
        "identifier" => Some(VarRef {
            name: node.text.clone()?,
            node_id,
        }),
        "pointer_declarator"
        | "array_declarator"
        | "parenthesized_declarator"
        | "function_declarator"
        | "reference_declarator"
        | "declarator"
        | "init_declarator" => node
            .children
            .iter()
            .find_map(|child_id| get_declared_variable(graph, *child_id)),
        _ => None,
    }
}

fn is_expression_like(graph: &BTreeMap<NodeId, AstNode>, node_id: NodeId) -> bool {
    graph
        .get(&node_id)
        .map(|node| {
            node.node_type.contains("expression")
                || matches!(
                    node.node_type.as_str(),
                    "call_expression"
                        | "initializer_list"
                        | "initializer_pair"
                        | "argument_list"
                        | "return_statement"
                        | "co_return_statement"
                )
        })
        .unwrap_or(false)
}

fn collect_identifiers_in_expr(
    graph: &BTreeMap<NodeId, AstNode>,
    node_id: NodeId,
    parent_map: Option<&BTreeMap<NodeId, NodeId>>,
) -> Vec<VarRef> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec![node_id];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(node) = graph.get(&id) else { continue };
        if node.is_identifier() {
            if let Some(name) = node.text.clone() {
                if !parent_map
                    .map(|pm| {
                        is_call_callee_identifier(graph, id) || is_lvalue_context(graph, pm, id)
                    })
                    .unwrap_or(false)
                {
                    out.push(VarRef { name, node_id: id });
                }
            }
        }
        stack.extend(node.children.iter().rev().copied());
    }
    out
}

fn find_call_expression_in_tree(
    graph: &BTreeMap<NodeId, AstNode>,
    node_id: NodeId,
) -> Option<NodeId> {
    let mut stack = vec![node_id];
    while let Some(id) = stack.pop() {
        let Some(node) = graph.get(&id) else { continue };
        if node.is_call() {
            return Some(id);
        }
        stack.extend(node.children.iter().rev().copied());
    }
    None
}

fn initializer_pair_field_name(
    graph: &BTreeMap<NodeId, AstNode>,
    node_id: NodeId,
) -> Option<String> {
    let node = graph.get(&node_id)?;
    for child_id in &node.children {
        let child = graph.get(child_id)?;
        match child.node_type.as_str() {
            "field_identifier" => return child.text.clone(),
            "field_designator" | "subscript_designator" => {
                for gc_id in &child.children {
                    let gc = graph.get(gc_id)?;
                    if gc.node_type == "field_identifier" {
                        return gc.text.clone();
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn record_func_ptr_alias(
    graph: &BTreeMap<NodeId, AstNode>,
    lhs_id: NodeId,
    rhs_id: NodeId,
    function_name_to_id: &BTreeMap<String, NodeId>,
    aliases: &mut BTreeMap<String, String>,
) {
    let Some(lhs_name) = get_declared_var_name(graph, lhs_id, 0) else {
        return;
    };
    let Some(rhs) = graph.get(&rhs_id) else {
        return;
    };
    // Handle both `fp = func` and `fp = &func` (address-of).
    // Use AST node type checks instead of text prefix matching (fixes A3).
    let rhs_name = if rhs.node_type == "identifier" {
        rhs.text.clone()
    } else if rhs.node_type == "pointer_expression" {
        // Address-of: first child should be `&` operator token, rest is the operand.
        // Find the identifier child (skip the `&` token child).
        rhs.children.iter().find_map(|child_id| {
            let child = graph.get(child_id)?;
            if child.node_type == "identifier" {
                child.text.clone()
            } else {
                None
            }
        })
    } else {
        None
    };
    let Some(rhs_name) = rhs_name else { return };
    if function_name_to_id.contains_key(&rhs_name) {
        aliases.insert(lhs_name, rhs_name);
    }
}

/// Populate `array_dispatch` from an initializer_list assignment like:
/// `void (*handlers[])(int) = {foo, bar, baz};`
/// Maps array variable name → list of function names in the initializer.
fn record_array_dispatch(
    graph: &BTreeMap<NodeId, AstNode>,
    lhs_id: NodeId,
    rhs_id: NodeId,
    function_name_to_id: &BTreeMap<String, NodeId>,
    dispatch: &mut BTreeMap<String, Vec<String>>,
) {
    // LHS must contain an array_declarator or the variable itself being an array
    let lhs_is_array = {
        let mut found = false;
        let mut stack = vec![lhs_id];
        while let Some(id) = stack.pop() {
            let Some(n) = graph.get(&id) else { continue };
            if n.node_type == "array_declarator" {
                found = true;
                break;
            }
            for child in &n.children {
                stack.push(*child);
            }
        }
        found
    };
    if !lhs_is_array {
        return;
    }

    // Extract the base variable name from the LHS
    let Some(arr_name) = get_declared_var_name(graph, lhs_id, 0) else {
        return;
    };

    // RHS must be an initializer_list
    let Some(rhs) = graph.get(&rhs_id) else {
        return;
    };
    if rhs.node_type != "initializer_list" {
        return;
    }

    let mut targets: Vec<String> = Vec::new();
    for elem_id in &rhs.children {
        let Some(elem) = graph.get(elem_id) else {
            continue;
        };
        let fn_name = if elem.node_type == "identifier" {
            elem.text.clone()
        } else if elem.node_type == "pointer_expression" {
            // &func
            elem.children.iter().find_map(|child_id| {
                let child = graph.get(child_id)?;
                if child.node_type == "identifier" {
                    child.text.clone()
                } else {
                    None
                }
            })
        } else {
            None
        };
        if let Some(name) = fn_name {
            if function_name_to_id.contains_key(&name) {
                targets.push(name);
            }
        }
    }

    if !targets.is_empty() {
        dispatch.entry(arr_name).or_default().extend(targets);
    }
}

fn def_precedes_use(graph: &BTreeMap<NodeId, AstNode>, def_id: NodeId, use_id: NodeId) -> bool {
    let Some(def) = graph.get(&def_id) else {
        return false;
    };
    let Some(u) = graph.get(&use_id) else {
        return false;
    };
    (def.line, def.column, def_id) <= (u.line, u.column, use_id)
}

/// Pre-compute CFG reachability for a set of basic blocks via BFS.
/// Returns a map `bb_id → set of BBs reachable from bb_id` (including self).
/// Follows both normal (`successors`) and exception (`exception_successors`) edges.
fn build_bb_reachability(
    basic_blocks: &BTreeMap<String, BasicBlock>,
    function_bbs: &FxHashSet<String>,
) -> FxHashMap<String, FxHashSet<String>> {
    let mut reachability: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();

    for start_bb in function_bbs {
        let reached = reachability.entry(start_bb.clone()).or_default();
        reached.insert(start_bb.clone());
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start_bb.clone());
        while let Some(bb) = queue.pop_front() {
            let Some(block) = basic_blocks.get(&bb) else {
                continue;
            };
            for succ in block
                .successors
                .iter()
                .chain(block.exception_successors.iter())
            {
                if function_bbs.contains(succ) && reached.insert(succ.clone()) {
                    queue.push_back(succ.clone());
                }
            }
        }
    }

    reachability
}

fn reachable_basic_blocks_from_function_entries(
    basic_blocks: &BTreeMap<String, BasicBlock>,
) -> FxHashSet<String> {
    let entries: Vec<String> = basic_blocks
        .iter()
        .filter_map(|(bb_id, block)| {
            block
                .nodes
                .contains(&block.function)
                .then_some(bb_id.clone())
        })
        .collect();

    if entries.is_empty() {
        return basic_blocks.keys().cloned().collect();
    }

    let mut reached = FxHashSet::default();
    let mut queue = std::collections::VecDeque::new();
    for entry in entries {
        if reached.insert(entry.clone()) {
            queue.push_back(entry);
        }
    }

    while let Some(bb) = queue.pop_front() {
        let Some(block) = basic_blocks.get(&bb) else {
            continue;
        };
        for succ in block
            .successors
            .iter()
            .chain(block.exception_successors.iter())
        {
            if basic_blocks.contains_key(succ) && reached.insert(succ.clone()) {
                queue.push_back(succ.clone());
            }
        }
    }

    reached
}

/// Check whether a definition can reach a use via CFG paths (including loop
/// back-edges).  Returns `true` if:
/// * Either node lacks a BB assignment (no CFG info) AND the def precedes the
///   use by source line (existing fallback), OR
/// * The def's BB can reach the use's BB via the CFG (any path, including
///   backward edges through loops).
///
/// When the def comes AFTER the use in source but is still reachable (loop-
/// carried), the caller should tag the edge `"LOOP_CARRY"` instead of
/// `"REACHING_DEF"` so rules can distinguish the two kinds.
fn def_reaches_use(
    graph: &BTreeMap<NodeId, AstNode>,
    bb_reachability: &FxHashMap<String, FxHashSet<String>>,
    def_id: NodeId,
    use_id: NodeId,
) -> bool {
    let def_bb = graph.get(&def_id).and_then(|n| n.basic_block.clone());
    let use_bb = graph.get(&use_id).and_then(|n| n.basic_block.clone());

    match (def_bb, use_bb) {
        (Some(dbb), Some(ubb)) => {
            // CFG path exists (including back-edges through loops).
            bb_reachability
                .get(&dbb)
                .map_or(false, |r| r.contains(&ubb))
        }
        // No CFG info for at least one endpoint → fall back to source order.
        _ => def_precedes_use(graph, def_id, use_id),
    }
}

fn push_edge(
    edges: &mut Vec<DataflowEdge>,
    source: NodeId,
    destination: NodeId,
    variable: String,
    edge_type: &str,
) {
    edges.push(DataflowEdge {
        source,
        destination,
        variable,
        edge_type: edge_type.to_string(),
        field_path: vec![],
    });
}

fn push_edge_field(
    edges: &mut Vec<DataflowEdge>,
    source: NodeId,
    destination: NodeId,
    variable: String,
    edge_type: &str,
    field_path: Vec<String>,
) {
    edges.push(DataflowEdge {
        source,
        destination,
        variable,
        edge_type: edge_type.to_string(),
        field_path,
    });
}

fn edge_touches_functions(
    edge: &DataflowEdge,
    function_map: &BTreeMap<NodeId, NodeId>,
    affected_function_ids: &BTreeSet<NodeId>,
    include_globals: bool,
) -> bool {
    node_in_scope(
        edge.source,
        function_map,
        Some(affected_function_ids),
        include_globals,
    ) || node_in_scope(
        edge.destination,
        function_map,
        Some(affected_function_ids),
        include_globals,
    )
}

fn node_in_scope(
    node_id: NodeId,
    function_map: &BTreeMap<NodeId, NodeId>,
    affected_function_ids: Option<&BTreeSet<NodeId>>,
    include_globals: bool,
) -> bool {
    let Some(affected_function_ids) = affected_function_ids else {
        return true;
    };
    match function_map.get(&node_id).copied() {
        Some(function_id) => affected_function_ids.contains(&function_id),
        None => include_globals,
    }
}

fn dataflow_item_in_scope(
    function_id: Option<NodeId>,
    affected_function_ids: &BTreeSet<NodeId>,
    include_globals: bool,
) -> bool {
    match function_id {
        Some(function_id) => affected_function_ids.contains(&function_id),
        None => include_globals,
    }
}

fn field_expression_field_identifier_id(
    graph: &BTreeMap<NodeId, AstNode>,
    node_id: NodeId,
) -> Option<NodeId> {
    let node = graph.get(&node_id)?;
    node.children.iter().find_map(|child_id| {
        let child = graph.get(child_id)?;
        (child.node_type == "field_identifier").then_some(*child_id)
    })
}

fn field_expression_field_name(
    graph: &BTreeMap<NodeId, AstNode>,
    node_id: NodeId,
) -> Option<String> {
    field_expression_field_identifier_id(graph, node_id)
        .and_then(|id| graph.get(&id).and_then(|n| n.text.clone()))
}

fn field_expression_object_expr_id(
    graph: &BTreeMap<NodeId, AstNode>,
    node_id: NodeId,
) -> Option<NodeId> {
    let node = graph.get(&node_id)?;
    node.children.iter().find_map(|child_id| {
        let child = graph.get(child_id)?;
        (!matches!(child.node_type.as_str(), "." | "->" | "field_identifier")).then_some(*child_id)
    })
}

fn field_expression_object_vars(
    graph: &BTreeMap<NodeId, AstNode>,
    parent_map: &BTreeMap<NodeId, NodeId>,
    node_id: NodeId,
) -> Vec<VarRef> {
    field_expression_object_expr_id(graph, node_id)
        .map(|id| collect_identifiers_in_expr(graph, id, Some(parent_map)))
        .unwrap_or_default()
}

fn enclosing_field_expression(
    graph: &BTreeMap<NodeId, AstNode>,
    parent_map: &BTreeMap<NodeId, NodeId>,
    node_id: NodeId,
) -> Option<NodeId> {
    let mut current = Some(node_id);
    while let Some(id) = current {
        let node = graph.get(&id)?;
        if node.is_member_access() {
            return Some(id);
        }
        current = parent_map.get(&id).copied();
    }
    None
}

/// `(field_name, object_base_paths, function_id)` when `node_id` is a field use.
fn field_use_context(
    graph: &BTreeMap<NodeId, AstNode>,
    parent_map: &BTreeMap<NodeId, NodeId>,
    node_id: NodeId,
) -> Option<(String, Vec<String>, Option<NodeId>)> {
    let fe_id = enclosing_field_expression(graph, parent_map, node_id)?;
    let field_name = field_expression_field_name(graph, fe_id)?;
    let bases: Vec<String> = field_expression_object_vars(graph, parent_map, fe_id)
        .into_iter()
        .map(|v| v.name)
        .collect();
    let bases = if bases.is_empty() {
        vec!["*".to_string()]
    } else {
        bases
    };
    let function_id = parent_map
        .get(&fe_id)
        .and_then(|p| function_map_for_node(graph, parent_map, *p));
    Some((field_name, bases, function_id))
}

fn function_map_for_node(
    graph: &BTreeMap<NodeId, AstNode>,
    parent_map: &BTreeMap<NodeId, NodeId>,
    node_id: NodeId,
) -> Option<NodeId> {
    let mut current = Some(node_id);
    while let Some(id) = current {
        if graph.get(&id)?.is_method_def() {
            return Some(id);
        }
        current = parent_map.get(&id).copied();
    }
    None
}

fn lookup_field_def_ids(
    field_defs: &BTreeMap<(Option<NodeId>, String, String), Vec<NodeId>>,
    func_id: Option<NodeId>,
    base_paths: &[String],
    field: &str,
    struct_type: Option<&str>,
    graph: &BTreeMap<NodeId, AstNode>,
    parent_map: &BTreeMap<NodeId, NodeId>,
) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut try_key = |key: (Option<NodeId>, String, String)| {
        for def_id in field_defs.get(&key).into_iter().flatten().copied() {
            if seen.insert(def_id) {
                out.push(def_id);
            }
        }
    };
    for base in base_paths {
        try_key((func_id, base.clone(), field.to_string()));
    }
    try_key((func_id, "*".to_string(), field.to_string()));
    if let Some(struct_type) = struct_type {
        for (key, def_ids) in field_defs {
            if key.2 != field {
                continue;
            }
            for &def_id in def_ids {
                if seen.contains(&def_id) {
                    continue;
                }
                let matches_struct = key.1 == struct_type
                    || enclosing_struct_name(graph, parent_map, def_id)
                        .as_deref()
                        .is_some_and(|name| name == struct_type);
                if matches_struct {
                    seen.insert(def_id);
                    out.push(def_id);
                }
            }
        }
    } else {
        for (key, def_ids) in field_defs {
            if key.2 != field {
                continue;
            }
            for &def_id in def_ids {
                if enclosing_struct_name(graph, parent_map, def_id).is_none() && seen.insert(def_id)
                {
                    out.push(def_id);
                }
            }
        }
    }
    out
}

fn enclosing_struct_name(
    graph: &BTreeMap<NodeId, AstNode>,
    parent_map: &BTreeMap<NodeId, NodeId>,
    node_id: NodeId,
) -> Option<String> {
    let mut current = Some(node_id);
    while let Some(id) = current {
        let node = graph.get(&id)?;
        if matches!(
            node.node_type.as_str(),
            "struct_specifier" | "union_specifier" | "class_specifier"
        ) {
            for child_id in &node.children {
                let child = graph.get(child_id)?;
                if matches!(child.node_type.as_str(), "type_identifier" | "name") {
                    if let Some(text) = child.text.clone() {
                        return Some(text);
                    }
                }
            }
        }
        current = parent_map.get(&id).copied();
    }
    None
}

fn declaration_type_name_for_identifier(
    graph: &BTreeMap<NodeId, AstNode>,
    parent_map: &BTreeMap<NodeId, NodeId>,
    node_id: NodeId,
) -> Option<String> {
    let mut current = Some(node_id);
    while let Some(id) = current {
        let node = graph.get(&id)?;
        if node.is_local_def() || node.is_param_def() {
            for child_id in &node.children {
                let child = graph.get(child_id)?;
                if matches!(
                    child.node_type.as_str(),
                    "type_identifier" | "primitive_type" | "sized_type_specifier"
                ) {
                    return child.text.clone();
                }
                if matches!(
                    child.node_type.as_str(),
                    "struct_specifier" | "union_specifier" | "class_specifier"
                ) {
                    if let Some(name) = enclosing_struct_name(graph, parent_map, *child_id) {
                        return Some(name);
                    }
                }
            }
        }
        current = parent_map.get(&id).copied();
    }
    None
}

fn resolve_field_access_struct_type(
    graph: &BTreeMap<NodeId, AstNode>,
    parent_map: &BTreeMap<NodeId, NodeId>,
    node_id: NodeId,
) -> Option<String> {
    let mut current = Some(node_id);
    let mut field_expr_id = None;
    while let Some(id) = current {
        let node = graph.get(&id)?;
        if node.is_member_access() {
            field_expr_id = Some(id);
            break;
        }
        current = parent_map.get(&id).copied();
    }
    let field_expr_id = field_expr_id?;
    let object_expr_id = field_expression_object_expr_id(graph, field_expr_id)?;
    let object_node = graph.get(&object_expr_id)?;
    match object_node.node_type.as_str() {
        "identifier" => declaration_type_name_for_identifier(graph, parent_map, object_expr_id),
        "field_expression" => resolve_field_access_struct_type(graph, parent_map, object_expr_id),
        _ => None,
    }
}

pub(crate) fn extract_call_argument_nodes(
    graph: &BTreeMap<NodeId, AstNode>,
    call_id: NodeId,
) -> Vec<NodeId> {
    let Some(call) = graph.get(&call_id) else {
        return Vec::new();
    };
    for child_id in &call.children {
        let Some(child) = graph.get(child_id) else {
            continue;
        };
        if child.node_type == "argument_list" {
            return child
                .children
                .iter()
                .copied()
                .filter(|id| graph.contains_key(id))
                .collect();
        }
    }
    Vec::new()
}

fn extract_return_value_node(
    graph: &BTreeMap<NodeId, AstNode>,
    return_id: NodeId,
) -> Option<NodeId> {
    let node = graph.get(&return_id)?;
    node.children.iter().find_map(|child_id| {
        let child = graph.get(child_id)?;
        (!matches!(child.node_type.as_str(), "return" | "co_return" | ";")).then_some(*child_id)
    })
}

pub(crate) fn extract_called_function_name(
    graph: &BTreeMap<NodeId, AstNode>,
    call_id: NodeId,
    macro_aliases: Option<&BTreeMap<String, String>>,
) -> Option<String> {
    let call = graph.get(&call_id)?;
    // Use pre-computed name if enrichment set it (Java, JS, Python, etc.)
    if let Some(name) = call.name.as_ref().filter(|n| !n.is_empty()) {
        return Some(name.clone());
    }
    let mut called_func = None;
    for child_id in &call.children {
        let child = graph.get(child_id)?;
        match child.node_type.as_str() {
            "identifier" => {
                called_func = child.text.clone();
                break;
            }
            // Namespace/class qualified calls: `ns::foo()`, `Foo::bar()`, `std::move()`.
            // Return the FULL qualified name so it can match the qualified key in
            // function_name_to_id (registered by build_call_graph_impl above).
            "qualified_identifier" | "scoped_namespace_identifier" => {
                // Try to return the complete qualified name from the node text.
                let full = child
                    .text
                    .as_ref()
                    .map(|t| t.split('(').next().unwrap_or(t).trim().to_string());
                if let Some(qname) = full.filter(|s| !s.is_empty()) {
                    called_func = Some(qname);
                } else {
                    // Fallback: last identifier child (unqualified part).
                    called_func = child.children.iter().rev().find_map(|cid| {
                        let c = graph.get(cid)?;
                        if matches!(
                            c.node_type.as_str(),
                            "identifier" | "operator_name" | "destructor_name"
                        ) {
                            c.text.clone()
                        } else {
                            None
                        }
                    });
                }
                break;
            }
            // Template calls: `foo<int>(x)`, `std::make_unique<T>(...)`.
            "template_function" | "template_method" => {
                // The first child is the function name (identifier or qualified_identifier).
                called_func = child.children.iter().find_map(|cid| {
                    let c = graph.get(cid)?;
                    match c.node_type.as_str() {
                        "identifier" => c.text.clone(),
                        "qualified_identifier" | "scoped_namespace_identifier" => c
                            .text
                            .as_ref()
                            .map(|t| t.split('(').next().unwrap_or(t).trim().to_string()),
                        _ => None,
                    }
                });
                break;
            }
            "field_expression" => {
                for gc_id in &child.children {
                    let gc = graph.get(gc_id)?;
                    if gc.node_type == "field_identifier" {
                        called_func = gc.text.clone();
                        break;
                    }
                }
                if called_func.is_none() {
                    if let Some(text) = &child.text {
                        let field = text
                            .split("->")
                            .last()
                            .or_else(|| text.split('.').last())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())?;
                        called_func = Some(field.to_string());
                    }
                }
                if called_func.is_some() {
                    break;
                }
            }
            // Go: receiver.method() → selector_expression [receiver, method]
            "selector_expression" => {
                for gc_id in child.children.iter().rev() {
                    let gc = graph.get(gc_id)?;
                    if gc.node_type == "field_identifier" || gc.node_type == "identifier" {
                        called_func = gc.text.clone();
                        break;
                    }
                }
                if called_func.is_some() {
                    break;
                }
            }
            "parenthesized_expression" => {
                for gc_id in &child.children {
                    let gc = graph.get(gc_id)?;
                    match gc.node_type.as_str() {
                        "identifier" => {
                            called_func = gc.text.clone();
                            break;
                        }
                        "pointer_expression" => {
                            for ggc_id in &gc.children {
                                let ggc = graph.get(ggc_id)?;
                                if ggc.node_type == "identifier" {
                                    called_func = ggc.text.clone();
                                    break;
                                }
                            }
                        }
                        _ => {}
                    }
                    if called_func.is_some() {
                        break;
                    }
                }
                if called_func.is_some() {
                    break;
                }
            }
            "subscript_expression" => {
                for gc_id in &child.children {
                    let gc = graph.get(gc_id)?;
                    if gc.node_type == "identifier" {
                        called_func = gc.text.clone();
                        break;
                    }
                }
                if called_func.is_some() {
                    break;
                }
            }
            _ => {}
        }
    }
    called_func.map(|name| {
        macro_aliases
            .and_then(|aliases| {
                aliases
                    .get(&name)
                    .cloned()
                    .or_else(|| aliases.get(&name.to_lowercase()).cloned())
            })
            .unwrap_or(name)
    })
}

/// Extract the fully-qualified callee name from a call_expression when it
/// contains a namespace separator (`::`) or member-access (`->`, `.`).
/// E.g. `std::filesystem::remove(path)` → `Some("std::filesystem::remove")`.
/// Returns `None` for plain unqualified calls to avoid polluting the short name.
fn extract_qualified_callee(graph: &BTreeMap<NodeId, AstNode>, call_id: NodeId) -> Option<String> {
    let call = graph.get(&call_id)?;
    let text = call.text.as_deref()?;
    let callee_part = text.split('(').next()?.trim();
    if callee_part.contains("::") || callee_part.contains("->") || callee_part.contains('.') {
        Some(callee_part.to_string())
    } else {
        None
    }
}

fn extract_callback_argument_names(
    graph: &BTreeMap<NodeId, AstNode>,
    call_id: NodeId,
    function_name_to_id: &BTreeMap<String, NodeId>,
) -> Vec<String> {
    let Some(call) = graph.get(&call_id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for child_id in &call.children {
        let Some(child) = graph.get(child_id) else {
            continue;
        };
        if child.node_type != "argument_list" {
            continue;
        }
        for arg_id in &child.children {
            let Some(arg) = graph.get(arg_id) else {
                continue;
            };
            let name = match arg.node_type.as_str() {
                "identifier" => arg.text.clone(),
                "pointer_expression" => arg.children.iter().find_map(|sub_id| {
                    let sub = graph.get(sub_id)?;
                    (sub.node_type == "identifier")
                        .then(|| sub.text.clone())
                        .flatten()
                }),
                _ => None,
            };
            if let Some(name) = name {
                if function_name_to_id.contains_key(&name) && seen.insert(name.clone()) {
                    out.push(name);
                }
            }
        }
    }
    out
}

fn enclosing_assignment_lhs_identifier(
    graph: &BTreeMap<NodeId, AstNode>,
    call_id: NodeId,
) -> Option<NodeId> {
    let call = graph.get(&call_id)?;
    let parent_id = call.parent_id?;
    let parent = graph.get(&parent_id)?;
    match parent.node_type.as_str() {
        "init_declarator" | "assignment_expression" => parent.children.first().copied(),
        _ => None,
    }
}

fn add_interprocedural_edges(
    graph: &BTreeMap<NodeId, AstNode>,
    edges: &mut Vec<DataflowEdge>,
    cross_file_calls: &mut Vec<crate::CrossFileCallEdge>,
    macro_aliases: Option<&BTreeMap<String, String>>,
    affected_function_ids: Option<&BTreeSet<NodeId>>,
    include_globals: bool,
    preprocessing_maps: &PreprocessingMaps,
) {
    let parent_map = &preprocessing_maps.0;
    let function_map = &preprocessing_maps.1;
    let type_index = &preprocessing_maps.2;
    let call_graph = build_call_graph(graph, Some(preprocessing_maps), macro_aliases);
    let mut function_name_to_id = BTreeMap::<String, NodeId>::new();
    for (fid, entry) in &call_graph {
        function_name_to_id.insert(entry.name.clone(), *fid);
    }

    // Precompute function_id → sorted param node ids once (O(n_nodes)) so the
    // per-call-expression lookup below is O(1) instead of O(n_nodes).
    let params_by_func: BTreeMap<NodeId, Vec<NodeId>> = {
        let mut map: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();
        for (id, node) in graph {
            if node.node_type == "identifier" {
                if let Some(fid) = node.function_id {
                    if is_parameter_name(graph, *id) {
                        map.entry(fid).or_default().push(*id);
                    }
                }
            }
        }
        for params in map.values_mut() {
            params.sort_by_key(|id| {
                let n = &graph[id];
                (n.line, n.column, *id)
            });
        }
        map
    };

    for (call_id, _call) in graph
        .iter()
        .filter(|(_, node)| node.is_call())
    {
        let caller_func_id = function_map.get(call_id).copied();
        let Some(callee_name) = extract_called_function_name(graph, *call_id, macro_aliases) else {
            continue;
        };
        let Some(callee_id) = function_name_to_id.get(&callee_name).copied() else {
            // Callee not in this file — record for cross-file resolution by the workspace layer.
            if let Some(caller_fn) = caller_func_id {
                let qualified_callee = extract_qualified_callee(graph, *call_id);
                let arg_nodes = extract_call_argument_nodes(graph, *call_id);
                cross_file_calls.push(crate::CrossFileCallEdge {
                    call_node: *call_id,
                    caller_fn,
                    callee_name: callee_name.clone(),
                    qualified_callee,
                    arg_positions: (0..arg_nodes.len()).collect(),
                });
            }
            continue;
        };
        if let Some(affected_function_ids) = affected_function_ids {
            let touches_affected = caller_func_id
                .is_some_and(|fid| affected_function_ids.contains(&fid))
                || affected_function_ids.contains(&callee_id)
                || (caller_func_id.is_none() && include_globals);
            if !touches_affected {
                continue;
            }
        }

        let arg_nodes = extract_call_argument_nodes(graph, *call_id);
        let empty = Vec::new();
        let param_nodes = params_by_func.get(&callee_id).unwrap_or(&empty);
        for (idx, arg_id) in arg_nodes.iter().enumerate() {
            let Some(param_id) = param_nodes.get(idx).copied().or_else(|| {
                (idx >= param_nodes.len() && !param_nodes.is_empty())
                    .then(|| *param_nodes.last().unwrap())
            }) else {
                continue;
            };
            let Some(param_node) = graph.get(&param_id) else {
                continue;
            };
            let variable = param_node.text.clone().unwrap_or_default();
            if variable.is_empty() {
                continue;
            }
            push_edge(
                edges,
                *arg_id,
                param_id,
                variable.clone(),
                "INTERPROCEDURAL_FLOW",
            );
            for var in collect_identifiers_in_expr(graph, *arg_id, Some(parent_map)) {
                push_edge(
                    edges,
                    var.node_id,
                    param_id,
                    variable.clone(),
                    "INTERPROCEDURAL_FLOW",
                );
            }
        }

        if let Some(lhs_id) = enclosing_assignment_lhs_identifier(graph, *call_id) {
            if let Some(lhs_node) = graph.get(&lhs_id) {
                if let Some(var) = lhs_node.text.clone() {
                    for ret_type in ["return_statement", "co_return_statement"] {
                        for ret_id in type_index.get(ret_type).into_iter().flatten().copied() {
                            if function_map.get(&ret_id).copied() != Some(callee_id) {
                                continue;
                            }
                            if let Some(ret_value_id) = extract_return_value_node(graph, ret_id) {
                                push_edge(
                                    edges,
                                    ret_value_id,
                                    lhs_id,
                                    var.clone(),
                                    "INTERPROCEDURAL_FLOW",
                                );
                                for used in collect_identifiers_in_expr(
                                    graph,
                                    ret_value_id,
                                    Some(parent_map),
                                ) {
                                    push_edge(
                                        edges,
                                        used.node_id,
                                        lhs_id,
                                        var.clone(),
                                        "INTERPROCEDURAL_FLOW",
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Walk an lhs expression ignoring lvalue-context filtering and return the
/// first identifier (the base variable).  Used for patterns like `arr[0] = &x`
/// where `arr` is the pointer-holder and is in lvalue position.
fn extract_base_identifier(graph: &BTreeMap<NodeId, AstNode>, node_id: NodeId) -> Option<VarRef> {
    let node = graph.get(&node_id)?;
    match node.node_type.as_str() {
        "identifier" | "field_identifier" => Some(VarRef {
            name: node.text.clone()?,
            node_id,
        }),
        "subscript_expression"
        | "field_expression"
        | "pointer_expression"
        | "parenthesized_expression"
        | "cast_expression" => node
            .children
            .iter()
            .find_map(|child_id| extract_base_identifier(graph, *child_id)),
        _ => None,
    }
}

fn add_points_to_edges(
    graph: &BTreeMap<NodeId, AstNode>,
    edges: &mut Vec<DataflowEdge>,
    affected_function_ids: Option<&BTreeSet<NodeId>>,
    include_globals: bool,
    function_map: &BTreeMap<NodeId, NodeId>,
) {
    let maps = build_preprocessing_maps(graph);
    let type_index = &maps.2;
    let assign_ids = type_index
        .get("init_declarator")
        .into_iter()
        .flatten()
        .copied()
        .chain(
            type_index
                .get("assignment_expression")
                .into_iter()
                .flatten()
                .copied(),
        );

    for assign_node_id in assign_ids {
        if !node_in_scope(
            assign_node_id,
            function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(assign_node) = graph.get(&assign_node_id) else {
            continue;
        };
        if assign_node.children.len() < 2 {
            continue;
        }
        let lhs_id = assign_node.children[0];
        let rhs_id = *assign_node.children.last().unwrap_or(&lhs_id);
        let Some(rhs_node) = graph.get(&rhs_id) else {
            continue;
        };
        if rhs_node.node_type != "pointer_expression" {
            continue;
        }
        // Verify this is an address-of expression by checking for an identifier child.
        // Using AST structure rather than text prefix matching (fixes A3).
        let operand_id = rhs_node.children.iter().find_map(|child_id| {
            let child = graph.get(child_id)?;
            matches!(child.node_type.as_str(), "identifier" | "field_identifier")
                .then_some(*child_id)
        });
        let Some(operand_id) = operand_id else {
            continue;
        };
        // For `arr[0] = &x`, lhs is subscript_expression whose base identifier
        // is in lvalue context — collect_identifiers_in_expr would skip it.
        // Walk the lhs tree ignoring lvalue filtering to get the base variable.
        let lhs_var =
            get_declared_variable(graph, lhs_id).or_else(|| extract_base_identifier(graph, lhs_id));
        if let Some(lhs_var) = lhs_var {
            push_edge(
                edges,
                lhs_var.node_id,
                operand_id,
                lhs_var.name,
                "POINTS_TO",
            );
        }
    }
}

/// For every `call_expression` that appears as the RHS of an
/// `init_declarator` or `assignment_expression`, emit a CALL_RETURN edge from
/// the call node to the identifier node that receives the return value.  This
/// closes the dataflow gap for external/library functions (e.g. `getenv`,
/// `malloc`, `fopen`) whose callees have no local definition, so no
/// INTERPROCEDURAL_FLOW edge is emitted for the return value.
fn add_call_return_edges(
    graph: &BTreeMap<NodeId, AstNode>,
    edges: &mut Vec<DataflowEdge>,
    type_index: &BTreeMap<String, Vec<NodeId>>,
    function_map: &BTreeMap<NodeId, NodeId>,
    affected_function_ids: Option<&BTreeSet<NodeId>>,
    include_globals: bool,
) {
    for call_id in type_index
        .get("call_expression")
        .into_iter()
        .flatten()
        .copied()
    {
        if !node_in_scope(
            call_id,
            function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(lhs_id) = enclosing_assignment_lhs_identifier(graph, call_id) else {
            continue;
        };
        let Some(lhs_node) = graph.get(&lhs_id) else {
            continue;
        };
        let var_name = lhs_node.text.clone().unwrap_or_default();
        if var_name.is_empty() {
            continue;
        }
        push_edge(edges, call_id, lhs_id, var_name, "CALL_RETURN");
    }
}

/// Propagators copy taint from one (or more) source arguments to a
/// destination argument.  Emit TAINT_PROPAGATOR edges in the dataflow graph so
/// that the BFS-based solver can follow taint through calls to these functions
/// without needing the call to be an internally-defined callee.
fn add_taint_propagator_edges(
    graph: &BTreeMap<NodeId, AstNode>,
    edges: &mut Vec<DataflowEdge>,
    type_index: &BTreeMap<String, Vec<NodeId>>,
    parent_map: &BTreeMap<NodeId, NodeId>,
    function_map: &BTreeMap<NodeId, NodeId>,
    affected_function_ids: Option<&BTreeSet<NodeId>>,
    include_globals: bool,
    macro_aliases: Option<&BTreeMap<String, String>>,
) {
    // (function_name, dst_arg_index, src_arg_indices)
    // -1 means "all remaining args after dst_arg_index"
    let propagators = crate::security_patterns::TAINT_PROPAGATORS;

    for call_id in type_index
        .get("call_expression")
        .into_iter()
        .flatten()
        .copied()
    {
        if !node_in_scope(
            call_id,
            function_map,
            affected_function_ids,
            include_globals,
        ) {
            continue;
        }
        let Some(call_node) = graph.get(&call_id) else {
            continue;
        };
        // Resolve through macro aliases (e.g. nginx's `ngx_memcpy` → `memcpy`) —
        // otherwise a project's own wrapper macros around stdlib propagator
        // functions would never match `TAINT_PROPAGATORS`' stdlib names.
        let Some(func_name) = extract_called_function_name(graph, call_id, macro_aliases) else {
            continue;
        };
        let Some((_, prop)) = propagators.iter().find(|(n, _)| *n == func_name.as_str()) else {
            continue;
        };
        let arg_nodes = extract_call_argument_nodes(graph, call_id);
        // dst == -1 means return-value propagation; no arg dst node.
        let dst_node_id_opt: Option<NodeId> = if prop.dst >= 0 {
            arg_nodes.get(prop.dst as usize).copied()
        } else {
            None
        };
        // Collect source arg identifiers
        let mut src_ids: Vec<NodeId> = Vec::new();
        let variadic_skip = (prop.dst.max(0) as usize).saturating_add(1);
        for &src_idx in prop.src {
            if src_idx == -1 {
                // all args after dst (only meaningful for dst >= 0)
                for &arg_id in arg_nodes.iter().skip(variadic_skip) {
                    for v in collect_identifiers_in_expr(graph, arg_id, Some(parent_map)) {
                        if !is_call_callee_identifier(graph, v.node_id) {
                            src_ids.push(v.node_id);
                        }
                    }
                }
            } else if let Some(&arg_id) = arg_nodes.get(src_idx as usize) {
                for v in collect_identifiers_in_expr(graph, arg_id, Some(parent_map)) {
                    if !is_call_callee_identifier(graph, v.node_id) {
                        src_ids.push(v.node_id);
                    }
                }
            }
        }
        // Collect dst identifiers (only when prop.dst refers to an arg, not return value)
        let dst_var_ids: Vec<VarRef> = if let Some(dst_node_id) = dst_node_id_opt {
            collect_identifiers_in_expr(graph, dst_node_id, Some(parent_map))
                .into_iter()
                .filter(|v| !is_call_callee_identifier(graph, v.node_id))
                .collect()
        } else {
            Vec::new()
        };

        for src_id in &src_ids {
            let src_node = graph.get(src_id);
            let var_name = src_node
                .and_then(|n| n.text.as_deref())
                .unwrap_or("_propagated")
                .to_string();
            for dst_var in &dst_var_ids {
                push_edge(
                    edges,
                    *src_id,
                    dst_var.node_id,
                    var_name.clone(),
                    "TAINT_PROPAGATOR",
                );
            }
            // Also emit an edge from the src identifier to the call node itself
            // so that "return value of propagator" is also reachable.
            push_edge(
                edges,
                *src_id,
                call_id,
                var_name.clone(),
                "TAINT_PROPAGATOR",
            );
        }

        // The CALL_RETURN edge from the call site to the LHS variable (if any)
        // is already emitted by add_call_return_edges; no need to duplicate it.
        let _ = call_node;
    }
}

fn add_return_flow_edges(
    graph: &BTreeMap<NodeId, AstNode>,
    edges: &mut Vec<DataflowEdge>,
    parent_map: &BTreeMap<NodeId, NodeId>,
    function_map: &BTreeMap<NodeId, NodeId>,
    type_index: &BTreeMap<String, Vec<NodeId>>,
    affected_function_ids: Option<&BTreeSet<NodeId>>,
    include_globals: bool,
) {
    for ret_type in ["return_statement", "co_return_statement"] {
        for ret_id in type_index.get(ret_type).into_iter().flatten().copied() {
            if !node_in_scope(ret_id, function_map, affected_function_ids, include_globals) {
                continue;
            }
            let Some(value_id) = extract_return_value_node(graph, ret_id) else {
                continue;
            };
            for used in collect_identifiers_in_expr(graph, value_id, Some(parent_map)) {
                if is_call_callee_identifier(graph, used.node_id) {
                    continue;
                }
                push_edge(edges, used.node_id, ret_id, used.name, "RETURN_FLOW");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preprocessing_maps_include_type_index() {
        let mut graph = BTreeMap::new();
        graph.insert(
            1,
            AstNode {
                kind: crate::IrNodeKind::MethodDef,
                node_type: "function_definition".to_string(),
                text: Some("int main()".to_string()),
                children: vec![2],
                ..AstNode::default()
            },
        );
        graph.insert(
            2,
            AstNode {
                kind: crate::IrNodeKind::Identifier,
                node_type: "identifier".to_string(),
                text: Some("main".to_string()),
                parent_id: Some(1),
                ..AstNode::default()
            },
        );
        let (_, _, type_index) = build_preprocessing_maps(&graph);
        assert!(type_index.contains_key("function_definition"));
        assert!(type_index.contains_key("identifier"));
    }
}
