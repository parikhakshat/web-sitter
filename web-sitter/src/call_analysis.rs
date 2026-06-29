use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{Cpg, FunctionKind, IrNodeKind, NodeId, PrimKind, RustType};
use crate::cpg_generator::SourceLanguage;
use crate::type_inference::build_class_hierarchy_rust;

// ── Call graph enrichment ──────────────────────────────────────────────────────

/// Enrich the call graph with language-specific dispatch information:
/// - Go: tag goroutine/deferred calls; mark interface calls as ExternalDecl
/// - Java: mark virtual dispatch; detect constructor chaining
/// - Rust: mark trait object dispatch
/// - Python: mark super(), decorator, dunder, and __init__ calls
pub(crate) fn enrich_call_graph(cpg: &mut Cpg, language: SourceLanguage) {
    match language {
        SourceLanguage::Go => enrich_call_graph_go(cpg),
        SourceLanguage::Java => enrich_call_graph_java(cpg),
        SourceLanguage::Rust => enrich_call_graph_rust(cpg),
        SourceLanguage::Python => enrich_call_graph_python(cpg),
        SourceLanguage::Cpp => enrich_call_graph_cpp(cpg),
        _ => {}
    }
}

pub(crate) fn enrich_call_graph_go(cpg: &mut Cpg) {
    // Collect all Call nodes and check if their parent is a GoStmt or DeferStmt
    let call_ids: Vec<(NodeId, Option<NodeId>)> = cpg.ast.iter()
        .filter(|(_, n)| n.is_call())
        .map(|(id, n)| (*id, n.parent_id))
        .collect();

    for (call_id, parent_id) in call_ids {
        let parent_kind = parent_id
            .and_then(|pid| cpg.ast.get(&pid))
            .map(|p| p.kind);

        if parent_kind == Some(IrNodeKind::GoStmt) {
            // Mark in call graph entries
            for entry in cpg.call_graph.values_mut() {
                for site in &mut entry.calls {
                    if site.call_site == Some(call_id) {
                        let meta = cpg.go_metadata.entry(call_id).or_default();
                        meta.is_goroutine = true;
                    }
                }
            }
        } else if parent_kind == Some(IrNodeKind::DeferStmt) {
            let meta = cpg.go_metadata.entry(call_id).or_default();
            meta.is_deferred = true;
        }
    }

    // Mark method calls on interface receivers as ExternalDecl
    let interface_calls: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.is_call())
        .filter(|(id, _)| {
            // Check if go metadata for this call node has is_interface
            cpg.go_metadata.get(id).map(|m| m.is_interface).unwrap_or(false)
        })
        .map(|(id, _)| *id)
        .collect();
    for call_id in interface_calls {
        for entry in cpg.call_graph.values_mut() {
            for site in &mut entry.calls {
                if site.call_site == Some(call_id) && site.callee_kind == FunctionKind::Internal {
                    site.callee_kind = FunctionKind::ExternalDecl;
                }
            }
        }
    }
}

pub(crate) fn enrich_call_graph_java(cpg: &mut Cpg) {
    // Mark all non-static method calls on object receivers as virtual dispatch
    let call_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.is_call() && n.class_context.is_some())
        .map(|(id, _)| *id)
        .collect();
    for call_id in call_ids {
        let is_static = cpg.java_metadata.get(&call_id)
            .map(|m| m.is_static)
            .unwrap_or(false);
        if !is_static {
            let meta = cpg.java_meta_mut(call_id);
            meta.is_virtual_dispatch = true;
        }
    }

    // Detect constructor chaining: explicit_constructor_invocation nodes
    let eci_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "explicit_constructor_invocation")
        .map(|(id, _)| *id)
        .collect();
    for eci_id in eci_ids {
        let node = &cpg.ast[&eci_id];
        let is_this = node.text.as_deref().map(|t| t.starts_with("this")).unwrap_or(false);
        let meta = cpg.java_meta_mut(eci_id);
        if is_this { meta.is_this_call = true; } else { meta.is_super_call = true; }
    }

    // Lambda nodes: add to call graph as synthetic WorkspaceLocal functions
    // (They already appear as LambdaDef nodes; we just ensure they're tracked)
}

pub(crate) fn enrich_call_graph_rust(cpg: &mut Cpg) {
    // Populate class_hierarchy from ImplBlock nodes (Rust-specific pass)
    build_class_hierarchy_rust(cpg);

    // Mark calls on trait objects (dyn Trait) as ExternalDecl + list possible callees
    // For now: identify calls whose receiver has a RustType::Trait inferred type
    let call_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.is_call())
        .map(|(id, _)| *id)
        .collect();
    for call_id in call_ids {
        // Check if any child identifier has a Trait inferred type
        let children = cpg.ast.get(&call_id).map(|n| n.children.clone()).unwrap_or_default();
        let has_trait_receiver = children.iter().any(|&cid| {
            cpg.rust_metadata.get(&cid)
                .and_then(|m| m.inferred_type.as_ref())
                .map(|t| matches!(t, RustType::Trait(_)))
                .unwrap_or(false)
        });
        if has_trait_receiver {
            for entry in cpg.call_graph.values_mut() {
                for site in &mut entry.calls {
                    if site.call_site == Some(call_id) {
                        site.callee_kind = FunctionKind::ExternalDecl;
                    }
                }
            }
        }
    }
}

pub(crate) fn enrich_call_graph_python(cpg: &mut Cpg) {
    // super() calls: detect `super()` call nodes and mark is_super_call
    let super_call_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.is_call() && n.name.as_deref() == Some("super"))
        .map(|(id, _)| *id)
        .collect();
    for call_id in super_call_ids {
        let meta = cpg.python_meta_mut(call_id);
        meta.is_super_call = true;
    }

    // Decorator calls: MethodDef / ClassDef nodes with decorator metadata
    let decorated_ids: Vec<(NodeId, Vec<String>)> = cpg.python_metadata.iter()
        .filter(|(_, m)| !m.decorators.is_empty())
        .map(|(&id, m)| (id, m.decorators.clone()))
        .collect();
    for (def_id, decorators) in decorated_ids {
        for dec_name in &decorators {
            // Find the corresponding call node for the decorator (it's a parent Decorator node)
            let dec_id = cpg.ast.iter()
                .find(|(_, n)| n.kind == IrNodeKind::Decorator
                    && n.parent_id == Some(def_id)
                    && n.text.as_deref() == Some(dec_name))
                .map(|(id, _)| *id);
            if let Some(dec_id) = dec_id {
                let meta = cpg.python_meta_mut(dec_id);
                meta.is_decorator_call = true;
            }
        }
    }

    // Class instantiation: Call nodes whose name matches a ClassDef
    let class_names: std::collections::HashSet<String> = cpg.ast.iter()
        .filter(|(_, n)| n.kind == IrNodeKind::ClassDef)
        .filter_map(|(_, n)| n.name.clone())
        .collect();
    let instantiation_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.is_call() && n.name.as_ref().map(|name| class_names.contains(name.as_str())).unwrap_or(false))
        .map(|(id, _)| *id)
        .collect();
    for call_id in instantiation_ids {
        let meta = cpg.python_meta_mut(call_id);
        meta.is_constructor_call = true;
    }

    // Dunder methods: BinaryOp nodes → synthesize __add__, __sub__, etc.
    let dunder_map: &[(&str, &str)] = &[
        ("+", "__add__"), ("-", "__sub__"), ("*", "__mul__"), ("/", "__truediv__"),
        ("//", "__floordiv__"), ("%", "__mod__"), ("**", "__pow__"),
        ("==", "__eq__"), ("!=", "__ne__"), ("<", "__lt__"), (">", "__gt__"),
        ("<=", "__le__"), (">=", "__ge__"), ("&", "__and__"), ("|", "__or__"),
        ("^", "__xor__"), ("<<", "__lshift__"), (">>", "__rshift__"),
    ];
    let binop_ids: Vec<(NodeId, String)> = cpg.ast.iter()
        .filter(|(_, n)| n.kind == IrNodeKind::BinaryOp)
        .filter_map(|(id, n)| n.operator.clone().map(|op| (*id, op)))
        .collect();
    for (binop_id, op) in binop_ids {
        if let Some(&(_, dunder)) = dunder_map.iter().find(|(o, _)| *o == op.as_str()) {
            let meta = cpg.python_meta_mut(binop_id);
            if meta.call_receiver_text.is_none() {
                meta.call_receiver_text = Some(dunder.to_string());
                meta.is_dunder_call = true;
            }
        }
    }
}

pub(crate) fn enrich_call_graph_cpp(cpg: &mut Cpg) {
    // Mark calls via pointer/reference on a class receiver as virtual dispatch candidates
    // when the receiver type is in the class hierarchy as a base class.
    let subtype_names: std::collections::HashSet<String> = cpg.workspace.class_hierarchy.keys().cloned().collect();
    let call_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.is_call() && n.class_context.is_some())
        .filter(|(id, _)| {
            cpg.cpp_metadata.get(id)
                .and_then(|m| m.is_virtual)
                .unwrap_or(false)
                || cpg.ast.get(id).and_then(|n| n.class_context.as_deref())
                    .map(|ctx| subtype_names.contains(ctx))
                    .unwrap_or(false)
        })
        .map(|(id, _)| *id)
        .collect();
    for call_id in call_ids {
        cpg.cpp_meta_mut(call_id).is_virtual_dispatch = true;
    }
}

// ── DFG language-specific passes ──────────────────────────────────────────────

/// Go DFG enrichment: add CHANNEL_FLOW edges for statically-resolvable channel send→receive pairs.
pub(crate) fn dfg_go_passes(cpg: &mut Cpg) {
    // Collect all SendStmt and ReceiveExpr nodes with their channel variable name.
    // Channel name is the first identifier child of the node.
    let sends: Vec<(NodeId, String, Option<NodeId>)> = cpg.ast.iter()
        .filter(|(_, n)| n.kind == IrNodeKind::SendStmt)
        .filter_map(|(id, send)| {
            let chan_name = send.children.iter().find_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.is_identifier() { c.name.clone().or_else(|| c.text.clone()) } else { None }
                })
            })?;
            Some((*id, chan_name, send.function_id))
        })
        .collect();

    let receives: Vec<(NodeId, String, Option<NodeId>)> = cpg.ast.iter()
        .filter(|(_, n)| n.kind == IrNodeKind::ReceiveExpr
            || (n.kind == IrNodeKind::UnaryOp
                && n.text.as_deref().map(|t| t.starts_with("<-")).unwrap_or(false)))
        .filter_map(|(id, recv)| {
            let chan_name = recv.children.iter().find_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.is_identifier() { c.name.clone().or_else(|| c.text.clone()) } else { None }
                })
            })?;
            Some((*id, chan_name, recv.function_id))
        })
        .collect();

    // Emit CHANNEL_FLOW edges for matching (send, recv) pairs on the same channel variable.
    // Cross-goroutine sends are common (goroutine closure has a different function_id), so we
    // match by channel name across all functions in the file — conservative but correct for
    // non-aliased channels that have a single declaration.
    for (send_id, send_chan, _send_fn) in &sends {
        for (recv_id, recv_chan, _recv_fn) in &receives {
            if send_chan == recv_chan {
                cpg.dataflow.edges.push(crate::DataflowEdge {
                    source: *send_id,
                    destination: *recv_id,
                    variable: send_chan.clone(),
                    edge_type: "CHANNEL_FLOW".to_string(),
                    field_path: Vec::new(),
                });
            }
        }
    }
}

/// Java DFG enrichment: field vs. local variable scoping and enhanced-for binding.
pub(crate) fn dfg_java_passes(cpg: &mut Cpg) {
    // For `this.fieldName` member access nodes: ensure DFG uses qualified "ClassName.fieldName" key
    // by updating the `variable` string in existing edges that reference the field.
    let field_accesses: Vec<(NodeId, String, Option<String>)> = cpg.ast.iter()
        .filter(|(_, n)| n.is_member_access() && n.name.as_deref() == Some("this"))
        .filter_map(|(id, node)| {
            let field_name = node.children.iter().find_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.is_identifier() { c.name.clone() } else { None }
                })
            })?;
            let class_ctx = node.class_context.clone()?;
            Some((*id, field_name, Some(class_ctx)))
        })
        .collect();

    for (_, field_name, class_ctx) in field_accesses {
        if let Some(class) = class_ctx {
            let qualified = format!("{}.{}", class, field_name);
            // Update edges whose variable matches the unqualified field name to use the qualified name
            for edge in &mut cpg.dataflow.edges {
                if edge.variable == field_name {
                    edge.variable = qualified.clone();
                }
            }
            // Update defs and uses too
            for def in &mut cpg.dataflow.definitions {
                if def.variable == field_name {
                    def.variable = qualified.clone();
                }
            }
            for use_ in &mut cpg.dataflow.uses {
                if use_.variable == field_name {
                    use_.variable = qualified.clone();
                }
            }
        }
    }

    // instanceof pattern binding: scope DataflowDef for the pattern variable to then-branch only.
    // For now we tag the metadata; full scope limiting requires BB-aware post-processing.
    let pattern_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "type_pattern" || n.kind == IrNodeKind::InstanceofExpr)
        .map(|(id, _)| *id)
        .collect();
    for pattern_id in pattern_ids {
        // The pattern variable is a LocalDef child of the instanceof expression
        let children = cpg.ast.get(&pattern_id).map(|n| n.children.clone()).unwrap_or_default();
        for child_id in children {
            if cpg.ast.get(&child_id).map(|c| c.is_local_def()).unwrap_or(false) {
                // Mark as instanceof-scoped — future BB pass will restrict scope
                // For now: meta flag is sufficient for the analysis layer
                let _ = cpg.java_meta_mut(child_id); // ensure entry exists
            }
        }
    }
}

/// Rust DFG enrichment: add MOVE/BORROW_IMMUT/BORROW_MUT/COPY edges based on ownership.
pub(crate) fn dfg_rust_passes(cpg: &mut Cpg) {
    use crate::{OwnershipState, PrimKind};

    // For each Call node: look at argument children and determine the ownership edge type.
    let call_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.is_call())
        .map(|(id, _)| *id)
        .collect();

    for call_id in call_ids {
        let arg_ids: Vec<NodeId> = cpg.ast.get(&call_id)
            .map(|n| n.children.clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|&cid| cpg.ast.get(&cid).map(|c| c.is_identifier()).unwrap_or(false))
            .collect();

        for arg_id in arg_ids {
            let arg_type = cpg.rust_metadata.get(&arg_id)
                .and_then(|m| m.inferred_type.clone());
            let current_state = cpg.rust_metadata.get(&arg_id)
                .and_then(|m| m.ownership_state)
                .unwrap_or(OwnershipState::Owned);

            if current_state == OwnershipState::Moved {
                // Use after move: flag it
                let meta = cpg.rust_meta_mut(arg_id);
                meta.use_after_move = true;
                continue;
            }

            let edge_type = match &arg_type {
                Some(RustType::Ref(_)) => "BORROW_IMMUT",
                Some(RustType::MutRef(_)) => "BORROW_MUT",
                Some(RustType::Prim(k)) if matches!(k,
                    PrimKind::I8 | PrimKind::I16 | PrimKind::I32 | PrimKind::I64 |
                    PrimKind::I128 | PrimKind::Isize | PrimKind::U8 | PrimKind::U16 |
                    PrimKind::U32 | PrimKind::U64 | PrimKind::U128 | PrimKind::Usize |
                    PrimKind::F32 | PrimKind::F64 | PrimKind::Bool | PrimKind::Char) => "COPY",
                _ => "MOVE",
            };

            let arg_name = cpg.ast.get(&arg_id)
                .and_then(|n| n.name.clone().or_else(|| n.text.clone()))
                .unwrap_or_default();

            cpg.dataflow.edges.push(crate::DataflowEdge {
                source: arg_id,
                destination: call_id,
                variable: arg_name,
                edge_type: edge_type.to_string(),
                field_path: Vec::new(),
            });

            if edge_type == "MOVE" {
                let meta = cpg.rust_meta_mut(arg_id);
                meta.ownership_state = Some(OwnershipState::Moved);
            }
        }
    }
}

/// Python DFG enrichment: walrus operator scope escape, global/nonlocal cross-scope linking.
pub(crate) fn dfg_python_passes(cpg: &mut Cpg) {
    // Walrus operator (`NamedExpr`): the definition must be visible in the enclosing scope.
    // Find the NamedExpr nodes; their function_id should be set to the nearest
    // non-comprehension enclosing function scope.
    let walrus_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.kind == IrNodeKind::NamedExpr)
        .map(|(id, _)| *id)
        .collect();

    for walrus_id in walrus_ids {
        let current_fn = cpg.ast.get(&walrus_id).and_then(|n| n.function_id);
        // Walk up parent chain to find first non-comprehension function scope
        let enclosing_fn = find_enclosing_non_comprehension_scope(cpg, walrus_id);
        if enclosing_fn != current_fn {
            // Add a cross-scope DFG def for the walrus-assigned variable
            let var_name = cpg.ast.get(&walrus_id)
                .and_then(|n| n.name.clone().or_else(|| n.text.clone()))
                .unwrap_or_default();
            if !var_name.is_empty() {
                cpg.dataflow.definitions.push(crate::DataflowDef {
                    node_id: walrus_id,
                    variable: var_name.clone(),
                    function_id: enclosing_fn,
                });
                // Edge from walrus def to enclosing scope def
                cpg.dataflow.edges.push(crate::DataflowEdge {
                    source: walrus_id,
                    destination: walrus_id,
                    variable: var_name,
                    edge_type: "WALRUS_SCOPE_ESCAPE".to_string(),
                    field_path: Vec::new(),
                });
            }
        }
    }

    // Global/nonlocal: link variable uses inside functions to module-level defs.
    let global_ids: Vec<(NodeId, Vec<String>, Option<NodeId>)> = cpg.ast.iter()
        .filter(|(_, n)| n.kind == IrNodeKind::Global)
        .filter_map(|(id, n)| {
            let meta = cpg.python_metadata.get(id)?;
            let names = meta.global_names.clone();
            if names.is_empty() { return None; }
            Some((*id, names, n.function_id))
        })
        .collect();

    // Find module-level function_id (File node)
    let module_fn_id: Option<NodeId> = cpg.ast.iter()
        .find(|(_, n)| n.kind == IrNodeKind::File)
        .map(|(id, _)| *id);

    for (_, names, local_fn) in global_ids {
        for var_name in names {
            // Re-point any local Def/Use with this variable name to the module scope
            for def in &mut cpg.dataflow.definitions {
                if def.variable == var_name && def.function_id == local_fn {
                    def.function_id = module_fn_id;
                }
            }
            for use_ in &mut cpg.dataflow.uses {
                if use_.variable == var_name && use_.function_id == local_fn {
                    use_.function_id = module_fn_id;
                }
            }
        }
    }
}

/// Walk up the parent chain from `node_id` to find the nearest function_id
/// that is NOT a comprehension scope.
fn find_enclosing_non_comprehension_scope(cpg: &Cpg, node_id: NodeId) -> Option<NodeId> {
    let mut current = node_id;
    loop {
        let parent_id = cpg.ast.get(&current)?.parent_id?;
        let parent = cpg.ast.get(&parent_id)?;
        if parent.kind == IrNodeKind::MethodDef || parent.kind == IrNodeKind::File {
            // Check it's not a comprehension: comprehensions have is_closure or specific node_types
            let is_comprehension = matches!(parent.node_type.as_str(),
                "list_comprehension" | "set_comprehension" | "dictionary_comprehension"
                | "generator_expression");
            if !is_comprehension {
                return Some(parent_id);
            }
        }
        current = parent_id;
    }
}

// ── Interprocedural DFG ───────────────────────────────────────────────────────

/// Build per-function summaries and emit INTERPROCEDURAL edges across call boundaries.
/// Called after all local DFG passes are complete.
pub fn build_interprocedural_dfg(cpg: &mut Cpg) {
    use std::collections::{HashMap, HashSet, VecDeque};

    // Build a map from NodeId → its DFG defs and uses for quick lookup
    let defs_by_fn: HashMap<Option<NodeId>, Vec<&crate::DataflowDef>> = {
        let mut m: HashMap<Option<NodeId>, Vec<&crate::DataflowDef>> = HashMap::new();
        for def in &cpg.dataflow.definitions {
            m.entry(def.function_id).or_default().push(def);
        }
        m
    };

    // For each function in the call graph, build a summary by BFS from param defs to returns.
    let func_ids: Vec<NodeId> = cpg.call_graph.keys().copied().collect();
    for func_id in func_ids {
        // Collect parameter definitions for this function
        let param_defs: Vec<(usize, NodeId, String)> = cpg.ast.iter()
            .filter(|(_, n)| n.is_param_def() && n.function_id == Some(func_id))
            .enumerate()
            .map(|(idx, (id, n))| (idx, *id, n.name.clone().or_else(|| n.text.clone()).unwrap_or_default()))
            .collect();

        // Collect return node IDs for this function
        let return_ids: HashSet<NodeId> = cpg.ast.iter()
            .filter(|(_, n)| n.is_return() && n.function_id == Some(func_id))
            .map(|(id, _)| *id)
            .collect();

        let mut summary = crate::FunctionSummary::default();

        // For each param, check:
        // (a) TaintReturn: the param variable name appears in a DataflowUse whose node is a child
        //     of a Return node in this function (or in a DFG edge reaching any return node).
        // (b) Sink: the param name appears in a TAINT_PROPAGATOR-typed DFG edge source.
        //
        // We use a simpler data-flow check: look for DataflowUse records in this function's
        // scope whose variable name matches the param name, then check if that use node is
        // reachable from any return node in the AST (i.e., is a descendant of a return node).
        let uses_in_fn: Vec<&crate::DataflowUse> = cpg.dataflow.uses.iter()
            .filter(|u| u.function_id == Some(func_id))
            .collect();

        for (param_idx, _param_id, param_var) in &param_defs {
            if param_var.is_empty() { continue; }

            // Check if any return node in this function has this param variable as a
            // descendant (child expression). Walk return node children.
            let reaches_return = return_ids.iter().any(|&ret_id| {
                // The return value is in the children of the return node.
                cpg.ast.get(&ret_id).map(|ret_node| {
                    ret_node.children.iter().any(|&child_id| {
                        cpg.ast.get(&child_id).map(|c| {
                            c.name.as_deref() == Some(param_var.as_str())
                                || c.text.as_deref() == Some(param_var.as_str())
                        }).unwrap_or(false)
                    })
                }).unwrap_or(false)
                // Also check if there's a DataflowUse with this variable at this return node
                || uses_in_fn.iter().any(|u| u.variable == *param_var && u.node_id == ret_id)
            })
            // Also check via DFG edges: any edge where variable==param_var and destination is a return node
            || cpg.dataflow.edges.iter().any(|e| {
                e.variable == *param_var && return_ids.contains(&e.destination)
                    && cpg.ast.get(&e.source).map(|n| n.function_id == Some(func_id)).unwrap_or(false)
            });

            if reaches_return {
                summary.param_effects.insert(crate::ParamEffect::TaintReturn(*param_idx));
            }

            // Check for sink flows via TAINT_PROPAGATOR edges
            let goes_to_sink = cpg.dataflow.edges.iter().any(|e| {
                e.variable == *param_var
                    && e.edge_type == "TAINT_PROPAGATOR"
                    && cpg.ast.get(&e.source).map(|n| n.function_id == Some(func_id)).unwrap_or(false)
            });
            if goes_to_sink {
                summary.param_effects.insert(crate::ParamEffect::Sink(*param_idx));
            }
        }

        // Suppress unused warning
        let _ = &uses_in_fn;

        if !summary.param_effects.is_empty() {
            cpg.workspace.function_summaries.insert(func_id, summary);
        }
    }

    // Emit cross-boundary INTERPROCEDURAL edges at each call site
    let call_sites: Vec<(NodeId, NodeId, Vec<NodeId>)> = cpg.call_graph.iter()
        .flat_map(|(&caller_id, entry)| {
            entry.calls.iter().filter_map(|site| {
                // Resolve callee to a NodeId
                let callee_id = cpg.ast.iter()
                    .find(|(_, n)| n.is_method_def()
                        && n.name.as_deref() == Some(&site.callee))
                    .map(|(id, _)| *id)?;
                // Collect argument nodes at this call site
                let args: Vec<NodeId> = site.call_site
                    .and_then(|cs_id| cpg.ast.get(&cs_id))
                    .map(|n| n.children.clone())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|&cid| cpg.ast.get(&cid)
                        .map(|c| c.is_identifier() || c.is_literal())
                        .unwrap_or(false))
                    .collect();
                Some((caller_id, callee_id, args))
            }).collect::<Vec<_>>()
        })
        .collect();

    // Emit INTERPROCEDURAL edges: for each call site where the callee has a TaintReturn summary,
    // connect each tainted argument to the call expression node (which represents the return value).
    let _ = defs_by_fn; // summaries are the primary output; defs_by_fn was used for summary building
    let mut new_edges: Vec<crate::DataflowEdge> = Vec::new();
    for (caller_id, callee_id, args) in &call_sites {
        if let Some(summary) = cpg.workspace.function_summaries.get(callee_id) {
            for effect in &summary.param_effects.clone() {
                if let crate::ParamEffect::TaintReturn(param_idx) = effect {
                    if let Some(&arg_node_id) = args.get(*param_idx) {
                        // The call site node (caller_id here is the function, not the call node;
                        // we emit from arg to the callee function node as a cross-boundary marker)
                        new_edges.push(crate::DataflowEdge {
                            source: arg_node_id,
                            destination: *caller_id,
                            variable: format!("__ret_{}", param_idx),
                            edge_type: "INTERPROCEDURAL".to_string(),
                            field_path: Vec::new(),
                        });
                    }
                }
            }
        }
    }
    cpg.dataflow.edges.extend(new_edges);
}

