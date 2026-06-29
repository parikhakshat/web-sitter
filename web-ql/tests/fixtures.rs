/// Test fixture builders for Cpg and related types.
///
/// These helpers allow tests to construct minimal, self-consistent CPG instances
/// without depending on the full tree-sitter parsing pipeline.
use std::collections::BTreeMap;
use web_sitter::{
    BasicBlock, Cpg, DataflowEdge, DataflowGraph, IrNode, IrNodeKind, LiteralKind, NodeId,
};

// ── IrNode builder ────────────────────────────────────────────────────────────

pub fn make_node(id: NodeId, kind: IrNodeKind, name: Option<&str>) -> IrNode {
    IrNode {
        kind,
        node_type: format!("{kind:?}").to_lowercase(),
        name: name.map(str::to_owned),
        text: name.map(str::to_owned),
        children: vec![],
        field_names: vec![],
        parent_id: None,
        function_id: None,
        basic_block: None,
        line: 1,
        column: 0,
        end_line: 1,
        end_column: 10,
        // all optional fields default to None / false
        loop_kind: None,
        try_kind: None,
        lit_kind: None,
        signature: None,
        string_length: None,
        array_size: None,
        array_size_expr: None,
        operator: None,
        argument_count: None,
        class_context: None,
        namespace: None,
        visibility: None,
        is_constructor: None,
        is_destructor: None,
        is_virtual: None,
        template_params: None,
        qualified_name: None,
        base_classes: None,
        start_byte: None,
        end_byte: None,
    }
}

pub fn make_node_at(id: NodeId, kind: IrNodeKind, name: Option<&str>, line: u32) -> IrNode {
    let mut n = make_node(id, kind, name);
    n.line = line;
    n.end_line = line;
    n
}

pub fn make_node_in_fn(id: NodeId, kind: IrNodeKind, name: Option<&str>, fn_id: NodeId) -> IrNode {
    let mut n = make_node(id, kind, name);
    n.function_id = Some(fn_id);
    n
}

pub fn make_literal_node(id: NodeId, lit_kind: LiteralKind, text: &str) -> IrNode {
    let mut n = make_node(id, IrNodeKind::Literal, None);
    n.lit_kind = Some(lit_kind);
    n.text = Some(text.to_owned());
    n
}

pub fn make_call_node(id: NodeId, callee: &str, args: Vec<NodeId>) -> IrNode {
    let mut n = make_node(id, IrNodeKind::Call, Some(callee));
    n.children = args;
    n.argument_count = Some(n.children.len() as u32);
    n
}

// ── Cpg builder ───────────────────────────────────────────────────────────────

pub fn make_cpg(nodes: Vec<IrNode>) -> Cpg {
    let ast: BTreeMap<NodeId, IrNode> = nodes
        .into_iter()
        .enumerate()
        .map(|(i, n)| (i as NodeId, n))
        .collect();
    Cpg {
        ast,
        language: "python".to_owned(),
        ..Cpg::default()
    }
}

pub fn make_cpg_with_ids(nodes: Vec<(NodeId, IrNode)>) -> Cpg {
    Cpg {
        ast: nodes.into_iter().collect(),
        language: "python".to_owned(),
        ..Cpg::default()
    }
}

pub fn make_cpg_with_lang(nodes: Vec<(NodeId, IrNode)>, lang: &str) -> Cpg {
    Cpg {
        ast: nodes.into_iter().collect(),
        language: lang.to_owned(),
        ..Cpg::default()
    }
}

/// Build a CPG with DFG edges.
/// `edges`: (source_id, destination_id, variable_name)
pub fn make_cpg_with_dfg(nodes: Vec<(NodeId, IrNode)>, edges: Vec<(NodeId, NodeId, &str)>) -> Cpg {
    let dfg_edges: Vec<DataflowEdge> = edges
        .into_iter()
        .map(|(src, dst, var)| DataflowEdge {
            source: src,
            destination: dst,
            variable: var.to_owned(),
            edge_type: "dataflow".to_owned(),
            field_path: vec![],
        })
        .collect();
    Cpg {
        ast: nodes.into_iter().collect(),
        dataflow: DataflowGraph {
            definitions: vec![],
            uses: vec![],
            edges: dfg_edges,
        },
        language: "python".to_owned(),
        ..Cpg::default()
    }
}

/// Build a CPG with basic blocks suitable for CFG testing.
/// `fn_id`: the NodeId of the MethodDef node for these blocks.
/// `blocks`: list of (block_id_str, node_ids_in_block, successor_ids)
pub fn make_cpg_with_blocks(
    nodes: Vec<(NodeId, IrNode)>,
    fn_id: NodeId,
    blocks: Vec<(&str, Vec<NodeId>, Vec<&str>)>,
) -> Cpg {
    let mut basic_blocks = BTreeMap::new();
    for (block_id, block_nodes, succs) in blocks {
        basic_blocks.insert(
            block_id.to_owned(),
            BasicBlock {
                block_type: "basic_block".to_owned(),
                nodes: block_nodes,
                successors: succs.into_iter().map(str::to_owned).collect(),
                exception_successors: vec![],
                function: fn_id,
                is_setjmp_target: false,
            },
        );
    }
    Cpg {
        ast: nodes.into_iter().collect(),
        basic_blocks,
        language: "python".to_owned(),
        ..Cpg::default()
    }
}

// ── Scenario builders ─────────────────────────────────────────────────────────

/// A trivial single-function CPG with one call node named `func`.
pub fn simple_call_cpg() -> (Cpg, NodeId) {
    const FN_ID: NodeId = 1;
    const CALL_ID: NodeId = 2;
    let fn_node = make_node(FN_ID, IrNodeKind::MethodDef, Some("outer"));
    let call_node = {
        let mut n = make_node_in_fn(CALL_ID, IrNodeKind::Call, Some("func"), FN_ID);
        n.argument_count = Some(0);
        n
    };
    let cpg = make_cpg_with_ids(vec![(FN_ID, fn_node), (CALL_ID, call_node)]);
    (cpg, CALL_ID)
}

/// A taint-flow CPG: source node → intermediate → sink node via DFG edges.
pub fn taint_flow_cpg() -> (Cpg, NodeId, NodeId) {
    const SRC: NodeId = 10;
    const MID: NodeId = 11;
    const SINK: NodeId = 12;

    let src = make_node(SRC, IrNodeKind::Call, Some("user_input"));
    let mid = make_node(MID, IrNodeKind::Assign, Some("x"));
    let sink = make_node(SINK, IrNodeKind::Call, Some("execute_sql"));

    let cpg = make_cpg_with_dfg(
        vec![(SRC, src), (MID, mid), (SINK, sink)],
        vec![(SRC, MID, "user_data"), (MID, SINK, "user_data")],
    );
    (cpg, SRC, SINK)
}

/// A CPG with a MethodDef and a few nodes inside a simple linear CFG.
/// Block layout (alphabetically sorted by name): bb0 → bb1 → bb2
/// Using numeric-prefixed names so alphabetical sort preserves execution order.
pub fn linear_cfg_cpg() -> (Cpg, NodeId) {
    const FN_ID: NodeId = 20;
    const N1: NodeId = 21;
    const N2: NodeId = 22;
    const N3: NodeId = 23;

    let fn_node = make_node(FN_ID, IrNodeKind::MethodDef, Some("linear_fn"));
    let n1 = make_node_in_fn(N1, IrNodeKind::Assign, Some("a"), FN_ID);
    let n2 = make_node_in_fn(N2, IrNodeKind::Assign, Some("b"), FN_ID);
    let n3 = make_node_in_fn(N3, IrNodeKind::Return, None, FN_ID);

    let cpg = make_cpg_with_blocks(
        vec![(FN_ID, fn_node), (N1, n1), (N2, n2), (N3, n3)],
        FN_ID,
        vec![
            ("bb0", vec![N1], vec!["bb1"]),
            ("bb1", vec![N2], vec!["bb2"]),
            ("bb2", vec![N3], vec![]),
        ],
    );
    (cpg, FN_ID)
}

/// A CPG with a branching CFG (if/else diamond).
/// Block layout (alphabetically): bb0(cond) → bb1(then), bb2(else) → bb3(merge)
pub fn branching_cfg_cpg() -> (Cpg, NodeId) {
    const FN_ID: NodeId = 30;
    const COND: NodeId = 31;
    const THEN_N: NodeId = 32;
    const ELSE_N: NodeId = 33;
    const MERGE_N: NodeId = 34;

    let fn_node = make_node(FN_ID, IrNodeKind::MethodDef, Some("branch_fn"));
    let cond = make_node_in_fn(COND, IrNodeKind::Conditional, None, FN_ID);
    let then_n = make_node_in_fn(THEN_N, IrNodeKind::Assign, Some("x"), FN_ID);
    let else_n = make_node_in_fn(ELSE_N, IrNodeKind::Assign, Some("y"), FN_ID);
    let merge_n = make_node_in_fn(MERGE_N, IrNodeKind::Return, None, FN_ID);

    let cpg = make_cpg_with_blocks(
        vec![
            (FN_ID, fn_node),
            (COND, cond),
            (THEN_N, then_n),
            (ELSE_N, else_n),
            (MERGE_N, merge_n),
        ],
        FN_ID,
        vec![
            ("bb0", vec![COND], vec!["bb1", "bb2"]),
            ("bb1", vec![THEN_N], vec!["bb3"]),
            ("bb2", vec![ELSE_N], vec!["bb3"]),
            ("bb3", vec![MERGE_N], vec![]),
        ],
    );
    (cpg, FN_ID)
}
