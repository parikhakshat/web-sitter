mod fixtures;
use fixtures::*;
use web_ql::dfg::DfgIndex;

// ── Build from empty CPG ──────────────────────────────────────────────────────

#[test]
fn build_empty_cpg_empty_index() {
    use web_sitter::Cpg;
    let cpg = Cpg::default();
    let idx = DfgIndex::build(&cpg);
    // No nodes → empty index
    assert_eq!(idx.successors(0).len(), 0);
    assert_eq!(idx.predecessors(0).len(), 0);
}

// ── direct_flow ───────────────────────────────────────────────────────────────

#[test]
fn direct_flow_true_for_direct_edge() {
    let cpg = make_cpg_with_dfg(
        vec![(1, make_node(1, web_sitter::IrNodeKind::Identifier, Some("a")))],
        vec![(1, 2, "x")],
    );
    let idx = DfgIndex::build(&cpg);
    assert!(idx.direct_flow(1, 2));
}

#[test]
fn direct_flow_false_for_reverse() {
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, web_sitter::IrNodeKind::Identifier, Some("a"))),
            (2, make_node(2, web_sitter::IrNodeKind::Identifier, Some("b"))),
        ],
        vec![(1, 2, "x")],
    );
    let idx = DfgIndex::build(&cpg);
    assert!(!idx.direct_flow(2, 1)); // no reverse edge
}

#[test]
fn direct_flow_false_for_unconnected() {
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, web_sitter::IrNodeKind::Identifier, Some("a"))),
            (2, make_node(2, web_sitter::IrNodeKind::Identifier, Some("b"))),
            (3, make_node(3, web_sitter::IrNodeKind::Identifier, Some("c"))),
        ],
        vec![(1, 2, "x")],
    );
    let idx = DfgIndex::build(&cpg);
    assert!(!idx.direct_flow(1, 3)); // 1→3 not a direct edge
    assert!(!idx.direct_flow(2, 3));
}

#[test]
fn direct_flow_multiple_edges_same_source() {
    use web_sitter::IrNodeKind;
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Assign, Some("a"))),
            (2, make_node(2, IrNodeKind::Assign, Some("b"))),
            (3, make_node(3, IrNodeKind::Assign, Some("c"))),
        ],
        vec![(1, 2, "x"), (1, 3, "y")],
    );
    let idx = DfgIndex::build(&cpg);
    assert!(idx.direct_flow(1, 2));
    assert!(idx.direct_flow(1, 3));
    assert!(!idx.direct_flow(2, 3));
}

// ── successors / predecessors ─────────────────────────────────────────────────

#[test]
fn successors_empty_for_sink_node() {
    use web_sitter::IrNodeKind;
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Call, Some("src"))),
            (2, make_node(2, IrNodeKind::Call, Some("sink"))),
        ],
        vec![(1, 2, "data")],
    );
    let idx = DfgIndex::build(&cpg);
    assert_eq!(idx.successors(2).len(), 0); // sink has no outgoing
    assert_eq!(idx.successors(1).len(), 1);
}

#[test]
fn predecessors_empty_for_source_node() {
    use web_sitter::IrNodeKind;
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Call, Some("src"))),
            (2, make_node(2, IrNodeKind::Call, Some("sink"))),
        ],
        vec![(1, 2, "data")],
    );
    let idx = DfgIndex::build(&cpg);
    assert_eq!(idx.predecessors(1).len(), 0); // source has no incoming
    assert_eq!(idx.predecessors(2).len(), 1);
}

#[test]
fn predecessors_diamond_multiple() {
    use web_sitter::IrNodeKind;
    // Two sources flowing into one sink
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Call, Some("src1"))),
            (2, make_node(2, IrNodeKind::Call, Some("src2"))),
            (3, make_node(3, IrNodeKind::Call, Some("sink"))),
        ],
        vec![(1, 3, "a"), (2, 3, "b")],
    );
    let idx = DfgIndex::build(&cpg);
    assert_eq!(idx.predecessors(3).len(), 2);
}

// ── reaches (transitive) ─────────────────────────────────────────────────────

#[test]
fn reaches_direct_edge() {
    use web_sitter::IrNodeKind;
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Call, Some("a"))),
            (2, make_node(2, IrNodeKind::Call, Some("b"))),
        ],
        vec![(1, 2, "x")],
    );
    let idx = DfgIndex::build(&cpg);
    assert!(idx.reaches(1, 2));
}

#[test]
fn reaches_transitive_chain() {
    use web_sitter::IrNodeKind;
    // 1 → 2 → 3 → 4
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Call, None)),
            (2, make_node(2, IrNodeKind::Call, None)),
            (3, make_node(3, IrNodeKind::Call, None)),
            (4, make_node(4, IrNodeKind::Call, None)),
        ],
        vec![(1, 2, "x"), (2, 3, "x"), (3, 4, "x")],
    );
    let idx = DfgIndex::build(&cpg);
    assert!(idx.reaches(1, 4)); // skips 2 and 3
    assert!(idx.reaches(1, 3));
    assert!(!idx.reaches(4, 1)); // no backward path
}

#[test]
fn reaches_false_for_disconnected() {
    use web_sitter::IrNodeKind;
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Call, None)),
            (2, make_node(2, IrNodeKind::Call, None)),
            (3, make_node(3, IrNodeKind::Call, None)),
        ],
        vec![(1, 2, "x")], // 3 is disconnected
    );
    let idx = DfgIndex::build(&cpg);
    assert!(!idx.reaches(1, 3));
    assert!(!idx.reaches(2, 3));
}

#[test]
fn reaches_cycle_no_infinite_loop() {
    use web_sitter::IrNodeKind;
    // 1 → 2 → 1 (cycle) + 2 → 3
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Call, None)),
            (2, make_node(2, IrNodeKind::Call, None)),
            (3, make_node(3, IrNodeKind::Call, None)),
        ],
        vec![(1, 2, "x"), (2, 1, "x"), (2, 3, "y")],
    );
    let idx = DfgIndex::build(&cpg);
    // Should terminate without infinite loop
    assert!(idx.reaches(1, 3));
    assert!(idx.reaches(2, 3));
}

// ── reachable_from / reaches_to ──────────────────────────────────────────────

#[test]
fn reachable_from_includes_all_descendants() {
    use web_sitter::IrNodeKind;
    // 1 → 2, 1 → 3, 2 → 4
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Call, None)),
            (2, make_node(2, IrNodeKind::Call, None)),
            (3, make_node(3, IrNodeKind::Call, None)),
            (4, make_node(4, IrNodeKind::Call, None)),
        ],
        vec![(1, 2, "a"), (1, 3, "b"), (2, 4, "c")],
    );
    let idx = DfgIndex::build(&cpg);
    let reachable = idx.reachable_from(1);
    assert!(reachable.contains(&1)); // BFS includes source node itself
    assert!(reachable.contains(&2));
    assert!(reachable.contains(&3));
    assert!(reachable.contains(&4));
}

#[test]
fn reaches_to_includes_all_ancestors() {
    use web_sitter::IrNodeKind;
    // 1 → 3, 2 → 3
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Call, None)),
            (2, make_node(2, IrNodeKind::Call, None)),
            (3, make_node(3, IrNodeKind::Call, None)),
        ],
        vec![(1, 3, "x"), (2, 3, "y")],
    );
    let idx = DfgIndex::build(&cpg);
    let ancestors = idx.reaches_to(3);
    assert!(ancestors.contains(&1));
    assert!(ancestors.contains(&2));
}

// ── reaches_with_barrier ─────────────────────────────────────────────────────

#[test]
fn reaches_with_barrier_blocked() {
    use web_sitter::IrNodeKind;
    // 1 → 2 → 3, barrier at node 2
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Call, Some("src"))),
            (2, make_node(2, IrNodeKind::Call, Some("sanitizer"))),
            (3, make_node(3, IrNodeKind::Call, Some("sink"))),
        ],
        vec![(1, 2, "x"), (2, 3, "x")],
    );
    let idx = DfgIndex::build(&cpg);
    let barriers = vec![IrNodeKind::Call]; // block at any Call node (simplified)
    // When the barrier blocks all Calls, 1→3 should not reach through 2
    let can_reach = idx.reaches_with_barrier(1, 3, &barriers, &cpg);
    assert!(!can_reach, "should be blocked by barrier at node 2");
}

#[test]
fn reaches_with_barrier_unblocked() {
    use web_sitter::IrNodeKind;
    // 1 → 2 → 3, barrier only blocks Literal nodes (not present)
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Assign, Some("src"))),
            (2, make_node(2, IrNodeKind::Assign, Some("mid"))),
            (3, make_node(3, IrNodeKind::Assign, Some("sink"))),
        ],
        vec![(1, 2, "x"), (2, 3, "x")],
    );
    let idx = DfgIndex::build(&cpg);
    let barriers = vec![IrNodeKind::Literal]; // only block Literals, none here
    let can_reach = idx.reaches_with_barrier(1, 3, &barriers, &cpg);
    assert!(can_reach, "should not be blocked");
}

// ── Full taint-flow scenario ──────────────────────────────────────────────────

#[test]
fn dfg_taint_flow_cpg_source_to_sink() {
    let (cpg, src, sink) = taint_flow_cpg();
    let idx = DfgIndex::build(&cpg);
    // Source (10) → intermediate (11) → sink (12)
    assert!(idx.reaches(src, sink), "taint should propagate source→sink");
}

#[test]
fn dfg_taint_flow_sink_does_not_reach_source() {
    let (cpg, src, sink) = taint_flow_cpg();
    let idx = DfgIndex::build(&cpg);
    assert!(!idx.reaches(sink, src), "no backward flow expected");
}
