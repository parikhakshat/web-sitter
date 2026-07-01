mod fixtures;
use fixtures::*;
use web_ql::cfg::{CfgReachability, DomTree, FunctionCfg};

// ── DomTree: linear CFG ───────────────────────────────────────────────────────

// Linear graph: 0 → 1 → 2 → 3
fn linear_succs() -> Vec<Vec<u32>> {
    vec![vec![1], vec![2], vec![3], vec![]]
}

#[test]
fn domtree_linear_entry_dominates_all() {
    let dom = DomTree::compute(&linear_succs(), 0);
    // 0 dominates everything
    assert!(dom.dominates(0, 0));
    assert!(dom.dominates(0, 1));
    assert!(dom.dominates(0, 2));
    assert!(dom.dominates(0, 3));
}

#[test]
fn domtree_linear_strictly_dominates() {
    let dom = DomTree::compute(&linear_succs(), 0);
    assert!(dom.strictly_dominates(0, 1));
    assert!(dom.strictly_dominates(1, 2));
    assert!(!dom.strictly_dominates(2, 1)); // not reverse
    assert!(!dom.strictly_dominates(0, 0)); // not itself
}

#[test]
fn domtree_linear_predecessor_does_not_dominate_reverse() {
    let dom = DomTree::compute(&linear_succs(), 0);
    assert!(!dom.dominates(3, 0));
    assert!(!dom.dominates(2, 0));
}

// ── DomTree: diamond (branch + merge) ────────────────────────────────────────

// Diamond: 0 → {1, 2}, 1 → 3, 2 → 3
fn diamond_succs() -> Vec<Vec<u32>> {
    vec![
        vec![1, 2], // 0 → 1, 2
        vec![3],    // 1 → 3
        vec![3],    // 2 → 3
        vec![],     // 3
    ]
}

#[test]
fn domtree_diamond_entry_dominates_all() {
    let dom = DomTree::compute(&diamond_succs(), 0);
    assert!(dom.dominates(0, 1));
    assert!(dom.dominates(0, 2));
    assert!(dom.dominates(0, 3));
}

#[test]
fn domtree_diamond_branches_dont_dominate_each_other() {
    let dom = DomTree::compute(&diamond_succs(), 0);
    // 1 does not dominate 2 and vice versa (both paths from 0 exist)
    assert!(!dom.dominates(1, 2));
    assert!(!dom.dominates(2, 1));
}

#[test]
fn domtree_diamond_merge_not_dominated_by_branches() {
    let dom = DomTree::compute(&diamond_succs(), 0);
    // 3 is reachable from both 1 and 2, so neither solely dominates it
    assert!(!dom.strictly_dominates(1, 3));
    assert!(!dom.strictly_dominates(2, 3));
    // But 0 dominates 3 (it's the only way to enter the diamond)
    assert!(dom.dominates(0, 3));
}

// ── DomTree: loop ────────────────────────────────────────────────────────────

// Loop: 0 → 1 → 2 → 1 (back edge), 1 → 3
fn loop_succs() -> Vec<Vec<u32>> {
    vec![
        vec![1],    // 0 → 1
        vec![2, 3], // 1 → 2 (body), 3 (exit)
        vec![1],    // 2 → 1 (back edge)
        vec![],     // 3 exit
    ]
}

#[test]
fn domtree_loop_entry_dominates_header() {
    let dom = DomTree::compute(&loop_succs(), 0);
    assert!(dom.dominates(0, 1));
    assert!(dom.dominates(1, 2)); // header dominates body
    assert!(dom.dominates(0, 3));
}

#[test]
fn domtree_loop_body_does_not_dominate_header() {
    let dom = DomTree::compute(&loop_succs(), 0);
    // 2 (body) does NOT dominate 1 (header) — 0→1 bypasses 2
    assert!(!dom.dominates(2, 1));
}

// ── DomTree: dominance frontier ───────────────────────────────────────────────

#[test]
fn domtree_diamond_frontier() {
    let dom = DomTree::compute(&diamond_succs(), 0);
    // Dominance frontier of block 1 is {3} (the merge point)
    let df1 = dom.frontier(1);
    assert!(df1.contains(3), "df(1) should include 3");
    let df2 = dom.frontier(2);
    assert!(df2.contains(3), "df(2) should include 3");
}

// ── CfgReachability ───────────────────────────────────────────────────────────

#[test]
fn reachability_linear_all_reach_forward() {
    let reach = CfgReachability::compute(&linear_succs());
    assert!(reach.can_reach(0, 1));
    assert!(reach.can_reach(0, 2));
    assert!(reach.can_reach(0, 3));
    assert!(reach.can_reach(1, 3));
    assert!(reach.can_reach(2, 3));
}

#[test]
fn reachability_linear_no_backward() {
    let reach = CfgReachability::compute(&linear_succs());
    assert!(!reach.can_reach(3, 0));
    assert!(!reach.can_reach(2, 0));
}

#[test]
fn reachability_self_reach() {
    let reach = CfgReachability::compute(&linear_succs());
    // A block reaches itself
    assert!(reach.can_reach(0, 0));
    assert!(reach.can_reach(2, 2));
}

#[test]
fn reachability_diamond_both_paths() {
    let reach = CfgReachability::compute(&diamond_succs());
    assert!(reach.can_reach(0, 3));
    assert!(reach.can_reach(1, 3));
    assert!(reach.can_reach(2, 3));
    // Neither branch reaches the other directly
    assert!(!reach.can_reach(1, 2));
    assert!(!reach.can_reach(2, 1));
}

#[test]
fn reachability_loop_back_edge() {
    let reach = CfgReachability::compute(&loop_succs());
    // Header (1) reaches body (2) and back-edge makes 2 reach 1
    assert!(reach.can_reach(1, 2));
    assert!(reach.can_reach(2, 1)); // via back edge
    assert!(reach.can_reach(0, 3));
}

#[test]
fn reachability_single_node() {
    let single = vec![vec![]]; // one node with no successors
    let reach = CfgReachability::compute(&single);
    assert!(reach.can_reach(0, 0));
}

#[test]
fn reachability_empty_graph() {
    let reach = CfgReachability::compute(&[]);
    assert_eq!(reach.n, 0);
    assert!(!reach.can_reach(0, 0));
}

#[test]
fn reachability_disconnected_components_dont_cross_reach() {
    // 0 → 1   and a separate, unreachable pair  2 → 3
    let succs = vec![vec![1], vec![], vec![3], vec![]];
    let reach = CfgReachability::compute(&succs);
    assert!(reach.can_reach(0, 1));
    assert!(reach.can_reach(2, 3));
    assert!(!reach.can_reach(0, 2));
    assert!(!reach.can_reach(0, 3));
    assert!(!reach.can_reach(2, 0));
    assert!(!reach.can_reach(2, 1));
}

#[test]
fn reachability_multi_node_cycle_reaches_shared_external_sink() {
    // A 3-node cycle (0 → 1 → 2 → 0) where only node 1 has an edge out to an
    // external sink (3). Since the cycle is one SCC, every member must reach the
    // sink, not just the block with the literal outgoing edge — this is exactly
    // what the SCC-condensation reach computation must get right (all SCC
    // members share one reach set).
    let succs = vec![
        vec![1],    // 0 → 1
        vec![2, 3], // 1 → 2 (cycle), 1 → 3 (external sink)
        vec![0],    // 2 → 0 (closes the cycle)
        vec![],     // 3: sink
    ];
    let reach = CfgReachability::compute(&succs);
    assert!(reach.can_reach(0, 3), "0 should reach the sink via the cycle");
    assert!(reach.can_reach(1, 3));
    assert!(reach.can_reach(2, 3), "2 should reach the sink even though only 1 has the direct edge");
    // All cycle members mutually reach each other.
    assert!(reach.can_reach(0, 1) && reach.can_reach(1, 2) && reach.can_reach(2, 0));
    assert!(reach.can_reach(0, 2) && reach.can_reach(1, 0) && reach.can_reach(2, 1));
    // The sink does not reach back into the cycle.
    assert!(!reach.can_reach(3, 0));
    assert!(!reach.can_reach(3, 1));
}

#[test]
fn reachability_two_cycles_chained_through_bridge() {
    // Cycle A {0,1}, bridge block 2, cycle B {3,4}: 0↔1 → 2 → 3↔4
    let succs = vec![
        vec![1],    // 0 → 1
        vec![0, 2], // 1 → 0 (cycle), 1 → 2 (bridge)
        vec![3],    // 2 → 3
        vec![4],    // 3 → 4
        vec![3],    // 4 → 3 (closes cycle B)
    ];
    let reach = CfgReachability::compute(&succs);
    // Cycle A reaches the bridge and all of cycle B.
    assert!(reach.can_reach(0, 2) && reach.can_reach(1, 2));
    assert!(reach.can_reach(0, 3) && reach.can_reach(0, 4));
    assert!(reach.can_reach(1, 3) && reach.can_reach(1, 4));
    // Cycle B does not reach back through the bridge into cycle A.
    assert!(!reach.can_reach(3, 0));
    assert!(!reach.can_reach(4, 1));
    assert!(!reach.can_reach(2, 0));
}

// ── FunctionCfg from real CPG ─────────────────────────────────────────────────

#[test]
fn function_cfg_build_linear() {
    let (cpg, fn_id) = linear_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    // Should have 3 blocks: entry, body, exit
    assert_eq!(cfg.succs.len(), 3);
}

#[test]
fn function_cfg_build_branching() {
    let (cpg, fn_id) = branching_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    // 4 blocks: entry, then_block, else_block, merge
    assert_eq!(cfg.succs.len(), 4);
}

#[test]
fn function_cfg_entry_block_is_first() {
    let (cpg, fn_id) = linear_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    // entry block index should be 0
    assert_eq!(cfg.entry, 0);
}

#[test]
fn function_cfg_node_reaches_in_linear() {
    let (cpg, fn_id) = linear_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);

    // node 21 (entry block) should reach node 22 (body) and 23 (exit)
    assert!(cfg.node_reaches(21, 22));
    assert!(cfg.node_reaches(21, 23));
    assert!(!cfg.node_reaches(23, 21)); // reverse not reachable
}

#[test]
fn function_cfg_node_dominates_in_linear() {
    let (cpg, fn_id) = linear_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    // Entry node 21 dominates all others
    assert!(cfg.node_dominates(21, 22));
    assert!(cfg.node_dominates(21, 23));
}

#[test]
fn function_cfg_same_block_detection() {
    let (cpg, fn_id) = linear_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    // Nodes 21 (in "entry" block) and 22 (in "body" block) are NOT in the same block
    assert!(!cfg.same_block(21, 22));
}

#[test]
fn function_cfg_empty_function() {
    // A function with no basic blocks produces an empty CFG gracefully
    use web_sitter::IrNodeKind;
    let fn_node = make_node(99, IrNodeKind::MethodDef, Some("empty_fn"));
    let cpg = make_cpg_with_ids(vec![(99, fn_node)]);
    let cfg = FunctionCfg::build_for_function(&cpg, 99);
    // Empty function: no blocks
    assert_eq!(cfg.succs.len(), 0);
}

#[test]
fn function_cfg_branching_entry_reaches_all() {
    let (cpg, fn_id) = branching_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    // The conditional node (31) is in the entry block, should reach all other nodes
    assert!(cfg.node_reaches(31, 32)); // then node
    assert!(cfg.node_reaches(31, 33)); // else node
    assert!(cfg.node_reaches(31, 34)); // merge node
}

// ── feasible_reaches / node_in_dead_branch (memoized) ─────────────────────────

#[test]
fn feasible_reaches_matches_node_reaches_without_symbolic_condition() {
    // branching_cfg_cpg's Conditional node has no recorded "condition" field
    // child, so block_to_condition is empty and feasible_reaches must fall
    // back to following every successor, exactly like node_reaches.
    let (cpg, fn_id) = branching_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    assert!(cfg.feasible_reaches(31, 32, &cpg));
    assert!(cfg.feasible_reaches(31, 33, &cpg));
    assert!(cfg.feasible_reaches(31, 34, &cpg));
    assert!(!cfg.feasible_reaches(32, 33, &cpg)); // then can't reach else
}

#[test]
fn feasible_reaches_is_stable_across_repeated_calls() {
    // Exercises the memoized `feasible_reach_cache`: the second call for the
    // same source block must return the same answer as the first (cache-hit
    // path), not a stale or empty set.
    let (cpg, fn_id) = branching_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    for _ in 0..3 {
        assert!(cfg.feasible_reaches(31, 34, &cpg));
        assert!(!cfg.feasible_reaches(34, 31, &cpg));
    }
}

#[test]
fn node_in_dead_branch_false_for_every_node_reachable_from_entry() {
    // Every node in branching_cfg_cpg is reachable from the entry block, so
    // none of them should be reported as being in a dead branch.
    let (cpg, fn_id) = branching_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    assert!(!cfg.node_in_dead_branch(31, &cpg));
    assert!(!cfg.node_in_dead_branch(32, &cpg));
    assert!(!cfg.node_in_dead_branch(33, &cpg));
    assert!(!cfg.node_in_dead_branch(34, &cpg));
}

#[test]
fn node_in_dead_branch_true_for_disconnected_block() {
    // bb1 is never listed as a successor of bb0 (entry), so it's structurally
    // unreachable — the node inside it must be reported as being in a dead branch.
    use web_sitter::{IrNodeKind, NodeId};
    const FN_ID: NodeId = 70;
    const N_ENTRY: NodeId = 71;
    const N_ORPHAN: NodeId = 72;

    let fn_node = make_node(FN_ID, IrNodeKind::MethodDef, Some("orphan_fn"));
    let n_entry = make_node_in_fn(N_ENTRY, IrNodeKind::Assign, Some("init"), FN_ID);
    let n_orphan = make_node_in_fn(N_ORPHAN, IrNodeKind::Return, None, FN_ID);

    let cpg = make_cpg_with_blocks(
        vec![(FN_ID, fn_node), (N_ENTRY, n_entry), (N_ORPHAN, n_orphan)],
        FN_ID,
        vec![
            ("bb0", vec![N_ENTRY], vec![]),   // entry, no successors
            ("bb1", vec![N_ORPHAN], vec![]),  // never referenced by bb0 — unreachable
        ],
    );
    let cfg = FunctionCfg::build_for_function(&cpg, FN_ID);
    assert!(!cfg.node_in_dead_branch(N_ENTRY, &cpg));
    assert!(cfg.node_in_dead_branch(N_ORPHAN, &cpg));
}

// ── loop_has_no_exit ──────────────────────────────────────────────────────────

#[test]
fn loop_has_no_exit_returns_false_for_loop_with_exit() {
    let (cpg, fn_id, header, body, _exit) = loop_with_exit_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    // The loop has an exit edge from the header, so this should be false
    assert!(!cfg.node_loop_has_no_exit(header, &cpg));
    assert!(!cfg.node_loop_has_no_exit(body, &cpg));
}

#[test]
fn loop_has_no_exit_returns_true_for_infinite_loop_header() {
    let (cpg, fn_id, header, _body) = loop_no_exit_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    assert!(cfg.node_loop_has_no_exit(header, &cpg));
}

#[test]
fn loop_has_no_exit_returns_true_for_infinite_loop_body() {
    let (cpg, fn_id, _header, body) = loop_no_exit_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    assert!(cfg.node_loop_has_no_exit(body, &cpg));
}

#[test]
fn loop_has_no_exit_returns_false_for_node_not_in_loop() {
    let (cpg, fn_id) = linear_cfg_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    // Node 21 is in a linear CFG with no loops
    assert!(!cfg.node_loop_has_no_exit(21, &cpg));
}

#[test]
fn in_loop_detects_back_edge_for_finite_loop() {
    let (cpg, fn_id, header, body, exit) = loop_with_exit_cpg();
    let cfg = FunctionCfg::build_for_function(&cpg, fn_id);
    // node_in_loop: true for any node whose block is within the loop's SCC.
    // The header is the loop entry (dominates body), body has the back edge to header.
    // Both header and body are part of the loop; the exit block is not.
    assert!(cfg.node_in_loop(body));
    assert!(cfg.node_in_loop(header));
    assert!(!cfg.node_in_loop(exit));
}
