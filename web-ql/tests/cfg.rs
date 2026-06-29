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
