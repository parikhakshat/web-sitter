use std::collections::{HashMap, HashSet, VecDeque};
use roaring::RoaringBitmap;
use web_sitter::{BasicBlock, Cpg, IrNodeKind, NodeId};
use crate::symbolic::{SymbolicEval, SymbolicValue};

/// Unique identifier for a basic block within a function.
pub type BlockId = u32;

// ── Dominance tree (Cooper et al. iterative algorithm) ────────────────────────

/// Pre-computed dominance information for a single function's CFG.
pub struct DomTree {
    /// Immediate dominator of each block (idom[entry] = entry).
    pub idom: Vec<BlockId>,
    /// Dominance frontier sets: df[b] = set of blocks y where b dominates a
    /// predecessor of y but does not strictly dominate y.
    pub df: Vec<RoaringBitmap>,
    /// Number of blocks
    pub n: usize,
}

impl DomTree {
    /// Compute the dominator tree using a simplified Lengauer-Tarjan algorithm.
    /// `succs[i]` gives the successors of block i; entry block is `entry`.
    pub fn compute(succs: &[Vec<BlockId>], entry: BlockId) -> Self {
        let n = succs.len();
        if n == 0 {
            return Self { idom: vec![], df: vec![], n: 0 };
        }

        // Build predecessor lists
        let mut preds: Vec<Vec<BlockId>> = vec![vec![]; n];
        for (b, bs) in succs.iter().enumerate() {
            for &s in bs {
                if (s as usize) < n {
                    preds[s as usize].push(b as BlockId);
                }
            }
        }

        // Iterative dataflow dominator algorithm (Cooper et al. "A Simple, Fast
        // Dominance Algorithm")
        let rpo = reverse_postorder(succs, entry as usize, n);
        let mut rpo_num = vec![n; n]; // rpo_num[block] = its index in RPO
        for (i, &b) in rpo.iter().enumerate() {
            rpo_num[b] = i;
        }

        let mut idom: Vec<Option<BlockId>> = vec![None; n];
        idom[entry as usize] = Some(entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                // find a processed predecessor
                let processed_preds: Vec<BlockId> = preds[b as usize]
                    .iter()
                    .copied()
                    .filter(|&p| idom[p as usize].is_some())
                    .collect();

                if processed_preds.is_empty() {
                    continue;
                }

                let mut new_idom = processed_preds[0];
                for &p in processed_preds.iter().skip(1) {
                    new_idom = intersect(&idom, new_idom, p, &rpo_num);
                }
                if idom[b as usize] != Some(new_idom) {
                    idom[b as usize] = Some(new_idom);
                    changed = true;
                }
            }
        }

        let idom_vec: Vec<BlockId> = (0..n)
            .map(|i| idom[i].unwrap_or(i as BlockId))
            .collect();

        // Compute dominance frontiers
        let df = compute_df(&idom_vec, &preds, n);

        Self { idom: idom_vec, df, n }
    }

    /// Returns true if `dominator` strictly dominates `dominated`.
    pub fn strictly_dominates(&self, dominator: BlockId, dominated: BlockId) -> bool {
        if dominator == dominated {
            return false;
        }
        self.dominates(dominator, dominated)
    }

    /// Returns true if `dominator` dominates `dominated` (reflexive).
    pub fn dominates(&self, dominator: BlockId, mut dominated: BlockId) -> bool {
        if (dominator as usize) >= self.n || (dominated as usize) >= self.n {
            return false;
        }
        loop {
            if dominated == dominator {
                return true;
            }
            let parent = self.idom[dominated as usize];
            if parent == dominated {
                return false; // reached entry without finding dominator
            }
            dominated = parent;
        }
    }

    /// Returns the dominance frontier of block `b`.
    pub fn frontier(&self, b: BlockId) -> &RoaringBitmap {
        &self.df[b as usize]
    }
}

// ── CFG reachability ──────────────────────────────────────────────────────────

/// Pre-computed forward reachability for all blocks in a function CFG.
pub struct CfgReachability {
    /// reach[b] = bitmap of all blocks reachable from b (including b itself).
    pub reach: Vec<RoaringBitmap>,
    pub n: usize,
}

impl CfgReachability {
    /// Compute reachability via transitive closure (BFS from each node).
    /// For larger CFGs this should be done with bit-matrix propagation in RPO.
    pub fn compute(succs: &[Vec<BlockId>]) -> Self {
        let n = succs.len();
        let mut reach: Vec<RoaringBitmap> = (0..n as u32)
            .map(|i| {
                let mut bm = RoaringBitmap::new();
                bm.insert(i);
                bm
            })
            .collect();

        // Propagate in RPO (conservative: iterative until fixed point)
        let mut changed = true;
        while changed {
            changed = false;
            for b in 0..n {
                for &s in &succs[b] {
                    let s = s as usize;
                    if s < n {
                        // reach[b] |= reach[s]  (forward reachability: b can reach whatever s can)
                        // Actually we want: for each successor s, reach[b] union= {s} union reach[s]
                        let additional: Vec<u32> = reach[s]
                            .iter()
                            .filter(|&x| !reach[b].contains(x))
                            .collect();
                        if !additional.is_empty() {
                            for x in additional {
                                reach[b].insert(x);
                            }
                            changed = true;
                        }
                        if !reach[b].contains(s as u32) {
                            reach[b].insert(s as u32);
                            changed = true;
                        }
                    }
                }
            }
        }

        Self { reach, n }
    }

    /// True if block `from` can reach block `to` via forward control flow.
    pub fn can_reach(&self, from: BlockId, to: BlockId) -> bool {
        self.reach
            .get(from as usize)
            .map_or(false, |bm| bm.contains(to))
    }
}

// ── Function CFG wrapper ──────────────────────────────────────────────────────

/// CFG analysis artifacts for a single function.
pub struct FunctionCfg {
    /// Block successors (indices into the ordered block vec)
    pub succs: Vec<Vec<BlockId>>,
    /// Block predecessors
    pub preds: Vec<Vec<BlockId>>,
    /// Which block each IrNode lives in (NodeId → BlockId)
    pub node_to_block: HashMap<NodeId, BlockId>,
    /// Forward dominance tree
    pub dom: DomTree,
    /// Post-dominance tree (dominance in the reversed CFG with virtual exit)
    pub post_dom: DomTree,
    pub reach: CfgReachability,
    pub entry: BlockId,
    /// Blocks reachable via exception_successors edges (propagated transitively)
    pub exception_blocks: HashSet<BlockId>,
    /// For each block that ends in a conditional branch, the CPG NodeId of the
    /// condition expression.  Derived from Conditional/Loop/Switch AST nodes
    /// whose condition-field child lands in that block.  Used by feasible-path
    /// analysis to prune provably-dead edges.
    pub block_to_condition: HashMap<BlockId, NodeId>,
}

impl FunctionCfg {
    /// Build the CFG analysis from a CPG's basic_blocks map for a given function.
    /// Only blocks whose `function` field matches `fn_id` are included.
    pub fn build_for_function(cpg: &Cpg, fn_id: NodeId) -> Self {
        // Collect blocks for this function, preserving consistent ordering
        let mut fn_blocks: Vec<(&String, &BasicBlock)> = cpg
            .basic_blocks
            .iter()
            .filter(|(_, b)| b.function == fn_id)
            .collect();

        // Sort by numeric suffix for deterministic ordering that matches
        // the block creation order (e.g. "bb_5" < "bb_12" < "bb_100").
        // Lexicographic sort would mis-order these ("bb_100" < "bb_5").
        fn_blocks.sort_by(|(a, _), (b, _)| {
            let num = |s: &str| -> u64 {
                s.rsplit('_').next().and_then(|n| n.parse().ok()).unwrap_or(0)
            };
            num(a).cmp(&num(b))
        });

        let n = fn_blocks.len();

        if n == 0 {
            return Self {
                succs: vec![],
                preds: vec![],
                node_to_block: HashMap::new(),
                dom: DomTree { idom: vec![], df: vec![], n: 0 },
                post_dom: DomTree { idom: vec![], df: vec![], n: 0 },
                reach: CfgReachability { reach: vec![], n: 0 },
                entry: 0,
                exception_blocks: HashSet::new(),
                block_to_condition: HashMap::new(),
            };
        }

        // Map block string ID → index
        let block_index: HashMap<&str, BlockId> = fn_blocks
            .iter()
            .enumerate()
            .map(|(i, (id, _))| (id.as_str(), i as BlockId))
            .collect();

        let mut succs: Vec<Vec<BlockId>> = vec![vec![]; n];
        let mut node_to_block: HashMap<NodeId, BlockId> = HashMap::new();

        for (i, (_, block)) in fn_blocks.iter().enumerate() {
            for &node_id in &block.nodes {
                node_to_block.insert(node_id, i as BlockId);
            }
            for succ_str in &block.successors {
                if let Some(&succ_idx) = block_index.get(succ_str.as_str()) {
                    succs[i].push(succ_idx);
                }
            }
        }

        // Build predecessor lists from succs
        let mut preds: Vec<Vec<BlockId>> = vec![vec![]; n];
        for (b, bs) in succs.iter().enumerate() {
            for &s in bs {
                if (s as usize) < n {
                    preds[s as usize].push(b as BlockId);
                }
            }
        }

        // Find exit blocks (no outgoing regular edges)
        let exit_blocks: Vec<BlockId> = (0..n)
            .filter(|&b| succs[b].is_empty())
            .map(|b| b as BlockId)
            .collect();

        // Build reversed graph for post-dominance.
        // In the reversed CFG: edges are flipped, so rev_succs[i] = preds[i] (original preds
        // become reversed successors). A virtual exit node (index n) links to all original
        // exit blocks, serving as the single root of the post-dominator tree.
        let virtual_exit = n as BlockId;
        let mut rev_succs: Vec<Vec<BlockId>> = preds.clone();
        rev_succs.push(exit_blocks); // virtual exit → all original exit blocks

        let entry: BlockId = 0;
        let dom = DomTree::compute(&succs, entry);
        let post_dom = DomTree::compute(&rev_succs, virtual_exit);
        let reach = CfgReachability::compute(&succs);

        // Find exception blocks: blocks reachable via exception_successors, propagated.
        let mut exception_blocks = HashSet::new();
        let mut exc_queue = VecDeque::new();
        for (_, block) in fn_blocks.iter() {
            for exc_succ in &block.exception_successors {
                if let Some(&exc_idx) = block_index.get(exc_succ.as_str()) {
                    if exception_blocks.insert(exc_idx) {
                        exc_queue.push_back(exc_idx);
                    }
                }
            }
        }
        while let Some(b) = exc_queue.pop_front() {
            for &s in &succs[b as usize] {
                if exception_blocks.insert(s) {
                    exc_queue.push_back(s);
                }
            }
        }

        // For each Conditional / Loop / Switch node in this function, find the
        // "condition" field child and record which block that child lives in.
        // This drives feasible-path analysis: when a block with 2 successors has
        // a statically-evaluable condition we can prune the dead arm.
        let mut block_to_condition: HashMap<BlockId, NodeId> = HashMap::new();
        for (&nid, node) in &cpg.ast {
            if node.function_id != Some(fn_id) {
                continue;
            }
            if !matches!(node.kind, IrNodeKind::Conditional | IrNodeKind::Loop | IrNodeKind::Switch) {
                continue;
            }
            // Prefer the "condition" named field; fall back to the first child.
            let cond_child = node.children.iter().enumerate().find_map(|(i, &cid)| {
                if node.field_names.get(i).and_then(|f| f.as_deref()) == Some("condition") {
                    Some(cid)
                } else {
                    None
                }
            }).or_else(|| node.children.first().copied());

            if let Some(cid) = cond_child {
                if let Some(&blk) = node_to_block.get(&cid) {
                    // Only map it if that block actually branches (2+ successors);
                    // otherwise we'd incorrectly annotate non-branching blocks.
                    if succs[blk as usize].len() >= 2 {
                        block_to_condition.insert(blk, cid);
                    }
                }
            }
        }

        Self { succs, preds, node_to_block, dom, post_dom, reach, entry, exception_blocks, block_to_condition }
    }

    /// True if node `a` dominates node `b` in this function's CFG.
    pub fn node_dominates(&self, a: NodeId, b: NodeId) -> bool {
        match (self.node_to_block.get(&a), self.node_to_block.get(&b)) {
            (Some(&ba), Some(&bb)) => self.dom.dominates(ba, bb),
            _ => false,
        }
    }

    /// True if node `a` post-dominates node `b` (every path from b to exit goes through a).
    pub fn node_post_dominates(&self, a: NodeId, b: NodeId) -> bool {
        match (self.node_to_block.get(&a), self.node_to_block.get(&b)) {
            (Some(&ba), Some(&bb)) => self.post_dom.dominates(ba, bb),
            _ => false,
        }
    }

    /// True if there is a control-flow path from node `a` to node `b`.
    pub fn node_reaches(&self, a: NodeId, b: NodeId) -> bool {
        match (self.node_to_block.get(&a), self.node_to_block.get(&b)) {
            (Some(&ba), Some(&bb)) => self.reach.can_reach(ba, bb),
            _ => false,
        }
    }

    /// True if `a` and `b` are in the same basic block.
    pub fn same_block(&self, a: NodeId, b: NodeId) -> bool {
        match (self.node_to_block.get(&a), self.node_to_block.get(&b)) {
            (Some(&ba), Some(&bb)) => ba == bb,
            _ => false,
        }
    }

    /// True if `node` is inside a loop (i.e., its block is part of the loop's SCC).
    pub fn node_in_loop(&self, node: NodeId) -> bool {
        let Some(&block) = self.node_to_block.get(&node) else { return false };
        let Some(header) = self.find_loop_header(block) else { return false };
        // The block IS the header (back edge discovered on header's predecessors), or
        // the block can reach the header (proving it's in the SCC, not just dominated by it).
        block == header || self.reach.can_reach(block, header)
    }

    /// Walk up the dominator chain from `block` to find the innermost enclosing
    /// loop header — a block that has a predecessor it dominates (back edge).
    fn find_loop_header(&self, block: BlockId) -> Option<BlockId> {
        let mut current = block;
        loop {
            for &pred in &self.preds[current as usize] {
                if self.dom.dominates(current, pred) {
                    return Some(current);
                }
            }
            let idom = self.dom.idom[current as usize];
            if idom == current {
                break;
            }
            current = idom;
        }
        None
    }

    /// True if `node` is inside a loop whose strongly-connected component has
    /// no exit edge to outside the loop body (i.e., infinite loop with no break/return).
    pub fn node_loop_has_no_exit(&self, node: NodeId, cpg: &Cpg) -> bool {
        let Some(&block) = self.node_to_block.get(&node) else { return false };
        let n = self.succs.len();
        let Some(header) = self.find_loop_header(block) else { return false };

        // Symbolic short-circuit: if the loop header's condition is constant-true,
        // the structural "exit" edge is dead and the loop never terminates.
        if let Some(&cond_node) = self.block_to_condition.get(&header) {
            let mut se = SymbolicEval::new(cpg);
            match se.eval_int(cond_node) {
                Some(v) if v != 0 => return true,
                _ => {}
            }
            if se.eval_bool(cond_node) == Some(true) {
                return true;
            }
        }

        // Structural check: no block in the SCC has an exit edge.
        let in_scc = |b: u32| -> bool {
            (b as usize) < n
                && self.reach.can_reach(header, b)
                && self.reach.can_reach(b, header)
        };
        for b in 0..n as u32 {
            if !in_scc(b) {
                continue;
            }
            for &succ in &self.succs[b as usize] {
                if !in_scc(succ) {
                    return false;
                }
            }
        }
        true
    }

    /// True if `node` is on an exception-handling path.
    pub fn node_in_exception_path(&self, node: NodeId) -> bool {
        let Some(&block) = self.node_to_block.get(&node) else { return false };
        self.exception_blocks.contains(&block)
    }

    /// True if there exists a CFG path from `from` to `to` that avoids `barrier`.
    pub fn node_cfg_reaches_without(&self, from: NodeId, to: NodeId, barrier: NodeId) -> bool {
        let (Some(&bf), Some(&bt)) = (self.node_to_block.get(&from), self.node_to_block.get(&to))
        else {
            return false;
        };
        let barrier_block = self.node_to_block.get(&barrier).copied();

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(bf);
        visited.insert(bf);

        while let Some(b) = queue.pop_front() {
            if b == bt {
                return true;
            }
            for &s in &self.succs[b as usize] {
                if !visited.contains(&s) && Some(s) != barrier_block {
                    visited.insert(s);
                    queue.push_back(s);
                }
            }
        }
        false
    }

    /// Path-sensitive reachability: same as `node_reaches` but prunes edges whose
    /// branch guard is a constant.  For a block with exactly two successors:
    /// - Condition evaluates to `true`/nonzero → only follow successor[0] (the
    ///   "then"/"body" arm, which the CPG generator always emits first).
    /// - Condition evaluates to `false`/zero → only follow successor[1] (the
    ///   "else"/"exit" arm).
    /// Falls back to following all successors when the condition isn't constant.
    pub fn feasible_reaches(&self, from: NodeId, to: NodeId, cpg: &Cpg) -> bool {
        let (Some(&bf), Some(&bt)) = (
            self.node_to_block.get(&from),
            self.node_to_block.get(&to),
        ) else {
            return false;
        };

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(bf);
        visited.insert(bf);

        while let Some(b) = queue.pop_front() {
            if b == bt {
                return true;
            }
            let succs = &self.succs[b as usize];
            let live: Vec<BlockId> = if succs.len() == 2 {
                if let Some(&cid) = self.block_to_condition.get(&b) {
                    let mut se = SymbolicEval::new(cpg);
                    match se.eval(cid) {
                        // Condition always true → only the "then/body" arm (index 0)
                        SymbolicValue::Bool(true) => vec![succs[0]],
                        SymbolicValue::Int(n) if n != 0 => vec![succs[0]],
                        // Condition always false → only the "else/exit" arm (index 1)
                        SymbolicValue::Bool(false) | SymbolicValue::Int(0) => vec![succs[1]],
                        _ => succs.to_vec(),
                    }
                } else {
                    succs.to_vec()
                }
            } else {
                succs.to_vec()
            };

            for s in live {
                if visited.insert(s) {
                    queue.push_back(s);
                }
            }
        }
        false
    }

    /// True if both nodes belong to this function's CFG (same function).
    pub fn contains_node(&self, node: NodeId) -> bool {
        self.node_to_block.contains_key(&node)
    }

    /// Returns the block ID string index for `node`, if present.
    pub fn block_id_for_node(&self, node: NodeId) -> Option<BlockId> {
        self.node_to_block.get(&node).copied()
    }

    /// Returns the dominance frontier of the block containing `node`.
    pub fn dominance_frontier_for_node(&self, node: NodeId) -> Vec<BlockId> {
        let Some(&block) = self.node_to_block.get(&node) else { return vec![] };
        self.dom.frontier(block).iter().collect()
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn reverse_postorder(succs: &[Vec<BlockId>], entry: usize, n: usize) -> Vec<usize> {
    let mut visited = vec![false; n];
    let mut postorder = Vec::with_capacity(n);
    dfs_postorder(succs, entry, &mut visited, &mut postorder);
    postorder.reverse();
    postorder
}

fn dfs_postorder(
    succs: &[Vec<BlockId>],
    node: usize,
    visited: &mut Vec<bool>,
    postorder: &mut Vec<usize>,
) {
    if visited[node] {
        return;
    }
    visited[node] = true;
    for &s in &succs[node] {
        let s = s as usize;
        if s < succs.len() {
            dfs_postorder(succs, s, visited, postorder);
        }
    }
    postorder.push(node);
}

fn intersect(
    idom: &[Option<BlockId>],
    mut b1: BlockId,
    mut b2: BlockId,
    rpo_num: &[usize],
) -> BlockId {
    loop {
        if b1 == b2 {
            return b1;
        }
        while rpo_num[b1 as usize] > rpo_num[b2 as usize] {
            b1 = idom[b1 as usize].unwrap_or(b1);
        }
        while rpo_num[b2 as usize] > rpo_num[b1 as usize] {
            b2 = idom[b2 as usize].unwrap_or(b2);
        }
    }
}

fn compute_df(idom: &[BlockId], preds: &[Vec<BlockId>], n: usize) -> Vec<RoaringBitmap> {
    let mut df: Vec<RoaringBitmap> = vec![RoaringBitmap::new(); n];

    for b in 0..n {
        if preds[b].len() >= 2 {
            for &p in &preds[b] {
                let mut runner = p;
                while runner != idom[b] {
                    df[runner as usize].insert(b as u32);
                    let next = idom[runner as usize];
                    if next == runner {
                        break;
                    }
                    runner = next;
                }
            }
        }
    }

    df
}
