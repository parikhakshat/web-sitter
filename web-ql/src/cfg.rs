use std::collections::HashMap;
use roaring::RoaringBitmap;
use web_sitter::{BasicBlock, Cpg, NodeId};

/// Unique identifier for a basic block within a function.
pub type BlockId = u32;

// ── Dominance tree (Lengauer-Tarjan) ─────────────────────────────────────────

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
    /// `succs[i]` gives the successors of block i; entry block is 0.
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
    /// Which block each IrNode lives in (NodeId → BlockId)
    pub node_to_block: HashMap<NodeId, BlockId>,
    pub dom: DomTree,
    pub reach: CfgReachability,
    pub entry: BlockId,
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

        // Sort by block ID string for deterministic ordering
        fn_blocks.sort_by_key(|(id, _)| id.as_str());

        let n = fn_blocks.len();
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

        let entry: BlockId = 0;
        let dom = DomTree::compute(&succs, entry);
        let reach = CfgReachability::compute(&succs);

        Self { succs, node_to_block, dom, reach, entry }
    }

    /// True if node `a` dominates node `b` in this function's CFG.
    pub fn node_dominates(&self, a: NodeId, b: NodeId) -> bool {
        match (self.node_to_block.get(&a), self.node_to_block.get(&b)) {
            (Some(&ba), Some(&bb)) => self.dom.dominates(ba, bb),
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
