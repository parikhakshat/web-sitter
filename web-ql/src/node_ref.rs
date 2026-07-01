use std::path::PathBuf;
use web_sitter::NodeId;

/// A reference to a specific node in a specific file's CPG.
///
/// `NodeId` (a bare `u32`) is only unique within the CPG of one file — it comes
/// from a per-file counter that starts fresh on every parse, so the same
/// integer id routinely shows up in many different files of a workspace. Any
/// map or edge that spans more than one file (cross-file call resolution,
/// cross-file taint propagation, anything else that needs to name "this node,
/// in that file") must key or address nodes with `NodeRef`, never a bare
/// `NodeId` — a workspace-wide structure keyed by `NodeId` alone will silently
/// collide call sites (or any other node) from different files.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeRef {
    pub file: PathBuf,
    pub id: NodeId,
}

impl NodeRef {
    pub fn new(file: PathBuf, id: NodeId) -> Self {
        Self { file, id }
    }
}
