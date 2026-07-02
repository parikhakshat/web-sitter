use crate::ast::Severity;
use serde::{Deserialize, Serialize};
use web_sitter::NodeId;

/// The source location of a finding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingLocation {
    pub file: String,
    pub line: u32,
    pub end_line: u32,
    pub column: u32,
    pub end_column: u32,
}

/// A single rule match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Option<Severity>,
    pub message: String,
    pub tags: Vec<String>,
    pub location: FindingLocation,
    /// All AST nodes involved in this finding (primary match + taint path).
    pub matched_nodes: Vec<NodeId>,
}

impl Finding {
    pub fn severity_str(&self) -> &'static str {
        match self.severity {
            Some(Severity::Critical) => "critical",
            Some(Severity::High) => "high",
            Some(Severity::Medium) => "medium",
            Some(Severity::Low) => "low",
            Some(Severity::Info) | None => "info",
        }
    }
}
