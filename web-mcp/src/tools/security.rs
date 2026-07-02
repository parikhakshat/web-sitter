//! Scoped security scanning: `run_security_scan(scope, path?, new_source?, rule_source?,
//! severity_threshold?)` — runs the built-in 52-rule `.wql` CWE corpus (`web-ql-queries/`,
//! loaded once at startup into `WebMcpServer::security_rules`) or a caller-supplied rule
//! set over a bounded slice of the workspace instead of always paying for a full
//! monorepo-wide scan.
//!
//! `scope` selects how that slice is computed:
//! - `workspace`: every indexed file (the historical, unscoped behavior).
//! - `file`: exactly `path`.
//! - `directory`: every indexed file under `path`.
//! - `diff`: `path`'s proposed `new_source` is diffed against its current on-disk
//!   contents (same byte-range diff `impact_of_change` uses), and the scope is the
//!   resulting blast radius's *files* — every file defining or referencing a changed
//!   symbol — rather than `impact_of_change`'s symbol-level blast radius. This is what
//!   lets a PR-review-style scan touch only what a patch could plausibly affect instead
//!   of the whole monorepo.
//!
//! Every scope still evaluates cross-file taint against the *whole* workspace's
//! `cross_file_dfgs`/`cross_file_callee_params` (see `Workspace::scan_scoped`) — only
//! which files get their own reported findings is restricted.

use std::collections::HashSet;
use std::path::PathBuf;

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use web_sitter::{CpgGenerator, GraphBuildOptions};

use crate::server::WebMcpServer;
use crate::tools::impact::diff_changed_symbols;

const SUPPORTED_SCOPES: &[&str] = &["workspace", "file", "directory", "diff"];

/// Severity rank, most severe first — used for `severity_threshold` filtering. Lower
/// index = more severe; a finding passes the filter when its rank is <= the threshold's.
const SEVERITY_ORDER: &[&str] = &["critical", "high", "medium", "low", "info"];

fn severity_rank(severity: &str) -> usize {
    SEVERITY_ORDER
        .iter()
        .position(|s| *s == severity)
        .unwrap_or(SEVERITY_ORDER.len() - 1)
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunSecurityScanRequest {
    /// "workspace" | "file" | "directory" | "diff"
    pub scope: String,
    /// Required for scope=file/directory/diff: the target file or directory.
    pub path: Option<String>,
    /// Required for scope=diff: the proposed full new source text for `path`.
    pub new_source: Option<String>,
    /// Custom ScuzzQL rule-file source text. If omitted, runs the built-in CWE corpus
    /// loaded at server startup.
    pub rule_source: Option<String>,
    /// Only report findings at or above this severity ("critical"|"high"|"medium"|
    /// "low"|"info"). Defaults to "info" (no filtering).
    pub severity_threshold: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SecurityFinding {
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    pub tags: Vec<String>,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct RunSecurityScanResponse {
    pub findings: Vec<SecurityFinding>,
    /// How many files were actually evaluated — lets a caller confirm a scoped scan
    /// really was scoped, not a silent full-workspace fallback.
    pub files_scanned: usize,
}

#[tool_router(router = security_tool_router, vis = "pub(crate)")]
impl WebMcpServer {
    #[tool(
        name = "run_security_scan",
        description = "Run the built-in CWE rule corpus (or a custom ScuzzQL rule set) \
                        over a bounded scope of the workspace: a single file, a \
                        directory, the blast radius of a proposed diff, or the whole \
                        workspace. Returns concrete findings with severity, message, and \
                        location — not just a pass/fail."
    )]
    pub async fn run_security_scan(
        &self,
        Parameters(req): Parameters<RunSecurityScanRequest>,
    ) -> Result<Json<RunSecurityScanResponse>, String> {
        if !SUPPORTED_SCOPES.contains(&req.scope.as_str()) {
            return Err(format!(
                "unsupported run_security_scan scope '{}': only {:?} are implemented",
                req.scope, SUPPORTED_SCOPES
            ));
        }

        let rule_set = match &req.rule_source {
            Some(source) => {
                web_ql::compile_rules(source).map_err(|e| format!("rule compile error: {e:#}"))?
            }
            None => (*self.security_rules).clone(),
        };

        let scope = self.compute_scan_scope(&req)?;

        let findings = match &scope {
            Some(files) => self.workspace.scan_scoped(&rule_set, files),
            None => self.workspace.scan(&rule_set),
        };

        let threshold_rank = severity_rank(
            req.severity_threshold
                .as_deref()
                .unwrap_or("info")
                .to_lowercase()
                .as_str(),
        );

        let findings = findings
            .into_iter()
            .map(|f| {
                let severity = f.severity_str().to_string();
                SecurityFinding {
                    rule_id: f.rule_id,
                    severity,
                    message: f.message,
                    tags: f.tags,
                    file: f.location.file,
                    line: f.location.line,
                    column: f.location.column,
                }
            })
            .filter(|f| severity_rank(&f.severity) <= threshold_rank)
            .collect();

        let files_scanned = scope
            .map(|files| files.len())
            .unwrap_or(self.workspace.files.len());

        Ok(Json(RunSecurityScanResponse {
            findings,
            files_scanned,
        }))
    }
}

impl WebMcpServer {
    /// Resolve `req.scope` into a concrete set of files to scan, or `None` for
    /// scope=workspace (meaning "everything", handled by the caller as a plain
    /// unscoped `scan()` rather than materializing every path into a `HashSet`).
    fn compute_scan_scope(
        &self,
        req: &RunSecurityScanRequest,
    ) -> Result<Option<HashSet<PathBuf>>, String> {
        match req.scope.as_str() {
            "workspace" => Ok(None),
            "file" => {
                let path = self.require_path(req)?;
                let resolved = self.resolve_path(&path);
                if !self.workspace.files.contains_key(&resolved) {
                    return Err(format!("file not indexed: {path}"));
                }
                Ok(Some(HashSet::from([resolved])))
            }
            "directory" => {
                let path = self.require_path(req)?;
                let resolved = self.resolve_path(&path);
                let files: HashSet<PathBuf> = self
                    .workspace
                    .files
                    .keys()
                    .filter(|f| f.starts_with(&resolved))
                    .cloned()
                    .collect();
                if files.is_empty() {
                    return Err(format!("no indexed files under directory: {path}"));
                }
                Ok(Some(files))
            }
            "diff" => {
                let path = self.require_path(req)?;
                let new_source_text = req
                    .new_source
                    .as_deref()
                    .ok_or_else(|| "scope=diff requires new_source".to_string())?;
                let resolved = self.resolve_path(&path);
                let idx = self
                    .workspace
                    .files
                    .get(&resolved)
                    .ok_or_else(|| format!("file not indexed: {path}"))?;

                let old_source = std::fs::read(&resolved)
                    .map_err(|e| format!("reading current contents of {path}: {e}"))?;
                let new_source = new_source_text.as_bytes();

                let language = web_sitter::language_from_path(&path);
                let mut generator = CpgGenerator::new_for_language(language)
                    .map_err(|e| format!("creating parser: {e}"))?;
                let new_cpg = generator
                    .generate_from_source_with_options(new_source, GraphBuildOptions::default())
                    .map_err(|e| format!("parsing new_source: {e}"))?;

                let changed = diff_changed_symbols(&idx.cpg, &old_source, &new_cpg, new_source);
                let changed_ids: Vec<_> = changed.into_iter().map(|(id, _)| id).collect();

                let mut files = self.reverse_index.affected_files(&changed_ids);
                files.insert(resolved);
                Ok(Some(files))
            }
            other => {
                unreachable!("validated against SUPPORTED_SCOPES before reaching here: {other}")
            }
        }
    }

    fn require_path(&self, req: &RunSecurityScanRequest) -> Result<String, String> {
        req.path
            .clone()
            .ok_or_else(|| format!("scope={} requires path", req.scope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_rank_orders_most_severe_first() {
        assert!(severity_rank("critical") < severity_rank("high"));
        assert!(severity_rank("high") < severity_rank("medium"));
        assert!(severity_rank("medium") < severity_rank("low"));
        assert!(severity_rank("low") < severity_rank("info"));
    }

    #[test]
    fn severity_rank_treats_unknown_as_least_severe() {
        assert_eq!(severity_rank("bogus"), severity_rank("info"));
    }
}
