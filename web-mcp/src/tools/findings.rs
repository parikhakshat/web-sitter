//! `verify_finding_status`/`record_finding_status`: query and set a security finding's
//! durable open/fixed/suppressed status (see `crate::store::findings`). `run_security_scan`
//! is what populates and auto-transitions records via `record_seen`/`sweep_fixed`; these
//! two tools are the explicit read/write surface an agent uses on top of that — e.g.
//! suppressing a known false positive, or checking whether a finding it fixed earlier in
//! the session has actually dropped out of the last scan.

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::server::WebMcpServer;
use crate::store::findings::FindingStatus;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyFindingStatusRequest {
    /// The finding id returned by `run_security_scan` (a stable fingerprint, not a
    /// scan-specific index).
    pub finding_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FindingStatusResponse {
    pub finding_id: String,
    /// "open" | "fixed" | "suppressed"
    pub status: String,
    pub first_seen_revision: u64,
    pub last_seen_revision: u64,
    pub rule_id: String,
    pub message: String,
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RecordFindingStatusRequest {
    pub finding_id: String,
    /// "open" | "fixed" | "suppressed"
    pub status: String,
}

#[tool_router(router = findings_tool_router, vis = "pub(crate)")]
impl WebMcpServer {
    #[tool(
        name = "verify_finding_status",
        description = "Look up a security finding's durable status (open/fixed/\
                        suppressed) and first/last-seen revision by its stable finding id \
                        — errors if the finding has never been observed by a scan."
    )]
    pub async fn verify_finding_status(
        &self,
        Parameters(req): Parameters<VerifyFindingStatusRequest>,
    ) -> Result<Json<FindingStatusResponse>, String> {
        let record = self
            .findings_store
            .get(&req.finding_id)
            .map_err(|e| format!("reading findings store: {e:#}"))?
            .ok_or_else(|| {
                format!(
                    "no finding record for '{}': never seen by a scan",
                    req.finding_id
                )
            })?;

        Ok(Json(FindingStatusResponse {
            finding_id: req.finding_id,
            status: record.status.as_str().to_string(),
            first_seen_revision: record.first_seen_revision,
            last_seen_revision: record.last_seen_revision,
            rule_id: record.rule_id,
            message: record.message,
            file: record.file,
            line: record.line,
        }))
    }

    #[tool(
        name = "record_finding_status",
        description = "Explicitly set a security finding's durable status to \"open\", \
                        \"fixed\", or \"suppressed\" — e.g. to silence a known false \
                        positive so future scans don't keep resurfacing it. Errors if the \
                        finding has never been observed by a scan (nothing to set a status \
                        on) or if `status` isn't one of the three supported values."
    )]
    pub async fn record_finding_status(
        &self,
        Parameters(req): Parameters<RecordFindingStatusRequest>,
    ) -> Result<Json<FindingStatusResponse>, String> {
        let status = FindingStatus::parse(&req.status).ok_or_else(|| {
            format!(
                "unsupported status '{}': only \"open\", \"fixed\", \"suppressed\" are supported",
                req.status
            )
        })?;
        let record = self
            .findings_store
            .set_status(&req.finding_id, status)
            .map_err(|e| format!("{e:#}"))?;

        Ok(Json(FindingStatusResponse {
            finding_id: req.finding_id,
            status: record.status.as_str().to_string(),
            first_seen_revision: record.first_seen_revision,
            last_seen_revision: record.last_seen_revision,
            rule_id: record.rule_id,
            message: record.message,
            file: record.file,
            line: record.line,
        }))
    }
}
