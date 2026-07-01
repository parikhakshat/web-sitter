use std::path::Path;

use anyhow::Result;
use serde_json::json;
use web_ql::Finding;
use web_sitter::CpgSubgraph;

use crate::html_report;

#[derive(Clone)]
pub enum OutputFormat {
    Json,
    Sarif,
    Markdown,
    Html,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            "md" | "markdown" => Ok(Self::Markdown),
            "html" => Ok(Self::Html),
            other => Err(format!("unknown format: {other}")),
        }
    }
}

pub fn render(
    findings: &[Finding],
    format: &OutputFormat,
    repo: &Path,
    output_path: Option<&Path>,
    files_scanned: usize,
    cpg_graphs: Option<&[Option<CpgSubgraph>]>,
) -> Result<String> {
    match format {
        OutputFormat::Json => render_json(findings),
        OutputFormat::Sarif => render_sarif(findings),
        OutputFormat::Markdown => render_markdown(findings),
        OutputFormat::Html => html_report::render(findings, output_path, repo, files_scanned, cpg_graphs),
    }
}

// ── JSON ──────────────────────────────────────────────────────────────────────

fn render_json(findings: &[Finding]) -> Result<String> {
    Ok(serde_json::to_string_pretty(findings)?)
}

// ── SARIF 2.1.0 ──────────────────────────────────────────────────────────────

fn render_sarif(findings: &[Finding]) -> Result<String> {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": sarif_level(f.severity_str()),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.location.file },
                        "region": {
                            "startLine": f.location.line,
                            "endLine": f.location.end_line,
                            "startColumn": f.location.column,
                            "endColumn": f.location.end_column,
                        }
                    }
                }],
                "properties": { "tags": f.tags }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "web-scan",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            },
            "results": results
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn sarif_level(sev: &str) -> &'static str {
    match sev {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

// ── Markdown ──────────────────────────────────────────────────────────────────

fn render_markdown(findings: &[Finding]) -> Result<String> {
    if findings.is_empty() {
        return Ok("# Scan Results\n\nNo findings.\n".to_string());
    }

    let mut out = String::from("# Scan Results\n\n");

    let mut by_file: std::collections::BTreeMap<&str, Vec<&Finding>> =
        std::collections::BTreeMap::new();
    for f in findings {
        by_file.entry(f.location.file.as_str()).or_default().push(f);
    }

    for (file, file_findings) in &by_file {
        out.push_str(&format!("## `{file}`\n\n"));
        out.push_str("| Rule | Severity | Line | Message |\n");
        out.push_str("|------|----------|------|---------|\n");
        for f in file_findings {
            let line = if f.location.line == f.location.end_line {
                format!("{}", f.location.line)
            } else {
                format!("{}–{}", f.location.line, f.location.end_line)
            };
            out.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                f.rule_id,
                f.severity_str(),
                line,
                escape_md(&f.message),
            ));
        }
        out.push('\n');
    }

    out.push_str(&format!("**Total: {} finding(s)**\n", findings.len()));
    Ok(out)
}

fn escape_md(s: &str) -> String {
    s.replace('|', "\\|")
}
