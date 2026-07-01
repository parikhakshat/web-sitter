use std::collections::{BTreeMap, HashMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{json, Value};
use web_ql::Finding;
use web_sitter::CpgSubgraph;

const REPORT_CSS: &str = include_str!("report.css");
const REPORT_JS: &str = include_str!("report.js");

const SNIPPET_CONTEXT: usize = 8;

pub fn render(findings: &[Finding], output_path: Option<&Path>, repo: &Path, files_scanned: usize, cpg_graphs: Option<&[Option<CpgSubgraph>]>) -> Result<String> {
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_rule: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_file: BTreeMap<String, usize> = BTreeMap::new();

    for f in findings {
        *by_severity.entry(f.severity_str().to_string()).or_default() += 1;
        *by_rule.entry(f.rule_id.clone()).or_default() += 1;
        *by_file.entry(f.location.file.clone()).or_default() += 1;
    }

    // Build findings JSON array
    let findings_json: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "rule_id": f.rule_id,
                "severity": f.severity_str(),
                "message": f.message,
                "tags": f.tags,
                "location": {
                    "file": f.location.file,
                    "line": f.location.line,
                    "end_line": f.location.end_line,
                    "column": f.location.column,
                    "end_column": f.location.end_column,
                },
                "matched_node_ids": f.matched_nodes,
            })
        })
        .collect();

    // Build snippet cache
    let snippets = build_snippets(findings, repo)?;

    let report_json = json!({
        "metadata": {
            "generated_at_unix": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "version": env!("CARGO_PKG_VERSION"),
            "files_scanned": files_scanned,
            "total_findings": findings.len(),
        },
        "summary": {
            "total_findings": findings.len(),
            "by_severity": by_severity,
            "by_rule": by_rule,
            "by_file": by_file,
        },
        "findings": findings_json,
        "snippets": snippets,
    });

    let json_str = serde_json::to_string(&report_json)?;
    let json_safe = json_str.replace("</script>", "<\\/script>");

    // Build per-finding CPG subgraph JSON islands
    let mut cpg_islands = String::new();
    if let Some(graphs) = cpg_graphs {
        for (i, maybe_graph) in graphs.iter().enumerate() {
            if let Some(graph) = maybe_graph {
                if !graph.nodes.is_empty() {
                    let g_json = serde_json::to_string(graph)?;
                    let g_safe = g_json.replace("</script>", "<\\/script>");
                    cpg_islands.push_str(&format!(
                        "<script type=\"application/json\" id=\"cpg-{i}\">{g_safe}</script>\n"
                    ));
                }
            }
        }
    }

    let _ = output_path; // reserved for future relative-path resolution

    Ok(build_html(&json_safe, &cpg_islands, findings.len()))
}

fn build_snippets(findings: &[Finding], repo: &Path) -> Result<HashMap<String, Value>> {
    let mut refs: BTreeSet<(String, u32)> = BTreeSet::new();
    for f in findings {
        if !f.location.file.is_empty() && f.location.line > 0 {
            refs.insert((f.location.file.clone(), f.location.line));
        }
    }

    let mut snippets = HashMap::new();
    for (file, line) in refs {
        if let Some(snip) = load_snippet(repo, &file, line)? {
            snippets.insert(format!("{file}:{line}"), snip);
        }
    }
    Ok(snippets)
}

fn load_snippet(repo: &Path, file: &str, line: u32) -> Result<Option<Value>> {
    let abs: PathBuf = if Path::new(file).is_absolute() {
        PathBuf::from(file)
    } else {
        repo.join(file)
    };
    let content = match std::fs::read_to_string(&abs) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() || line == 0 {
        return Ok(None);
    }
    let idx = (line - 1) as usize;
    if idx >= lines.len() {
        return Ok(None);
    }
    let start = idx.saturating_sub(SNIPPET_CONTEXT);
    let end = (idx + SNIPPET_CONTEXT + 1).min(lines.len());
    let slice: Vec<String> = lines[start..end].iter().map(|s| (*s).to_string()).collect();
    Ok(Some(json!({ "start_line": start + 1, "lines": slice })))
}

fn build_html(report_json: &str, cpg_islands: &str, total: usize) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>web-scan — {total} finding(s)</title>
<style>{css}</style>
</head>
<body>
<header class="page-header">
  <h1>web-scan</h1>
  <div class="meta-grid">
    <span><strong>Version</strong> {version}</span>
    <span><strong>Findings</strong> {total}</span>
  </div>
</header>
<main>
  <div id="summary-cards" class="summary-cards"></div>
  <div class="toolbar">
    <input id="search-input" type="search" placeholder="Search rule, message, file…">
    <select id="sev-filter">
      <option value="all">All severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="info">Info</option>
    </select>
  </div>
  <div id="findings-root"></div>
</main>
<div id="drawer-backdrop"></div>
<aside id="snippet-drawer" aria-label="Source snippet">
  <div class="drawer-header">
    <h3 id="drawer-title">Source</h3>
    <button id="drawer-close" class="drawer-close" aria-label="Close">&times;</button>
  </div>
  <div id="drawer-body" class="drawer-body"></div>
</aside>
{cpg_islands}<script>const REPORT = {report_json};</script>
<script>{js}</script>
</body>
</html>"#,
        total = total,
        version = env!("CARGO_PKG_VERSION"),
        css = REPORT_CSS,
        js = REPORT_JS,
        report_json = report_json,
        cpg_islands = cpg_islands,
    )
}
