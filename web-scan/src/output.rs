use anyhow::Result;
use serde::Serialize;
use serde_json::json;
use web_ql::Finding;

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

pub fn render(findings: &[Finding], format: &OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => render_json(findings),
        OutputFormat::Sarif => render_sarif(findings),
        OutputFormat::Markdown => render_markdown(findings),
        OutputFormat::Html => render_html(findings),
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
                    "informationUri": "https://github.com/your-org/cpg"
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

    // Group by file
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

// ── HTML ──────────────────────────────────────────────────────────────────────

fn render_html(findings: &[Finding]) -> Result<String> {
    let total = findings.len();
    let rows = findings
        .iter()
        .map(|f| {
            let sev = f.severity_str();
            let line = if f.location.line == f.location.end_line {
                format!("{}", f.location.line)
            } else {
                format!("{}–{}", f.location.line, f.location.end_line)
            };
            let tags = f.tags.join(", ");
            format!(
                r#"<tr class="sev-{sev}">
  <td><code>{rule_id}</code></td>
  <td class="sev-badge">{sev}</td>
  <td class="file-col">{file}</td>
  <td>{line}</td>
  <td>{message}</td>
  <td>{tags}</td>
</tr>"#,
                sev = sev,
                rule_id = html_escape(&f.rule_id),
                file = html_escape(&f.location.file),
                line = line,
                message = html_escape(&f.message),
                tags = html_escape(&tags),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>web-scan results</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f1117; color: #e2e8f0; margin: 0; padding: 2rem; }}
  h1 {{ color: #f8f9fa; font-size: 1.5rem; margin-bottom: 0.25rem; }}
  .meta {{ color: #94a3b8; font-size: 0.85rem; margin-bottom: 1.5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ background: #1e2330; color: #94a3b8; text-transform: uppercase;
        font-size: 0.75rem; letter-spacing: 0.05em; padding: 0.6rem 0.75rem;
        text-align: left; border-bottom: 1px solid #2d3748; }}
  td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid #1e2330; vertical-align: top; }}
  tr:hover td {{ background: #1a1f2e; }}
  code {{ background: #1e2330; padding: 0.1em 0.35em; border-radius: 3px;
          font-size: 0.85em; color: #a3d4ff; }}
  .file-col {{ color: #7dd3fc; font-family: monospace; font-size: 0.8rem; max-width: 300px;
               overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .sev-badge {{ font-weight: 600; text-transform: uppercase; font-size: 0.72rem; }}
  .sev-critical .sev-badge {{ color: #f87171; }}
  .sev-high .sev-badge {{ color: #fb923c; }}
  .sev-medium .sev-badge {{ color: #fbbf24; }}
  .sev-low .sev-badge {{ color: #34d399; }}
  .sev-info .sev-badge {{ color: #94a3b8; }}
  .summary {{ margin-top: 1.5rem; color: #94a3b8; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>web-scan</h1>
<p class="meta">Generated by web-scan v{version}</p>
{empty_msg}
<table>
<thead>
<tr><th>Rule</th><th>Severity</th><th>File</th><th>Line</th><th>Message</th><th>Tags</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
<p class="summary">{total} finding(s)</p>
</body>
</html>
"#,
        version = env!("CARGO_PKG_VERSION"),
        empty_msg = if total == 0 { "<p>No findings.</p>" } else { "" },
        rows = rows,
        total = total,
    ))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
