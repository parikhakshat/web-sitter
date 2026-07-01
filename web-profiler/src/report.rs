use std::fmt::Write as FmtWrite;
use serde::Serialize;
use crate::histogram::Histogram;
use crate::metrics::{CounterSnapshot, ThreadMetrics};
use crate::profiler::{CacheSnapshot, StageSnapshot, ParallelStageSnapshot};

/// A point-in-time snapshot of all profiler data.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileReport {
    pub elapsed_secs: f64,
    pub stages: Vec<StageSnapshot>,
    pub caches: Vec<CacheSnapshot>,
    pub counters: Vec<CounterSnapshot>,
    pub threads: ThreadMetrics,
    pub parallel_stages: Vec<ParallelStageSnapshot>,
}

impl ProfileReport {
    /// Render as a human-readable text report.
    pub fn human_readable(&self) -> String {
        let mut out = String::new();
        let elapsed = self.elapsed_secs;

        writeln!(out, "\n╔══════════════════════════════════════════════════════════════╗").unwrap();
        writeln!(out, "║                    web-profiler Report                       ║").unwrap();
        writeln!(out, "╚══════════════════════════════════════════════════════════════╝").unwrap();
        writeln!(out, "  Wall elapsed: {:.3}s", elapsed).unwrap();
        writeln!(out).unwrap();

        // ── Stage timings ─────────────────────────────────────────────────────
        if !self.stages.is_empty() {
            writeln!(out, "── Stage Timings ───────────────────────────────────────────────").unwrap();
            writeln!(
                out,
                "  {:<32} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9}",
                "Stage", "Count", "Total", "Mean", "P50", "P95", "Max"
            ).unwrap();
            writeln!(out, "  {}", "─".repeat(87)).unwrap();
            for s in &self.stages {
                let total_nanos = s.mean_nanos.saturating_mul(s.count);
                writeln!(
                    out,
                    "  {:<32} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9}",
                    truncate(&s.name, 32),
                    s.count,
                    Histogram::fmt_nanos(total_nanos),
                    Histogram::fmt_nanos(s.mean_nanos),
                    Histogram::fmt_nanos(s.p50_nanos),
                    Histogram::fmt_nanos(s.p95_nanos),
                    Histogram::fmt_nanos(s.max_nanos),
                ).unwrap();
            }
            writeln!(out).unwrap();
        }

        // ── Cache efficiency ──────────────────────────────────────────────────
        if !self.caches.is_empty() {
            writeln!(out, "── Cache Efficiency ────────────────────────────────────────────").unwrap();
            writeln!(
                out,
                "  {:<24} {:>8} {:>8} {:>9} {:>9} {:>9}",
                "Cache", "Hits", "Misses", "Hit Rate", "Inserts", "Bytes"
            ).unwrap();
            writeln!(out, "  {}", "─".repeat(71)).unwrap();
            for c in &self.caches {
                writeln!(
                    out,
                    "  {:<24} {:>8} {:>8} {:>8.1}% {:>9} {:>9}",
                    truncate(&c.name, 24),
                    c.hits,
                    c.misses,
                    c.hit_rate_pct,
                    c.inserts,
                    fmt_bytes(c.bytes_used),
                ).unwrap();
            }
            writeln!(out).unwrap();
        }

        // ── Throughput counters ───────────────────────────────────────────────
        if !self.counters.is_empty() {
            writeln!(out, "── Throughput ──────────────────────────────────────────────────").unwrap();
            for c in &self.counters {
                let rate = if elapsed > 0.0 {
                    format!("  ({:.1}/s)", c.value as f64 / elapsed)
                } else {
                    String::new()
                };
                writeln!(out, "  {:<32} {:>10}{}", c.name, fmt_count(c.value), rate).unwrap();
            }
            writeln!(out).unwrap();
        }

        // ── Thread pool ───────────────────────────────────────────────────────
        let t = &self.threads;
        writeln!(out, "── Thread Pool ─────────────────────────────────────────────────").unwrap();
        writeln!(out, "  Pool threads:     {:>6}", t.pool_threads).unwrap();
        writeln!(out, "  Threads started:  {:>6}", t.threads_started).unwrap();
        writeln!(out, "  Tasks submitted:  {:>6}", t.tasks_submitted).unwrap();
        writeln!(out, "  Tasks completed:  {:>6}", t.tasks_completed).unwrap();
        writeln!(out, "  Peak in-flight:   {:>6}", t.peak_in_flight).unwrap();
        writeln!(out, "  Avg utilization:  {:>5.1}%", t.avg_utilization_pct).unwrap();

        let in_flight = t.tasks_submitted.saturating_sub(t.tasks_completed);
        if in_flight > 0 {
            writeln!(out, "  Still in-flight:  {:>6}", in_flight).unwrap();
        }

        writeln!(out).unwrap();
        out
    }

    /// Serialize as compact JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Serialize as pretty-printed JSON.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

impl std::fmt::Display for ProfileReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.human_readable())
    }
}

// ── HTML report ───────────────────────────────────────────────────────────────

impl ProfileReport {
    pub fn to_html(&self) -> String {
        let elapsed = self.elapsed_secs;
        let mut html = String::from(HTML_HEAD);

        // Separate rule-timing stages from pipeline stages
        let pipeline_stages: Vec<_> = self.stages.iter().filter(|s| !s.name.starts_with("rule.")).collect();
        let rule_stages: Vec<_> = self.stages.iter().filter(|s| s.name.starts_with("rule.")).collect();

        // Header
        html.push_str("<header class=\"page-header\">\n<h1>web-scan profiler</h1>\n");
        html.push_str("<div class=\"meta-grid\">\n");
        html.push_str(&format!("<span><strong>Wall time</strong> {:.3}s</span>\n", elapsed));
        html.push_str(&format!("<span><strong>Pipeline stages</strong> {}</span>\n", pipeline_stages.len()));
        html.push_str(&format!("<span><strong>Rules timed</strong> {}</span>\n", rule_stages.len()));
        html.push_str(&format!("<span><strong>Pool threads</strong> {}</span>\n", self.threads.pool_threads));
        html.push_str("</div>\n</header>\n<main>\n");

        // Summary cards — top 4 pipeline stages by total time
        let top_stages: Vec<_> = pipeline_stages.iter().take(4).collect();
        if !top_stages.is_empty() {
            html.push_str("<section class=\"summary-cards\">\n");
            for s in &top_stages {
                let total_ms = s.total_nanos as f64 / 1_000_000.0;
                let color = stage_color_html(&s.name);
                html.push_str(&format!(
                    "<div class=\"summary-card\" style=\"border-left:3px solid {color}\">\n\
                     <div class=\"label\">{}</div>\n\
                     <div class=\"value\">{}</div>\n\
                     <div class=\"sub-label\">count: {}</div>\n\
                     </div>\n",
                    esc_html(&truncate(&s.name, 22)),
                    fmt_ms(total_ms),
                    s.count,
                ));
            }
            html.push_str("</section>\n");
        }

        // Pipeline layer bar chart
        {
            struct Layer { name: &'static str, color: &'static str, total_ms: f64 }
            let mut layers: Vec<Layer> = Vec::new();
            for (prefix, label, color) in [
                ("stage.", "Pipeline stages", "#d29922"),
                ("query.", "Query evaluation", "#3fb950"),
            ] {
                let total_ms: f64 = pipeline_stages.iter()
                    .filter(|s| s.name.starts_with(prefix))
                    .map(|s| s.total_nanos as f64 / 1_000_000.0)
                    .sum();
                if total_ms > 0.0 {
                    layers.push(Layer { name: label, color, total_ms });
                }
            }
            if !rule_stages.is_empty() {
                let total_ms: f64 = rule_stages.iter().map(|s| s.total_nanos as f64 / 1_000_000.0).sum();
                layers.push(Layer { name: "Rule timing", color: "#58a6ff", total_ms });
            }
            if !layers.is_empty() {
                let max_ms = layers.iter().map(|l| l.total_ms).fold(0.0_f64, f64::max).max(1.0);
                html.push_str("<section class=\"panel\">\n<h2>Pipeline layers</h2>\n<div class=\"layer-bars\">\n");
                for l in &layers {
                    let pct = (l.total_ms / max_ms * 100.0).min(100.0);
                    html.push_str(&format!(
                        "<div class=\"layer-row\">\
                        <div class=\"layer-label\">{}</div>\
                        <div class=\"layer-bar-wrap\"><div class=\"layer-bar-fill\" style=\"width:{pct:.1}%;background:{}\"></div></div>\
                        <div class=\"layer-value\">{}</div>\
                        </div>\n",
                        esc_html(l.name), l.color, fmt_ms(l.total_ms),
                    ));
                }
                html.push_str("</div></section>\n");
            }
        }

        // Thread utilization per stage
        if !self.parallel_stages.is_empty() {
            html.push_str("<section class=\"panel\">\n<h2>Thread utilization per stage</h2>\n");
            html.push_str("<div class=\"table-wrap\"><table>\n<thead><tr>\
                <th>Stage</th><th>Workers</th><th>Wall</th><th>CPU (sum)</th><th>Efficiency</th>\
                </tr></thead><tbody>\n");
            for ps in &self.parallel_stages {
                let eff_color = if ps.efficiency_pct >= 75.0 { "#3fb950" }
                    else if ps.efficiency_pct >= 40.0 { "#d29922" }
                    else { "#f85149" };
                html.push_str(&format!(
                    "<tr>\
                    <td><code>{}</code></td>\
                    <td>{}</td>\
                    <td>{}</td>\
                    <td>{}</td>\
                    <td><div style=\"display:flex;align-items:center;gap:6px\">\
                    <div style=\"flex:1;height:6px;background:#1c2128;border-radius:3px\">\
                    <div style=\"height:6px;border-radius:3px;background:{eff_color};width:{:.1}%\"></div></div>\
                    <span style=\"color:{eff_color};font-weight:600\">{:.0}%</span></div></td>\
                    </tr>\n",
                    esc_html(&ps.label),
                    ps.n_workers,
                    fmt_ms(ps.wall_ms),
                    fmt_ms(ps.cpu_ms),
                    ps.efficiency_pct,
                    ps.efficiency_pct,
                ));
            }
            html.push_str("</tbody></table></div></section>\n");
        }

        // Stage timings table (pipeline stages only)
        if !pipeline_stages.is_empty() {
            let max_ms = pipeline_stages.iter().map(|s| s.total_nanos).max().unwrap_or(1).max(1) as f64 / 1_000_000.0;
            html.push_str("<section class=\"panel\">\n<h2>Stage timings</h2>\n");
            html.push_str("<div class=\"table-wrap\"><table>\n<thead><tr>\
                <th>Stage</th><th>Total</th><th>Count</th><th>Mean</th><th>P50</th><th>P95</th><th>Max</th>\
                </tr></thead><tbody>\n");
            for s in &pipeline_stages {
                let total_ms = s.total_nanos as f64 / 1_000_000.0;
                let mean_ms = s.mean_nanos as f64 / 1_000_000.0;
                let p50_ms = s.p50_nanos as f64 / 1_000_000.0;
                let p95_ms = s.p95_nanos as f64 / 1_000_000.0;
                let max_ms2 = s.max_nanos as f64 / 1_000_000.0;
                let pct = (total_ms / max_ms * 100.0).min(100.0);
                let color = stage_color_html(&s.name);
                html.push_str(&format!(
                    "<tr>\
                    <td class=\"stage-name\"><span class=\"stage-dot\" style=\"background:{color}\"></span>\
                    <code>{}</code>\
                    <div class=\"inline-bar\"><div class=\"inline-bar-fill\" style=\"width:{pct:.1}%;background:{color}\"></div></div>\
                    </td>\
                    <td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                    </tr>\n",
                    esc_html(&s.name),
                    fmt_ms(total_ms),
                    s.count,
                    fmt_ms(mean_ms),
                    fmt_ms(p50_ms),
                    fmt_ms(p95_ms),
                    fmt_ms(max_ms2),
                ));
            }
            html.push_str("</tbody></table></div></section>\n");
        }

        // Top rules by time
        if !rule_stages.is_empty() {
            let mut sorted_rules = rule_stages.clone();
            sorted_rules.sort_by(|a, b| b.total_nanos.cmp(&a.total_nanos));
            let display_rules: Vec<_> = sorted_rules.iter().take(50).collect();
            let max_rule_ms = display_rules.first().map(|s| s.total_nanos).unwrap_or(1).max(1) as f64 / 1_000_000.0;
            html.push_str("<section class=\"panel\">\n<h2>Top rules by time</h2>\n");
            html.push_str("<div class=\"table-wrap\"><table>\n<thead><tr>\
                <th>Rule</th><th>Total</th><th>Count</th><th>Mean</th><th>P95</th><th>Max</th>\
                </tr></thead><tbody>\n");
            for s in &display_rules {
                let rule_name = s.name.strip_prefix("rule.").unwrap_or(&s.name);
                let total_ms = s.total_nanos as f64 / 1_000_000.0;
                let mean_ms = s.mean_nanos as f64 / 1_000_000.0;
                let p95_ms = s.p95_nanos as f64 / 1_000_000.0;
                let max_ms2 = s.max_nanos as f64 / 1_000_000.0;
                let pct = (total_ms / max_rule_ms * 100.0).min(100.0);
                html.push_str(&format!(
                    "<tr>\
                    <td class=\"stage-name\"><code>{}</code>\
                    <div class=\"inline-bar\"><div class=\"inline-bar-fill\" style=\"width:{pct:.1}%;background:#58a6ff\"></div></div>\
                    </td>\
                    <td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                    </tr>\n",
                    esc_html(rule_name),
                    fmt_ms(total_ms),
                    s.count,
                    fmt_ms(mean_ms),
                    fmt_ms(p95_ms),
                    fmt_ms(max_ms2),
                ));
            }
            html.push_str("</tbody></table></div></section>\n");
        }

        // Cache statistics
        if !self.caches.is_empty() {
            html.push_str("<section class=\"panel\">\n<h2>Cache statistics</h2>\n");
            html.push_str("<div class=\"table-wrap\"><table>\n<thead><tr>\
                <th>Cache</th><th>Hits</th><th>Misses</th><th>Hit rate</th><th>Inserts</th><th>Evictions</th><th>Bytes</th>\
                </tr></thead><tbody>\n");
            for c in &self.caches {
                let total = c.hits + c.misses;
                let pct = if total > 0 { c.hits as f64 / total as f64 * 100.0 } else { 0.0 };
                let bar_pct = pct.min(100.0);
                let rate_color = if pct >= 80.0 { "#3fb950" } else if pct >= 40.0 { "#d29922" } else { "#8b949e" };
                html.push_str(&format!(
                    "<tr>\
                    <td class=\"stage-name\"><code>{}</code>\
                    <div class=\"inline-bar\"><div class=\"inline-bar-fill\" style=\"width:{bar_pct:.1}%;background:{rate_color}\"></div></div></td>\
                    <td>{}</td><td>{}</td><td style=\"color:{rate_color}\">{:.1}%</td><td>{}</td><td>{}</td><td>{}</td>\
                    </tr>\n",
                    esc_html(&c.name),
                    c.hits,
                    c.misses,
                    pct,
                    c.inserts,
                    c.evictions,
                    fmt_bytes(c.bytes_used),
                ));
            }
            html.push_str("</tbody></table></div></section>\n");
        }

        // Counters
        if !self.counters.is_empty() {
            html.push_str("<section class=\"panel\">\n<h2>Counters</h2>\n<div class=\"counter-grid\">\n");
            for c in &self.counters {
                let rate = if elapsed > 0.0 {
                    format!(" ({:.1}/s)", c.value as f64 / elapsed)
                } else {
                    String::new()
                };
                html.push_str(&format!(
                    "<div class=\"counter-card\"><div class=\"counter-name\">{}</div>\
                    <div class=\"counter-value\">{}{}</div></div>\n",
                    esc_html(&c.name),
                    fmt_count(c.value),
                    rate,
                ));
            }
            html.push_str("</div></section>\n");
        }

        // Thread pool
        let t = &self.threads;
        html.push_str("<section class=\"panel\">\n<h2>Thread pool</h2>\n<div class=\"counter-grid\">\n");
        for (label, val) in [
            ("Pool threads", t.pool_threads.to_string()),
            ("Threads started", t.threads_started.to_string()),
            ("Tasks submitted", t.tasks_submitted.to_string()),
            ("Tasks completed", t.tasks_completed.to_string()),
            ("Peak in-flight", t.peak_in_flight.to_string()),
            ("Avg utilization", format!("{:.1}%", t.avg_utilization_pct)),
        ] {
            html.push_str(&format!(
                "<div class=\"counter-card\"><div class=\"counter-name\">{label}</div>\
                <div class=\"counter-value\">{val}</div></div>\n"
            ));
        }
        html.push_str("</div></section>\n");

        html.push_str("</main>\n</body>\n</html>\n");
        html
    }
}

const HTML_HEAD: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>web-scan profiler report</title>
<style>
:root {
  --bg: #0f1117; --surface: #161b22; --border: #30363d;
  --text: #e6edf3; --muted: #8b949e; --font: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: var(--font); font-size: 14px; color: var(--text); background: var(--bg); }
.page-header { padding: 24px 32px; border-bottom: 1px solid var(--border); background: linear-gradient(180deg, #161b22 0%, #0f1117 100%); }
.page-header h1 { margin: 0 0 8px; font-size: 1.4rem; font-weight: 700; }
.meta-grid { display: flex; flex-wrap: wrap; gap: 16px 28px; color: var(--muted); font-size: 13px; }
.meta-grid strong { color: var(--text); }
main { max-width: 1100px; margin: 0 auto; padding: 24px 32px 64px; }
.summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 28px; }
.summary-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
.summary-card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
.summary-card .value { font-size: 1.4rem; font-weight: 700; margin-top: 4px; }
.summary-card .sub-label { font-size: 11px; color: var(--muted); margin-top: 2px; }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px 24px; margin-bottom: 20px; }
.panel h2 { margin: 0 0 14px; font-size: 1rem; font-weight: 600; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #1c2128; color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
td { padding: 7px 10px; border-bottom: 1px solid #1c2128; vertical-align: top; }
tr:hover td { background: #1a1f2e; }
code { background: #1c2128; padding: 0.1em 0.35em; border-radius: 3px; font-size: 0.85em; color: #a3d4ff; font-family: var(--mono); }
.stage-name { min-width: 240px; }
.stage-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
.inline-bar { height: 3px; background: #1c2128; border-radius: 2px; margin-top: 4px; }
.inline-bar-fill { height: 3px; border-radius: 2px; }
.counter-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; }
.counter-card { background: #1c2128; border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; }
.counter-name { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
.counter-value { font-size: 1.2rem; font-weight: 700; margin-top: 2px; font-family: var(--mono); }
.layer-bars { display: flex; flex-direction: column; gap: 10px; }
.layer-row { display: grid; grid-template-columns: 160px 1fr 80px; align-items: center; gap: 12px; }
.layer-label { font-size: 12px; color: var(--muted); white-space: nowrap; }
.layer-bar-wrap { height: 10px; background: #1c2128; border-radius: 5px; overflow: hidden; }
.layer-bar-fill { height: 100%; border-radius: 5px; }
.layer-value { font-family: var(--mono); font-size: 12px; text-align: right; }
</style>
</head>
<body>
"#;

// ── Formatting helpers ────────────────────────────────────────────────────────

fn esc_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn fmt_ms(ms: f64) -> String {
    if ms >= 1000.0 { format!("{:.2}s", ms / 1000.0) }
    else if ms >= 1.0 { format!("{:.2}ms", ms) }
    else { format!("{:.0}µs", ms * 1000.0) }
}

fn stage_color_html(name: &str) -> &'static str {
    let prefix = name.split('.').next().unwrap_or(name);
    match prefix {
        "query" => "#3fb950",
        "cpg" => "#58a6ff",
        "workspace" => "#a371f7",
        "stage" => "#d29922",
        _ => "#8b949e",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn fmt_bytes(b: u64) -> String {
    if b < 1_024 {
        format!("{b}B")
    } else if b < 1_024 * 1_024 {
        format!("{:.1}KB", b as f64 / 1_024.0)
    } else if b < 1_024 * 1_024 * 1_024 {
        format!("{:.1}MB", b as f64 / (1_024.0 * 1_024.0))
    } else {
        format!("{:.2}GB", b as f64 / (1_024.0 * 1_024.0 * 1_024.0))
    }
}

fn fmt_count(n: u64) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 1_000_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    }
}
