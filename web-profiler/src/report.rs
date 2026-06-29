use std::fmt::Write as FmtWrite;
use serde::Serialize;
use crate::histogram::Histogram;
use crate::metrics::{CounterSnapshot, ThreadMetrics};
use crate::profiler::{CacheSnapshot, StageSnapshot};

/// A point-in-time snapshot of all profiler data.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileReport {
    pub elapsed_secs: f64,
    pub stages: Vec<StageSnapshot>,
    pub caches: Vec<CacheSnapshot>,
    pub counters: Vec<CounterSnapshot>,
    pub threads: ThreadMetrics,
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

// ── Formatting helpers ────────────────────────────────────────────────────────

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
