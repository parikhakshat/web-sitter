use serde::Serialize;
use crate::histogram::Histogram;

// ── Stage summary ─────────────────────────────────────────────────────────────

/// Aggregated timing statistics for a single named pipeline stage.
pub struct StageSummary {
    pub name: String,
    pub hist: Histogram,
}

impl StageSummary {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), hist: Histogram::default() }
    }

    pub fn record_nanos(&mut self, nanos: u64) {
        self.hist.record(nanos);
    }
}

// ── Cache metrics ─────────────────────────────────────────────────────────────

/// Hit/miss/eviction statistics for a single named cache.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evictions: u64,
    /// Approximate bytes currently held by the cache (caller-supplied).
    pub bytes_used: u64,
}

impl CacheMetrics {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64 * 100.0
        }
    }
}

// ── Thread pool metrics ───────────────────────────────────────────────────────

/// Snapshot of thread pool utilization.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ThreadMetrics {
    /// Number of threads in the profiled pool.
    pub pool_threads: usize,
    /// Number of threads that have started (from `start_handler`).
    pub threads_started: u64,
    /// Peak number of tasks simultaneously in-flight.
    pub peak_in_flight: u64,
    /// Total tasks submitted.
    pub tasks_submitted: u64,
    /// Total tasks completed.
    pub tasks_completed: u64,
    /// Average utilization (0–100 %).
    pub avg_utilization_pct: f64,
}

// ── Counter snapshot ──────────────────────────────────────────────────────────

/// A point-in-time value for a named counter.
#[derive(Debug, Clone, Serialize)]
pub struct CounterSnapshot {
    pub name: String,
    pub value: u64,
}
