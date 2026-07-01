//! **web-profiler** — in-depth pipeline profiling for web-sitter & web-ql.
//!
//! Provides:
//! - **Stage timing** with histogram-based percentiles (P50/P95/P99)
//! - **Cache hit/miss tracking** with byte-usage accounting
//! - **Thread pool utilization** via rayon hooks + task guards
//! - **Throughput counters** (files, nodes, findings, etc.)
//! - **Human-readable and JSON reports**
//!
//! # Quick start
//!
//! ```rust
//! use web_profiler as prof;
//!
//! // One-time global init
//! prof::init();
//!
//! // Time a stage
//! let _span = prof::span("cpg.parse");
//!
//! // Track cache activity
//! prof::cache_hit("cfg_cache");
//!
//! // Increment a counter
//! prof::count("files_scanned", 1);
//!
//! // Print the report
//! println!("{}", prof::report());
//! ```

pub mod histogram;
pub mod metrics;
pub mod profiler;
pub mod report;
pub mod thread_pool;

pub use profiler::{CacheTracker, Profiler, StageSpan, OwnedStageSpan, TaskGuard, CacheSnapshot, StageSnapshot, ParallelStageSnapshot};
pub use report::ProfileReport;
pub use thread_pool::ProfiledPool;
pub use metrics::{CacheMetrics, CounterSnapshot, StageSummary, ThreadMetrics};

use std::sync::OnceLock;

static GLOBAL: OnceLock<Profiler> = OnceLock::new();

/// Initialize the global profiler. Idempotent — subsequent calls return the same instance.
pub fn init() -> &'static Profiler {
    GLOBAL.get_or_init(Profiler::new)
}

/// Initialize the global profiler and immediately return it.
/// Panics if already initialized with a different instance (OnceLock semantics).
pub fn init_and_get() -> &'static Profiler {
    init()
}

/// Access the global profiler, or `None` if [`init`] has not been called.
pub fn global() -> Option<&'static Profiler> {
    GLOBAL.get()
}

// ── Convenience free functions (delegate to global profiler if set) ───────────

/// Begin timing a stage. The returned guard records elapsed time when dropped.
/// No-op if the global profiler has not been initialized.
pub fn span(name: &'static str) -> Option<StageSpan> {
    GLOBAL.get().map(|p| p.span(name))
}

/// Like [`span`] but accepts a dynamic stage name (e.g. for per-rule timing).
pub fn span_dyn(name: impl Into<String>) -> Option<OwnedStageSpan> {
    GLOBAL.get().map(|p| p.span_owned(name))
}

/// Record that a parallel stage ran with `n_workers` threads.
/// See [`Profiler::record_parallel_work`] for semantics.
pub fn record_parallel_work(label: &str, wall_stage: &str, cpu_stage: &str, n_workers: usize) {
    if let Some(p) = GLOBAL.get() {
        p.record_parallel_work(label, wall_stage, cpu_stage, n_workers);
    }
}

/// Record a cache hit on the named cache.
pub fn cache_hit(name: &str) {
    if let Some(p) = GLOBAL.get() {
        p.cache(name).hit();
    }
}

/// Record a cache miss on the named cache.
pub fn cache_miss(name: &str) {
    if let Some(p) = GLOBAL.get() {
        p.cache(name).miss();
    }
}

/// Record a cache insert of `bytes` bytes on the named cache.
pub fn cache_insert(name: &str, bytes: u64) {
    if let Some(p) = GLOBAL.get() {
        p.cache(name).insert(bytes);
    }
}

/// Increment the named counter by `n`.
pub fn count(name: &str, n: u64) {
    if let Some(p) = GLOBAL.get() {
        p.count(name, n);
    }
}

/// Start tracking a task in the global pool. Drop the returned guard when done.
pub fn task() -> Option<TaskGuard> {
    GLOBAL.get().map(|p| p.task_guard())
}

/// Generate a full profiler report from the global profiler.
/// Returns an empty report if the profiler was not initialized.
pub fn report() -> ProfileReport {
    match GLOBAL.get() {
        Some(p) => ProfileReport {
            elapsed_secs: p.elapsed_secs(),
            stages: p.stage_snapshots(),
            caches: p.cache_snapshots(),
            counters: p.counter_snapshots(),
            threads: p.thread_metrics(),
            parallel_stages: p.parallel_stage_snapshots(),
        },
        None => ProfileReport {
            elapsed_secs: 0.0,
            stages: vec![],
            caches: vec![],
            counters: vec![],
            threads: ThreadMetrics::default(),
            parallel_stages: vec![],
        },
    }
}
