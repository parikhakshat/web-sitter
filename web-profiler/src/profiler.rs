use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use crate::metrics::{CacheMetrics, StageSummary, ThreadMetrics, CounterSnapshot};

// ── Inner shared state ────────────────────────────────────────────────────────

pub(crate) struct Inner {
    pub stages: Mutex<HashMap<String, StageSummary>>,
    pub caches: Mutex<HashMap<String, CacheMetrics>>,
    pub counters: Mutex<HashMap<String, u64>>,
    pub parallel_stages: Mutex<HashMap<String, ParallelWorkEntry>>,

    // Thread-pool tracking (lock-free hot path)
    pub threads_started: AtomicU64,
    pub tasks_submitted: AtomicU64,
    pub tasks_completed: AtomicU64,
    pub tasks_in_flight: AtomicI64,
    pub peak_in_flight: AtomicU64,

    // Throughput sampling
    pub utilization_samples: Mutex<Vec<f64>>,

    pub pool_threads: AtomicU64,
    pub wall_start: Instant,
}

impl Inner {
    fn new() -> Self {
        Self {
            stages: Mutex::new(HashMap::new()),
            caches: Mutex::new(HashMap::new()),
            counters: Mutex::new(HashMap::new()),
            parallel_stages: Mutex::new(HashMap::new()),
            threads_started: AtomicU64::new(0),
            tasks_submitted: AtomicU64::new(0),
            tasks_completed: AtomicU64::new(0),
            tasks_in_flight: AtomicI64::new(0),
            peak_in_flight: AtomicU64::new(0),
            utilization_samples: Mutex::new(Vec::new()),
            pool_threads: AtomicU64::new(rayon::current_num_threads() as u64),
            wall_start: Instant::now(),
        }
    }
}

pub(crate) struct ParallelWorkEntry {
    pub n_workers: usize,
    pub wall_stage_name: String,
    pub cpu_stage_name: String,
}

// ── Profiler ──────────────────────────────────────────────────────────────────

/// The main profiler handle. Cheaply cloneable — backed by `Arc`.
#[derive(Clone)]
pub struct Profiler {
    pub(crate) inner: Arc<Inner>,
}

impl Profiler {
    pub fn new() -> Self {
        Self { inner: Arc::new(Inner::new()) }
    }

    // ── Stage spans ───────────────────────────────────────────────────────────

    /// Begin timing a named pipeline stage. Returns a guard that records the
    /// elapsed time when dropped.
    pub fn span(&self, name: &'static str) -> StageSpan {
        StageSpan {
            inner: Arc::clone(&self.inner),
            name,
            start: Instant::now(),
        }
    }

    /// Like [`span`] but accepts a dynamic (runtime) stage name. Useful for
    /// per-rule or per-file timing where the name is not known at compile time.
    pub fn span_owned(&self, name: impl Into<String>) -> OwnedStageSpan {
        OwnedStageSpan {
            inner: Arc::clone(&self.inner),
            name: name.into(),
            start: Instant::now(),
        }
    }

    // ── Cache tracking ────────────────────────────────────────────────────────

    /// Get a tracker handle for the named cache.
    pub fn cache(&self, name: impl Into<String>) -> CacheTracker {
        CacheTracker {
            inner: Arc::clone(&self.inner),
            name: name.into(),
        }
    }

    // ── Task / thread lifecycle ───────────────────────────────────────────────

    /// Call when a thread in a profiled pool starts.
    pub fn thread_started(&self, pool_threads: usize) {
        self.inner.threads_started.fetch_add(1, Ordering::Relaxed);
        self.inner.pool_threads.store(pool_threads as u64, Ordering::Relaxed);
    }

    /// Call when a thread in a profiled pool exits.
    pub fn thread_exited(&self) {}

    /// Return a guard that tracks one in-flight task. Drop it when the task ends.
    pub fn task_guard(&self) -> TaskGuard {
        self.inner.tasks_submitted.fetch_add(1, Ordering::Relaxed);
        let prev = self.inner.tasks_in_flight.fetch_add(1, Ordering::AcqRel);
        let cur = (prev + 1) as u64;
        // Update peak atomically (compare-and-swap loop)
        let mut peak = self.inner.peak_in_flight.load(Ordering::Relaxed);
        while cur > peak {
            match self.inner.peak_in_flight.compare_exchange_weak(
                peak,
                cur,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
        // Sample utilization
        let pool = self.inner.pool_threads.load(Ordering::Relaxed).max(1);
        let util = (cur as f64 / pool as f64 * 100.0).min(100.0);
        if let Ok(mut v) = self.inner.utilization_samples.lock() {
            v.push(util);
        }
        TaskGuard { inner: Arc::clone(&self.inner) }
    }

    // ── Parallel stage tracking ───────────────────────────────────────────────

    /// Record that a parallel stage ran with `n_workers` threads.
    /// `wall_stage` is the name of an existing stage span that measures wall time
    /// (e.g. one span wrapping the whole `par_iter().collect()`).
    /// `cpu_stage` is the name of the per-item stage span whose total gives CPU time
    /// (e.g. the per-file span run in parallel). Both are looked up in the stage map.
    pub fn record_parallel_work(&self, label: &str, wall_stage: &str, cpu_stage: &str, n_workers: usize) {
        if let Ok(mut m) = self.inner.parallel_stages.lock() {
            m.insert(label.to_owned(), ParallelWorkEntry {
                n_workers,
                wall_stage_name: wall_stage.to_owned(),
                cpu_stage_name: cpu_stage.to_owned(),
            });
        }
    }

    pub fn parallel_stage_snapshots(&self) -> Vec<ParallelStageSnapshot> {
        let parallel = self.inner.parallel_stages.lock().unwrap();
        let stages = self.inner.stages.lock().unwrap();
        let mut v: Vec<ParallelStageSnapshot> = parallel.iter().map(|(label, entry)| {
            let stage_total_nanos = |name: &str| -> u64 {
                stages.get(name).map(|s| {
                    if s.hist.count == 0 { 0 } else { s.hist.mean_nanos().saturating_mul(s.hist.count) }
                }).unwrap_or(0)
            };
            let wall_nanos = stage_total_nanos(&entry.wall_stage_name);
            let cpu_nanos = stage_total_nanos(&entry.cpu_stage_name);
            let wall_ms = wall_nanos as f64 / 1_000_000.0;
            let cpu_ms = cpu_nanos as f64 / 1_000_000.0;
            let max_cpu_ms = wall_ms * entry.n_workers as f64;
            let efficiency_pct = if max_cpu_ms > 0.0 { (cpu_ms / max_cpu_ms * 100.0).min(100.0) } else { 0.0 };
            ParallelStageSnapshot {
                label: label.clone(),
                n_workers: entry.n_workers,
                wall_ms,
                cpu_ms,
                efficiency_pct,
            }
        }).collect();
        v.sort_by(|a, b| a.label.cmp(&b.label));
        v
    }

    // ── Counters ──────────────────────────────────────────────────────────────

    /// Increment a named counter by `n`.
    pub fn count(&self, name: &str, n: u64) {
        if let Ok(mut m) = self.inner.counters.lock() {
            *m.entry(name.to_owned()).or_insert(0) += n;
        }
    }

    // ── Snapshot ──────────────────────────────────────────────────────────────

    pub fn elapsed_secs(&self) -> f64 {
        self.inner.wall_start.elapsed().as_secs_f64()
    }

    pub fn stage_snapshots(&self) -> Vec<StageSnapshot> {
        let stages = self.inner.stages.lock().unwrap();
        let mut v: Vec<StageSnapshot> = stages
            .values()
            .map(|s| StageSnapshot {
                name: s.name.clone(),
                count: s.hist.count,
                total_nanos: if s.hist.count == 0 { 0 } else {
                    s.hist.mean_nanos() * s.hist.count
                },
                mean_nanos: s.hist.mean_nanos(),
                p50_nanos: s.hist.percentile(50.0),
                p95_nanos: s.hist.percentile(95.0),
                p99_nanos: s.hist.percentile(99.0),
                max_nanos: s.hist.max,
                min_nanos: s.hist.min,
                stddev_nanos: s.hist.stddev_nanos(),
            })
            .collect();
        v.sort_by(|a, b| b.total_nanos.cmp(&a.total_nanos));
        v
    }

    pub fn cache_snapshots(&self) -> Vec<CacheSnapshot> {
        let caches = self.inner.caches.lock().unwrap();
        let mut v: Vec<CacheSnapshot> = caches
            .iter()
            .map(|(name, m)| CacheSnapshot {
                name: name.clone(),
                hits: m.hits,
                misses: m.misses,
                inserts: m.inserts,
                evictions: m.evictions,
                bytes_used: m.bytes_used,
                hit_rate_pct: m.hit_rate(),
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn counter_snapshots(&self) -> Vec<CounterSnapshot> {
        let counters = self.inner.counters.lock().unwrap();
        let mut v: Vec<CounterSnapshot> = counters
            .iter()
            .map(|(k, &v)| CounterSnapshot { name: k.clone(), value: v })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn thread_metrics(&self) -> ThreadMetrics {
        let submitted = self.inner.tasks_submitted.load(Ordering::Relaxed);
        let completed = self.inner.tasks_completed.load(Ordering::Relaxed);
        let pool = self.inner.pool_threads.load(Ordering::Relaxed) as usize;
        let avg_util = {
            let samples = self.inner.utilization_samples.lock().unwrap();
            if samples.is_empty() {
                0.0
            } else {
                samples.iter().sum::<f64>() / samples.len() as f64
            }
        };
        ThreadMetrics {
            pool_threads: pool.max(rayon::current_num_threads()),
            threads_started: self.inner.threads_started.load(Ordering::Relaxed),
            peak_in_flight: self.inner.peak_in_flight.load(Ordering::Relaxed),
            tasks_submitted: submitted,
            tasks_completed: completed,
            avg_utilization_pct: avg_util,
        }
    }
}

impl Default for Profiler {
    fn default() -> Self {
        Self::new()
    }
}

// ── StageSpan ─────────────────────────────────────────────────────────────────

/// RAII guard: records elapsed time for a stage when dropped.
pub struct StageSpan {
    pub(crate) inner: Arc<Inner>,
    pub(crate) name: &'static str,
    pub(crate) start: Instant,
}

impl Drop for StageSpan {
    fn drop(&mut self) {
        let nanos = self.start.elapsed().as_nanos() as u64;
        if let Ok(mut stages) = self.inner.stages.lock() {
            stages
                .entry(self.name.to_owned())
                .or_insert_with(|| StageSummary::new(self.name))
                .record_nanos(nanos);
        }
    }
}

// ── OwnedStageSpan ────────────────────────────────────────────────────────────

/// Like `StageSpan` but for dynamically-named stages (e.g. per-rule timing).
pub struct OwnedStageSpan {
    pub(crate) inner: Arc<Inner>,
    pub(crate) name: String,
    pub(crate) start: Instant,
}

impl Drop for OwnedStageSpan {
    fn drop(&mut self) {
        let nanos = self.start.elapsed().as_nanos() as u64;
        if let Ok(mut stages) = self.inner.stages.lock() {
            let name = std::mem::take(&mut self.name);
            stages
                .entry(name.clone())
                .or_insert_with(|| StageSummary::new(name))
                .record_nanos(nanos);
        }
    }
}

// ── CacheTracker ──────────────────────────────────────────────────────────────

/// Handle for recording cache activity for a specific named cache.
pub struct CacheTracker {
    inner: Arc<Inner>,
    name: String,
}

impl CacheTracker {
    pub fn hit(&self) {
        self.with(|m| m.hits += 1);
    }
    pub fn miss(&self) {
        self.with(|m| m.misses += 1);
    }
    pub fn insert(&self, bytes: u64) {
        self.with(|m| {
            m.inserts += 1;
            m.bytes_used += bytes;
        });
    }
    pub fn evict(&self, bytes: u64) {
        self.with(|m| {
            m.evictions += 1;
            m.bytes_used = m.bytes_used.saturating_sub(bytes);
        });
    }
    fn with(&self, f: impl FnOnce(&mut CacheMetrics)) {
        if let Ok(mut caches) = self.inner.caches.lock() {
            f(caches.entry(self.name.clone()).or_default());
        }
    }
}

// ── TaskGuard ─────────────────────────────────────────────────────────────────

/// RAII guard: decrements the in-flight task counter when dropped.
pub struct TaskGuard {
    inner: Arc<Inner>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.inner.tasks_completed.fetch_add(1, Ordering::Relaxed);
        self.inner.tasks_in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

// ── Snapshot types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct StageSnapshot {
    pub name: String,
    pub count: u64,
    pub total_nanos: u64,
    pub mean_nanos: u64,
    pub p50_nanos: u64,
    pub p95_nanos: u64,
    pub p99_nanos: u64,
    pub max_nanos: u64,
    pub min_nanos: u64,
    pub stddev_nanos: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheSnapshot {
    pub name: String,
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evictions: u64,
    pub bytes_used: u64,
    pub hit_rate_pct: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ParallelStageSnapshot {
    pub label: String,
    pub n_workers: usize,
    pub wall_ms: f64,
    pub cpu_ms: f64,
    pub efficiency_pct: f64,
}
