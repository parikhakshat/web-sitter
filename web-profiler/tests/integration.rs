use std::sync::{Arc, Barrier};
use std::thread;
use web_profiler::{Profiler, ProfileReport};

// ── Profiler: span timing ─────────────────────────────────────────────────────

#[test]
fn span_records_stage_on_drop() {
    let p = Profiler::new();
    {
        let _s = p.span("test.stage");
        // sleep briefly so the measurement is non-zero
        std::thread::sleep(std::time::Duration::from_micros(100));
    } // span drops here
    let snaps = p.stage_snapshots();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].name, "test.stage");
    assert_eq!(snaps[0].count, 1);
    assert!(snaps[0].mean_nanos > 0, "expected non-zero timing");
}

#[test]
fn multiple_spans_same_stage_accumulate() {
    let p = Profiler::new();
    for _ in 0..5 {
        let _s = p.span("test.loop");
    }
    let snaps = p.stage_snapshots();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].count, 5);
}

#[test]
fn multiple_named_stages() {
    let p = Profiler::new();
    { let _s = p.span("stage.a"); }
    { let _s = p.span("stage.b"); }
    { let _s = p.span("stage.a"); }
    let snaps = p.stage_snapshots();
    assert_eq!(snaps.len(), 2);
    let a = snaps.iter().find(|s| s.name == "stage.a").unwrap();
    let b = snaps.iter().find(|s| s.name == "stage.b").unwrap();
    assert_eq!(a.count, 2);
    assert_eq!(b.count, 1);
}

#[test]
fn stage_snapshots_sorted_by_total_nanos_desc() {
    let p = Profiler::new();
    // stage.fast: 1 tiny span; stage.slow: 1 slightly longer span
    { let _s = p.span("stage.fast"); }
    {
        let _s = p.span("stage.slow");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let snaps = p.stage_snapshots();
    assert_eq!(snaps.len(), 2);
    // slow should appear first because total_nanos is higher
    assert!(
        snaps[0].total_nanos >= snaps[1].total_nanos,
        "snapshots not sorted descending: {:?}",
        snaps.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
}

// ── Profiler: cache tracking ──────────────────────────────────────────────────

#[test]
fn cache_hit_miss_insert_tracking() {
    let p = Profiler::new();
    let c = p.cache("my_cache");
    c.hit();
    c.hit();
    c.miss();
    c.insert(1024);

    let snaps = p.cache_snapshots();
    let snap = snaps.iter().find(|s| s.name == "my_cache").unwrap();
    assert_eq!(snap.hits, 2);
    assert_eq!(snap.misses, 1);
    assert_eq!(snap.inserts, 1);
    assert_eq!(snap.bytes_used, 1024);
    assert!((snap.hit_rate_pct - 66.666).abs() < 0.01, "hit_rate={}", snap.hit_rate_pct);
}

#[test]
fn cache_evict_reduces_bytes() {
    let p = Profiler::new();
    let c = p.cache("evict_cache");
    c.insert(2048);
    c.evict(512);

    let snaps = p.cache_snapshots();
    let snap = snaps.iter().find(|s| s.name == "evict_cache").unwrap();
    assert_eq!(snap.bytes_used, 1536);
    assert_eq!(snap.evictions, 1);
}

#[test]
fn cache_evict_does_not_underflow() {
    let p = Profiler::new();
    let c = p.cache("safe_evict");
    c.insert(100);
    c.evict(200); // evict more than inserted — saturating_sub
    let snaps = p.cache_snapshots();
    let snap = snaps.iter().find(|s| s.name == "safe_evict").unwrap();
    assert_eq!(snap.bytes_used, 0);
}

#[test]
fn cache_snapshots_sorted_by_name() {
    let p = Profiler::new();
    p.cache("zzz").hit();
    p.cache("aaa").hit();
    p.cache("mmm").hit();
    let snaps = p.cache_snapshots();
    let names: Vec<&str> = snaps.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["aaa", "mmm", "zzz"]);
}

#[test]
fn zero_accesses_hit_rate_is_zero() {
    let p = Profiler::new();
    p.cache("empty").insert(0);
    let snaps = p.cache_snapshots();
    let snap = snaps.iter().find(|s| s.name == "empty").unwrap();
    assert_eq!(snap.hit_rate_pct, 0.0);
}

// ── Profiler: counters ────────────────────────────────────────────────────────

#[test]
fn counter_accumulates() {
    let p = Profiler::new();
    p.count("files", 3);
    p.count("files", 7);
    p.count("nodes", 100);

    let snaps = p.counter_snapshots();
    let files = snaps.iter().find(|s| s.name == "files").unwrap();
    let nodes = snaps.iter().find(|s| s.name == "nodes").unwrap();
    assert_eq!(files.value, 10);
    assert_eq!(nodes.value, 100);
}

#[test]
fn counter_snapshots_sorted_by_name() {
    let p = Profiler::new();
    p.count("z_counter", 1);
    p.count("a_counter", 1);
    let snaps = p.counter_snapshots();
    assert_eq!(snaps[0].name, "a_counter");
    assert_eq!(snaps[1].name, "z_counter");
}

// ── Profiler: task guards ─────────────────────────────────────────────────────

#[test]
fn task_guard_submitted_and_completed() {
    let p = Profiler::new();
    {
        let _g1 = p.task_guard();
        let _g2 = p.task_guard();
        // 2 tasks in flight
        let m = p.thread_metrics();
        assert_eq!(m.tasks_submitted, 2);
        assert_eq!(m.tasks_completed, 0);
    }
    // both guards dropped
    let m = p.thread_metrics();
    assert_eq!(m.tasks_submitted, 2);
    assert_eq!(m.tasks_completed, 2);
}

#[test]
fn task_guard_peak_in_flight() {
    let p = Profiler::new();
    let g1 = p.task_guard();
    let g2 = p.task_guard();
    let g3 = p.task_guard();
    drop(g1);
    drop(g2);
    drop(g3);
    let m = p.thread_metrics();
    assert_eq!(m.peak_in_flight, 3);
}

// ── Profiler: thread lifecycle ────────────────────────────────────────────────

#[test]
fn thread_started_increments() {
    let p = Profiler::new();
    p.thread_started(4);
    p.thread_started(4);
    let m = p.thread_metrics();
    assert_eq!(m.threads_started, 2);
}

// ── Profiler: elapsed time ────────────────────────────────────────────────────

#[test]
fn elapsed_secs_increases() {
    let p = Profiler::new();
    let t0 = p.elapsed_secs();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let t1 = p.elapsed_secs();
    assert!(t1 > t0, "elapsed_secs should increase");
}

// ── Profiler: Clone / Arc sharing ────────────────────────────────────────────

#[test]
fn clone_shares_state() {
    let p1 = Profiler::new();
    let p2 = p1.clone();
    { let _s = p1.span("shared.stage"); }
    { let _s = p2.span("shared.stage"); }
    let snaps = p1.stage_snapshots();
    assert_eq!(snaps[0].count, 2);
}

#[test]
fn concurrent_spans_threadsafe() {
    let p = Arc::new(Profiler::new());
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let p = Arc::clone(&p);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            for _ in 0..25 {
                let _s = p.span("concurrent");
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    let snaps = p.stage_snapshots();
    assert_eq!(snaps[0].count, 100); // 4 threads × 25
}

// ── ProfileReport ─────────────────────────────────────────────────────────────

#[test]
fn report_human_readable_contains_sections() {
    let p = Profiler::new();
    { let _s = p.span("report.stage"); }
    p.cache("report.cache").hit();
    p.count("report.counter", 42);
    let report = web_profiler::report::ProfileReport {
        elapsed_secs: 1.5,
        stages: p.stage_snapshots(),
        caches: p.cache_snapshots(),
        counters: p.counter_snapshots(),
        threads: p.thread_metrics(),
        parallel_stages: p.parallel_stage_snapshots(),
    };
    let text = report.human_readable();
    assert!(text.contains("Stage Timings"), "missing stage timings section");
    assert!(text.contains("Cache Efficiency"), "missing cache section");
    assert!(text.contains("Throughput"), "missing throughput section");
    assert!(text.contains("Thread Pool"), "missing thread pool section");
    assert!(text.contains("report.stage"), "stage name missing");
    assert!(text.contains("report.cache"), "cache name missing");
    assert!(text.contains("report.counter"), "counter name missing");
}

#[test]
fn report_json_roundtrip() {
    let p = Profiler::new();
    { let _s = p.span("json.stage"); }
    p.count("json.counter", 7);
    let report = web_profiler::report::ProfileReport {
        elapsed_secs: 0.5,
        stages: p.stage_snapshots(),
        caches: p.cache_snapshots(),
        counters: p.counter_snapshots(),
        threads: p.thread_metrics(),
        parallel_stages: p.parallel_stage_snapshots(),
    };
    let json = report.to_json();
    assert!(json.contains("\"elapsed_secs\""));
    assert!(json.contains("json.stage"));
    assert!(json.contains("json.counter"));

    // pretty JSON also works
    let pretty = report.to_json_pretty();
    assert!(pretty.contains('\n'));
}

#[test]
fn report_display_impl() {
    let p = Profiler::new();
    let report = web_profiler::report::ProfileReport {
        elapsed_secs: 0.0,
        stages: vec![],
        caches: vec![],
        counters: vec![],
        threads: p.thread_metrics(),
        parallel_stages: vec![],
    };
    let s = format!("{}", report);
    assert!(s.contains("web-profiler Report"));
}

// ── ProfiledPool ─────────────────────────────────────────────────────────────

#[test]
fn profiled_pool_runs_closure() {
    let p = Profiler::new();
    let pool = web_profiler::ProfiledPool::build("test-pool", 2, &p)
        .expect("pool build failed");
    assert_eq!(pool.num_threads(), 2);
    assert_eq!(pool.name(), "test-pool");

    let result = pool.install(|| 42u32 + 1);
    assert_eq!(result, 43);
}

#[test]
fn profiled_pool_zero_threads_uses_cpu_count() {
    let p = Profiler::new();
    let pool = web_profiler::ProfiledPool::build("auto-pool", 0, &p)
        .expect("pool build failed");
    assert!(pool.num_threads() >= 1);
}

#[test]
fn profiled_pool_parallel_work() {
    use rayon::prelude::*;
    let p = Profiler::new();
    let pool = web_profiler::ProfiledPool::build("par-pool", 2, &p)
        .expect("pool build failed");

    let sum: u64 = pool.install(|| {
        (0u64..1000).into_par_iter().sum()
    });
    assert_eq!(sum, 999 * 1000 / 2);
}

// ── Global profiler API ───────────────────────────────────────────────────────

#[test]
fn global_init_returns_same_instance() {
    // Note: other tests may have already called init(), so we just verify
    // idempotency — calling init() twice returns consistent state.
    let p1 = web_profiler::init();
    let p2 = web_profiler::init();
    // Both refer to the same global — count in one, see it in the other
    p1.count("global.init.test", 5);
    let val = p2
        .counter_snapshots()
        .iter()
        .find(|c| c.name == "global.init.test")
        .map(|c| c.value)
        .unwrap_or(0);
    assert!(val >= 5);
}

#[test]
fn global_convenience_fns_no_panic_before_init() {
    // These should be no-ops if the global isn't initialized yet.
    // After init() is called (by the test above or the #[test] order),
    // they should record to the global.
    web_profiler::init();
    web_profiler::cache_hit("global.test.cache");
    web_profiler::cache_miss("global.test.cache");
    web_profiler::cache_insert("global.test.cache", 256);
    web_profiler::count("global.test.count", 1);
    let _guard = web_profiler::task();
    drop(_guard);
    let _ = web_profiler::span("global.test.span");
}
