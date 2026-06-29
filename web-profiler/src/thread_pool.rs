use crate::profiler::Profiler;

/// A rayon thread pool instrumented with profiler hooks.
/// Use `install()` to run a closure inside this pool so that `par_iter()` and
/// `join()` calls automatically use the instrumented pool.
pub struct ProfiledPool {
    pool: rayon::ThreadPool,
    name: String,
}

impl ProfiledPool {
    /// Create a new profiled thread pool.
    ///
    /// - `name`: logical name shown in reports (e.g. `"cpg-gen"`, `"scanner"`)
    /// - `num_threads`: how many OS threads to spawn (0 = use `num_cpus::get()`)
    /// - `profiler`: a cloneable profiler handle to inject into thread hooks
    pub fn build(
        name: impl Into<String>,
        num_threads: usize,
        profiler: &Profiler,
    ) -> Result<Self, rayon::ThreadPoolBuildError> {
        let name = name.into();
        let n = if num_threads == 0 { num_cpus::get() } else { num_threads };
        let name_clone = name.clone();
        let prof_start = profiler.clone();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .thread_name({
                let name_c = name.clone();
                move |i| format!("{name_c}-{i}")
            })
            .start_handler(move |_| {
                prof_start.thread_started(n);
            })
            .build()?;
        Ok(Self { pool, name: name_clone })
    }

    /// Run a closure on this pool. Any `par_iter()` / `rayon::join()` calls
    /// inside `f` will be scheduled on this pool's threads.
    pub fn install<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R + Send,
        R: Send,
    {
        self.pool.install(f)
    }

    /// Number of threads in this pool.
    pub fn num_threads(&self) -> usize {
        self.pool.current_num_threads()
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}
