/// Reservoir histogram: stores up to CAP exact samples for accurate percentiles,
/// then switches to count-only (min/max/mean still exact) above that.
pub struct Histogram {
    samples: Vec<u64>,
    pub count: u64,
    sum_nanos: u128,
    pub min: u64,
    pub max: u64,
}

const CAP: usize = 2_000;

impl Histogram {
    pub fn record(&mut self, nanos: u64) {
        if self.samples.len() < CAP {
            self.samples.push(nanos);
        }
        self.count += 1;
        self.sum_nanos += nanos as u128;
        if self.count == 1 || nanos < self.min {
            self.min = nanos;
        }
        if nanos > self.max {
            self.max = nanos;
        }
    }

    /// Mean latency in nanoseconds.
    pub fn mean_nanos(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            (self.sum_nanos / self.count as u128) as u64
        }
    }

    /// Estimate the p-th percentile (0–100). Sorted sort on demand — call only at report time.
    pub fn percentile(&self, p: f64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64 - 1.0) * (p / 100.0)).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Standard deviation in nanoseconds.
    pub fn stddev_nanos(&self) -> u64 {
        if self.samples.len() < 2 {
            return 0;
        }
        let mean = self.mean_nanos() as f64;
        let variance = self
            .samples
            .iter()
            .map(|&s| {
                let d = s as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / self.samples.len() as f64;
        variance.sqrt() as u64
    }

    /// Format nanoseconds as a human-readable duration string.
    pub fn fmt_nanos(nanos: u64) -> String {
        if nanos < 1_000 {
            format!("{nanos}ns")
        } else if nanos < 1_000_000 {
            format!("{:.1}µs", nanos as f64 / 1e3)
        } else if nanos < 1_000_000_000 {
            format!("{:.2}ms", nanos as f64 / 1e6)
        } else {
            format!("{:.3}s", nanos as f64 / 1e9)
        }
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            samples: Vec::new(),
            count: 0,
            sum_nanos: 0,
            min: u64::MAX,
            max: 0,
        }
    }
}
