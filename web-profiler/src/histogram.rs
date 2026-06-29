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

#[cfg(test)]
mod tests {
    use super::*;

    fn hist_from(values: &[u64]) -> Histogram {
        let mut h = Histogram::default();
        for &v in values {
            h.record(v);
        }
        h
    }

    #[test]
    fn empty_defaults() {
        let h = Histogram::default();
        assert_eq!(h.count, 0);
        assert_eq!(h.mean_nanos(), 0);
        assert_eq!(h.percentile(50.0), 0);
        assert_eq!(h.stddev_nanos(), 0);
    }

    #[test]
    fn single_record() {
        let h = hist_from(&[500]);
        assert_eq!(h.count, 1);
        assert_eq!(h.min, 500);
        assert_eq!(h.max, 500);
        assert_eq!(h.mean_nanos(), 500);
        assert_eq!(h.percentile(0.0), 500);
        assert_eq!(h.percentile(50.0), 500);
        assert_eq!(h.percentile(100.0), 500);
        assert_eq!(h.stddev_nanos(), 0); // single sample
    }

    #[test]
    fn two_records_mean_and_min_max() {
        let h = hist_from(&[100, 300]);
        assert_eq!(h.count, 2);
        assert_eq!(h.min, 100);
        assert_eq!(h.max, 300);
        assert_eq!(h.mean_nanos(), 200);
    }

    #[test]
    fn percentile_sorted_order() {
        // Values 1..=10: median = 5 or 6 depending on rounding
        let h = hist_from(&[10, 1, 5, 3, 8, 2, 7, 4, 9, 6]);
        assert_eq!(h.count, 10);
        assert_eq!(h.percentile(0.0), 1);
        assert_eq!(h.percentile(100.0), 10);
        // p50 at index round((9) * 0.5) = round(4.5) = 5 → sorted[5] = 6
        let p50 = h.percentile(50.0);
        assert!((5..=6).contains(&p50), "p50={p50}");
    }

    #[test]
    fn percentile_p95_and_p99() {
        // 100 ascending values 1..=100
        let vals: Vec<u64> = (1..=100).collect();
        let h = hist_from(&vals);
        let p95 = h.percentile(95.0);
        let p99 = h.percentile(99.0);
        assert!(p95 >= 95 && p95 <= 96, "p95={p95}");
        assert!(p99 >= 99 && p99 <= 100, "p99={p99}");
    }

    #[test]
    fn stddev_uniform_values() {
        // All same value → stddev = 0
        let h = hist_from(&[42, 42, 42, 42]);
        assert_eq!(h.stddev_nanos(), 0);
    }

    #[test]
    fn stddev_known_values() {
        // Values: 2, 4, 4, 4, 5, 5, 7, 9 → mean=5, variance=4, stddev=2
        let h = hist_from(&[2, 4, 4, 4, 5, 5, 7, 9]);
        assert_eq!(h.mean_nanos(), 5);
        assert_eq!(h.stddev_nanos(), 2);
    }

    #[test]
    fn reservoir_cap_count_continues() {
        let mut h = Histogram::default();
        // Insert 2100 samples (more than CAP=2000)
        for i in 0u64..2100 {
            h.record(i);
        }
        // count tracks all inserts
        assert_eq!(h.count, 2100);
        // min/max are exact
        assert_eq!(h.min, 0);
        assert_eq!(h.max, 2099);
        // mean is exact (sum over all 2100)
        let expected_mean = (0u64..2100).sum::<u64>() / 2100;
        assert_eq!(h.mean_nanos(), expected_mean);
    }

    #[test]
    fn fmt_nanos_boundaries() {
        assert_eq!(Histogram::fmt_nanos(0), "0ns");
        assert_eq!(Histogram::fmt_nanos(999), "999ns");
        assert_eq!(Histogram::fmt_nanos(1_000), "1.0µs");
        assert_eq!(Histogram::fmt_nanos(1_500), "1.5µs");
        assert_eq!(Histogram::fmt_nanos(999_999), "1000.0µs");
        assert_eq!(Histogram::fmt_nanos(1_000_000), "1.00ms");
        assert_eq!(Histogram::fmt_nanos(2_500_000), "2.50ms");
        assert_eq!(Histogram::fmt_nanos(999_999_999), "1000.00ms");
        assert_eq!(Histogram::fmt_nanos(1_000_000_000), "1.000s");
        assert_eq!(Histogram::fmt_nanos(2_500_000_000), "2.500s");
    }

    #[test]
    fn monotonically_increasing_min_max() {
        let mut h = Histogram::default();
        h.record(50);
        assert_eq!(h.min, 50);
        assert_eq!(h.max, 50);
        h.record(10);
        assert_eq!(h.min, 10);
        assert_eq!(h.max, 50);
        h.record(200);
        assert_eq!(h.min, 10);
        assert_eq!(h.max, 200);
    }
}
