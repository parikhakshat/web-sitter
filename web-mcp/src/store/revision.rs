//! Monotonic revision counters (Salsa-inspired): a global counter plus one counter per
//! shard, bumped whenever an edit is applied. Every tool response is meant to be stamped
//! with the revision(s) it was computed against, so a caller across a multi-turn edit
//! session can detect "the answer you're holding is stale" without a full re-query.
//!
//! Scope for this task: the counters themselves, standalone and tested. Stamping actual
//! tool responses with them happens once the live-update path (file watcher, task #14)
//! exists to have something to bump them *for* — right now there is nothing yet that
//! calls `record_edit`.

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use super::shard::ShardId;

/// Tracks a global revision plus one revision per shard. Reads use `Acquire`/writes use
/// `Release` ordering so a reader that observes a bumped revision is guaranteed to also
/// observe every write that happened-before that bump (paired with `ShardedLocks`' RwLock
/// acquire/release, which already provides this ordering for the *data* itself — the
/// counters need their own ordering since they're read independently of any lock).
pub struct Revisions {
    global: AtomicU64,
    per_shard: DashMap<ShardId, AtomicU64>,
}

impl Default for Revisions {
    fn default() -> Self {
        Self::new()
    }
}

impl Revisions {
    pub fn new() -> Self {
        Self {
            global: AtomicU64::new(0),
            per_shard: DashMap::new(),
        }
    }

    /// Current global revision.
    pub fn global(&self) -> u64 {
        self.global.load(Ordering::Acquire)
    }

    /// Current revision of `shard`, or 0 if it has never had an edit recorded.
    pub fn shard(&self, shard: &ShardId) -> u64 {
        self.per_shard
            .get(shard)
            .map(|counter| counter.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// Record that an edit was applied to `shard`: bumps both the shard's revision and
    /// the global revision, and returns the new `(global, shard)` pair. Call this once
    /// per applied edit, after the edit itself is durably visible (e.g. after the
    /// corresponding `ShardedLocks` write guard would be dropped) — bumping the counter
    /// before the data is visible would let a reader observe a revision number for data
    /// it can't actually see yet.
    pub fn record_edit(&self, shard: &ShardId) -> (u64, u64) {
        let new_global = self.global.fetch_add(1, Ordering::AcqRel) + 1;
        let new_shard = self
            .per_shard
            .entry(shard.clone())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::AcqRel)
            + 1;
        (new_global, new_shard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_zero() {
        let revisions = Revisions::new();
        assert_eq!(revisions.global(), 0);
        assert_eq!(revisions.shard(&ShardId("src".into())), 0);
    }

    #[test]
    fn record_edit_bumps_both_global_and_shard() {
        let revisions = Revisions::new();
        let shard = ShardId("src".into());

        let (global, shard_rev) = revisions.record_edit(&shard);
        assert_eq!(global, 1);
        assert_eq!(shard_rev, 1);
        assert_eq!(revisions.global(), 1);
        assert_eq!(revisions.shard(&shard), 1);
    }

    #[test]
    fn unrelated_shards_have_independent_revisions() {
        let revisions = Revisions::new();
        let a = ShardId("a".into());
        let b = ShardId("b".into());

        revisions.record_edit(&a);
        revisions.record_edit(&a);
        revisions.record_edit(&b);

        assert_eq!(revisions.shard(&a), 2);
        assert_eq!(revisions.shard(&b), 1);
        assert_eq!(
            revisions.global(),
            3,
            "global must count every edit regardless of shard"
        );
    }

    #[test]
    fn concurrent_edits_to_different_shards_all_land() {
        use std::sync::Arc;
        use std::thread;

        let revisions = Arc::new(Revisions::new());
        let shards: Vec<ShardId> = (0..8).map(|i| ShardId(format!("shard-{i}"))).collect();

        let handles: Vec<_> = shards
            .iter()
            .map(|shard| {
                let shard = shard.clone();
                let revisions = Arc::clone(&revisions);
                thread::spawn(move || {
                    for _ in 0..100 {
                        revisions.record_edit(&shard);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            revisions.global(),
            800,
            "no lost updates across concurrent shards"
        );
        for shard in &shards {
            assert_eq!(revisions.shard(shard), 100);
        }
    }
}
