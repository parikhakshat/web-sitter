//! Per-shard locking (`DashMap<ShardId, RwLock<()>>`), replacing the single global
//! `RwLock<Workspace>` the codebase would otherwise default to. Concurrent tool calls
//! touching unrelated shards must not block each other, and a live-update watcher (task
//! #14) must only take a write lock on the shard(s) containing the changed file — a
//! global lock fails both of these at monorepo scale.
//!
//! Scope for this task: the locking primitive itself, standalone and tested for the
//! properties that actually matter (unrelated shards don't block, same-shard writes
//! serialize, readers can run concurrently). What guards *which data* is a later task's
//! concern once `ShardedLocks` is wired into `WorkspaceStore`/the live server.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use super::shard::ShardId;

/// A `DashMap`-backed collection of per-shard `RwLock`s. Locks are created lazily on
/// first access and never removed — for the shard counts a real monorepo has (thousands,
/// not millions), an empty `RwLock<()>` per shard is a few dozen bytes and not worth the
/// complexity of eviction.
#[derive(Default)]
pub struct ShardedLocks {
    locks: DashMap<ShardId, Arc<RwLock<()>>>,
}

impl ShardedLocks {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_for(&self, shard: &ShardId) -> Arc<RwLock<()>> {
        // `entry` takes a write lock on the DashMap's internal shard for the duration of
        // this call only — released before we ever touch the returned `RwLock` itself,
        // so this never holds two locks at once.
        Arc::clone(
            &self
                .locks
                .entry(shard.clone())
                .or_insert_with(|| Arc::new(RwLock::new(()))),
        )
    }

    /// Acquire a read guard for `shard`. Multiple readers of the same shard, and any
    /// number of readers/writers of *other* shards, can proceed concurrently.
    pub async fn read(&self, shard: &ShardId) -> OwnedRwLockReadGuard<()> {
        self.lock_for(shard).read_owned().await
    }

    /// Acquire a write guard for `shard`. Exclusive against every other reader/writer of
    /// the *same* shard; other shards are unaffected.
    pub async fn write(&self, shard: &ShardId) -> OwnedRwLockWriteGuard<()> {
        self.lock_for(shard).write_owned().await
    }

    /// Number of shards that have ever been locked (for observability/tests — not a
    /// capacity bound, `ShardedLocks` grows to however many distinct shards are touched).
    pub fn known_shard_count(&self) -> usize {
        self.locks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn read_locks_on_the_same_shard_can_run_concurrently() {
        let locks = Arc::new(ShardedLocks::new());
        let shard = ShardId("src".into());

        let g1 = locks.read(&shard).await;
        let g2 = tokio::time::timeout(Duration::from_millis(200), locks.read(&shard)).await;
        assert!(
            g2.is_ok(),
            "a second reader must not block behind the first"
        );
        drop(g1);
    }

    #[tokio::test]
    async fn write_lock_excludes_readers_on_the_same_shard() {
        let locks = Arc::new(ShardedLocks::new());
        let shard = ShardId("src".into());

        let _write_guard = locks.write(&shard).await;
        let read_attempt =
            tokio::time::timeout(Duration::from_millis(100), locks.read(&shard)).await;
        assert!(
            read_attempt.is_err(),
            "a reader must block while a writer holds the same shard"
        );
    }

    #[tokio::test]
    async fn locks_on_different_shards_never_block_each_other() {
        let locks = Arc::new(ShardedLocks::new());
        let a = ShardId("a".into());
        let b = ShardId("b".into());

        let _write_a = locks.write(&a).await;
        // A write on an unrelated shard must proceed immediately, not wait for `a`.
        let write_b = tokio::time::timeout(Duration::from_millis(200), locks.write(&b)).await;
        assert!(write_b.is_ok(), "unrelated shards must not contend");
    }

    #[tokio::test]
    async fn same_shard_writes_serialize_without_lost_updates() {
        let locks = Arc::new(ShardedLocks::new());
        let shard = ShardId("src".into());
        let counter = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..20 {
            let locks = Arc::clone(&locks);
            let shard = shard.clone();
            let counter = Arc::clone(&counter);
            handles.push(tokio::spawn(async move {
                let _guard = locks.write(&shard).await;
                // A non-atomic read-modify-write: only safe if the lock truly serializes.
                let current = counter.load(Ordering::Relaxed);
                tokio::task::yield_now().await;
                counter.store(current + 1, Ordering::Relaxed);
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(
            counter.load(Ordering::Relaxed),
            20,
            "no lost updates under contention"
        );
    }

    #[tokio::test]
    async fn known_shard_count_tracks_distinct_shards_touched() {
        let locks = ShardedLocks::new();
        assert_eq!(locks.known_shard_count(), 0);
        let _ = locks.read(&ShardId("a".into())).await;
        let _ = locks.read(&ShardId("b".into())).await;
        let _ = locks.read(&ShardId("a".into())).await; // revisiting a shard, not a new one
        assert_eq!(locks.known_shard_count(), 2);
    }
}
