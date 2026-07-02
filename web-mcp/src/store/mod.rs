//! `WorkspaceStore`: an LRU-bounded in-memory cache of *hot* `Cpg`s over the durable
//! on-disk `PersistentStore`. This is what lets a 100k+ file monorepo's steady-state
//! memory footprint stay bounded — `Workspace` no longer needs to hold every file's `Cpg`
//! in a plain `HashMap` for the process lifetime; only recently-touched files stay
//! resident, everything else is a cheap on-disk lookup away.
//!
//! Scope for this task: the store itself, standalone and fully tested. Wiring it into
//! `WebMcpServer`/the live tool handlers (replacing the batch-built, all-in-memory
//! `Workspace` from `crate::index`) is later Phase 2 work (sharded locking, the
//! incremental-system unification, and the file watcher all need to land first) —
//! bolting it on now, before those pieces exist, would just be dead code wearing a
//! server-shaped costume.

pub mod persistence;
pub mod shard;

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use lru::LruCache;
use web_sitter::Cpg;

pub use persistence::PersistentStore;
pub use shard::ShardId;

pub struct WorkspaceStore {
    persistent: PersistentStore,
    root: PathBuf,
    hot: Mutex<LruCache<PathBuf, Arc<Cpg>>>,
}

impl WorkspaceStore {
    /// Open (or create) the on-disk store at `db_path`, indexing files under `root`.
    /// `hot_capacity` bounds how many `Cpg`s stay resident in memory at once.
    pub fn open(
        db_path: impl AsRef<Path>,
        root: PathBuf,
        hot_capacity: NonZeroUsize,
    ) -> Result<Self> {
        Ok(Self {
            persistent: PersistentStore::open(db_path)?,
            root,
            hot: Mutex::new(LruCache::new(hot_capacity)),
        })
    }

    /// Persist `cpg` for `file` and make it the most-recently-used hot entry.
    pub fn put(&self, file: &Path, cpg: Cpg) -> Result<Arc<Cpg>> {
        let key = file.to_path_buf();
        self.persistent.put(&path_key(file), &cpg)?;
        let cpg = Arc::new(cpg);
        self.hot.lock().unwrap().put(key, Arc::clone(&cpg));
        Ok(cpg)
    }

    /// Get `file`'s `Cpg`, preferring the hot in-memory cache; on a miss, loads from the
    /// on-disk store and promotes it to hot. Returns `Ok(None)` if `file` has never been
    /// indexed (not an error — a normal "not present" outcome).
    pub fn get(&self, file: &Path) -> Result<Option<Arc<Cpg>>> {
        let key = file.to_path_buf();
        if let Some(hit) = self.hot.lock().unwrap().get(&key) {
            return Ok(Some(Arc::clone(hit)));
        }
        let Some(cpg) = self.persistent.get(&path_key(file))? else {
            return Ok(None);
        };
        let cpg = Arc::new(cpg);
        self.hot.lock().unwrap().put(key, Arc::clone(&cpg));
        Ok(Some(cpg))
    }

    /// Remove `file` from both the hot cache and the durable store.
    pub fn remove(&self, file: &Path) -> Result<()> {
        self.hot.lock().unwrap().pop(&file.to_path_buf());
        self.persistent.remove(&path_key(file))
    }

    pub fn shard_of(&self, file: &Path) -> ShardId {
        shard::shard_of(file, &self.root)
    }

    /// Number of `Cpg`s currently resident in the hot cache (not the total persisted).
    pub fn hot_len(&self) -> usize {
        self.hot.lock().unwrap().len()
    }

    /// Total number of `Cpg`s durably persisted (hot or not).
    pub fn persisted_len(&self) -> Result<u64> {
        self.persistent.len()
    }
}

fn path_key(file: &Path) -> String {
    file.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use web_sitter::cpg_generator::{GraphBuildOptions, SourceLanguage};
    use web_sitter::incremental::IncrementalCpgGenerator;

    fn sample_cpg(src: &str) -> Cpg {
        let mut generator = IncrementalCpgGenerator::new_for_language(
            SourceLanguage::Cpp,
            GraphBuildOptions::default(),
        )
        .expect("generator");
        generator.parse_full(src.as_bytes()).expect("parse").clone()
    }

    fn open_store(dir: &tempfile::TempDir, capacity: usize) -> WorkspaceStore {
        WorkspaceStore::open(
            dir.path().join("store.redb"),
            dir.path().to_path_buf(),
            NonZeroUsize::new(capacity).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn put_then_get_returns_the_same_cpg() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir, 10);
        let file = dir.path().join("a.cpp");
        let cpg = sample_cpg("int helper() { return 1; }");

        store.put(&file, cpg.clone()).unwrap();
        let loaded = store.get(&file).unwrap().expect("must be present");
        assert_eq!(loaded.ast.len(), cpg.ast.len());
    }

    #[test]
    fn get_survives_hot_cache_eviction_via_disk_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir, 1); // capacity 1: the second put evicts the first
        let a = dir.path().join("a.cpp");
        let b = dir.path().join("b.cpp");

        store
            .put(&a, sample_cpg("int a_fn() { return 1; }"))
            .unwrap();
        store
            .put(&b, sample_cpg("int b_fn() { return 2; }"))
            .unwrap();
        assert_eq!(
            store.hot_len(),
            1,
            "capacity 1 must have evicted a.cpp from the hot cache"
        );

        // a.cpp is gone from the hot cache but still durably persisted — get() must
        // still succeed via a disk fallback, not return None.
        let loaded = store.get(&a).unwrap();
        assert!(
            loaded.is_some(),
            "eviction from the hot cache must not lose durably-persisted data"
        );
    }

    #[test]
    fn get_returns_none_for_never_indexed_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir, 10);
        assert!(store.get(&dir.path().join("nope.cpp")).unwrap().is_none());
    }

    #[test]
    fn remove_clears_both_hot_cache_and_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir, 10);
        let file = dir.path().join("a.cpp");
        store
            .put(&file, sample_cpg("int a() { return 1; }"))
            .unwrap();
        assert!(store.get(&file).unwrap().is_some());

        store.remove(&file).unwrap();
        assert!(store.get(&file).unwrap().is_none());
        assert_eq!(store.persisted_len().unwrap(), 0);
    }

    #[test]
    fn shard_of_delegates_to_shard_module() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir, 10);
        let file = dir.path().join("src/lib.rs");
        assert_eq!(store.shard_of(&file), shard::shard_of(&file, dir.path()));
    }

    #[test]
    fn persisted_len_counts_all_entries_regardless_of_hot_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir, 1);
        store
            .put(
                &dir.path().join("a.cpp"),
                sample_cpg("int a() { return 1; }"),
            )
            .unwrap();
        store
            .put(
                &dir.path().join("b.cpp"),
                sample_cpg("int b() { return 2; }"),
            )
            .unwrap();
        assert_eq!(
            store.persisted_len().unwrap(),
            2,
            "both entries persisted even though hot capacity is 1"
        );
        assert_eq!(store.hot_len(), 1);
    }
}
