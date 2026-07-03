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

pub mod findings;
pub mod incremental_file;
pub mod live_workspace;
#[cfg(test)]
mod load_test;
pub mod persistence;
pub mod revision;
pub mod shard;
pub mod sharded_lock;

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use lru::LruCache;
use web_sitter::Cpg;

pub use persistence::PersistentStore;
pub use shard::ShardId;

/// One entry in a batched write, mirroring `persistence::BatchOp` at the `WorkspaceStore`
/// layer (owning its `Cpg` rather than borrowing, since callers assembling a batch often
/// don't have a stable reference to hold across the whole call). See
/// `WorkspaceStore::apply_batch`.
pub enum StoreOp {
    Put(PathBuf, Box<Cpg>),
    Remove(PathBuf),
}

/// Default `WorkspaceStore` hot-cache capacity, pending a real `--hot-capacity` CLI flag
/// once `LiveWorkspace` is wired into `WebMcpServer` (still batch-`Workspace`-only as of
/// this task — see `crate::index`). Chosen from `store::load_test`'s benchmark: 200 hot
/// entries keeps steady-state memory bounded independent of total repo size while still
/// giving a typical multi-file edit session (a handful of files touched per turn) a very
/// high hit rate before anything gets evicted.
pub const DEFAULT_HOT_CAPACITY: usize = 200;

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
        let results = self.apply_batch(vec![StoreOp::Put(file.to_path_buf(), Box::new(cpg))])?;
        Ok(results
            .into_iter()
            .next()
            .flatten()
            .expect("a single Put always yields a Some result"))
    }

    /// Persist every op in `ops` as one redb transaction (see
    /// `PersistentStore::apply_batch`), then update the hot cache per-entry: a `Put`
    /// inserts+promotes, a `Remove` evicts. Returns one entry per input op, in the same
    /// order — `Some(Arc<Cpg>)` for a `Put` (the `Cpg` now held hot), `None` for a
    /// `Remove`.
    pub fn apply_batch(&self, ops: Vec<StoreOp>) -> Result<Vec<Option<Arc<Cpg>>>> {
        let keys: Vec<String> = ops
            .iter()
            .map(|op| match op {
                StoreOp::Put(file, _) | StoreOp::Remove(file) => path_key(file),
            })
            .collect();
        let batch_ops: Vec<persistence::BatchOp<'_>> = ops
            .iter()
            .zip(&keys)
            .map(|(op, key)| match op {
                StoreOp::Put(_, cpg) => persistence::BatchOp::Put(key, cpg.as_ref()),
                StoreOp::Remove(_) => persistence::BatchOp::Remove(key),
            })
            .collect();
        self.persistent.apply_batch(&batch_ops)?;

        let mut hot = self.hot.lock().unwrap();
        let results = ops
            .into_iter()
            .map(|op| match op {
                StoreOp::Put(file, cpg) => {
                    let cpg: Arc<Cpg> = Arc::new(*cpg);
                    hot.put(file, Arc::clone(&cpg));
                    Some(cpg)
                }
                StoreOp::Remove(file) => {
                    hot.pop(&file);
                    None
                }
            })
            .collect();
        drop(hot);
        Ok(results)
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
        self.apply_batch(vec![StoreOp::Remove(file.to_path_buf())])?;
        Ok(())
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
    fn apply_batch_puts_update_hot_cache_for_every_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir, 10);
        let a = dir.path().join("a.cpp");
        let b = dir.path().join("b.cpp");
        let c = dir.path().join("c.cpp");

        store
            .apply_batch(vec![
                StoreOp::Put(a.clone(), Box::new(sample_cpg("int a_fn() { return 1; }"))),
                StoreOp::Put(b.clone(), Box::new(sample_cpg("int b_fn() { return 2; }"))),
                StoreOp::Put(c.clone(), Box::new(sample_cpg("int c_fn() { return 3; }"))),
            ])
            .unwrap();

        assert_eq!(store.hot_len(), 3);
        assert!(store.get(&a).unwrap().is_some());
        assert!(store.get(&b).unwrap().is_some());
        assert!(store.get(&c).unwrap().is_some());
    }

    #[test]
    fn apply_batch_remove_evicts_from_hot_cache_and_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir, 10);
        let file = dir.path().join("a.cpp");
        store
            .put(&file, sample_cpg("int a() { return 1; }"))
            .unwrap();
        assert_eq!(store.hot_len(), 1);

        store
            .apply_batch(vec![StoreOp::Remove(file.clone())])
            .unwrap();

        assert_eq!(store.hot_len(), 0);
        assert!(store.get(&file).unwrap().is_none());
        assert_eq!(store.persisted_len().unwrap(), 0);
    }

    #[test]
    fn apply_batch_returns_arcs_in_input_order_with_none_for_removes() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir, 10);
        let a = dir.path().join("a.cpp");
        let b = dir.path().join("b.cpp");
        store
            .put(&b, sample_cpg("int b_fn() { return 1; }"))
            .unwrap();

        let results = store
            .apply_batch(vec![
                StoreOp::Put(a.clone(), Box::new(sample_cpg("int a_fn() { return 2; }"))),
                StoreOp::Remove(b.clone()),
            ])
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0].is_some(), "Put must yield Some(Arc<Cpg>)");
        assert!(results[1].is_none(), "Remove must yield None");
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
