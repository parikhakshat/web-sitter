//! `LiveWorkspace`: the point where every Phase 2 piece built so far actually gets wired
//! together into a coordinated live-update path. A file change comes in as raw bytes
//! (from the file watcher in `crate::watcher`, or directly from a test/caller); this type
//! takes the shard's write lock (`ShardedLocks`, task #12), finds-or-creates that file's
//! `IncrementalFileState` (task #13) and applies the edit through it, persists the
//! resulting `Cpg` (`WorkspaceStore`, task #11), and bumps the shard/global revision
//! (`Revisions`, task #12) — returning exactly the `SymbolId`s that changed, ready to feed
//! into `ReverseSymbolIndex`'s scoped invalidation.
//!
//! Concurrency note: `apply_file_change`/`apply_file_removal` are batch-of-one wrappers
//! around `apply_batch`, which uses a **two-phase** protocol rather than holding one
//! shard's write lock across the whole apply. Phase 1 (per file: incremental reparse/diff)
//! takes that file's shard write lock and releases it immediately, before phase 2 persists
//! every file in the batch as a single redb transaction (`WorkspaceStore::apply_batch`) —
//! collapsing what used to be N individual write transactions (a measured bottleneck:
//! `redb::Database` allows only one live write transaction process-wide, so N concurrent
//! `put`s serialized on that slot regardless of `ShardedLocks` parallelizing the reparse
//! work) into one. Phase 3 bumps each touched shard's revision after phase 2 commits,
//! preserving "the revision I observe corresponds to durably-persisted data."
//!
//! Accepted trade-off from this change: a concurrent same-shard *reader*
//! (`ShardedLocks::read`) can now briefly observe a file's new `Cpg` in the live `files`
//! map before phase 2 has durably persisted it (previously impossible, since the write
//! lock used to span persist too). This is safe for this type's own callers (they only
//! read after the whole `apply_batch`/`apply_file_change` call returns), but is a real,
//! deliberate semantic change worth calling out explicitly rather than leaving it implicit.

use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use web_sitter::language_from_path;
use web_sitter::symbol_id::{SymbolId, build_symbol_table};

use super::StoreOp;
use super::WorkspaceStore;
use super::incremental_file::IncrementalFileState;
use super::revision::Revisions;
use super::shard::ShardId;
use super::sharded_lock::ShardedLocks;

/// The outcome of applying one file change: which symbols changed, and the revisions the
/// change landed at.
#[derive(Debug)]
pub struct AppliedChange {
    pub changed_symbols: BTreeSet<SymbolId>,
    pub global_revision: u64,
    pub shard_revision: u64,
    pub shard: ShardId,
}

/// One entry in an `apply_batch` call: either new full source bytes for a file, or a
/// removal. Re-exported for `LiveIndex`/`watcher` to reuse rather than duplicating an
/// equivalent enum.
pub enum FileChangeKind {
    Changed(Vec<u8>),
    Removed,
}

pub struct LiveWorkspace {
    store: WorkspaceStore,
    locks: ShardedLocks,
    revisions: Revisions,
    /// Live per-file incremental generators — the thing `WorkspaceStore` doesn't hold
    /// (it only caches the derived `Cpg`, not the generator that can cheaply extend it).
    files: DashMap<PathBuf, IncrementalFileState>,
    root: PathBuf,
    /// Where per-file `IncrementalFileState` snapshots (`save_snapshot`/`load_snapshot`)
    /// live — separate from `store`'s redb file since a snapshot is a full generator
    /// state blob (source + derived indexes), not just the `Cpg` `WorkspaceStore` caches.
    snapshot_dir: PathBuf,
}

impl LiveWorkspace {
    pub fn open(
        db_path: impl AsRef<Path>,
        root: PathBuf,
        hot_capacity: NonZeroUsize,
        snapshot_dir: PathBuf,
    ) -> Result<Self> {
        std::fs::create_dir_all(&snapshot_dir)
            .with_context(|| format!("creating snapshot directory {}", snapshot_dir.display()))?;
        Ok(Self {
            store: WorkspaceStore::open(db_path, root.clone(), hot_capacity)?,
            locks: ShardedLocks::new(),
            revisions: Revisions::new(),
            files: DashMap::new(),
            root,
            snapshot_dir,
        })
    }

    /// Deterministic per-file snapshot path under `snapshot_dir` — hashed rather than
    /// mirroring the file's own relative path, so it's insensitive to path length/
    /// character restrictions on the host filesystem and never collides with the
    /// directory structure of the codebase being indexed.
    fn snapshot_path_for(&self, file: &Path) -> PathBuf {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        file.hash(&mut hasher);
        self.snapshot_dir
            .join(format!("{:x}.state", hasher.finish()))
    }

    /// Try a warm restart of `file`: if a snapshot exists and its saved source matches
    /// `file`'s current on-disk bytes exactly, restore straight from the snapshot —
    /// skipping a full tree-sitter reparse — and return `Ok(true)`. Otherwise falls back
    /// to a fresh full parse (`Ok(false)`, a "cold" restart) — a stale or missing snapshot
    /// is an ordinary, expected outcome (the file changed since last snapshot, or this is
    /// truly the first time seeing it), not a warning-worthy condition on its own.
    ///
    /// Either way, `file` ends up live in `self.files` and persisted in `self.store`
    /// exactly as if `apply_file_change` had just been called for it — but this method
    /// does *not* bump any revision or take a shard lock: it's meant for startup
    /// initialization (before the watcher goes live), not a live edit event.
    pub fn warm_restart_file(&self, file: &Path) -> Result<bool> {
        let current_source = std::fs::read(file)
            .with_context(|| format!("reading {} for warm restart", file.display()))?;
        let language = language_from_path(&file.to_string_lossy());
        let snapshot_path = self.snapshot_path_for(file);

        let (state, warm) = match IncrementalFileState::load_snapshot(language, &snapshot_path)? {
            Some(state) if state.source_bytes() == current_source.as_slice() => (state, true),
            _ => (
                IncrementalFileState::from_source(language, &current_source)?,
                false,
            ),
        };

        self.store.put(file, state.cpg().clone())?;
        self.files.insert(file.to_path_buf(), state);
        Ok(warm)
    }

    /// Snapshot `file`'s current live state to disk, for a future `warm_restart_file` to
    /// find. A no-op (not an error) if `file` has no live state.
    pub fn snapshot_file(&self, file: &Path) -> Result<()> {
        let Some(state) = self.files.get(file) else {
            return Ok(());
        };
        state.save_snapshot(self.snapshot_path_for(file))
    }

    /// Snapshot every file with live state. Returns how many were snapshotted — the
    /// "whole-store snapshot" operation, meant to be called on a clean shutdown (or
    /// periodically) so the *next* process start can warm-restart from it.
    pub fn snapshot_all(&self) -> Result<usize> {
        let files: Vec<PathBuf> = self.files.iter().map(|entry| entry.key().clone()).collect();
        for file in &files {
            self.snapshot_file(file)?;
        }
        Ok(files.len())
    }

    /// Apply `new_source` as the new full contents of `file`. Creates the file's
    /// `IncrementalFileState` on first sight (every symbol in the initial parse counts as
    /// "changed" — there's nothing to diff against yet) or incrementally reparses it
    /// against the previous state. A batch-of-one wrapper around `apply_batch`.
    pub async fn apply_file_change(&self, file: &Path, new_source: &[u8]) -> Result<AppliedChange> {
        let changes = vec![(
            file.to_path_buf(),
            FileChangeKind::Changed(new_source.to_vec()),
        )];
        let mut results = self.apply_batch(changes).await?;
        Ok(results
            .pop()
            .expect("batch of one always yields one result"))
    }

    /// Remove `file` from live state, the on-disk store, and bump its shard's revision.
    /// Returns the symbols that were defined in the file just before removal (the "now
    /// gone" set, for the same cross-file-invalidation purpose `apply_file_change`'s
    /// return value serves). A batch-of-one wrapper around `apply_batch`.
    pub async fn apply_file_removal(&self, file: &Path) -> Result<AppliedChange> {
        let changes = vec![(file.to_path_buf(), FileChangeKind::Removed)];
        let mut results = self.apply_batch(changes).await?;
        Ok(results
            .pop()
            .expect("batch of one always yields one result"))
    }

    /// Apply every `(file, kind)` pair in `changes` as one batch — see the module doc
    /// comment for the two-phase protocol and its accepted trade-off versus the old
    /// single-item locking discipline. Returns one `AppliedChange` per input, in the same
    /// order. If `changes` contains more than one entry for the same file, they're applied
    /// in order against that file's `IncrementalFileState` (phase 1 iterates sequentially).
    ///
    /// Phase 1 (reparse) runs sequentially over `changes` in this implementation — the
    /// reparse itself is synchronous CPU-bound work, and genuine intra-batch parallelism
    /// across different files' reparses would need spawning `'static` tasks (an
    /// `Arc<Self>`-threading change not made here). The fix this batching exists for —
    /// collapsing N redb write transactions into one — is fully realized by phase 2
    /// regardless of phase 1's own concurrency.
    pub async fn apply_batch(
        &self,
        changes: Vec<(PathBuf, FileChangeKind)>,
    ) -> Result<Vec<AppliedChange>> {
        struct Phase1Result {
            shard: ShardId,
            changed_symbols: BTreeSet<SymbolId>,
            op: StoreOp,
        }

        let mut phase1_results = Vec::with_capacity(changes.len());
        for (file, kind) in changes {
            let shard = self.store.shard_of(&file);
            let write_guard = self.locks.write(&shard).await;

            let (changed_symbols, op) = match kind {
                FileChangeKind::Changed(new_source) => {
                    let changed_symbols = match self.files.entry(file.clone()) {
                        Entry::Occupied(mut occupied) => {
                            occupied.get_mut().apply_edit(&new_source)?
                        }
                        Entry::Vacant(vacant) => {
                            let language = language_from_path(&file.to_string_lossy());
                            let state = IncrementalFileState::from_source(language, &new_source)?;
                            let initial_symbols =
                                build_symbol_table(state.cpg()).into_values().collect();
                            vacant.insert(state);
                            initial_symbols
                        }
                    };
                    let cpg = self
                        .files
                        .get(&file)
                        .expect("just inserted or updated above")
                        .cpg()
                        .clone();
                    (changed_symbols, StoreOp::Put(file, Box::new(cpg)))
                }
                FileChangeKind::Removed => {
                    let changed_symbols = match self.files.remove(&file) {
                        Some((_, state)) => build_symbol_table(state.cpg()).into_values().collect(),
                        None => BTreeSet::new(),
                    };
                    (changed_symbols, StoreOp::Remove(file))
                }
            };
            // Released here, before phase 2's persist — see the module doc comment's
            // accepted-trade-off note.
            drop(write_guard);

            phase1_results.push(Phase1Result {
                shard,
                changed_symbols,
                op,
            });
        }

        let (metas, ops): (Vec<(ShardId, BTreeSet<SymbolId>)>, Vec<StoreOp>) = phase1_results
            .into_iter()
            .map(|r| ((r.shard, r.changed_symbols), r.op))
            .unzip();

        self.store.apply_batch(ops)?;

        let mut out = Vec::with_capacity(metas.len());
        for (shard, changed_symbols) in metas {
            let (global_revision, shard_revision) = self.revisions.record_edit(&shard);
            out.push(AppliedChange {
                changed_symbols,
                global_revision,
                shard_revision,
                shard,
            });
        }
        Ok(out)
    }

    pub fn shard_of(&self, file: &Path) -> ShardId {
        self.store.shard_of(file)
    }

    pub fn global_revision(&self) -> u64 {
        self.revisions.global()
    }

    pub fn shard_revision(&self, shard: &ShardId) -> u64 {
        self.revisions.shard(shard)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Number of files with live in-memory incremental state (not the total persisted —
    /// see `WorkspaceStore::persisted_len`).
    pub fn live_file_count(&self) -> usize {
        self.files.len()
    }

    /// Access to the underlying `WorkspaceStore` — for callers (namely
    /// `store::load_test`) that need to inspect hot-cache/persistence stats directly
    /// rather than through `LiveWorkspace`'s edit-oriented API.
    pub(crate) fn store(&self) -> &WorkspaceStore {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_workspace(dir: &tempfile::TempDir) -> LiveWorkspace {
        LiveWorkspace::open(
            dir.path().join("store.redb"),
            dir.path().to_path_buf(),
            NonZeroUsize::new(64).unwrap(),
            dir.path().join("snapshots"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn first_sight_of_a_file_reports_every_symbol_as_changed() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = open_workspace(&dir);
        let file = dir.path().join("a.cpp");

        let applied = workspace
            .apply_file_change(&file, b"int a() { return 1; }\nint b() { return 2; }\n")
            .await
            .unwrap();

        let names: BTreeSet<&str> = applied.changed_symbols.iter().map(|s| s.as_str()).collect();
        assert_eq!(names, BTreeSet::from(["cpp:a", "cpp:b"]));
        assert_eq!(applied.global_revision, 1);
        assert_eq!(applied.shard_revision, 1);
    }

    #[tokio::test]
    async fn subsequent_edit_only_reports_the_symbol_that_actually_changed() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = open_workspace(&dir);
        let file = dir.path().join("a.cpp");

        workspace
            .apply_file_change(&file, b"int a() { return 1; }\nint b() { return 2; }\n")
            .await
            .unwrap();
        let applied = workspace
            .apply_file_change(&file, b"int a() { return 100; }\nint b() { return 2; }\n")
            .await
            .unwrap();

        let names: BTreeSet<&str> = applied.changed_symbols.iter().map(|s| s.as_str()).collect();
        assert_eq!(names, BTreeSet::from(["cpp:a"]));
        assert_eq!(applied.global_revision, 2);
        assert_eq!(applied.shard_revision, 2, "same shard as the first edit");
    }

    #[tokio::test]
    async fn edits_to_different_shards_get_independent_shard_revisions() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::create_dir(dir.path().join("tests")).unwrap();
        let workspace = open_workspace(&dir);

        workspace
            .apply_file_change(&dir.path().join("src/a.cpp"), b"int a() { return 1; }\n")
            .await
            .unwrap();
        let second = workspace
            .apply_file_change(&dir.path().join("tests/b.cpp"), b"int b() { return 2; }\n")
            .await
            .unwrap();

        assert_eq!(
            second.global_revision, 2,
            "global counts every edit across shards"
        );
        assert_eq!(
            second.shard_revision, 1,
            "a fresh shard starts its own revision at 1"
        );
    }

    #[tokio::test]
    async fn removal_reports_the_removed_symbols_and_clears_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = open_workspace(&dir);
        let file = dir.path().join("a.cpp");

        workspace
            .apply_file_change(&file, b"int a() { return 1; }\n")
            .await
            .unwrap();
        assert_eq!(workspace.live_file_count(), 1);

        let removed = workspace.apply_file_removal(&file).await.unwrap();
        let names: BTreeSet<&str> = removed.changed_symbols.iter().map(|s| s.as_str()).collect();
        assert_eq!(names, BTreeSet::from(["cpp:a"]));
        assert_eq!(workspace.live_file_count(), 0);
        assert_eq!(workspace.store.persisted_len().unwrap(), 0);
    }

    #[tokio::test]
    async fn removal_of_an_unknown_file_is_a_harmless_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = open_workspace(&dir);
        let removed = workspace
            .apply_file_removal(&dir.path().join("never_existed.cpp"))
            .await
            .unwrap();
        assert!(removed.changed_symbols.is_empty());
        // Still counts as an edit for revision purposes — a watcher can't tell "delete of
        // a file we never indexed" apart from "delete of a file we did" without doing the
        // exact lookup this method already does, so it's simplest for the revision to
        // always advance on any FS event we're told to process.
        assert_eq!(removed.global_revision, 1);
    }

    #[tokio::test]
    async fn a_persisted_cpg_survives_across_workspace_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("store.redb");
        let snapshot_dir = dir.path().join("snapshots");
        let file = dir.path().join("a.cpp");
        {
            let workspace = LiveWorkspace::open(
                db_path.clone(),
                dir.path().to_path_buf(),
                NonZeroUsize::new(64).unwrap(),
                snapshot_dir.clone(),
            )
            .unwrap();
            workspace
                .apply_file_change(&file, b"int a() { return 1; }\n")
                .await
                .unwrap();
        }
        let reopened = LiveWorkspace::open(
            db_path,
            dir.path().to_path_buf(),
            NonZeroUsize::new(64).unwrap(),
            snapshot_dir,
        )
        .unwrap();
        assert_eq!(reopened.store.persisted_len().unwrap(), 1);
    }

    #[test]
    fn warm_restart_is_a_cold_start_when_no_snapshot_exists_yet() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = open_workspace(&dir);
        let file = dir.path().join("a.cpp");
        std::fs::write(&file, "int a() { return 1; }\n").unwrap();

        let warm = workspace.warm_restart_file(&file).unwrap();
        assert!(!warm, "no snapshot exists yet — must be a cold start");
        assert_eq!(workspace.live_file_count(), 1);
    }

    #[test]
    fn warm_restart_hits_when_content_is_unchanged_since_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = open_workspace(&dir);
        let file = dir.path().join("a.cpp");
        std::fs::write(&file, "int a() { return 1; }\n").unwrap();

        workspace.warm_restart_file(&file).unwrap();
        workspace.snapshot_file(&file).unwrap();

        // A fresh LiveWorkspace over the same snapshot directory — simulating a process
        // restart — must warm-restart instead of re-parsing.
        let restarted = LiveWorkspace::open(
            dir.path().join("store2.redb"),
            dir.path().to_path_buf(),
            NonZeroUsize::new(64).unwrap(),
            dir.path().join("snapshots"),
        )
        .unwrap();
        let warm = restarted.warm_restart_file(&file).unwrap();
        assert!(
            warm,
            "content unchanged since the snapshot — must warm-restart"
        );

        let names: BTreeSet<String> = build_symbol_table(
            restarted
                .files
                .get(&file)
                .expect("file must be live after warm restart")
                .cpg(),
        )
        .into_values()
        .map(|s| s.as_str().to_string())
        .collect();
        assert_eq!(names, BTreeSet::from(["cpp:a".to_string()]));
    }

    #[test]
    fn warm_restart_falls_back_to_cold_when_content_changed_since_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = open_workspace(&dir);
        let file = dir.path().join("a.cpp");
        std::fs::write(&file, "int a() { return 1; }\n").unwrap();
        workspace.warm_restart_file(&file).unwrap();
        workspace.snapshot_file(&file).unwrap();

        // The file changed on disk after the snapshot was taken.
        std::fs::write(&file, "int a() { return 2; }\nint b() { return 3; }\n").unwrap();

        let restarted = LiveWorkspace::open(
            dir.path().join("store2.redb"),
            dir.path().to_path_buf(),
            NonZeroUsize::new(64).unwrap(),
            dir.path().join("snapshots"),
        )
        .unwrap();
        let warm = restarted.warm_restart_file(&file).unwrap();
        assert!(
            !warm,
            "content changed since the snapshot — must fall back to cold"
        );

        let names: BTreeSet<String> = build_symbol_table(
            restarted
                .files
                .get(&file)
                .expect("file must be live after warm restart")
                .cpg(),
        )
        .into_values()
        .map(|s| s.as_str().to_string())
        .collect();
        assert_eq!(
            names,
            BTreeSet::from(["cpp:a".to_string(), "cpp:b".to_string()]),
            "must reflect the current on-disk content, not the stale snapshot"
        );
    }

    #[test]
    fn snapshot_all_snapshots_every_live_file() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = open_workspace(&dir);
        let a = dir.path().join("a.cpp");
        let b = dir.path().join("b.cpp");
        std::fs::write(&a, "int a() { return 1; }\n").unwrap();
        std::fs::write(&b, "int b() { return 2; }\n").unwrap();
        workspace.warm_restart_file(&a).unwrap();
        workspace.warm_restart_file(&b).unwrap();

        let count = workspace.snapshot_all().unwrap();
        assert_eq!(count, 2);

        let restarted = LiveWorkspace::open(
            dir.path().join("store2.redb"),
            dir.path().to_path_buf(),
            NonZeroUsize::new(64).unwrap(),
            dir.path().join("snapshots"),
        )
        .unwrap();
        assert!(restarted.warm_restart_file(&a).unwrap());
        assert!(restarted.warm_restart_file(&b).unwrap());
    }

    #[test]
    fn snapshot_file_is_a_no_op_for_a_file_with_no_live_state() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = open_workspace(&dir);
        // Never touched via warm_restart_file/apply_file_change — must not error.
        workspace
            .snapshot_file(&dir.path().join("never_seen.cpp"))
            .unwrap();
    }

    #[tokio::test]
    async fn apply_batch_persists_all_files_via_one_call_and_returns_one_applied_change_each() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        std::fs::create_dir(dir.path().join("b")).unwrap();
        std::fs::create_dir(dir.path().join("c")).unwrap();
        let workspace = open_workspace(&dir);

        let results = workspace
            .apply_batch(vec![
                (
                    dir.path().join("a/x.cpp"),
                    FileChangeKind::Changed(b"int x() { return 1; }\n".to_vec()),
                ),
                (
                    dir.path().join("b/y.cpp"),
                    FileChangeKind::Changed(b"int y() { return 2; }\n".to_vec()),
                ),
                (
                    dir.path().join("c/z.cpp"),
                    FileChangeKind::Changed(b"int z() { return 3; }\n".to_vec()),
                ),
            ])
            .await
            .unwrap();

        assert_eq!(results.len(), 3);
        let symbol_names: Vec<&str> = results
            .iter()
            .map(|r| {
                r.changed_symbols
                    .iter()
                    .next()
                    .expect("each file has one symbol")
                    .as_str()
            })
            .collect();
        assert_eq!(symbol_names, vec!["cpp:x", "cpp:y", "cpp:z"]);
        assert_eq!(workspace.store.persisted_len().unwrap(), 3);
    }

    #[tokio::test]
    async fn apply_batch_bumps_each_touched_shards_revision_independently() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        std::fs::create_dir(dir.path().join("b")).unwrap();
        let workspace = open_workspace(&dir);

        let results = workspace
            .apply_batch(vec![
                (
                    dir.path().join("a/one.cpp"),
                    FileChangeKind::Changed(b"int one() { return 1; }\n".to_vec()),
                ),
                (
                    dir.path().join("a/two.cpp"),
                    FileChangeKind::Changed(b"int two() { return 2; }\n".to_vec()),
                ),
                (
                    dir.path().join("b/three.cpp"),
                    FileChangeKind::Changed(b"int three() { return 3; }\n".to_vec()),
                ),
            ])
            .await
            .unwrap();

        assert_eq!(results[0].shard_revision, 1);
        assert_eq!(results[1].shard_revision, 2, "second edit to shard a");
        assert_eq!(results[2].shard_revision, 1, "fresh shard b starts at 1");
        assert_eq!(results[2].global_revision, 3);
    }

    #[tokio::test]
    async fn apply_batch_mixing_changes_and_removals() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = open_workspace(&dir);
        let existing = dir.path().join("existing.cpp");
        let fresh = dir.path().join("fresh.cpp");

        workspace
            .apply_file_change(&existing, b"int existing_fn() { return 0; }\n")
            .await
            .unwrap();
        assert_eq!(workspace.live_file_count(), 1);

        let results = workspace
            .apply_batch(vec![
                (existing.clone(), FileChangeKind::Removed),
                (
                    fresh.clone(),
                    FileChangeKind::Changed(b"int fresh_fn() { return 1; }\n".to_vec()),
                ),
            ])
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        let removed_names: BTreeSet<&str> = results[0]
            .changed_symbols
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(removed_names, BTreeSet::from(["cpp:existing_fn"]));
        assert_eq!(
            workspace.live_file_count(),
            1,
            "fresh.cpp is now the only live file"
        );
        assert_eq!(workspace.store.persisted_len().unwrap(), 1);
        assert!(workspace.store.get(&fresh).unwrap().is_some());
        assert!(workspace.store.get(&existing).unwrap().is_none());
    }
}
