//! `LiveWorkspace`: the point where every Phase 2 piece built so far actually gets wired
//! together into a coordinated live-update path. A file change comes in as raw bytes
//! (from the file watcher in `crate::watcher`, or directly from a test/caller); this type
//! takes the shard's write lock (`ShardedLocks`, task #12), finds-or-creates that file's
//! `IncrementalFileState` (task #13) and applies the edit through it, persists the
//! resulting `Cpg` (`WorkspaceStore`, task #11), and bumps the shard/global revision
//! (`Revisions`, task #12) — returning exactly the `SymbolId`s that changed, ready to feed
//! into `ReverseSymbolIndex`'s scoped invalidation.
//!
//! Concurrency note: the per-shard write lock is held for the *entire* apply (incremental
//! reparse + persist + revision bump), not released and re-acquired between steps — this
//! is what makes "the revision I observe corresponds to data I can actually read" hold
//! without extra coordination. Readers only need `ShardedLocks::read` for the same shard
//! to get a consistent snapshot.

use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use web_sitter::language_from_path;
use web_sitter::symbol_id::{SymbolId, build_symbol_table};

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
    /// against the previous state.
    pub async fn apply_file_change(&self, file: &Path, new_source: &[u8]) -> Result<AppliedChange> {
        let shard = self.store.shard_of(file);
        let _write_guard = self.locks.write(&shard).await;

        let changed_symbols = match self.files.entry(file.to_path_buf()) {
            Entry::Occupied(mut occupied) => occupied.get_mut().apply_edit(new_source)?,
            Entry::Vacant(vacant) => {
                let language = language_from_path(&file.to_string_lossy());
                let state = IncrementalFileState::from_source(language, new_source)?;
                let initial_symbols = build_symbol_table(state.cpg()).into_values().collect();
                vacant.insert(state);
                initial_symbols
            }
        };

        let cpg = self
            .files
            .get(file)
            .expect("just inserted or updated above")
            .cpg()
            .clone();
        self.store.put(file, cpg)?;

        let (global_revision, shard_revision) = self.revisions.record_edit(&shard);
        Ok(AppliedChange {
            changed_symbols,
            global_revision,
            shard_revision,
            shard,
        })
    }

    /// Remove `file` from live state, the on-disk store, and bump its shard's revision.
    /// Returns the symbols that were defined in the file just before removal (the "now
    /// gone" set, for the same cross-file-invalidation purpose `apply_file_change`'s
    /// return value serves).
    pub async fn apply_file_removal(&self, file: &Path) -> Result<AppliedChange> {
        let shard = self.store.shard_of(file);
        let _write_guard = self.locks.write(&shard).await;

        let changed_symbols = match self.files.remove(file) {
            Some((_, state)) => build_symbol_table(state.cpg()).into_values().collect(),
            None => BTreeSet::new(),
        };
        self.store.remove(file)?;

        let (global_revision, shard_revision) = self.revisions.record_edit(&shard);
        Ok(AppliedChange {
            changed_symbols,
            global_revision,
            shard_revision,
            shard,
        })
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
}
