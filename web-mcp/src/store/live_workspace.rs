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
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::Result;
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
}

impl LiveWorkspace {
    pub fn open(
        db_path: impl AsRef<Path>,
        root: PathBuf,
        hot_capacity: NonZeroUsize,
    ) -> Result<Self> {
        Ok(Self {
            store: WorkspaceStore::open(db_path, root.clone(), hot_capacity)?,
            locks: ShardedLocks::new(),
            revisions: Revisions::new(),
            files: DashMap::new(),
            root,
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_workspace(dir: &tempfile::TempDir) -> LiveWorkspace {
        LiveWorkspace::open(
            dir.path().join("store.redb"),
            dir.path().to_path_buf(),
            NonZeroUsize::new(64).unwrap(),
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
        let file = dir.path().join("a.cpp");
        {
            let workspace = LiveWorkspace::open(
                db_path.clone(),
                dir.path().to_path_buf(),
                NonZeroUsize::new(64).unwrap(),
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
        )
        .unwrap();
        assert_eq!(reopened.store.persisted_len().unwrap(), 1);
    }
}
