//! `LiveIndex`: bridges `store::live_workspace::LiveWorkspace`'s per-file incremental
//! machinery (redb persistence, sharded locks, revision counters — see `store/`) into the
//! query-serving state `WebMcpServer`'s tools actually read (`web_ql::Workspace`,
//! `ReverseSymbolIndex`, `SymbolCallGraph` — see `server.rs`).
//!
//! Why a separate bridge instead of having tools read `LiveWorkspace` directly: tools need
//! *cross-file* facts (`build_cross_file_edges`, the reverse symbol index, the call graph)
//! that `LiveWorkspace` deliberately doesn't know about — it only tracks live per-file
//! state (see its own module docs). `LiveIndex::apply_file_change`/`apply_file_removal`
//! are what a file-watcher event actually calls: drive `LiveWorkspace`'s incremental
//! reparse first (cheap, scoped to the one file), then use its result to update the
//! query-serving structures tools hold handles into.
//!
//! Update strategy, and why it isn't itself scoped/incremental yet: `Workspace` is mutated
//! in place (`upsert_file`/`remove_file`/`build_cross_file_edges`, all `&mut self`), which
//! is genuinely scoped to the changed file *except* `build_cross_file_edges`, which is a
//! full O(all files) rebuild — `Workspace` has no scoped variant of it today.
//! `ReverseSymbolIndex`/`SymbolCallGraph` are rebuilt from scratch every call for the same
//! reason (no incremental `SymbolCallGraph` builder exists, and threading
//! `LayeredSymbolIndex`'s base/overlay split through here — it already solves exactly this
//! for `ReverseSymbolIndex` — is being left as a follow-up rather than bolted on under this
//! task's already-large scope). At monorepo scale this is the next thing worth measuring
//! and optimizing, same spirit as `store::load_test`'s benchmark-driven approach.

use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tokio::sync::{Mutex, RwLock};
use web_ql::Workspace;
use web_ql::symbol_index::ReverseSymbolIndex;

use crate::callgraph::SymbolCallGraph;
use crate::store::live_workspace::{AppliedChange, FileChangeKind, LiveWorkspace};

pub struct LiveIndex {
    live_workspace: Arc<LiveWorkspace>,
    workspace: Arc<RwLock<Workspace>>,
    reverse_index: Arc<ArcSwap<ReverseSymbolIndex>>,
    call_graph: Arc<ArcSwap<SymbolCallGraph>>,
    /// Serializes the whole apply-and-rebuild sequence across concurrent file-change
    /// events. `LiveWorkspace` itself is safe to call concurrently (per-shard locks), but
    /// the *rebuild* steps here (`build_cross_file_edges`, rebuilding `ReverseSymbolIndex`/
    /// `SymbolCallGraph` from the current state of `workspace`) read/write global state —
    /// two concurrent applies interleaving their rebuild steps could publish a
    /// `ReverseSymbolIndex`/`SymbolCallGraph` pair that doesn't correspond to the same
    /// `Workspace` state either one actually produced. One event at a time through the
    /// rebuild keeps that impossible, at the cost of edits to unrelated files serializing
    /// here even though `LiveWorkspace`'s own per-shard locks wouldn't have required it —
    /// a real limitation, and the natural next target once `build_cross_file_edges`/
    /// `ReverseSymbolIndex`/`SymbolCallGraph` gain scoped/incremental update paths of
    /// their own (see module docs).
    apply_lock: Mutex<()>,
}

impl LiveIndex {
    pub fn new(
        live_workspace: Arc<LiveWorkspace>,
        workspace: Arc<RwLock<Workspace>>,
        reverse_index: Arc<ArcSwap<ReverseSymbolIndex>>,
        call_graph: Arc<ArcSwap<SymbolCallGraph>>,
    ) -> Self {
        Self {
            live_workspace,
            workspace,
            reverse_index,
            call_graph,
            apply_lock: Mutex::new(()),
        }
    }

    /// Apply `new_source` as `file`'s new full contents: reparse it through
    /// `LiveWorkspace` (incremental, persisted, revision-stamped), then fold the result
    /// into `Workspace`/`ReverseSymbolIndex`/`SymbolCallGraph` and publish. Matches
    /// `LiveWorkspace::apply_file_change`'s signature/return type so `crate::watcher`'s
    /// pipeline can drive either one interchangeably. A batch-of-one wrapper around
    /// `apply_batch`.
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

    /// Remove `file` from live state. Matches `LiveWorkspace::apply_file_removal`'s
    /// signature/return type for the same reason as `apply_file_change`. A batch-of-one
    /// wrapper around `apply_batch`.
    pub async fn apply_file_removal(&self, file: &Path) -> Result<AppliedChange> {
        let changes = vec![(file.to_path_buf(), FileChangeKind::Removed)];
        let mut results = self.apply_batch(changes).await?;
        Ok(results
            .pop()
            .expect("batch of one always yields one result"))
    }

    /// Apply every `(file, kind)` pair in `changes` as one batch: drives
    /// `LiveWorkspace::apply_batch` once, folds every result into `Workspace` via a loop of
    /// `upsert_file`/`remove_file` calls followed by a **single** `build_cross_file_edges()`
    /// call (not one per file — see module docs on why this is correctness-neutral), then
    /// republishes `ReverseSymbolIndex`/`SymbolCallGraph` **once** for the whole batch
    /// instead of once per file. Returns one `AppliedChange` per input, in the same order.
    pub async fn apply_batch(
        &self,
        changes: Vec<(PathBuf, FileChangeKind)>,
    ) -> Result<Vec<AppliedChange>> {
        let _guard = self.apply_lock.lock().await;

        // `LiveWorkspace::apply_batch` consumes `changes` — keep each file's source bytes
        // (needed for `content_hash`) around separately rather than re-reading the store.
        let file_kinds: Vec<(PathBuf, Option<Vec<u8>>)> = changes
            .iter()
            .map(|(file, kind)| {
                let source = match kind {
                    FileChangeKind::Changed(bytes) => Some(bytes.clone()),
                    FileChangeKind::Removed => None,
                };
                (file.clone(), source)
            })
            .collect();

        let applied = self.live_workspace.apply_batch(changes).await?;

        {
            let mut workspace = self.workspace.write().await;
            for (file, source) in &file_kinds {
                match source {
                    Some(new_source) => {
                        let cpg = self
                            .live_workspace
                            .store()
                            .get(file)
                            .with_context(|| {
                                format!("reading back persisted Cpg for {}", file.display())
                            })?
                            .with_context(|| {
                                format!(
                                    "LiveWorkspace::apply_batch just persisted {} but it's not in the store",
                                    file.display()
                                )
                            })?;
                        workspace.upsert_file(
                            file.clone(),
                            (*cpg).clone(),
                            content_hash(new_source),
                        );
                    }
                    None => {
                        workspace.remove_file(file);
                    }
                }
            }
            workspace.build_cross_file_edges();
        }
        self.republish_derived_indexes().await;

        Ok(applied)
    }

    /// Rebuild `ReverseSymbolIndex`/`SymbolCallGraph` from `workspace`'s current state and
    /// atomically publish both. Full rebuild, not scoped — see module docs.
    async fn republish_derived_indexes(&self) {
        let workspace = self.workspace.read().await;
        let reverse_index = ReverseSymbolIndex::build(
            workspace
                .files
                .iter()
                .map(|(path, idx)| (path.as_path(), idx.cpg.as_ref())),
        );
        let call_graph = SymbolCallGraph::build(&workspace, &reverse_index);
        self.reverse_index.store(Arc::new(reverse_index));
        self.call_graph.store(Arc::new(call_graph));
    }
}

/// A real, edit-sensitive content hash for `Workspace::upsert_file`'s dedup check —
/// `crate::index::build_workspace` always passes a constant `0` (fine for a one-shot batch
/// build where every file is upserted exactly once), but `LiveIndex` upserts the *same*
/// file repeatedly across its lifetime, and `upsert_file` treats an equal hash as "no
/// change, skip" — passing a constant here would make every edit after the first to a
/// given file silently vanish.
fn content_hash(source: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    source.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;
    use web_ql::Workspace as WqWorkspace;
    use web_sitter::symbol_id::build_symbol_table;

    fn open_live_index(dir: &tempfile::TempDir) -> LiveIndex {
        let live_workspace = Arc::new(
            LiveWorkspace::open(
                dir.path().join("store.redb"),
                dir.path().to_path_buf(),
                NonZeroUsize::new(64).unwrap(),
                dir.path().join("snapshots"),
            )
            .unwrap(),
        );
        let registry = web_ql::security_patterns::builtin_endpoint_registry();
        let empty_workspace = WqWorkspace::new(registry);
        let empty_reverse_index = ReverseSymbolIndex::new();
        let empty_call_graph = SymbolCallGraph::build(&empty_workspace, &empty_reverse_index);
        let workspace = Arc::new(RwLock::new(empty_workspace));
        let reverse_index = Arc::new(ArcSwap::new(Arc::new(empty_reverse_index)));
        let call_graph = Arc::new(ArcSwap::new(Arc::new(empty_call_graph)));
        LiveIndex::new(live_workspace, workspace, reverse_index, call_graph)
    }

    #[tokio::test]
    async fn apply_file_change_makes_the_symbol_visible_in_the_workspace_and_reverse_index() {
        let dir = tempfile::tempdir().unwrap();
        let index = open_live_index(&dir);
        let file = dir.path().join("a.cpp");

        index
            .apply_file_change(&file, b"int helper(int y) { return y; }\n")
            .await
            .unwrap();

        let workspace = index.workspace.read().await;
        assert_eq!(workspace.files.len(), 1);
        let cpg = &workspace.files.get(&file).unwrap().cpg;
        let names: std::collections::BTreeSet<String> = build_symbol_table(cpg)
            .into_values()
            .map(|s| s.as_str().to_string())
            .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["cpp:helper".to_string()])
        );

        let reverse_index = index.reverse_index.load();
        assert_eq!(reverse_index.symbol_count(), 1);
    }

    #[tokio::test]
    async fn a_second_edit_to_the_same_file_actually_updates_it() {
        // Regression test for the exact bug `content_hash` exists to prevent: a naive
        // constant content_hash would make upsert_file silently ignore every edit after
        // the first to a given file.
        let dir = tempfile::tempdir().unwrap();
        let index = open_live_index(&dir);
        let file = dir.path().join("a.cpp");

        index
            .apply_file_change(&file, b"int helper(int y) { return y; }\n")
            .await
            .unwrap();
        index
            .apply_file_change(
                &file,
                b"int helper(int y) { return y + 1; }\nint added() { return 2; }\n",
            )
            .await
            .unwrap();

        let workspace = index.workspace.read().await;
        let cpg = &workspace.files.get(&file).unwrap().cpg;
        let names: std::collections::BTreeSet<String> = build_symbol_table(cpg)
            .into_values()
            .map(|s| s.as_str().to_string())
            .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["cpp:helper".to_string(), "cpp:added".to_string()]),
            "the second edit's new function must actually show up — the file must not \
             have been silently treated as unchanged"
        );
    }

    #[tokio::test]
    async fn apply_file_removal_drops_it_from_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let index = open_live_index(&dir);
        let file = dir.path().join("a.cpp");

        index
            .apply_file_change(&file, b"int helper(int y) { return y; }\n")
            .await
            .unwrap();
        assert_eq!(index.workspace.read().await.files.len(), 1);

        index.apply_file_removal(&file).await.unwrap();
        assert_eq!(index.workspace.read().await.files.len(), 0);
        assert_eq!(index.reverse_index.load().symbol_count(), 0);
    }

    #[tokio::test]
    async fn a_new_cross_file_call_is_visible_in_the_rebuilt_call_graph() {
        let dir = tempfile::tempdir().unwrap();
        let index = open_live_index(&dir);
        let callee = dir.path().join("callee.cpp");
        let caller = dir.path().join("caller.cpp");

        index
            .apply_file_change(&callee, b"int helper(int y) { return y; }\n")
            .await
            .unwrap();
        index
            .apply_file_change(&caller, b"int caller() { return helper(1); }\n")
            .await
            .unwrap();

        let reverse_index = index.reverse_index.load_full();
        let helper_id = reverse_index
            .definitions()
            .find(|(id, _)| id.as_str() == "cpp:helper")
            .map(|(id, _)| id.clone())
            .expect("helper must be indexed");

        let call_graph = index.call_graph.load();
        let callers = call_graph.transitive_callers(&helper_id, 5);
        assert!(
            callers.iter().any(|(id, _)| id.as_str() == "cpp:caller"),
            "{callers:?}"
        );
    }

    #[tokio::test]
    async fn apply_batch_makes_every_files_symbols_visible_after_one_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let index = open_live_index(&dir);
        let callee = dir.path().join("callee.cpp");
        let caller = dir.path().join("caller.cpp");

        let results = index
            .apply_batch(vec![
                (
                    callee.clone(),
                    FileChangeKind::Changed(b"int helper(int y) { return y; }\n".to_vec()),
                ),
                (
                    caller.clone(),
                    FileChangeKind::Changed(b"int caller() { return helper(1); }\n".to_vec()),
                ),
            ])
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        let workspace = index.workspace.read().await;
        assert_eq!(workspace.files.len(), 2);
        drop(workspace);

        let reverse_index = index.reverse_index.load_full();
        assert_eq!(reverse_index.symbol_count(), 2);
        let helper_id = reverse_index
            .definitions()
            .find(|(id, _)| id.as_str() == "cpp:helper")
            .map(|(id, _)| id.clone())
            .expect("helper must be indexed");

        let call_graph = index.call_graph.load();
        let callers = call_graph.transitive_callers(&helper_id, 5);
        assert!(
            callers.iter().any(|(id, _)| id.as_str() == "cpp:caller"),
            "the cross-file call must show up after just one batched rebuild: {callers:?}"
        );
    }

    #[tokio::test]
    async fn apply_batch_amortizes_the_rebuild_across_many_files() {
        // Proves the amortization claim via wall-clock comparison rather than a call-
        // counting test seam on web-ql's public API (consistent with this codebase's
        // existing benchmark style, e.g. store::load_test) — a batch of N files should
        // complete in roughly the cost of ONE build_cross_file_edges()/index-rebuild pass,
        // not N of them. Uses the same "baseline single-op latency times a loose
        // multiplier" ceiling pattern store::load_test uses, rather than racing two
        // differently-shaped phases against each other in one test run — that direct-race
        // shape is sensitive to unrelated tests' CPU contention under the default parallel
        // test runner and flaked under load; a precomputed ceiling doesn't have that
        // problem.
        const FILE_COUNT: usize = 40;

        // Baseline: latency of one single-file apply (its own full rebuild included) in an
        // otherwise-empty workspace — the per-file unit the "unamortized" ceiling below is
        // built from. A fresh index per sample (not accumulating files) keeps every sample
        // measuring the same "one file in an empty workspace" cost; a lone cold sample pays
        // one-time warmup the later ones don't (tree-sitter grammar / allocator warmup),
        // same rationale `store::load_test`'s reparse benchmark documents — discard the
        // first sample and average several more.
        const BASELINE_SAMPLES: u32 = 5;
        let mut baseline_total = std::time::Duration::ZERO;
        for i in 0..=BASELINE_SAMPLES {
            let dir = tempfile::tempdir().unwrap();
            let index = open_live_index(&dir);
            let started = std::time::Instant::now();
            index
                .apply_file_change(
                    &dir.path().join("baseline.cpp"),
                    b"int baseline_fn() { return 0; }\n",
                )
                .await
                .unwrap();
            let elapsed = started.elapsed();
            if i > 0 {
                // sample 0 is warmup, discarded
                baseline_total += elapsed;
            }
        }
        let baseline_latency = baseline_total / BASELINE_SAMPLES;

        let dir = tempfile::tempdir().unwrap();
        let index = open_live_index(&dir);
        let changes: Vec<_> = (0..FILE_COUNT)
            .map(|i| {
                let file = dir.path().join(format!("f{i}.cpp"));
                let source = format!("int fn_{i}() {{ return {i}; }}\n").into_bytes();
                (file, FileChangeKind::Changed(source))
            })
            .collect();

        let batched_start = std::time::Instant::now();
        index.apply_batch(changes).await.unwrap();
        let batched_elapsed = batched_start.elapsed();

        // Loose ceiling: if the rebuild were NOT amortized (one full rebuild per file, as
        // before this change), FILE_COUNT files would cost roughly FILE_COUNT times the
        // single-file baseline. A batched apply doing ~1 rebuild instead of FILE_COUNT
        // should land well under that. Half is already a generous margin over the "should
        // be ~1/FILE_COUNT-th the cost" expectation; this test flaked under `cargo test`'s
        // default parallel-test contention with a tighter, single-sample baseline (see
        // `store::load_test`'s own documented experience with the same class of flakiness)
        // — the averaged, warmup-discarded baseline above is the fix, not a tighter margin.
        let unamortized_ceiling = baseline_latency * (FILE_COUNT as u32) / 2;
        assert!(
            batched_elapsed < unamortized_ceiling,
            "batching {FILE_COUNT} files took {batched_elapsed:?}, expected well under \
             {unamortized_ceiling:?} (baseline single-file latency {baseline_latency:?} × \
             {FILE_COUNT} / 2) if the rebuild is really amortized to ~1 pass"
        );
    }

    #[tokio::test]
    async fn apply_batch_mixing_change_and_removal_updates_workspace_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let index = open_live_index(&dir);
        let existing = dir.path().join("existing.cpp");
        let fresh = dir.path().join("fresh.cpp");

        index
            .apply_file_change(&existing, b"int existing_fn() { return 0; }\n")
            .await
            .unwrap();
        assert_eq!(index.workspace.read().await.files.len(), 1);

        index
            .apply_batch(vec![
                (existing.clone(), FileChangeKind::Removed),
                (
                    fresh.clone(),
                    FileChangeKind::Changed(b"int fresh_fn() { return 1; }\n".to_vec()),
                ),
            ])
            .await
            .unwrap();

        let workspace = index.workspace.read().await;
        assert_eq!(workspace.files.len(), 1, "fresh.cpp is now the only file");
        assert!(workspace.files.contains_key(&fresh));
        assert!(!workspace.files.contains_key(&existing));
        drop(workspace);

        let reverse_index = index.reverse_index.load();
        assert_eq!(reverse_index.symbol_count(), 1);
    }
}
