//! File-watcher + debounced edit pipeline: the last piece connecting a real filesystem
//! change to `LiveWorkspace::apply_file_change`/`apply_file_removal`. Wraps
//! `notify-debouncer-mini` (debounce window per the design's 50-150ms target) so a burst
//! of writes to the same file — a save that touches the file twice, an editor's
//! atomic-rename-based save — collapses into one re-index instead of several.
//!
//! "Fall back to full-file reparse when a byte-diff isn't available" (the design's other
//! requirement for this task) needs no special-casing here: every event, however it was
//! produced (edit, external rewrite, rename-over), is handled identically — read the
//! file's current full contents and hand them to `LiveWorkspace::apply_file_change`,
//! which diffs against whatever it last saw via `compute_edit`. An external full-file
//! rewrite is simply a `TextEdit` with an unusually large span; there is no separate path
//! to fall back *to*.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use notify_debouncer_mini::notify::RecursiveMode;
use notify_debouncer_mini::{DebounceEventResult, Debouncer, new_debouncer};
use tokio::sync::mpsc;

use crate::store::live_workspace::{AppliedChange, LiveWorkspace};

/// Default debounce window — within the design's stated 50-150ms target.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(100);

/// One coalesced filesystem change, ready to hand to `LiveWorkspace`.
#[derive(Debug, Clone)]
pub struct FileChangeEvent {
    pub path: PathBuf,
    /// True when the path no longer exists on disk at debounce-settle time (covers
    /// delete and rename-away; a rename-into-existence just looks like a normal change
    /// to the new path, which is the correct behavior — it needs indexing like any other
    /// new/changed file).
    pub removed: bool,
}

/// Start watching `root` recursively, debounced by `debounce_window`. Returns the
/// `Debouncer` guard (drop it to stop watching — keep it alive for as long as you want
/// events) and a channel of coalesced change events.
pub fn watch(
    root: &Path,
    debounce_window: Duration,
) -> Result<(
    Debouncer<notify_debouncer_mini::notify::RecommendedWatcher>,
    mpsc::UnboundedReceiver<FileChangeEvent>,
)> {
    let (tx, rx) = mpsc::unbounded_channel();

    let mut debouncer = new_debouncer(debounce_window, move |result: DebounceEventResult| {
        let events = match result {
            Ok(events) => events,
            Err(err) => {
                tracing::warn!(?err, "file watcher error");
                return;
            }
        };
        for event in events {
            let removed = !event.path.exists();
            // The channel's other end may already be gone (server shutting down) — a
            // send failure here is expected in that case, not worth logging as an error.
            let _ = tx.send(FileChangeEvent {
                path: event.path,
                removed,
            });
        }
    })
    .context("creating file watcher")?;

    debouncer
        .watcher()
        .watch(root, RecursiveMode::Recursive)
        .with_context(|| format!("watching {}", root.display()))?;

    Ok((debouncer, rx))
}

/// Drive `workspace` from a stream of watcher events until the channel closes (the
/// `Debouncer` was dropped). Returns once `rx` is exhausted — callers typically
/// `tokio::spawn` this alongside keeping the `Debouncer` guard alive elsewhere. Takes an
/// `Arc` (rather than a bare reference) because this is meant to be spawned as a `'static`
/// background task, exactly like `WebMcpServer` already `Arc`-wraps its other shared state.
pub async fn run_pipeline(
    workspace: std::sync::Arc<LiveWorkspace>,
    mut rx: mpsc::UnboundedReceiver<FileChangeEvent>,
) {
    while let Some(event) = rx.recv().await {
        if let Err(err) = apply_one(&workspace, &event).await {
            tracing::warn!(path = %event.path.display(), ?err, "failed to apply file change");
        }
    }
}

async fn apply_one(workspace: &LiveWorkspace, event: &FileChangeEvent) -> Result<AppliedChange> {
    if event.removed {
        return workspace.apply_file_removal(&event.path).await;
    }
    let contents = tokio::fs::read(&event.path)
        .await
        .with_context(|| format!("reading changed file {}", event.path.display()))?;
    workspace.apply_file_change(&event.path, &contents).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;
    use std::time::Duration as StdDuration;

    async fn recv_with_timeout(
        rx: &mut mpsc::UnboundedReceiver<FileChangeEvent>,
    ) -> Option<FileChangeEvent> {
        tokio::time::timeout(StdDuration::from_secs(5), rx.recv())
            .await
            .ok()
            .flatten()
    }

    #[tokio::test]
    async fn detects_a_new_file_write() {
        let dir = tempfile::tempdir().unwrap();
        let (_debouncer, mut rx) = watch(dir.path(), Duration::from_millis(50)).unwrap();

        let file = dir.path().join("a.cpp");
        std::fs::write(&file, "int a() { return 1; }\n").unwrap();

        let event = recv_with_timeout(&mut rx)
            .await
            .expect("must receive a change event");
        assert_eq!(event.path, file);
        assert!(!event.removed);
    }

    #[tokio::test]
    async fn detects_a_file_removal() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.cpp");
        std::fs::write(&file, "int a() { return 1; }\n").unwrap();

        let (_debouncer, mut rx) = watch(dir.path(), Duration::from_millis(50)).unwrap();
        std::fs::remove_file(&file).unwrap();

        let event = recv_with_timeout(&mut rx)
            .await
            .expect("must receive a removal event");
        assert_eq!(event.path, file);
        assert!(event.removed);
    }

    #[tokio::test]
    async fn run_pipeline_applies_a_real_watched_change_to_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = std::sync::Arc::new(
            LiveWorkspace::open(
                dir.path().join("store.redb"),
                dir.path().to_path_buf(),
                NonZeroUsize::new(64).unwrap(),
            )
            .unwrap(),
        );

        let (_debouncer, rx) = watch(dir.path(), Duration::from_millis(50)).unwrap();
        let pipeline = tokio::spawn(run_pipeline(std::sync::Arc::clone(&workspace), rx));

        let file = dir.path().join("a.cpp");
        std::fs::write(&file, "int a() { return 1; }\n").unwrap();

        // Poll for the pipeline to have processed the write — real FS + debounce timing,
        // not instantaneous.
        let deadline = tokio::time::Instant::now() + StdDuration::from_secs(5);
        while workspace.live_file_count() == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        assert_eq!(
            workspace.live_file_count(),
            1,
            "pipeline must have applied the watched change"
        );

        drop(_debouncer);
        let _ = tokio::time::timeout(StdDuration::from_secs(2), pipeline).await;
    }
}
