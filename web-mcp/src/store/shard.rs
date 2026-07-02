//! Shard-granularity computation: which shard a file belongs to. Sharding by directory
//! matches how large monorepos are naturally partitioned (a directory is usually a
//! cohesive module/package) and is what enables parallel warm-indexing and, in a later
//! task, per-shard locking so concurrent tool calls touching unrelated shards don't block
//! each other.

use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShardId(pub String);

impl std::fmt::Display for ShardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The shard a file belongs to: its parent directory, relative to `root`. Files directly
/// under `root` share the shard id `"."`. `file` need not exist on disk (this is a pure
/// path computation); if `file` isn't under `root` at all, falls back to the file's own
/// parent directory as an absolute-path shard id rather than panicking — callers outside
/// the indexed root (shouldn't normally happen) still get a stable, if degenerate, shard.
pub fn shard_of(file: &Path, root: &Path) -> ShardId {
    let relative = file.strip_prefix(root).unwrap_or(file);
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let id = if parent.as_os_str().is_empty() {
        ".".to_string()
    } else {
        normalize(parent)
    };
    ShardId(id)
}

/// Render a directory path using forward slashes regardless of platform, so shard ids
/// are stable across OSes (the on-disk store and any future distributed indexing must
/// agree on shard identity independent of how paths are joined locally).
fn normalize(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn files_in_the_same_directory_share_a_shard() {
        let root = PathBuf::from("/repo");
        let a = shard_of(&PathBuf::from("/repo/src/lib.rs"), &root);
        let b = shard_of(&PathBuf::from("/repo/src/main.rs"), &root);
        assert_eq!(a, b);
        assert_eq!(a.0, "src");
    }

    #[test]
    fn files_in_different_directories_have_different_shards() {
        let root = PathBuf::from("/repo");
        let a = shard_of(&PathBuf::from("/repo/src/lib.rs"), &root);
        let b = shard_of(&PathBuf::from("/repo/tests/it.rs"), &root);
        assert_ne!(a, b);
    }

    #[test]
    fn root_level_files_share_the_dot_shard() {
        let root = PathBuf::from("/repo");
        let a = shard_of(&PathBuf::from("/repo/README.md"), &root);
        assert_eq!(a.0, ".");
    }

    #[test]
    fn nested_directories_produce_a_slash_joined_shard_id() {
        let root = PathBuf::from("/repo");
        let a = shard_of(&PathBuf::from("/repo/a/b/c/file.rs"), &root);
        assert_eq!(a.0, "a/b/c");
    }

    #[test]
    fn file_outside_root_falls_back_to_its_own_parent() {
        let root = PathBuf::from("/repo");
        let a = shard_of(&PathBuf::from("/elsewhere/file.rs"), &root);
        assert_eq!(a.0, "/elsewhere");
    }
}
