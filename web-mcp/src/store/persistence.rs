//! On-disk fact store: persists per-file `Cpg` state in an embedded KV database (`redb`),
//! reusing the same bincode+lz4 serialization pattern `IncrementalCpgGenerator::save_state`/
//! `load_state` already use. This is the durable backing store `WorkspaceStore` (in
//! `store/mod.rs`) caches hot shards over — plain `redb`, not a container of every file's
//! `Cpg` in memory, is what makes a 100k+ file monorepo's cold-start and steady-state
//! memory footprint tractable.

use std::path::Path;

use anyhow::{Context, Result};
use redb::{Database, ReadableTableMetadata, TableDefinition};
use web_sitter::Cpg;

/// Bumped whenever the on-disk encoding of a stored `Cpg` changes incompatibly, mirroring
/// `incremental.rs`'s `CACHE_FORMAT_VERSION` guard — a version mismatch means "treat as a
/// cache miss and re-derive", never "attempt to decode and hope."
const STORE_FORMAT_VERSION: u32 = 1;

const CPG_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("cpg_by_path");

/// One versioned, compressed `Cpg` blob as stored on disk.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredCpg {
    format_version: u32,
    cpg: Cpg,
}

/// Embedded on-disk fact store, keyed by absolute file path. Safe to share across threads
/// (`redb::Database` is internally synchronized); callers needing coordinated multi-shard
/// transactions still need their own locking (see `store/shard.rs`, wired in a later task).
pub struct PersistentStore {
    db: Database,
}

impl PersistentStore {
    /// Open (or create) the on-disk store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path.as_ref())
            .with_context(|| format!("opening fact store at {}", path.as_ref().display()))?;
        // Ensure the table exists even on a brand-new database — otherwise the first
        // `get` on an empty store would need to special-case "table not found" as
        // "definitely a cache miss" vs. a real I/O error, which redb already
        // distinguishes for us once the table has been created at least once.
        let write_txn = db
            .begin_write()
            .context("opening initial write transaction")?;
        {
            write_txn
                .open_table(CPG_TABLE)
                .context("creating cpg_by_path table")?;
        }
        write_txn
            .commit()
            .context("committing initial table creation")?;
        Ok(Self { db })
    }

    /// Persist `cpg` under `file_path`, overwriting any prior entry.
    pub fn put(&self, file_path: &str, cpg: &Cpg) -> Result<()> {
        let stored = StoredCpg {
            format_version: STORE_FORMAT_VERSION,
            cpg: cpg.clone(),
        };
        let encoded = bincode::serde::encode_to_vec(&stored, bincode::config::standard())
            .context("encoding Cpg for on-disk storage")?;
        let payload = lz4_flex::compress_prepend_size(&encoded);

        let write_txn = self.db.begin_write().context("opening write transaction")?;
        {
            let mut table = write_txn
                .open_table(CPG_TABLE)
                .context("opening cpg_by_path table")?;
            table
                .insert(file_path, payload.as_slice())
                .with_context(|| format!("writing {file_path} to fact store"))?;
        }
        write_txn.commit().context("committing fact store write")?;
        Ok(())
    }

    /// Load the `Cpg` stored under `file_path`, or `None` if absent. A format-version
    /// mismatch is treated as absence (the caller should re-derive and `put` again),
    /// never as an error — this is exactly the "cache miss on version bump" contract
    /// `incremental.rs::load_state` already follows.
    pub fn get(&self, file_path: &str) -> Result<Option<Cpg>> {
        let read_txn = self.db.begin_read().context("opening read transaction")?;
        let table = read_txn
            .open_table(CPG_TABLE)
            .context("opening cpg_by_path table")?;
        let Some(entry) = table.get(file_path).context("reading from fact store")? else {
            return Ok(None);
        };
        let payload = entry.value();
        let decompressed = lz4_flex::decompress_size_prepended(payload)
            .with_context(|| format!("decompressing stored Cpg for {file_path}"))?;
        let (stored, _): (StoredCpg, usize) =
            bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())
                .with_context(|| format!("decoding stored Cpg for {file_path}"))?;
        if stored.format_version != STORE_FORMAT_VERSION {
            return Ok(None);
        }
        Ok(Some(stored.cpg))
    }

    /// Remove any entry stored under `file_path`. Safe to call when absent (no-op).
    pub fn remove(&self, file_path: &str) -> Result<()> {
        let write_txn = self.db.begin_write().context("opening write transaction")?;
        {
            let mut table = write_txn
                .open_table(CPG_TABLE)
                .context("opening cpg_by_path table")?;
            table
                .remove(file_path)
                .with_context(|| format!("removing {file_path} from fact store"))?;
        }
        write_txn
            .commit()
            .context("committing fact store removal")?;
        Ok(())
    }

    /// Number of entries currently persisted.
    pub fn len(&self) -> Result<u64> {
        let read_txn = self.db.begin_read().context("opening read transaction")?;
        let table = read_txn
            .open_table(CPG_TABLE)
            .context("opening cpg_by_path table")?;
        table.len().context("counting fact store entries")
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
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

    #[test]
    fn put_then_get_round_trips_a_cpg() {
        let dir = tempfile::tempdir().unwrap();
        let store = PersistentStore::open(dir.path().join("store.redb")).unwrap();
        let cpg = sample_cpg("int helper(int y) { return y; }");

        store.put("a.cpp", &cpg).unwrap();
        let loaded = store.get("a.cpp").unwrap().expect("entry must be present");

        assert_eq!(loaded.ast.len(), cpg.ast.len());
        assert_eq!(loaded.language, cpg.language);
    }

    #[test]
    fn get_returns_none_for_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = PersistentStore::open(dir.path().join("store.redb")).unwrap();
        assert!(store.get("does_not_exist.cpp").unwrap().is_none());
    }

    #[test]
    fn remove_deletes_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = PersistentStore::open(dir.path().join("store.redb")).unwrap();
        let cpg = sample_cpg("int helper() { return 1; }");
        store.put("a.cpp", &cpg).unwrap();
        assert!(store.get("a.cpp").unwrap().is_some());

        store.remove("a.cpp").unwrap();
        assert!(store.get("a.cpp").unwrap().is_none());
    }

    #[test]
    fn put_overwrites_an_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = PersistentStore::open(dir.path().join("store.redb")).unwrap();
        store
            .put("a.cpp", &sample_cpg("int one() { return 1; }"))
            .unwrap();
        store
            .put(
                "a.cpp",
                &sample_cpg("int two() { return 2; }\nint three() { return 3; }"),
            )
            .unwrap();

        let loaded = store.get("a.cpp").unwrap().unwrap();
        let names: std::collections::BTreeSet<_> =
            loaded.ast.values().filter_map(|n| n.name.clone()).collect();
        assert!(names.contains("two"));
        assert!(names.contains("three"));
        assert!(!names.contains("one"));
    }

    #[test]
    fn len_tracks_entry_count() {
        let dir = tempfile::tempdir().unwrap();
        let store = PersistentStore::open(dir.path().join("store.redb")).unwrap();
        assert!(store.is_empty().unwrap());

        store
            .put("a.cpp", &sample_cpg("int a() { return 1; }"))
            .unwrap();
        store
            .put("b.cpp", &sample_cpg("int b() { return 2; }"))
            .unwrap();
        assert_eq!(store.len().unwrap(), 2);

        store.remove("a.cpp").unwrap();
        assert_eq!(store.len().unwrap(), 1);
    }

    #[test]
    fn reopening_the_same_path_persists_data_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("store.redb");
        {
            let store = PersistentStore::open(&db_path).unwrap();
            store
                .put("a.cpp", &sample_cpg("int a() { return 1; }"))
                .unwrap();
        }
        let reopened = PersistentStore::open(&db_path).unwrap();
        assert!(reopened.get("a.cpp").unwrap().is_some());
    }
}
