//! Persistent findings store: durable open/fixed/suppressed status tracking for security
//! findings, keyed by a stable fingerprint (rule id + defining symbol + file) rather than
//! an exact line/column — a cosmetic edit elsewhere in the same function shouldn't make a
//! previously-tracked finding look like a brand-new one.
//!
//! This is what turns `run_security_scan` from "here's what's wrong right now" into
//! "here's what's wrong, and here's what changed since last time" across sessions and
//! process restarts: a finding seen again after being marked `Fixed` is automatically
//! reopened (a regression), a finding no longer observed in a scan that covered its file
//! is automatically marked `Fixed`, and `Suppressed` findings stay suppressed (still
//! tracked, just not surfaced as actionable) until a caller explicitly un-suppresses them.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

const FINDINGS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("findings_by_fingerprint");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    Open,
    Fixed,
    Suppressed,
}

impl FindingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingStatus::Open => "open",
            FindingStatus::Fixed => "fixed",
            FindingStatus::Suppressed => "suppressed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(FindingStatus::Open),
            "fixed" => Some(FindingStatus::Fixed),
            "suppressed" => Some(FindingStatus::Suppressed),
            _ => None,
        }
    }
}

/// A tracked finding's durable state, plus enough denormalized context (rule/message/
/// location) that a caller can display it without re-running the scan that produced it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingRecord {
    pub status: FindingStatus,
    /// The revision (see `store::revision::Revisions`) at which this finding was first
    /// observed.
    pub first_seen_revision: u64,
    /// The revision at which this finding was most recently observed by a scan. Not
    /// bumped by `set_status` alone — only by `record_seen`/`sweep_fixed`, since those are
    /// the operations that actually re-ran a scan and looked for it.
    pub last_seen_revision: u64,
    pub rule_id: String,
    pub message: String,
    pub file: String,
    pub line: u32,
}

/// Compute a fingerprint stable across cosmetic/unrelated edits: the rule that matched,
/// the enclosing symbol if one could be resolved (preferred — survives the finding's line
/// moving within the same function), or the file path as a fallback for findings with no
/// resolvable enclosing symbol (e.g. file-level/global-scope matches).
pub fn fingerprint(rule_id: &str, symbol_id: Option<&str>, file: &str) -> String {
    match symbol_id {
        Some(id) => format!("{rule_id}::symbol:{id}"),
        None => format!("{rule_id}::file:{file}"),
    }
}

pub struct FindingsStore {
    db: Database,
}

impl FindingsStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path.as_ref())
            .with_context(|| format!("opening findings store at {}", path.as_ref().display()))?;
        let write_txn = db
            .begin_write()
            .context("opening initial write transaction")?;
        {
            write_txn
                .open_table(FINDINGS_TABLE)
                .context("creating findings_by_fingerprint table")?;
        }
        write_txn
            .commit()
            .context("committing initial table creation")?;
        Ok(Self { db })
    }

    /// Record that `finding_id` was observed by a scan at `revision`. First sight creates
    /// a new `Open` record. A later sight bumps `last_seen_revision`; if the record had
    /// been `Fixed`, seeing it again means it regressed, so it's reopened to `Open`.
    /// `Suppressed` findings are left `Suppressed` — a caller explicitly chose to silence
    /// this one, and a scan re-finding the same underlying issue shouldn't override that.
    pub fn record_seen(
        &self,
        finding_id: &str,
        revision: u64,
        rule_id: &str,
        message: &str,
        file: &str,
        line: u32,
    ) -> Result<FindingRecord> {
        let existing = self.get(finding_id)?;
        let record = match existing {
            Some(mut record) => {
                record.last_seen_revision = revision;
                record.message = message.to_string();
                record.line = line;
                if record.status == FindingStatus::Fixed {
                    record.status = FindingStatus::Open;
                }
                record
            }
            None => FindingRecord {
                status: FindingStatus::Open,
                first_seen_revision: revision,
                last_seen_revision: revision,
                rule_id: rule_id.to_string(),
                message: message.to_string(),
                file: file.to_string(),
                line,
            },
        };
        self.put(finding_id, &record)?;
        Ok(record)
    }

    pub fn get(&self, finding_id: &str) -> Result<Option<FindingRecord>> {
        let read_txn = self.db.begin_read().context("opening read transaction")?;
        let table = read_txn
            .open_table(FINDINGS_TABLE)
            .context("opening findings table")?;
        let Some(entry) = table
            .get(finding_id)
            .context("reading from findings store")?
        else {
            return Ok(None);
        };
        let (record, _): (FindingRecord, usize) =
            bincode::serde::decode_from_slice(entry.value(), bincode::config::standard())
                .with_context(|| format!("decoding finding record for {finding_id}"))?;
        Ok(Some(record))
    }

    /// Explicitly set `finding_id`'s status — the operation behind `record_finding_status`.
    /// Errors if the finding has never been seen (nothing to set a status *on*); a status
    /// can only be recorded for a finding a scan has actually produced at least once via
    /// `record_seen`.
    pub fn set_status(&self, finding_id: &str, status: FindingStatus) -> Result<FindingRecord> {
        let mut record = self
            .get(finding_id)?
            .with_context(|| format!("no finding record for {finding_id}: never seen by a scan"))?;
        record.status = status;
        self.put(finding_id, &record)?;
        Ok(record)
    }

    /// After a scan covering `scanned_files`, mark any `Open` record whose `file` is among
    /// those but whose id isn't in `seen_ids` as `Fixed` — the finding used to be there and
    /// the file was actually re-scanned, so its absence means it's genuinely gone, not just
    /// "outside this scan's scope." Returns the finding ids transitioned to `Fixed`.
    pub fn sweep_fixed(
        &self,
        scanned_files: &HashSet<String>,
        seen_ids: &HashSet<String>,
        revision: u64,
    ) -> Result<Vec<String>> {
        let to_fix: Vec<(String, FindingRecord)> = {
            let read_txn = self.db.begin_read().context("opening read transaction")?;
            let table = read_txn
                .open_table(FINDINGS_TABLE)
                .context("opening findings table")?;
            table
                .iter()
                .context("iterating findings table")?
                .filter_map(|entry| {
                    let (key, value) = entry.ok()?;
                    let (record, _): (FindingRecord, usize) = bincode::serde::decode_from_slice(
                        value.value(),
                        bincode::config::standard(),
                    )
                    .ok()?;
                    Some((key.value().to_string(), record))
                })
                .filter(|(id, record)| {
                    record.status == FindingStatus::Open
                        && scanned_files.contains(&record.file)
                        && !seen_ids.contains(id)
                })
                .collect()
        };

        let mut fixed_ids = Vec::with_capacity(to_fix.len());
        for (id, mut record) in to_fix {
            record.status = FindingStatus::Fixed;
            record.last_seen_revision = revision;
            self.put(&id, &record)?;
            fixed_ids.push(id);
        }
        Ok(fixed_ids)
    }

    fn put(&self, finding_id: &str, record: &FindingRecord) -> Result<()> {
        let encoded = bincode::serde::encode_to_vec(record, bincode::config::standard())
            .context("encoding finding record")?;
        let write_txn = self.db.begin_write().context("opening write transaction")?;
        {
            let mut table = write_txn
                .open_table(FINDINGS_TABLE)
                .context("opening findings table")?;
            table
                .insert(finding_id, encoded.as_slice())
                .with_context(|| format!("writing finding record for {finding_id}"))?;
        }
        write_txn.commit().context("committing findings write")?;
        Ok(())
    }

    pub fn len(&self) -> Result<u64> {
        let read_txn = self.db.begin_read().context("opening read transaction")?;
        let table = read_txn
            .open_table(FINDINGS_TABLE)
            .context("opening findings table")?;
        table.len().context("counting findings store entries")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_store(dir: &tempfile::TempDir) -> FindingsStore {
        FindingsStore::open(dir.path().join("findings.redb")).unwrap()
    }

    #[test]
    fn fingerprint_prefers_symbol_over_file() {
        assert_eq!(
            fingerprint("cwe-89", Some("cpp:run"), "a.cpp"),
            fingerprint("cwe-89", Some("cpp:run"), "b.cpp"),
            "the same rule+symbol must fingerprint identically regardless of which file \
             happens to be passed alongside it (symbol already implies the file)"
        );
        assert_ne!(
            fingerprint("cwe-89", None, "a.cpp"),
            fingerprint("cwe-89", None, "b.cpp"),
            "without a resolvable symbol, file must distinguish otherwise-identical findings"
        );
    }

    #[test]
    fn first_sight_creates_an_open_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);

        let record = store
            .record_seen("fp1", 1, "cwe-89", "sql injection", "a.cpp", 10)
            .unwrap();
        assert_eq!(record.status, FindingStatus::Open);
        assert_eq!(record.first_seen_revision, 1);
        assert_eq!(record.last_seen_revision, 1);
    }

    #[test]
    fn seeing_it_again_bumps_last_seen_but_not_first_seen() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);

        store
            .record_seen("fp1", 1, "cwe-89", "sql injection", "a.cpp", 10)
            .unwrap();
        let record = store
            .record_seen("fp1", 5, "cwe-89", "sql injection", "a.cpp", 12)
            .unwrap();
        assert_eq!(record.first_seen_revision, 1);
        assert_eq!(record.last_seen_revision, 5);
        assert_eq!(record.line, 12, "line context should refresh on re-sight");
    }

    #[test]
    fn a_fixed_finding_seen_again_is_reopened() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);

        store
            .record_seen("fp1", 1, "cwe-89", "sql injection", "a.cpp", 10)
            .unwrap();
        store.set_status("fp1", FindingStatus::Fixed).unwrap();

        let record = store
            .record_seen("fp1", 2, "cwe-89", "sql injection", "a.cpp", 10)
            .unwrap();
        assert_eq!(
            record.status,
            FindingStatus::Open,
            "a fixed finding regressing must be reopened"
        );
    }

    #[test]
    fn a_suppressed_finding_stays_suppressed_when_seen_again() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);

        store
            .record_seen("fp1", 1, "cwe-89", "sql injection", "a.cpp", 10)
            .unwrap();
        store.set_status("fp1", FindingStatus::Suppressed).unwrap();

        let record = store
            .record_seen("fp1", 2, "cwe-89", "sql injection", "a.cpp", 10)
            .unwrap();
        assert_eq!(record.status, FindingStatus::Suppressed);
    }

    #[test]
    fn set_status_errors_for_a_finding_never_seen() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);
        assert!(
            store
                .set_status("never-seen", FindingStatus::Fixed)
                .is_err()
        );
    }

    #[test]
    fn sweep_fixed_marks_open_findings_absent_from_a_rescan_of_their_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);

        store
            .record_seen("fp1", 1, "cwe-89", "sql injection", "a.cpp", 10)
            .unwrap();
        store
            .record_seen("fp2", 1, "cwe-78", "command injection", "b.cpp", 20)
            .unwrap();

        // Re-scan a.cpp only; fp1 is no longer found there, fp2's file wasn't rescanned at
        // all so it must be left alone even though it's also absent from `seen_ids`.
        let scanned_files: HashSet<String> = HashSet::from(["a.cpp".to_string()]);
        let seen_ids: HashSet<String> = HashSet::new();
        let fixed = store.sweep_fixed(&scanned_files, &seen_ids, 2).unwrap();

        assert_eq!(fixed, vec!["fp1".to_string()]);
        assert_eq!(
            store.get("fp1").unwrap().unwrap().status,
            FindingStatus::Fixed
        );
        assert_eq!(
            store.get("fp2").unwrap().unwrap().status,
            FindingStatus::Open,
            "fp2's file was never rescanned, so it must not be swept"
        );
    }

    #[test]
    fn sweep_fixed_does_not_touch_already_suppressed_findings() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);

        store
            .record_seen("fp1", 1, "cwe-89", "sql injection", "a.cpp", 10)
            .unwrap();
        store.set_status("fp1", FindingStatus::Suppressed).unwrap();

        let scanned_files: HashSet<String> = HashSet::from(["a.cpp".to_string()]);
        let fixed = store
            .sweep_fixed(&scanned_files, &HashSet::new(), 2)
            .unwrap();
        assert!(fixed.is_empty());
        assert_eq!(
            store.get("fp1").unwrap().unwrap().status,
            FindingStatus::Suppressed
        );
    }

    #[test]
    fn findings_persist_across_store_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.redb");
        {
            let store = FindingsStore::open(&path).unwrap();
            store
                .record_seen("fp1", 1, "cwe-89", "sql injection", "a.cpp", 10)
                .unwrap();
        }
        let reopened = FindingsStore::open(&path).unwrap();
        assert!(reopened.get("fp1").unwrap().is_some());
        assert_eq!(reopened.len().unwrap(), 1);
    }
}
