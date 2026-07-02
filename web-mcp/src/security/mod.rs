//! Variant-analysis building blocks: turning one known bug instance into a query that
//! finds structurally similar ones elsewhere in the codebase. `generalize` is the
//! standalone module for this task; the MCP tools that call it (`find_variants`/
//! `explain_variant`) are follow-up work.

pub mod generalize;
