//! **web-ql** — ScuzzQL: a Datalog-inspired query language over the CPG IR
//! with taint tracking, CFG analysis, DFG reachability, and an integrated
//! three-phase scanning pipeline.

pub mod lexer;
pub mod ast;
pub mod parser;
pub mod types;
pub mod ir;
pub mod planner;
pub mod cfg;
pub mod dfg;
pub mod taint;
pub mod engine;
pub mod finding;
pub mod library;
pub mod workspace;
pub mod loader;

// Re-export the primary public API surface.
pub use parser::parse_rule_file;
pub use planner::Planner;
pub use loader::{compile_rules, load_rules, load_rules_dir, load_cpg};
pub use workspace::Workspace;
pub use finding::Finding;
pub use ir::RuleSet;
pub use taint::EndpointRegistry;
