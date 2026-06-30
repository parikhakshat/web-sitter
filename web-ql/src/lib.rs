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
pub mod alias;
pub mod size_tracking;
pub mod symbolic;
pub mod nullability;
pub mod taint;
pub mod engine;
pub mod finding;
pub mod workspace;
pub mod loader;
pub mod security_patterns;

// Re-export the primary public API surface.
pub use parser::parse_rule_file;
pub use planner::Planner;
pub use loader::{compile_rules, load_rules, load_rules_dir, load_cpg};
pub use workspace::Workspace;
pub use finding::Finding;
pub use ir::RuleSet;
pub use taint::EndpointRegistry;
pub use security_patterns::builtin_endpoint_registry;
