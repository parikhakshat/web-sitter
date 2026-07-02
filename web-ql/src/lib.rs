//! **web-ql** — ScuzzQL: a Datalog-inspired query language over the CPG IR
//! with taint tracking, CFG analysis, DFG reachability, and an integrated
//! three-phase scanning pipeline.

pub mod alias;
pub mod ast;
pub mod cfg;
pub mod dfg;
pub mod engine;
pub mod finding;
pub mod guard;
pub mod ir;
pub mod kind_index;
pub mod layered_symbol_index;
pub mod lexer;
pub mod loader;
pub mod node_ref;
pub mod nullability;
pub mod parser;
pub mod planner;
pub mod security_patterns;
pub mod size_tracking;
pub mod symbol_index;
pub mod symbolic;
pub mod taint;
pub mod types;
pub mod workspace;

// Re-export the primary public API surface.
pub use finding::Finding;
pub use ir::RuleSet;
pub use layered_symbol_index::LayeredSymbolIndex;
pub use loader::{compile_rules, load_cpg, load_rules, load_rules_dir};
pub use node_ref::NodeRef;
pub use parser::parse_rule_file;
pub use planner::Planner;
pub use security_patterns::builtin_endpoint_registry;
pub use taint::EndpointRegistry;
pub use workspace::Workspace;
