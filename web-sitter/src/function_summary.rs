use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Effect that a function has on a parameter at a specific index.
///
/// Used in `FunctionSummary.param_effects` in place of the old separate
/// `sink_params`, `frees_param`, `tainted_params`, and `returned_params` fields.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamEffect {
    /// Tainted data passed at this index constitutes a vulnerability at the call site.
    Sink(usize),
    /// The pointer at this index is freed by the function.
    Frees(usize),
    /// The function writes tainted data *into* this output parameter.
    /// After the call, the caller's variable at this argument position is tainted.
    TaintOut(usize),
    /// If this parameter is tainted, the function's return value is also tainted.
    TaintReturn(usize),
}

impl ParamEffect {
    pub fn index(&self) -> usize {
        match self {
            ParamEffect::Sink(i)
            | ParamEffect::Frees(i)
            | ParamEffect::TaintOut(i)
            | ParamEffect::TaintReturn(i) => *i,
        }
    }
}

/// Unified per-function summary used across the entire analysis pipeline.
///
/// Replaces two separate types that were bridged by a lossy JSON round-trip:
/// - `FunctionTaintSummary` in `scuzz-core` (LSP-side, keyed by `u64`)
/// - `FunctionSummary` in `scuzz-rule-matcher` (matcher-side, keyed by `u32`)
///
/// The `function_id` field holds the CPG AST node ID (u32).  LSP-sourced
/// summaries set it to `0`; the LSP's codebase-index map (`FxHashMap<u64, ...>`)
/// carries the u64 identity as its key and does not require this struct field.
///
/// NOTE: Do NOT add `#[serde(skip_serializing_if)]` to any field.  This struct
/// is serialized with both JSON (for LSP communication) and bincode (for the
/// `TaintSummaryCache`).  Bincode is a positional binary format — skipping a
/// field during serialization shifts all subsequent field offsets and breaks
/// round-trip decode.  Use `#[serde(default)]` only (safe for both formats).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionSummary {
    /// CPG AST node ID of the `function_definition` node.
    /// `0` for externally-sourced (LSP) summaries.
    #[serde(default)]
    pub function_id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub file: String,

    /// Parameter names, in declaration order.
    #[serde(default)]
    pub parameters: Vec<String>,

    /// Unified parameter effects — replaces the old separate fields:
    /// `sink_params`, `frees_param`, `tainted_params` (TaintOut),
    /// and `returned_params`/`tainted_return_params` (TaintReturn).
    #[serde(default)]
    pub param_effects: BTreeSet<ParamEffect>,

    /// True when this function returns tainted data.
    #[serde(default)]
    pub tainted_return: bool,

    /// Taint-source names that cause this function's return value to be tainted.
    #[serde(default)]
    pub return_taint: BTreeSet<String>,

    /// Taint-source function names directly called by this function.
    #[serde(default)]
    pub source_calls: BTreeSet<String>,

    /// Known sink function names directly called by this function.
    #[serde(default)]
    pub sink_calls: BTreeSet<String>,

    /// All function names called (superset; populated from CPG analysis).
    #[serde(default)]
    pub calls: BTreeSet<String>,

    /// Sink names this function reaches internally (for cross-file sink detection).
    #[serde(default)]
    pub internal_sinks_reached: BTreeSet<String>,

    /// Variable names returned from the function body.
    #[serde(default)]
    pub returned_variables: BTreeSet<String>,

    /// FNV-1a hash of (fn_id + sorted resolved callee fn_ids).
    /// Non-None only for summaries computed by `FunctionSummarizationPool`.
    /// When the inputs hash matches, recomputation can be skipped.
    #[serde(default)]
    pub summary_input_hash: Option<u64>,
}

impl FunctionSummary {
    /// Parameter indices where tainted input constitutes a vulnerability.
    pub fn sink_params(&self) -> impl Iterator<Item = usize> + '_ {
        self.param_effects.iter().filter_map(|e| {
            if let ParamEffect::Sink(i) = e {
                Some(*i)
            } else {
                None
            }
        })
    }

    /// Parameter indices whose pointed-to memory is freed by this function.
    pub fn frees_params(&self) -> impl Iterator<Item = usize> + '_ {
        self.param_effects.iter().filter_map(|e| {
            if let ParamEffect::Frees(i) = e {
                Some(*i)
            } else {
                None
            }
        })
    }

    /// Parameter indices that the function writes tainted data into (output params).
    pub fn taint_out_params(&self) -> impl Iterator<Item = usize> + '_ {
        self.param_effects.iter().filter_map(|e| {
            if let ParamEffect::TaintOut(i) = e {
                Some(*i)
            } else {
                None
            }
        })
    }

    /// Parameter indices that, when tainted, cause the return value to be tainted.
    pub fn taint_return_params(&self) -> impl Iterator<Item = usize> + '_ {
        self.param_effects.iter().filter_map(|e| {
            if let ParamEffect::TaintReturn(i) = e {
                Some(*i)
            } else {
                None
            }
        })
    }

    pub fn has_sink_param(&self, idx: usize) -> bool {
        self.param_effects.contains(&ParamEffect::Sink(idx))
    }

    pub fn has_taint_out_param(&self, idx: usize) -> bool {
        self.param_effects.contains(&ParamEffect::TaintOut(idx))
    }
}
