# MCP Server Design: Deterministic Memory & Verification Layer for Coding Agents

This document designs an MCP (Model Context Protocol) server on top of the existing `web-sitter`/`web-ql` CPG and query-engine stack, and analyzes the gaps in the current incremental-analysis subsystems that must be closed to make it production-grade at monorepo scale.

## Motivation

Coding agents today typically retrieve code context via grep and/or a language server (LSP):

- **Grep** is O(repo) per query, text-only, and gives no structural or dataflow guarantees. An agent re-derives call graphs and taint paths from raw text on every turn, and its conclusions about the code aren't checkable — if the agent claims "function A calls function B", there's no cheap way to confirm that.
- **LSP servers** are per-request, non-deterministic-latency, and expose symbol resolution (go-to-definition, references) but not CFG/DFG/interprocedural facts: call graph edges, taint paths, dominance relationships, function effect summaries.

`web-sitter` already has the two hardest ingredients for something better: an incremental CPG builder (`web-sitter/src/incremental.rs`, tree-sitter edit-driven) and a Datalog-inspired structural/dataflow query engine (`web-ql`, "ScuzzQL"). What's missing is the layer that lets an agent *use* these deterministically:

- `web-sitter` has never been given a live daemon. `IncrementalCpgGenerator` is edit-driven but has no file-watcher and requires a caller to supply `TextEdit`s.
- `Workspace` (`web-ql/src/workspace.rs`) is a *separate*, hash-driven, full-rebuild-on-touch system — `Workspace::upsert_file` never calls into `IncrementalCpgGenerator`'s edit machinery. These two incremental systems are disconnected today.
- The README already frames the project's mission around "incremental re-analysis on every keystroke" and serde for "RPC" — an MCP server is the capstone the authors clearly anticipated but never built.

**Goal**: an MCP server (`web-mcp/`) that gives coding agents a persistent, versioned, queryable fact store — sub-millisecond structural/call-graph/taint answers backed by real CPG data, plus a verification tool category that checks claims against the graph instead of trusting LLM inference from text context — scaled to large monorepos (100k+ files).

Design parameters fixed for this iteration:
- **Transport**: stdio only (standard local-subprocess MCP pattern used by Claude Code, Cursor, etc.). HTTP/SSE multi-client daemon mode is an explicit non-goal for now.
- **Live updates**: in scope from the start — startup index + file-watcher-driven incremental updates, with incremental *analysis* (query-engine layer) on top of the incrementally-maintained graphs, not just incremental parsing.
- **Verification**: includes persistent finding-state tracking (open/fixed/suppressed) across sessions, not just real-time structural checks.
- **Scale target**: large monorepo (100k+ files). This rules out "hold the whole workspace in one in-memory struct," which is the existing codebase's default posture, and requires an on-disk backing store (addressed below).

## Prior art considered

- **rust-analyzer / Salsa**: query-based incremental computation over a DAG of memoized derived queries; automatic reuse/invalidation via revision counters. Model for how MCP tool calls should be backed by demand-driven, cached queries rather than full re-analysis per request.
- **Meta Glean**: incremental code-fact indexing designed so indexing cost is O(changes) not O(repo); a "stack of DBs" (each layer non-destructively adds/hides facts over the layer below) enables querying without full reindex.
- **CodeQL / Datalog incrementalization** (Szabó et al., "Incrementalizing Production CodeQL Analyses"): retrofitting incremental evaluation onto a batch Datalog-style analysis is tractable — update time proportional to change size — relevant since ScuzzQL is Datalog-inspired and currently batch-evaluated per file.
- **SCIP (Sourcegraph)**: succeeded LSIF specifically because LSIF's opaque global IDs blocked incremental indexing; SCIP's human-readable string symbol IDs unlock incremental merge. Direct precedent for minting stable cross-file symbol IDs (today `NodeId` is file-local only).
- **Joern / Code Property Graph spec**: multi-layered schema (AST+CFG+PDG+call graph unified); incremental CPG construction reuses unchanged subgraphs — the same idea `web-sitter`'s `stabilize_cpg_ids` already partially implements.
- **Serena MCP server**: existing precedent for an LSP-backed "semantic retrieval" MCP server. Useful comparison point for tool-surface shape, but it's per-request/LSP-backed with no persistent fact store — exactly the weakness a CPG+query-engine-backed server should improve on (deterministic, cached, verifiable answers).

## Architecture Overview

New workspace member `web-mcp/`, registered in root `Cargo.toml` `[workspace] members`, depending on `web-sitter` and `web-ql` as libraries.

```
web-mcp/
  src/
    main.rs              # CLI args (--root <path>, --cache-dir), stdio transport wiring
    server.rs            # rmcp ServerHandler impl, tool registry
    store/
      mod.rs              # WorkspaceStore: sharded fact store + revision counter
      watcher.rs           # notify-based FS watcher -> debounced edit pipeline
      persistence.rs       # on-disk backing store (see Monorepo-Scale Storage)
      shard.rs             # per-shard (directory/module) load/evict/lock management
      findings.rs           # persistent finding-state tracking
    tools/
      lookup.rs, callgraph.rs, dataflow.rs, query.rs, impact.rs, verify.rs, anonymize.rs
    schema.rs             # shared MCP tool input/output types
```

**MCP SDK**: `rmcp` (official `modelcontextprotocol/rust-sdk`) — tokio-async, stdio transport, `#[tool]` macros. Verify the exact version/feature-flags at implementation time; the SDK is young and its API has moved between 0.x releases — pin a specific version rather than a wildcard.

**Concurrency/consistency model** (Salsa-inspired): a monotonic `AtomicU64` revision counter incremented on every applied edit. Every tool response is stamped with the revision it was computed against, so an agent can detect staleness across a multi-turn edit session. Locking is **per-shard**, not global — a single `RwLock<Workspace>` does not survive contention at monorepo scale, so sharded locking is required from the live-update phase onward, not deferred as an optimization.

## Monorepo-Scale Storage

The existing `Cpg`/`Workspace` design holds every file's full CPG in memory as plain `BTreeMap`s with no DB backend — fine for thousands of files, but it will not fit in RAM for a 100k+ file monorepo, and a cold-start full index would be unacceptably slow. Three changes go beyond what a single-project design would need:

1. **On-disk fact store with lazy shard loading.** An embedded KV/DB layer (evaluate `redb` or `sled` at implementation time — both pure-Rust, embedded, no external service, consistent with the project's "no external graph-DB" philosophy) persists per-file `Cpg` state (reusing the existing bincode+lz4 serialization already used by `save_state`/`load_state`) plus the cross-file reverse-symbol-index as a durable table, not an in-memory `HashMap`. `WorkspaceStore` becomes an LRU-bounded in-memory cache of *hot* shards over this on-disk store, not a container of all of them. Shard granularity = directory or build-module (configurable), matching how large monorepos are naturally partitioned and enabling parallel warm-indexing.
2. **Glean-style layered facts instead of full rebuild.** A base layer (facts stable across most edits — vendor code, rarely-touched modules) plus thin incremental overlay layers for actively-edited files, merged at query time. This keeps `build_cross_file_edges()`-style global rebuilds bounded to the overlay, not the whole monorepo, which is what makes live-update latency acceptable at this scale.
3. **Sharded locking**: `DashMap<ShardId, RwLock<ShardState>>` instead of one global `RwLock<Workspace>`. Concurrent tool calls touching unrelated shards don't block each other; the watcher only takes a write lock on the shard(s) containing the changed file.

These three points are a deliberate deviation from `web-sitter`'s current in-memory-only design philosophy, driven entirely by the monorepo-scale requirement — worth flagging explicitly during implementation review.

## Deterministic Memory Concept

- **Stable addressing**: today `NodeId` is file-local only (`web-ql/src/node_ref.rs::NodeRef(PathBuf, NodeId)`). Mint SCIP-style human-readable string symbol IDs (`<lang>:<qualified-path>#<disambiguator>`) at index time as a side table, so MCP responses cite checkable IDs across files and sessions — also the prerequisite for scoped (non-O(all-files)) cross-file invalidation.
- **Versioned**: every response carries the revision counter (per-shard + global) it was computed against.
- **Persistent across turns and process restarts**: the on-disk store survives server restarts; only shards touched since the last snapshot need re-validation (content-hash check), not a full re-index.
- **Verifiable, not inferred**: the verification tool category returns the actual CFG/DFG path or call-graph edge used to answer, never prose-only.

## Tool Surface

**Lookup/navigation**
- `find_definition(symbol, file?, line?)`, `find_references(symbol, scope?)`
- `symbol_summary(symbol)` — signature, `FunctionSummary` param effects (`web-sitter/src/function_summary.rs`: Sink/TaintOut/TaintReturn/Frees), type info from `type_inference.rs` — a dense fact card for context-budget management instead of dumping raw source.

**Call graph**
- `get_callers(function, transitive?, max_depth?)`, `get_callees(function, transitive?, max_depth?)`
- `call_path_exists(from, to, max_depth?)` — boolean + witness path.

**Dataflow/structural**
- `taint_path(source, sink, sanitizers?)` — wraps `web-ql`'s taint blocks, returns the concrete DFG edge chain.
- `dfg_reaches(from_node, to_node)` — passthrough to the `dfg_reaches` predicate.
- `query(scuzzql_source)` — general ScuzzQL passthrough for ad-hoc structural queries.
- `scan_rules(rule_names[])` — convenience wrapper over the 52-rule `.wql` corpus in `web-ql-queries/`.

**Change-impact**
- `impact_of_change(file, edits[])` — runs edits through `try_targeted_update`'s classification (unaffected/preserved/affected-function/affected-class) *without committing*, returning the blast radius (functions/callers needing re-verification) so an agent can decide whether a patch needs wider re-testing before applying it.

**Verification** (persistent state)
- `verify_edge(kind: calls|dominates|reaches|reads|writes, from, to)` — checks a specific claim against the live CPG, returns true/false + witness path. Directly targets agent hallucination: instead of trusting an LLM's claim, the agent gets a graph-checked answer.
- `explain_path(from, to, kind)` — full node-by-node trace as evidence the agent can quote.
- `verify_finding_status(finding_id)` / `record_finding_status(finding_id, status)` — durable open/fixed/suppressed tracking keyed by a stable fingerprint (rule id + symbol id + normalized location), stored in the on-disk store, with first-seen/last-seen revision.

**Privacy-aware context**
- `anonymized_context(file_or_symbol)` — wraps `SymbolAnonymizer::anonymize` (`web-sitter/src/symbol_anonymizer.rs`); the README already frames this as intentional (for sending CPGs to external/less-trusted models), the MCP tool just exposes it.

## Incremental-System Unification

Today `IncrementalCpgGenerator` (single-file, edit-driven) and `Workspace`/`FileIndex` (multi-file, hash-driven, full-rebuild) are disconnected. Proposed unification (new module, e.g. `web-ql/src/incremental_workspace.rs`):

1. `Workspace`/shard state holds one `IncrementalCpgGenerator` per file instead of rebuilding `Cpg` from scratch. The watcher converts FS diffs to `TextEdit`s and calls `try_targeted_update` instead of `FileIndex::build`'s full reparse.
2. `FileIndex`'s derived indexes (kind/DFG/CFG/alias/size/nullability) become memoized-and-invalidated using the generator's existing generation-stamp/CFG-topology-signature machinery (FNV-1a hash of SCC structure) — skip recompute when a function's topology signature is unchanged.
3. Cross-file invalidation is scoped, not O(all files): a persistent reverse index (symbol → referencing files) maps a changed file's affected-symbol set (already computed by `try_targeted_update`) to the minimal set of other files/shards needing `cross_file_callee_params`/`cross_file_dfgs` patches.
4. This scoping is only cheap once stable cross-file symbol IDs exist — a hard prerequisite at monorepo scale, not a nice-to-have.

## Gap Analysis — Production-Grade Checklist

| Gap | Where | Why it matters | Proposed fix |
|---|---|---|---|
| No file-watcher/daemon mode | no `notify` dep anywhere in the workspace | live server needs to detect edits made outside MCP tool calls | Add `notify` to `web-mcp`; debounce 50-150ms coalescing window; batch multi-file saves; fall back to full-file reparse when a byte-diff isn't available (external rewrite/rename) rather than synthesizing a bad `TextEdit` |
| File-local-only `NodeId`, no stable cross-file symbol ID | `web-sitter/src/lib.rs` (`NodeId=u32`, unique only within one file's CPG) | needed for citable MCP tool output and scoped cross-file invalidation | Mint SCIP-style string symbol IDs at index time as a side table; keep `NodeId` as the fast in-process key |
| No persistent whole-workspace cache / restart story | only `IncrementalCpgGenerator::save_state/load_state` exists (single-file, `web-sitter/src/incremental.rs:1383,1407`, `CACHE_FORMAT_VERSION`-gated) | MCP server warm-start on large repos shouldn't require full re-index every launch | Sharded on-disk store (redb/sled), reusing bincode+lz4 pattern; per-shard content-hash validation on load, not whole-snapshot discard |
| Cross-file cache invalidation is all-or-nothing | `build_cross_file_edges()`, `web-ql/src/workspace.rs:267-410` | O(all files) per edit is untenable for a live server on a large repo | Scoped invalidation via persistent reverse symbol index (see Unification step 3) |
| `type_inference.rs` mostly `pub(crate)` | 14 `pub(crate)` items, `web-sitter/src/type_inference.rs` | `symbol_summary` and type-aware tools need type info | Stabilize a public read API (`TypeInfo::for_node`, class-hierarchy accessor) before wiring the tool |
| No verification/assertion/finding-persistence state | none today; `web-scan` is stateless batch | `verify_finding_status` needs durable state across scans | New persisted store keyed by stable fingerprint (rule id + symbol id + normalized location), tracking first-seen/last-seen revision and open/fixed/suppressed status |
| Query engine has no incremental re-evaluation of queries themselves | `web-ql/src/engine.rs::RuleRunner::run` is a full-file batch evaluator; `scan_incremental` only gates on file-level dirty + rule-set-signature | full rule rerun on any touched file, even for tiny localized edits | Treat true Salsa-style memoized sub-query incrementality as a stretch goal, not a blocker — per-file rerun is likely cheap once CPGs are incrementally maintained; revisit only if benchmarking shows rule evaluation (not cross-file rebuild) dominates latency |
| No concurrency/consistency model for a long-lived server | n/a (nothing runs long-lived today) | concurrent MCP tool calls vs. in-flight incremental updates | Sharded `RwLock` + revision counter (see Monorepo-Scale Storage); global lock explicitly rejected at this scale |
| CI is build+test only | `.github/workflows/` | no clippy/fmt gate, no incremental-vs-full parity fuzzing beyond existing tests, no perf-regression gate | Add `cargo clippy --workspace -- -D warnings` + `cargo fmt --check`; differential fuzz test applying random edit sequences and asserting `try_targeted_update` result equals a from-scratch full rebuild; `criterion`-based benchmark suite (index time, incremental-update latency, cross-file rebuild time) with a regression threshold, exercised at monorepo-scale fixture size |

## Phased Build Order

- **Phase 0 — Foundation**: stable cross-file symbol IDs; reverse-symbol-index scaffolding; stabilize `type_inference.rs` public API. Lands inside `web-sitter`/`web-ql`, no new crate yet.
- **Phase 1 — MCP server skeleton, read-only, single-shard**: `web-mcp/` with `rmcp` stdio transport; lookup/call-graph/dataflow/query tools over a `Workspace` built once at startup via existing batch APIs. Validates the tool surface and SDK integration before tackling storage/scale.
- **Phase 2 — Monorepo-scale storage + live incremental updates**: on-disk sharded store, LRU hot-shard cache, `notify` watcher wired through the unification plan (FS event → debounce → `TextEdit` synthesis or full-reparse fallback → `try_targeted_update` → scoped shard/cross-file update); sharded locking + revision counter goes live.
- **Phase 3 — Verification tools + persistent findings store**: `verify_edge`/`explain_path`/`verify_finding_status`/`record_finding_status`, durable findings-state store, whole-store snapshot/warm-restart validated at monorepo scale.
- **Phase 4 — Production hardening**: benchmark-driven concurrency tuning, CI gates (clippy/fmt/parity-fuzz/perf), evaluate query-engine memoization only if a measured bottleneck, optional SSE/HTTP transport as a later stretch.

## Verification / Testing Per Phase

- **Phase 0**: unit tests that symbol IDs are stable across a no-op-affecting reparse (mirroring the existing `stabilize_cpg_ids` test pattern in `incremental.rs`); differential test that scoped cross-file invalidation matches full-rebuild output for arbitrary single-file edits (keep both paths until confidence is established, then delete the O(all files) path).
- **Phase 1**: integration test driving `web-mcp` over stdio against a fixture repo with hand-verified expected answers (callers/callees/taint paths); manual smoke test wiring the server into an actual coding-agent MCP config to sanity-check the protocol handshake and tool-call ergonomics.
- **Phase 2**: differential fuzz applying randomized edit sequences through the watcher path, asserting live sharded state matches from-scratch full rebuild at each step; large-fixture (synthetic 50k-100k file) load test for cold-start time, hot-shard cache hit rate, and live-edit p99 latency under a simulated rapid-edit storm.
- **Phase 3**: findings-state lifecycle test (fixed → reintroduced → suppressed) across a sequence of scans; snapshot save/load round-trip test with selective per-shard re-index on content-hash mismatch, not whole-snapshot discard.
- **Phase 4**: CI gate validation by intentionally introducing a clippy warning / an incremental-vs-full divergence / a perf regression on a throwaway branch and confirming each gate catches it before merge.

## Critical Files

- `web-sitter/src/incremental.rs` — `IncrementalCpgGenerator`, `try_targeted_update`, `save_state`/`load_state`, `CACHE_FORMAT_VERSION`.
- `web-ql/src/workspace.rs` — `Workspace`, `FileIndex::build`, `build_cross_file_edges()`, `cross_file_callee_params`/`cross_file_dfgs`.
- `web-ql/src/engine.rs` — `RuleRunner`/`EvalContext`, backs the `query`/`scan_rules`/taint tools.
- `web-sitter/src/function_summary.rs`, `web-sitter/src/type_inference.rs` — interprocedural summaries and type info backing `symbol_summary`.
- `web-sitter/src/symbol_anonymizer.rs` — backs the anonymized-context tool.
- Root `Cargo.toml` — where the new `web-mcp` workspace member is registered.
