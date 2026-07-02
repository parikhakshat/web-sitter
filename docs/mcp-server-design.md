# MCP Server Design: Deterministic Memory & Verification Layer for Coding Agents

This document designs an MCP (Model Context Protocol) server on top of the existing `web-sitter`/`web-ql` CPG and query-engine stack, and analyzes the gaps in the current incremental-analysis subsystems that must be closed to make it production-grade at monorepo scale. The server serves two co-equal purposes for a coding agent: **memory** (deterministic, cached retrieval replacing grep/LSP) and **verification** (running security scans, checking specific claims, and variant analysis — hunting for other instances of a known bug class) — see Motivation and the two-pillar breakdown below.

## Motivation

Coding agents today typically retrieve code context via grep and/or a language server (LSP):

- **Grep** is O(repo) per query, text-only, and gives no structural or dataflow guarantees. An agent re-derives call graphs and taint paths from raw text on every turn, and its conclusions about the code aren't checkable — if the agent claims "function A calls function B", there's no cheap way to confirm that.
- **LSP servers** are per-request, non-deterministic-latency, and expose symbol resolution (go-to-definition, references) but not CFG/DFG/interprocedural facts: call graph edges, taint paths, dominance relationships, function effect summaries.

`web-sitter` already has the two hardest ingredients for something better: an incremental CPG builder (`web-sitter/src/incremental.rs`, tree-sitter edit-driven) and a Datalog-inspired structural/dataflow query engine (`web-ql`, "ScuzzQL"). What's missing is the layer that lets an agent *use* these deterministically:

- `web-sitter` has never been given a live daemon. `IncrementalCpgGenerator` is edit-driven but has no file-watcher and requires a caller to supply `TextEdit`s.
- `Workspace` (`web-ql/src/workspace.rs`) is a *separate*, hash-driven, full-rebuild-on-touch system — `Workspace::upsert_file` never calls into `IncrementalCpgGenerator`'s edit machinery. These two incremental systems are disconnected today.
- The README already frames the project's mission around "incremental re-analysis on every keystroke" and serde for "RPC" — an MCP server is the capstone the authors clearly anticipated but never built.

**Goal**: an MCP server (`web-mcp/`) built around two co-equal pillars, both backed by the same live CPG/query-engine state:

1. **Memory (agentic retrieval)** — a persistent, versioned, queryable fact store giving sub-millisecond structural/call-graph/taint answers backed by real CPG data, replacing an agent's per-turn grep/LSP re-derivation.
2. **Verification (security analysis)** — the ability to *run* deterministic checks, not just answer lookups: execute security rule scans and interprocedural taint queries over the live graph, check specific claims (edge/path existence) against it, and — critically — take a single known bug instance and search the rest of the codebase (or monorepo) for structurally/semantically similar instances (**variant analysis**), the same workflow security teams use CodeQL/Semgrep for after triaging one real vulnerability.

These aren't separable concerns: variant analysis and security scanning *are* memory-consuming operations (they read the same fact store), and retrieval tools are what let an agent narrow a scan's scope (e.g. "only rerun taint analysis on functions reachable from this changed file"). The tool surface (below) is organized around this split, but both pillars share one server, one store, and one incremental-update pipeline.

Design parameters fixed for this iteration:
- **Transport**: stdio only (standard local-subprocess MCP pattern used by Claude Code, Cursor, etc.). HTTP/SSE multi-client daemon mode is an explicit non-goal for now.
- **Live updates**: in scope from the start — startup index + file-watcher-driven incremental updates, with incremental *analysis* (query-engine layer) on top of the incrementally-maintained graphs, not just incremental parsing.
- **Verification**: includes persistent finding-state tracking (open/fixed/suppressed) across sessions, on-demand full/scoped security scans, and variant analysis from a concrete example — not just real-time single-edge structural checks.
- **Scale target**: large monorepo (100k+ files). This rules out "hold the whole workspace in one in-memory struct," which is the existing codebase's default posture, and requires an on-disk backing store (addressed below). It also means security scans and variant-analysis queries must be scopeable (by directory/shard/changed-files) rather than always running whole-repo.

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
      lookup.rs, callgraph.rs, dataflow.rs, query.rs, impact.rs                # pillar 1: memory
      verify.rs, scan.rs, variants.rs                                          # pillar 2: verification
    security/
      generalize.rs         # "query by example": CPG subgraph -> generated ScuzzQL query (backs find_variants)
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

## Pillar 1: Deterministic Memory

- **Stable addressing**: today `NodeId` is file-local only (`web-ql/src/node_ref.rs::NodeRef(PathBuf, NodeId)`). Mint SCIP-style human-readable string symbol IDs (`<lang>:<qualified-path>#<disambiguator>`) at index time as a side table, so MCP responses cite checkable IDs across files and sessions — also the prerequisite for scoped (non-O(all-files)) cross-file invalidation.
- **Versioned**: every response carries the revision counter (per-shard + global) it was computed against.
- **Persistent across turns and process restarts**: the on-disk store survives server restarts; only shards touched since the last snapshot need re-validation (content-hash check), not a full re-index.
- **Verifiable, not inferred**: even memory/lookup tools return the actual CFG/DFG path or call-graph edge used to answer, never prose-only — this is what pillar 2 builds on.

## Pillar 2: Verification & Security Analysis

The verification pillar has three distinct capabilities, each answering a different question an agent (or a human directing one) actually asks:

1. **Claim checking** — "is this specific fact true?" (`verify_edge`, `explain_path`). O(1)-ish graph lookups against the live CPG; the building block the other two capabilities are expressed in terms of.
2. **Security scanning** — "does this code (file / directory / diff / whole repo) contain any known-bad pattern?" Runs the existing `web-ql` rule engine (52-rule CWE corpus in `web-ql-queries/`, or ad-hoc ScuzzQL) over a *scoped* subset of the graph, backed by persistent finding-state so the same bug isn't re-reported as new on every scan and fixes/regressions are tracked across sessions.
3. **Variant analysis** — "I found one instance of this bug by hand; are there others?" Given a concrete finding or a code example, generalize its structural/dataflow shape into a query and run it workspace-wide. This is the CodeQL/Semgrep "found one, hunt for the class" workflow, and it's new territory for `web-ql`: today rules must be hand-authored `.wql`. See the `find_variants` tool and the corresponding gap-analysis row below — it needs a "query by example" generalization step (built from the existing `extract_cpg_subgraph` BFS utility plus the taint-block/structural-matcher primitives already in `web-ql`) that isn't in the codebase yet.

All three read from — and, for finding-state, write to — the same on-disk store as pillar 1, so a variant-analysis result can cite the same stable symbol IDs and revision stamps a memory-lookup tool would.

## Tool Surface

### Pillar 1 — Memory / Agentic Retrieval

**Lookup/navigation**
- `find_definition(symbol, file?, line?)`, `find_references(symbol, scope?)`
- `symbol_summary(symbol)` — signature, `FunctionSummary` param effects (`web-sitter/src/function_summary.rs`: Sink/TaintOut/TaintReturn/Frees), type info from `type_inference.rs` — a dense fact card for context-budget management instead of dumping raw source.

**Call graph**
- `get_callers(function, transitive?, max_depth?)`, `get_callees(function, transitive?, max_depth?)`
- `call_path_exists(from, to, max_depth?)` — boolean + witness path.

**Dataflow/structural**
- `dfg_reaches(from_node, to_node)` — passthrough to the `dfg_reaches` predicate.
- `query(scuzzql_source)` — general ScuzzQL passthrough for ad-hoc structural queries (also usable for verification purposes; classified here because it's the general-purpose escape hatch, not a canned check).

**Change-impact**
- `impact_of_change(file, edits[])` — runs edits through `try_targeted_update`'s classification (unaffected/preserved/affected-function/affected-class) *without committing*, returning the blast radius (functions/callers needing re-verification) so an agent can decide whether a patch needs wider re-testing before applying it. Also the scoping mechanism pillar 2's scans use to avoid whole-repo reruns after a small diff.

### Pillar 2 — Verification / Security Analysis

**Claim checking**
- `verify_edge(kind: calls|dominates|reaches|reads|writes, from, to)` — checks a specific claim against the live CPG, returns true/false + witness path. Directly targets agent hallucination: instead of trusting an LLM's claim, the agent gets a graph-checked answer.
- `explain_path(from, to, kind)` — full node-by-node trace as evidence the agent can quote.
- `taint_path(source, sink, sanitizers?)` — wraps `web-ql`'s interprocedural taint blocks, returns the concrete DFG edge chain for a specific source→sink hypothesis.

**Security scanning** (bug hunting over a scope, not a single claim)
- `run_security_scan(scope: file[] | directory | diff | workspace, rule_set?: names[] | "all", severity_threshold?)` — runs the `web-ql` rule engine (the 52-rule CWE corpus in `web-ql-queries/`, or a caller-supplied `.wql`/ScuzzQL rule set) over the requested scope. `scope: diff` composes with `impact_of_change`'s blast-radius output so a PR-review-style agent scans only what a patch could plausibly affect, not the whole monorepo. Supersedes/extends the earlier `scan_rules` sketch with explicit scoping — required at monorepo scale.
- `verify_finding_status(finding_id)` / `record_finding_status(finding_id, status)` — durable open/fixed/suppressed tracking keyed by a stable fingerprint (rule id + symbol id + normalized location), stored in the on-disk store, with first-seen/last-seen revision, so repeated scans over a live-edited monorepo don't re-report the same bug as new.

**Variant analysis** (generalize one instance, search for the class)
- `find_variants(example: finding_id | {file, node_range}, generalization?: {structural_only | include_dataflow}, scope?)` — takes a concrete bug instance (either an existing finding or an arbitrary CPG node range the agent points at) and:
  1. extracts its local CPG subgraph (reusing `Workspace::extract_cpg_subgraph`'s BFS extraction),
  2. generalizes it into a ScuzzQL structural/taint query (new capability — see gap analysis),
  3. runs that generated query over `scope` (default: whole workspace) and returns matches ranked by structural similarity.
  This is the CodeQL/Semgrep "found one instance by hand, now hunt for the whole class of the same bug" workflow — a distinct capability from `run_security_scan` (which only finds instances of *already-known, hand-authored* rules).
- `explain_variant(match_id)` — for a `find_variants` hit, returns the same node-by-node trace format as `explain_path`, so each reported variant is independently checkable, not a similarity-score guess.

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
| No "query by example" / pattern-generalization capability | none today; `web-ql` rules must be hand-authored `.wql` | `find_variants` needs to turn a concrete finding/code example into a general structural+dataflow query, not just replay existing rules | New `web-mcp/src/security/generalize.rs`: build on `Workspace::extract_cpg_subgraph`'s BFS extraction plus `web-ql`'s existing structural-matcher and taint-block primitives; generalize literal values/identifiers into typed placeholders (similar in spirit to what `symbol_anonymizer.rs` already does for identifiers) while preserving node-kind/CFG/DFG shape; start with structural-only generalization (Phase 3) and treat dataflow-aware generalization as a stretch refinement once structural variant-hunting is validated |
| Security scans have no scoping mechanism at monorepo scale | `web-ql`'s `scan`/`scan_incremental` operate over the files already loaded into a `Workspace`, not a query-time scope parameter | `run_security_scan`/`find_variants` need to run over "just this diff" or "just this directory" without touching unrelated shards, and without re-triggering a full cross-file rebuild | Thread a `scope` parameter through to the sharded store (Monorepo-Scale Storage) so scans only load/lock the shards in scope; compose with `impact_of_change`'s blast-radius output for diff-scoped scans |

## Phased Build Order

- **Phase 0 — Foundation**: stable cross-file symbol IDs; reverse-symbol-index scaffolding; stabilize `type_inference.rs` public API. Lands inside `web-sitter`/`web-ql`, no new crate yet.
- **Phase 1 — MCP server skeleton, read-only, single-shard**: `web-mcp/` with `rmcp` stdio transport; pillar-1 lookup/call-graph/dataflow/query tools plus `verify_edge`/`explain_path`/`taint_path` (pillar 2's claim-checking tier, which needs no new infrastructure beyond a built `Workspace`) over a `Workspace` built once at startup via existing batch APIs. Validates the tool surface and SDK integration before tackling storage/scale.
- **Phase 2 — Monorepo-scale storage + live incremental updates**: on-disk sharded store, LRU hot-shard cache, `notify` watcher wired through the unification plan (FS event → debounce → `TextEdit` synthesis or full-reparse fallback → `try_targeted_update` → scoped shard/cross-file update); sharded locking + revision counter goes live; `run_security_scan` ships with `scope` support (composes with `impact_of_change`) since scoped scanning depends directly on the sharded store landing here.
- **Phase 3 — Persistent findings store + variant analysis**: `verify_finding_status`/`record_finding_status` with a durable findings-state store; `find_variants`/`explain_variant` including the new query-generalization capability (`security/generalize.rs`, structural-only first); whole-store snapshot/warm-restart validated at monorepo scale.
- **Phase 4 — Production hardening**: benchmark-driven concurrency tuning, CI gates (clippy/fmt/parity-fuzz/perf), dataflow-aware variant generalization as a stretch refinement, evaluate query-engine memoization only if a measured bottleneck, optional SSE/HTTP transport as a later stretch.

## Verification / Testing Per Phase

- **Phase 0**: unit tests that symbol IDs are stable across a no-op-affecting reparse (mirroring the existing `stabilize_cpg_ids` test pattern in `incremental.rs`); differential test that scoped cross-file invalidation matches full-rebuild output for arbitrary single-file edits (keep both paths until confidence is established, then delete the O(all files) path).
- **Phase 1**: integration test driving `web-mcp` over stdio against a fixture repo with hand-verified expected answers (callers/callees/taint paths, plus `verify_edge` true/false cases against known-true and known-false claims in the fixture); manual smoke test wiring the server into an actual coding-agent MCP config to sanity-check the protocol handshake and tool-call ergonomics.
- **Phase 2**: differential fuzz applying randomized edit sequences through the watcher path, asserting live sharded state matches from-scratch full rebuild at each step; large-fixture (synthetic 50k-100k file) load test for cold-start time, hot-shard cache hit rate, and live-edit p99 latency under a simulated rapid-edit storm; `run_security_scan(scope: diff)` correctness test confirming a scoped scan finds the same bugs a whole-workspace scan would for a given diff, without touching unrelated shards (assert via lock/load instrumentation, not just result equality).
- **Phase 3**: findings-state lifecycle test (fixed → reintroduced → suppressed) across a sequence of scans; snapshot save/load round-trip test with selective per-shard re-index on content-hash mismatch, not whole-snapshot discard; `find_variants` precision/recall test against `testfiles/` fixtures with known injected variants of an existing CWE pattern (seed N variants, assert the generalized query recovers them without excessive false positives against the surrounding non-vulnerable code).
- **Phase 4**: CI gate validation by intentionally introducing a clippy warning / an incremental-vs-full divergence / a perf regression on a throwaway branch and confirming each gate catches it before merge.

## Critical Files

- `web-sitter/src/incremental.rs` — `IncrementalCpgGenerator`, `try_targeted_update`, `save_state`/`load_state`, `CACHE_FORMAT_VERSION`.
- `web-ql/src/workspace.rs` — `Workspace`, `FileIndex::build`, `build_cross_file_edges()`, `cross_file_callee_params`/`cross_file_dfgs`.
- `web-ql/src/engine.rs` — `RuleRunner`/`EvalContext`, backs the `query`/`run_security_scan`/taint tools.
- `web-ql/src/workspace.rs::extract_cpg_subgraph` — BFS subgraph extraction, the starting point for `find_variants`'s generalization step.
- `web-ql-queries/` — the 52-rule CWE corpus `run_security_scan`'s default rule set draws from.
- `web-sitter/src/function_summary.rs`, `web-sitter/src/type_inference.rs` — interprocedural summaries and type info backing `symbol_summary`.
- `web-sitter/src/symbol_anonymizer.rs` — a useful reference pattern (identifier→placeholder generalization) for `security/generalize.rs`.
- Root `Cargo.toml` — where the new `web-mcp` workspace member is registered.
