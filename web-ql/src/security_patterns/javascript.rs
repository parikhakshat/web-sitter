/// JavaScript / Node.js security patterns.
///
/// # Naming convention
///
/// The JavaScript CPG stores **bare function names** on `Call` nodes:
/// - Global functions (`eval`, `require`, `setTimeout`) → their identifier text.
/// - Method calls on objects: `extract_called_function_name` checks the callee
///   identifier child.  For `member_expression` callees (e.g., `fs.readFile`),
///   the current implementation does NOT strip the qualifier, so those only
///   match when the function is imported directly:
///   ```js
///   const { exec } = require('child_process');
///   exec("ls");  // call.name = "exec"
///   ```
///   Qualified calls (`child_process.exec(...)`) do not currently match.
///   Patterns below are still included for forward-compatibility and rules
///   that perform their own name extraction.
///
/// Covered environments: Node.js LTS stdlib, Express.js, Koa, Fastify,
/// browser DOM / Web APIs, Next.js API routes.

use web_sitter::security_patterns::{SourceSpec, SinkSpec, PropagatorSpec};

// =============================================================================
// Taint sources
// =============================================================================

pub const JS_TAINT_SOURCES: &[(&str, SourceSpec)] = &[
    // ── Browser — user input ──────────────────────────────────────────────────
    // window.prompt() — explicit user input dialog
    (
        "prompt",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // window.confirm / alert return value (attacker-observable timing / content)
    (
        "confirm",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // document.cookie parsing utility
    (
        "getCookie",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // localStorage / sessionStorage
    (
        "getItem",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // Web Storage key enumeration
    (
        "key",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── Node.js — process / environment ───────────────────────────────────────
    // process.argv is a property; direct reads are DFG edges, but some
    // frameworks wrap it in a function call.
    (
        "minimist",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "yargs",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "commander",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── Node.js — fs — filesystem read (path may be attacker-controlled) ──────
    (
        "readFileSync",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "readFile",
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    (
        "readSync",
        SourceSpec { tainted_params: &[1], tainted_return: true },
    ),
    (
        "read",
        SourceSpec { tainted_params: &[1], tainted_return: true },
    ),
    (
        "readdirSync",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "readdir",
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    (
        "readlinkSync",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "readlink",
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    // ── Node.js — Express / Koa / Fastify — HTTP request ─────────────────────
    // req.param(name) (Express < 4.x deprecated API)
    (
        "param",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // req.get(headerName) / req.header(headerName)
    (
        "get",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "header",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── Node.js — http.IncomingMessage stream ─────────────────────────────────
    // Note: req.body, req.query, req.params are properties (DFG edges), not calls.
    // The stream.read() API is modelled here.
    (
        "read",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── Node.js — child_process — output from executed commands ───────────────
    (
        "execSync",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "execFileSync",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "spawnSync",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── Node.js — net — socket data ───────────────────────────────────────────
    (
        "on",
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    // ── Miscellaneous node utility packages ───────────────────────────────────
    // qs / querystring.parse returns attacker-controlled object
    (
        "parse",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // csv-parse / fast-csv
    (
        "parseString",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
];

// =============================================================================
// Taint sinks
// =============================================================================

pub const JS_TAINT_SINKS: &[(&str, SinkSpec)] = &[
    // ── Code execution ────────────────────────────────────────────────────────
    (
        "eval",
        SinkSpec { sink_args: &[0] },
    ),
    // new Function(code) — call.name = "Function" for `new Function(...)`
    (
        "Function",
        SinkSpec { sink_args: &[0] },
    ),
    // setTimeout / setInterval with a string argument
    (
        "setTimeout",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "setInterval",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "setImmediate",
        SinkSpec { sink_args: &[0] },
    ),
    // ── OS command injection — child_process ──────────────────────────────────
    (
        "exec",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "execSync",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "spawn",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "spawnSync",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "execFile",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "execFileSync",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "fork",
        SinkSpec { sink_args: &[0] },
    ),
    // ── File operations — path traversal / file write ─────────────────────────
    (
        "writeFile",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "writeFileSync",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "appendFile",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "appendFileSync",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "unlink",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "unlinkSync",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "rmdir",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "rmdirSync",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "mkdir",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "mkdirSync",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "rename",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "renameSync",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "copyFile",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "copyFileSync",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "open",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "openSync",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "createWriteStream",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "createReadStream",
        SinkSpec { sink_args: &[0] },
    ),
    // ── XSS — DOM manipulation ────────────────────────────────────────────────
    // Note: innerHTML / outerHTML are property *assignments*, not function calls.
    // Browser-side XSS sinks that are function calls:
    (
        "write",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "writeln",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "insertAdjacentHTML",
        SinkSpec { sink_args: &[1] },
    ),
    (
        "createContextualFragment",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "setAttribute",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "setAttributeNS",
        SinkSpec { sink_args: &[0, 1, 2] },
    ),
    // jQuery html() / append() / prepend() etc.
    (
        "html",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "append",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "prepend",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "after",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "before",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "replaceWith",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "wrap",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "wrapAll",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "wrapInner",
        SinkSpec { sink_args: &[0] },
    ),
    // ── SQL injection — various Node.js database libraries ────────────────────
    (
        "query",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "run",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "all",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "get",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "execute",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "raw",
        SinkSpec { sink_args: &[0] },
    ),
    // Knex .whereRaw / .havingRaw
    (
        "whereRaw",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "havingRaw",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "orderByRaw",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "groupByRaw",
        SinkSpec { sink_args: &[0] },
    ),
    // Mongoose / MongoDB — NoSQL injection
    (
        "find",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "findOne",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "findById",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "findOneAndUpdate",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "findOneAndDelete",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "updateOne",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "deleteOne",
        SinkSpec { sink_args: &[0] },
    ),
    // ── SSRF — HTTP requests ──────────────────────────────────────────────────
    (
        "fetch",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "request",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "get",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "post",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "put",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "delete",
        SinkSpec { sink_args: &[0] },
    ),
    // ── Open redirect — Express / Koa ─────────────────────────────────────────
    (
        "redirect",
        SinkSpec { sink_args: &[0] },
    ),
    // ── Template injection ────────────────────────────────────────────────────
    (
        "render",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "renderFile",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "compile",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "template",
        SinkSpec { sink_args: &[0] },
    ),
    // Pug / Jade
    (
        "renderSync",
        SinkSpec { sink_args: &[0] },
    ),
    // ── LDAP injection — ldapjs ───────────────────────────────────────────────
    (
        "search",
        SinkSpec { sink_args: &[0, 1] },
    ),
    // ── Path traversal helpers ────────────────────────────────────────────────
    (
        "sendFile",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "download",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "pipe",
        SinkSpec { sink_args: &[0] },
    ),
    // ── Node.js vm module — sandbox escape ────────────────────────────────────
    (
        "runInNewContext",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "runInContext",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "runInThisContext",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Script",
        SinkSpec { sink_args: &[0] },
    ),
    // ── node-serialize / serialize-javascript — deserialization RCE ───────────
    (
        "unserialize",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "deserialize",
        SinkSpec { sink_args: &[0] },
    ),
];

// =============================================================================
// Taint propagators
// =============================================================================

pub const JS_TAINT_PROPAGATORS: &[(&str, PropagatorSpec)] = &[
    // ── String methods ────────────────────────────────────────────────────────
    (
        "concat",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "slice",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "substring",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "substr",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "replace",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    (
        "replaceAll",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    (
        "toLowerCase",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "toUpperCase",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "toLocaleLowerCase",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "toLocaleUpperCase",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "trim",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "trimStart",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "trimEnd",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "padStart",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    (
        "padEnd",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    (
        "repeat",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "split",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "at",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "charAt",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "charCodeAt",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "codePointAt",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "toString",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "valueOf",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "normalize",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    // ── Array methods ─────────────────────────────────────────────────────────
    (
        "join",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "map",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "filter",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "reduce",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "reduceRight",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "flat",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "flatMap",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "slice",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "splice",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    (
        "at",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "find",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "findIndex",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "sort",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "reverse",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "concat",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    // ── JSON — does not sanitize taint ────────────────────────────────────────
    (
        "stringify",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── URL / path manipulation — taint passes through ────────────────────────
    (
        "encodeURIComponent",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "encodeURI",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "decodeURIComponent",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "decodeURI",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "btoa",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "atob",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── path (Node.js) ────────────────────────────────────────────────────────
    (
        "join",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    (
        "resolve",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    (
        "normalize",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "basename",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "dirname",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "extname",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── Buffer (Node.js) ─────────────────────────────────────────────────────
    (
        "toString",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "from",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
];

// =============================================================================
// Named sets
// =============================================================================

/// DOM / HTML manipulation sinks — XSS.
pub const JS_DOM_XSS_SINKS: &[&str] = &[
    "write", "writeln", "insertAdjacentHTML", "createContextualFragment",
    "setAttribute", "setAttributeNS",
    "html", "append", "prepend", "after", "before", "replaceWith", "wrap", "wrapAll", "wrapInner",
];

/// OS command execution sinks.
pub const JS_EXEC_SINKS: &[&str] = &[
    "exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork",
];

/// File system write sinks (path traversal / arbitrary write).
pub const JS_FILE_WRITE_SINKS: &[&str] = &[
    "writeFile", "writeFileSync", "appendFile", "appendFileSync",
    "unlink", "unlinkSync", "rmdir", "rmdirSync", "mkdir", "mkdirSync",
    "rename", "renameSync", "copyFile", "copyFileSync",
    "open", "openSync", "createWriteStream",
];

/// Database query sinks — SQL / NoSQL injection.
pub const JS_DB_SINKS: &[&str] = &[
    "query", "run", "all", "get", "execute", "raw",
    "whereRaw", "havingRaw", "orderByRaw", "groupByRaw",
    "find", "findOne", "findById", "findOneAndUpdate", "findOneAndDelete",
    "updateOne", "deleteOne",
];

/// Server-side request forgery sinks.
pub const JS_SSRF_SINKS: &[&str] = &[
    "fetch", "request", "get", "post", "put", "delete",
];

/// Code evaluation sinks.
pub const JS_EVAL_SINKS: &[&str] = &[
    "eval", "Function", "setTimeout", "setInterval", "setImmediate",
    "runInNewContext", "runInContext", "runInThisContext", "Script",
];

/// Template injection sinks.
pub const JS_TEMPLATE_SINKS: &[&str] = &[
    "render", "renderFile", "compile", "template", "renderSync",
];

/// Open redirect sinks.
pub const JS_REDIRECT_SINKS: &[&str] = &["redirect", "sendFile", "download"];

/// Deserialization sinks.
pub const JS_DESERIALIZATION_SINKS: &[&str] = &["unserialize", "deserialize", "parse"];

/// LDAP injection sinks.
pub const JS_LDAP_SINKS: &[&str] = &["search"];

/// vm-module sandbox escape sinks.
pub const JS_VM_SINKS: &[&str] = &[
    "runInNewContext", "runInContext", "runInThisContext", "Script",
];
