use std::collections::HashMap;
use crate::taint::EndpointRegistry;
use web_sitter::{Cpg, IrNodeKind, NodeId};

/// Register well-known library sources, sinks, and sanitizers into an endpoint registry.
/// These cover the most common vulnerability patterns across all supported languages.
pub fn register_builtins(registry: &mut EndpointRegistry) {
    // ── Common sinks ──────────────────────────────────────────────────────────

    // SQL injection sinks
    registry.register("sql_sink", |cpg: &Cpg| {
        let sql_fns: &[&str] = &[
            "query", "execute", "exec", "raw", "rawQuery", "prepare",
            "db.Exec", "db.Query", "db.QueryRow", "cursor.execute",
        ];
        find_calls_to(cpg, sql_fns)
    });

    // Command injection sinks
    registry.register("cmd_sink", |cpg: &Cpg| {
        let cmd_fns: &[&str] = &[
            "system", "exec", "popen", "subprocess.run", "subprocess.call",
            "os.system", "os.popen", "Runtime.exec", "ProcessBuilder",
            "exec.Command", "os/exec",
        ];
        find_calls_to(cpg, cmd_fns)
    });

    // Path traversal sinks
    registry.register("path_sink", |cpg: &Cpg| {
        let path_fns: &[&str] = &[
            "open", "fopen", "os.Open", "os.ReadFile", "os.WriteFile",
            "filepath.Join", "path.join", "open(", "readFile", "writeFile",
        ];
        find_calls_to(cpg, path_fns)
    });

    // XSS sinks
    registry.register("xss_sink", |cpg: &Cpg| {
        let xss_fns: &[&str] = &[
            "innerHTML", "document.write", "eval", "dangerouslySetInnerHTML",
            "outerHTML", "insertAdjacentHTML",
        ];
        find_calls_to(cpg, xss_fns)
    });

    // Deserialization sinks
    registry.register("deser_sink", |cpg: &Cpg| {
        let deser_fns: &[&str] = &[
            "pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load",
            "marshal.loads", "ObjectInputStream", "deserialize",
            "json.Unmarshal", "encoding/gob",
        ];
        find_calls_to(cpg, deser_fns)
    });

    // ── Common sources ────────────────────────────────────────────────────────

    // HTTP request parameters
    registry.register("http_source", |cpg: &Cpg| {
        let http_fns: &[&str] = &[
            "request.GET", "request.POST", "request.args", "request.form",
            "r.URL.Query", "r.FormValue", "req.body", "req.params",
            "req.query", "ctx.Request", "c.Query", "c.Param", "c.PostForm",
        ];
        find_calls_to(cpg, http_fns)
    });

    // Environment variables (often used as config injection points)
    registry.register("env_source", |cpg: &Cpg| {
        let env_fns: &[&str] = &[
            "os.Getenv", "os.environ", "os.environ.get", "System.getenv",
            "process.env", "getenv",
        ];
        find_calls_to(cpg, env_fns)
    });

    // Command-line arguments
    registry.register("argv_source", |cpg: &Cpg| {
        // os.Args in Go, sys.argv in Python, process.argv in Node, etc.
        find_identifier_refs(cpg, &["os.Args", "sys.argv", "process.argv", "argv"])
    });

    // ── Common sanitizers ─────────────────────────────────────────────────────

    registry.register("html_escape", |cpg: &Cpg| {
        let esc_fns: &[&str] = &[
            "html.EscapeString", "html.escape", "escape", "escapeHtml",
            "sanitize", "DOMPurify.sanitize", "encodeURIComponent",
        ];
        find_calls_to(cpg, esc_fns)
    });

    registry.register("sql_escape", |cpg: &Cpg| {
        let esc_fns: &[&str] = &[
            "db.Escape", "mysql_real_escape_string", "pg_escape_string",
            "quote_ident", "parameterize", "prepared_statement",
        ];
        find_calls_to(cpg, esc_fns)
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn find_calls_to(cpg: &Cpg, fn_names: &[&str]) -> Vec<NodeId> {
    let mut result = Vec::new();
    for (id, node) in &cpg.ast {
        if node.kind == IrNodeKind::Call {
            let callee = node.name.as_deref().unwrap_or("");
            if fn_names.iter().any(|&f| callee.contains(f)) {
                result.push(*id);
            }
        }
    }
    result
}

fn find_identifier_refs(cpg: &Cpg, names: &[&str]) -> Vec<NodeId> {
    let mut result = Vec::new();
    for (id, node) in &cpg.ast {
        if node.kind == IrNodeKind::Identifier || node.kind == IrNodeKind::MemberAccess {
            let name = node.name.as_deref().unwrap_or("");
            if names.iter().any(|&n| name == n) {
                result.push(*id);
            }
        }
    }
    result
}
