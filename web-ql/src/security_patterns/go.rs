/// Go stdlib / framework security patterns.
///
/// # Naming convention
///
/// The Go CPG's `extract_called_function_name` walks the `selector_expression`
/// in reverse and returns the **last identifier** — the method or function name
/// without the package qualifier.  Examples:
///
/// | Source text          | `call.name` |
/// |----------------------|-------------|
/// | `os.Getenv("K")`     | `"Getenv"`  |
/// | `exec.Command("ls")` | `"Command"` |
/// | `r.FormValue("k")`   | `"FormValue"` |
/// | `fmt.Sprintf(...)`   | `"Sprintf"` |
///
/// All keys below use this unqualified form.  Names are PascalCase / camelCase
/// as exported by the Go standard library.
///
/// Covered packages: `os`, `io`, `io/ioutil` (deprecated), `bufio`, `fmt`,
/// `net/http`, `os/exec`, `database/sql`, `text/template`, `html/template`,
/// `path`, `path/filepath`, `net`, `net/url`, `flag`, `log`, `syscall`,
/// `crypto/...`, `encoding/...`, `regexp`.

use web_sitter::security_patterns::{SourceSpec, SinkSpec, PropagatorSpec};

// =============================================================================
// Taint sources
// =============================================================================

pub const GO_TAINT_SOURCES: &[(&str, SourceSpec)] = &[
    // ── os — environment variables ────────────────────────────────────────────
    (
        "Getenv",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "LookupEnv",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Expand",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "ExpandEnv",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Environ",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── os — file I/O ─────────────────────────────────────────────────────────
    (
        "ReadFile",      // os.ReadFile / ioutil.ReadFile
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── io — stream reading ───────────────────────────────────────────────────
    (
        "ReadAll",       // io.ReadAll / ioutil.ReadAll
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "ReadFull",      // io.ReadFull — reads exactly len(buf) bytes
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    (
        "ReadAtLeast",
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    // ── bufio — buffered reader ───────────────────────────────────────────────
    (
        "ReadString",    // bufio.Reader.ReadString
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "ReadLine",      // bufio.Reader.ReadLine
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "ReadBytes",     // bufio.Reader.ReadBytes
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "ReadRune",      // bufio.Reader.ReadRune
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "ReadByte",      // bufio.Reader.ReadByte
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "ReadSlice",     // bufio.Reader.ReadSlice
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Text",          // bufio.Scanner.Text
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Bytes",         // bufio.Scanner.Bytes
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── fmt — stdin scanning ──────────────────────────────────────────────────
    (
        "Scan",          // fmt.Scan
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    (
        "Scanf",         // fmt.Scanf
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    (
        "Scanln",        // fmt.Scanln
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    (
        "Sscan",         // fmt.Sscan — scan from string
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    (
        "Sscanf",
        SourceSpec { tainted_params: &[2], tainted_return: false },
    ),
    (
        "Sscanln",
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    (
        "Fscan",         // fmt.Fscan — scan from reader
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    (
        "Fscanf",
        SourceSpec { tainted_params: &[2], tainted_return: false },
    ),
    (
        "Fscanln",
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    // ── net/http — HTTP server request values ─────────────────────────────────
    // Method calls on *http.Request; receiver is NOT arg 0
    (
        "FormValue",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "PostFormValue",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "PathValue",     // Go 1.22+ ServeMux path params
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "UserAgent",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Referer",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Cookie",        // *http.Request.Cookie — returns *Cookie
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Cookies",       // *http.Request.Cookies — returns []*Cookie
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // http.Header.Get — reads a single header value
    (
        "Get",           // Header.Get, url.Values.Get
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── flag — command-line flags ─────────────────────────────────────────────
    // flag.String / flag.Int etc. return pointers; the *ptr is the tainted value.
    // Model as tainted_return since the pointer itself is attacker-controlled.
    (
        "String",        // flag.String
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Int",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Int64",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Float64",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Bool",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Duration",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Args",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Arg",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── os — stdin raw read ────────────────────────────────────────────────────
    (
        "Read",          // (*os.File).Read (os.Stdin.Read)
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
];

// =============================================================================
// Taint sinks
// =============================================================================

pub const GO_TAINT_SINKS: &[(&str, SinkSpec)] = &[
    // ── os/exec — OS command injection ────────────────────────────────────────
    // exec.Command(name, args...) — both name and args must be clean
    (
        "Command",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "CommandContext",
        SinkSpec { sink_args: &[1] },
    ),
    // (*exec.Cmd).Run / Output / CombinedOutput execute the command
    (
        "Run",
        SinkSpec { sink_args: &[] },
    ),
    (
        "Output",
        SinkSpec { sink_args: &[] },
    ),
    (
        "CombinedOutput",
        SinkSpec { sink_args: &[] },
    ),
    (
        "Start",
        SinkSpec { sink_args: &[] },
    ),
    (
        "Wait",
        SinkSpec { sink_args: &[] },
    ),
    // syscall.Exec / syscall.ForkExec
    (
        "Exec",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "ForkExec",
        SinkSpec { sink_args: &[0, 1] },
    ),
    // ── database/sql — SQL injection ──────────────────────────────────────────
    (
        "Query",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "QueryRow",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "QueryContext",
        SinkSpec { sink_args: &[1] },
    ),
    (
        "QueryRowContext",
        SinkSpec { sink_args: &[1] },
    ),
    (
        "Prepare",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "PrepareContext",
        SinkSpec { sink_args: &[1] },
    ),
    // ── text/template — template injection (use html/template for HTML) ────────
    // template.Execute with user-controlled template name
    (
        "Execute",
        SinkSpec { sink_args: &[1] },
    ),
    (
        "ExecuteTemplate",
        SinkSpec { sink_args: &[1, 2] },
    ),
    (
        "ParseFiles",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "ParseGlob",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "ParseFS",
        SinkSpec { sink_args: &[0, 1] },
    ),
    // ── html/template — unsafe conversions (bypass HTML escaping) ─────────────
    // template.HTML(s), template.JS(s), template.URL(s) etc.
    (
        "HTML",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "JS",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "URL",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Attr",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "CSS",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "JSStr",
        SinkSpec { sink_args: &[0] },
    ),
    // ── os — file system path traversal ──────────────────────────────────────
    (
        "Open",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "OpenFile",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Create",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "CreateTemp",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "Mkdir",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "MkdirAll",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "MkdirTemp",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "Remove",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "RemoveAll",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Rename",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "Symlink",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "Link",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "WriteFile",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "Chown",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Chmod",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Stat",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Lstat",
        SinkSpec { sink_args: &[0] },
    ),
    // ── net/http — SSRF / HTTP response ──────────────────────────────────────
    (
        "Get",           // http.Get(url) — SSRF
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Post",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Head",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Do",            // (*http.Client).Do
        SinkSpec { sink_args: &[0] },
    ),
    (
        "NewRequest",
        SinkSpec { sink_args: &[1] },
    ),
    (
        "NewRequestWithContext",
        SinkSpec { sink_args: &[2] },
    ),
    (
        "ServeFile",
        SinkSpec { sink_args: &[2] },
    ),
    (
        "ServeContent",
        SinkSpec { sink_args: &[2] },
    ),
    (
        "Redirect",
        SinkSpec { sink_args: &[2] },
    ),
    // http.ResponseWriter.Header().Set() — header injection
    (
        "Set",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "Add",
        SinkSpec { sink_args: &[0, 1] },
    ),
    // ── net — network dial (SSRF) ─────────────────────────────────────────────
    (
        "Dial",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "DialContext",
        SinkSpec { sink_args: &[1, 2] },
    ),
    (
        "DialTimeout",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "DialTCP",
        SinkSpec { sink_args: &[0, 1, 2] },
    ),
    (
        "DialUDP",
        SinkSpec { sink_args: &[0, 1, 2] },
    ),
    (
        "LookupHost",    // DNS lookup — SSRF via DNS rebinding
        SinkSpec { sink_args: &[0] },
    ),
    (
        "LookupIP",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "LookupAddr",
        SinkSpec { sink_args: &[0] },
    ),
    // ── log — log injection ────────────────────────────────────────────────────
    (
        "Print",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Println",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Printf",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Fatal",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Fatalf",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Fatalln",
        SinkSpec { sink_args: &[0] },
    ),
    // ── fmt — formatted I/O write sinks ──────────────────────────────────────
    (
        "Fprintf",       // fmt.Fprintf(w, format, ...) — write to http.ResponseWriter
        SinkSpec { sink_args: &[1] },
    ),
    (
        "Fprintln",
        SinkSpec { sink_args: &[1] },
    ),
    (
        "Fprint",
        SinkSpec { sink_args: &[1] },
    ),
    // ── LDAP (various Go LDAP packages) ───────────────────────────────────────
    (
        "Search",
        SinkSpec { sink_args: &[0] },
    ),
    // ── go-redis / MongoDB Go driver ──────────────────────────────────────────
    (
        "Do",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "FindOne",
        SinkSpec { sink_args: &[1] },
    ),
    (
        "Find",
        SinkSpec { sink_args: &[1] },
    ),
    (
        "UpdateOne",
        SinkSpec { sink_args: &[1, 2] },
    ),
    (
        "DeleteOne",
        SinkSpec { sink_args: &[1] },
    ),
    // ── url.Parse — SSRF input validation bypass ──────────────────────────────
    (
        "Parse",         // url.Parse — attacker supplies URL
        SinkSpec { sink_args: &[0] },
    ),
    (
        "ParseRequestURI",
        SinkSpec { sink_args: &[0] },
    ),
];

// =============================================================================
// Taint propagators
// =============================================================================

pub const GO_TAINT_PROPAGATORS: &[(&str, PropagatorSpec)] = &[
    // ── fmt — string formatting ────────────────────────────────────────────────
    (
        "Sprintf",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    (
        "Sprint",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    (
        "Sprintln",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    (
        "Errorf",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    // ── strings ───────────────────────────────────────────────────────────────
    (
        "Join",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Replace",
        PropagatorSpec { dst: -1, src: &[0, 2] },
    ),
    (
        "ReplaceAll",
        PropagatorSpec { dst: -1, src: &[0, 2] },
    ),
    (
        "ToLower",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "ToUpper",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "ToTitle",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "TrimSpace",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Trim",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "TrimLeft",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "TrimRight",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "TrimPrefix",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "TrimSuffix",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "TrimFunc",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Split",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "SplitN",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "SplitAfter",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "SplitAfterN",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Fields",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "FieldsFunc",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Repeat",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Map",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    (
        "NewReplacer",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    // strings.Builder.WriteString / Write
    (
        "WriteString",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Write",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "WriteByte",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "WriteRune",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // strings.Builder.String() — returns the built string
    (
        "String",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    // ── bytes ─────────────────────────────────────────────────────────────────
    (
        "Join",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Replace",
        PropagatorSpec { dst: -1, src: &[0, 2] },
    ),
    (
        "ReplaceAll",
        PropagatorSpec { dst: -1, src: &[0, 2] },
    ),
    (
        "ToLower",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "ToUpper",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "TrimSpace",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Trim",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Split",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── path / path/filepath — taint passes through path construction ─────────
    (
        "Join",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    (
        "Base",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Dir",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Ext",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Clean",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "EvalSymlinks",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Abs",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Rel",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    // ── strconv ───────────────────────────────────────────────────────────────
    (
        "Itoa",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "FormatInt",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "FormatFloat",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "FormatBool",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Quote",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Unquote",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "AppendInt",
        PropagatorSpec { dst: -1, src: &[0, 1] },
    ),
    (
        "AppendFloat",
        PropagatorSpec { dst: -1, src: &[0, 1] },
    ),
    // ── url — URL manipulation carries taint ──────────────────────────────────
    (
        "QueryEscape",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "PathEscape",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "QueryUnescape",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "PathUnescape",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── encoding/base64 — encoding does not sanitize taint ────────────────────
    (
        "EncodeToString",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "DecodeString",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Encode",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    (
        "Decode",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    // ── encoding/json — taint passes through marshaling ───────────────────────
    (
        "Marshal",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "Unmarshal",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── regexp — replacement result inherits taint ────────────────────────────
    (
        "ReplaceAllString",
        PropagatorSpec { dst: -1, src: &[0, 2] },
    ),
    (
        "ReplaceAllStringFunc",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "ReplaceAll",
        PropagatorSpec { dst: -1, src: &[0, 2] },
    ),
    (
        "FindString",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "FindAllString",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "FindStringSubmatch",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
];

// =============================================================================
// Named sets
// =============================================================================

/// Go os/exec command execution sinks.
pub const GO_EXEC_SINKS: &[&str] = &[
    "Command", "CommandContext", "Run", "Output", "CombinedOutput", "Start", "Wait",
    "Exec", "ForkExec",
];

/// Go database/sql sinks.
pub const GO_SQL_SINKS: &[&str] = &[
    "Query", "QueryRow", "QueryContext", "QueryRowContext",
    "Prepare", "PrepareContext",
];

/// Go file system sinks (path traversal).
pub const GO_FILE_SINKS: &[&str] = &[
    "Open", "OpenFile", "Create", "CreateTemp", "Mkdir", "MkdirAll", "MkdirTemp",
    "Remove", "RemoveAll", "Rename", "Symlink", "Link", "WriteFile", "Chown", "Chmod",
    "Stat", "Lstat",
];

/// Go network / SSRF sinks.
pub const GO_NET_SINKS: &[&str] = &[
    "Get", "Post", "Head", "Do", "NewRequest", "NewRequestWithContext",
    "Dial", "DialContext", "DialTimeout", "DialTCP", "DialUDP",
    "LookupHost", "LookupIP", "LookupAddr", "Parse", "ParseRequestURI",
];

/// Go http response sinks.
pub const GO_HTTP_RESPONSE_SINKS: &[&str] = &[
    "ServeFile", "ServeContent", "Redirect", "Fprintf", "Fprintln", "Fprint",
    "Set", "Add",
];

/// Go template injection sinks.
pub const GO_TEMPLATE_SINKS: &[&str] = &[
    "Execute", "ExecuteTemplate", "ParseFiles", "ParseGlob", "ParseFS",
    "HTML", "JS", "URL", "Attr", "CSS", "JSStr",
];

/// Go environment variable sources.
pub const GO_ENV_SOURCES: &[&str] = &[
    "Getenv", "LookupEnv", "Expand", "ExpandEnv", "Environ",
];

/// Go HTTP request sources (method calls on *http.Request).
pub const GO_HTTP_REQUEST_SOURCES: &[&str] = &[
    "FormValue", "PostFormValue", "PathValue", "UserAgent", "Referer",
    "Cookie", "Cookies", "Get",
];

/// Go stdin / file read sources.
pub const GO_READ_SOURCES: &[&str] = &[
    "ReadFile", "ReadAll", "ReadFull", "ReadAtLeast",
    "ReadString", "ReadLine", "ReadBytes", "ReadRune", "ReadByte", "ReadSlice",
    "Text", "Bytes", "Read",
    "Scan", "Scanf", "Scanln", "Sscan", "Sscanf", "Sscanln",
    "Fscan", "Fscanf", "Fscanln",
];

/// Go flag sources.
pub const GO_FLAG_SOURCES: &[&str] = &[
    "String", "Int", "Int64", "Float64", "Bool", "Duration", "Args", "Arg",
];
