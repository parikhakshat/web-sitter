/// Java stdlib / framework security patterns.
///
/// # Naming convention
///
/// The Java CPG lifter stores **bare method names** on `Call` nodes
/// (`method_invocation` → `child_with_field("name")`).  A call like
/// `request.getParameter("key")` has `call.name = "getParameter"`.
/// All keys in the tables below must match that unqualified form.
///
/// Covered packages / frameworks:
///   `java.io`, `java.net`, `java.sql`, `java.lang`, `java.util`,
///   `javax.servlet` / `jakarta.servlet`, Spring MVC, Spring WebFlux,
///   Spring Data JPA, Hibernate ORM, Jackson, Gson, JNDI, Reflection API,
///   Apache Commons, Log4j, ScriptEngine (JSR-223), XXE (JAXP).
use web_sitter::security_patterns::{PropagatorSpec, SinkSpec, SourceSpec};

// =============================================================================
// Taint sources — functions / methods that return attacker-controlled data
// =============================================================================

pub const JAVA_TAINT_SOURCES: &[(&str, SourceSpec)] = &[
    // ── javax.servlet / jakarta.servlet — HttpServletRequest ─────────────────
    (
        "getParameter",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getParameterValues",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getParameterMap",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getParameterNames",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getHeader",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getHeaders",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getHeaderNames",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getIntHeader",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getDateHeader",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getQueryString",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getRequestURI",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getRequestURL",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getPathInfo",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getPathTranslated",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getServletPath",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getContextPath",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getRemoteAddr",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getRemoteHost",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getRemoteUser",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getRemotePort",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getCookies",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getInputStream",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getReader",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getMethod",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getAuthType",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // Cookie.getValue / Cookie.getName
    (
        "getValue",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getName",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── java.io — BufferedReader / InputStream ────────────────────────────────
    (
        "readLine",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "read",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    (
        "readAllBytes",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "readNBytes",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── java.util.Scanner ─────────────────────────────────────────────────────
    (
        "next",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "nextLine",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "nextInt",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "nextLong",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "nextFloat",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "nextDouble",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "nextBoolean",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "nextBigDecimal",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "nextBigInteger",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── java.sql — ResultSet (database data can be attacker-influenced) ───────
    (
        "getString",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getInt",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getLong",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getDouble",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getFloat",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getBytes",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getObject",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getClob",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getBlob",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getNString",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getArray",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getURL",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── java.lang / java.util — environment / properties ─────────────────────
    (
        "getenv",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getProperty",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getProperties",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // System.in.read — InputStreamReader on stdin
    (
        "readAllBytes",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── java.io — ObjectInputStream deserialization ───────────────────────────
    (
        "readObject",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "readUnshared",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── Spring MVC — @RequestParam / @PathVariable / HttpEntity ──────────────
    // Spring WebFlux ServerRequest
    (
        "queryParam",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "queryParams",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "pathVariable",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "pathVariables",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "formData",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "bodyToMono",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "bodyToFlux",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // HttpEntity.getBody
    (
        "getBody",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── Jackson ObjectMapper.readValue ────────────────────────────────────────
    (
        "readValue",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "readTree",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── Gson fromJson ─────────────────────────────────────────────────────────
    (
        "fromJson",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── java.net — URLConnection / HttpURLConnection ──────────────────────────
    (
        "getContent",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getResponseMessage",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── java.util.Properties ─────────────────────────────────────────────────
    (
        "getProperty",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── Apache Commons CLI / args4j ───────────────────────────────────────────
    (
        "getOptionValue",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getOptionValues",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getArgs",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── java.util.ResourceBundle (locale-specific user messages) ─────────────
    (
        "getString",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
];

// =============================================================================
// Taint sinks — methods that must not receive tainted data
// =============================================================================

pub const JAVA_TAINT_SINKS: &[(&str, SinkSpec)] = &[
    // ── java.lang.Runtime — OS command injection ──────────────────────────────
    ("exec", SinkSpec { sink_args: &[0] }),
    // ── java.lang.ProcessBuilder — OS command injection ───────────────────────
    ("start", SinkSpec { sink_args: &[0] }),
    ("command", SinkSpec { sink_args: &[0] }),
    // ── java.sql — SQL injection ──────────────────────────────────────────────
    ("execute", SinkSpec { sink_args: &[0] }),
    ("executeQuery", SinkSpec { sink_args: &[0] }),
    ("executeUpdate", SinkSpec { sink_args: &[0] }),
    ("executeLargeUpdate", SinkSpec { sink_args: &[0] }),
    ("executeBatch", SinkSpec { sink_args: &[] }),
    ("addBatch", SinkSpec { sink_args: &[0] }),
    ("prepareStatement", SinkSpec { sink_args: &[0] }),
    ("prepareCall", SinkSpec { sink_args: &[0] }),
    ("createStatement", SinkSpec { sink_args: &[] }),
    // ── JPA / Hibernate — HQL / JPQL injection ───────────────────────────────
    ("createQuery", SinkSpec { sink_args: &[0] }),
    ("createNativeQuery", SinkSpec { sink_args: &[0] }),
    ("createNamedQuery", SinkSpec { sink_args: &[0] }),
    // Hibernate Criteria API (deprecated but found in legacy code)
    ("add", SinkSpec { sink_args: &[0] }),
    // ── javax.script — ScriptEngine code injection ────────────────────────────
    ("eval", SinkSpec { sink_args: &[0] }),
    // ── java.lang.Class / ClassLoader — reflection injection ──────────────────
    ("forName", SinkSpec { sink_args: &[0] }),
    ("loadClass", SinkSpec { sink_args: &[0] }),
    ("newInstance", SinkSpec { sink_args: &[] }),
    ("getMethod", SinkSpec { sink_args: &[0] }),
    ("getDeclaredMethod", SinkSpec { sink_args: &[0] }),
    ("getField", SinkSpec { sink_args: &[0] }),
    ("getDeclaredField", SinkSpec { sink_args: &[0] }),
    ("invoke", SinkSpec { sink_args: &[0, 1] }),
    // ── JNDI — JNDI injection (Log4Shell pattern) ─────────────────────────────
    ("lookup", SinkSpec { sink_args: &[0] }),
    ("bind", SinkSpec { sink_args: &[0] }),
    ("rebind", SinkSpec { sink_args: &[0] }),
    // ── javax.servlet — XSS / open redirect / header injection ───────────────
    ("print", SinkSpec { sink_args: &[0] }),
    ("println", SinkSpec { sink_args: &[0] }),
    ("write", SinkSpec { sink_args: &[0] }),
    ("sendRedirect", SinkSpec { sink_args: &[0] }),
    ("setHeader", SinkSpec { sink_args: &[0, 1] }),
    ("addHeader", SinkSpec { sink_args: &[0, 1] }),
    ("addCookie", SinkSpec { sink_args: &[0] }),
    ("setContentType", SinkSpec { sink_args: &[0] }),
    // RequestDispatcher — path traversal / forced browsing
    ("forward", SinkSpec { sink_args: &[0] }),
    ("include", SinkSpec { sink_args: &[0] }),
    // ── java.io — file write path traversal ──────────────────────────────────
    ("write", SinkSpec { sink_args: &[0] }),
    ("writeBytes", SinkSpec { sink_args: &[0] }),
    ("writeTo", SinkSpec { sink_args: &[0] }),
    // ── java.nio.file.Files ───────────────────────────────────────────────────
    ("copy", SinkSpec { sink_args: &[0, 1] }),
    ("move", SinkSpec { sink_args: &[0, 1] }),
    ("delete", SinkSpec { sink_args: &[0] }),
    ("createFile", SinkSpec { sink_args: &[0] }),
    ("createDirectory", SinkSpec { sink_args: &[0] }),
    (
        "createTempFile",
        SinkSpec {
            sink_args: &[0, 1, 2],
        },
    ),
    ("createTempDirectory", SinkSpec { sink_args: &[0] }),
    ("newOutputStream", SinkSpec { sink_args: &[0] }),
    ("newInputStream", SinkSpec { sink_args: &[0] }),
    ("writeString", SinkSpec { sink_args: &[0, 1] }),
    // ── JAXP — XML eXternal Entity (XXE) injection ───────────────────────────
    ("parse", SinkSpec { sink_args: &[0] }),
    ("newSAXParser", SinkSpec { sink_args: &[] }),
    // ── Spring RestTemplate — SSRF ────────────────────────────────────────────
    ("getForObject", SinkSpec { sink_args: &[0] }),
    ("getForEntity", SinkSpec { sink_args: &[0] }),
    ("postForObject", SinkSpec { sink_args: &[0] }),
    ("postForEntity", SinkSpec { sink_args: &[0] }),
    ("exchange", SinkSpec { sink_args: &[0] }),
    // ── java.net — URL / URLConnection — SSRF ────────────────────────────────
    ("openConnection", SinkSpec { sink_args: &[] }),
    ("openStream", SinkSpec { sink_args: &[] }),
    // ── Apache HttpClient ─────────────────────────────────────────────────────
    ("execute", SinkSpec { sink_args: &[0] }),
    // ── java.io — ObjectOutputStream deserialization gadget sink ──────────────
    ("writeObject", SinkSpec { sink_args: &[0] }),
    // ── Velocity / FreeMarker / Thymeleaf — template injection ───────────────
    ("process", SinkSpec { sink_args: &[0] }),
    ("mergeTemplate", SinkSpec { sink_args: &[0, 1] }),
    ("render", SinkSpec { sink_args: &[0] }),
    // ── Log4j — log injection (log messages can contain JNDI lookups) ─────────
    ("debug", SinkSpec { sink_args: &[0] }),
    ("info", SinkSpec { sink_args: &[0] }),
    ("warn", SinkSpec { sink_args: &[0] }),
    ("error", SinkSpec { sink_args: &[0] }),
    ("fatal", SinkSpec { sink_args: &[0] }),
    ("trace", SinkSpec { sink_args: &[0] }),
    ("log", SinkSpec { sink_args: &[0] }),
    // ── LDAP — LDAP injection ─────────────────────────────────────────────────
    (
        "search",
        SinkSpec {
            sink_args: &[0, 1, 2],
        },
    ),
    (
        "searchSubtree",
        SinkSpec {
            sink_args: &[0, 1, 2],
        },
    ),
    // ── XPath injection ───────────────────────────────────────────────────────
    ("compile", SinkSpec { sink_args: &[0] }),
    ("evaluate", SinkSpec { sink_args: &[0] }),
    ("selectNodes", SinkSpec { sink_args: &[0] }),
    ("selectSingleNode", SinkSpec { sink_args: &[0] }),
    // ── Spring Security — authentication bypass patterns ──────────────────────
    ("hasRole", SinkSpec { sink_args: &[0] }),
    ("hasAuthority", SinkSpec { sink_args: &[0] }),
    // ── JSP / template output ─────────────────────────────────────────────────
    ("printWriter", SinkSpec { sink_args: &[0] }),
];

// =============================================================================
// Taint propagators — methods that carry taint from arguments to return value
// =============================================================================

/// For Java method calls the receiver (the object before `.`) is NOT modelled
/// as argument 0 in the IR.  Only the explicit argument list is indexed.
/// Therefore propagators below model "if any arg is tainted, the return is
/// tainted" via `src: &[0]` or `src: &[-1]` (all args).
pub const JAVA_TAINT_PROPAGATORS: &[(&str, PropagatorSpec)] = &[
    // ── java.lang.String ──────────────────────────────────────────────────────
    ("concat", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "format",
        PropagatorSpec {
            dst: -1,
            src: &[-1],
        },
    ),
    (
        "formatted",
        PropagatorSpec {
            dst: -1,
            src: &[-1],
        },
    ),
    ("substring", PropagatorSpec { dst: -1, src: &[] }),
    ("replace", PropagatorSpec { dst: -1, src: &[1] }),
    ("replaceAll", PropagatorSpec { dst: -1, src: &[1] }),
    ("replaceFirst", PropagatorSpec { dst: -1, src: &[1] }),
    ("toLowerCase", PropagatorSpec { dst: -1, src: &[] }),
    ("toUpperCase", PropagatorSpec { dst: -1, src: &[] }),
    ("trim", PropagatorSpec { dst: -1, src: &[] }),
    ("strip", PropagatorSpec { dst: -1, src: &[] }),
    ("stripLeading", PropagatorSpec { dst: -1, src: &[] }),
    ("stripTrailing", PropagatorSpec { dst: -1, src: &[] }),
    ("intern", PropagatorSpec { dst: -1, src: &[] }),
    ("toCharArray", PropagatorSpec { dst: -1, src: &[] }),
    ("getBytes", PropagatorSpec { dst: -1, src: &[] }),
    ("toString", PropagatorSpec { dst: -1, src: &[] }),
    ("valueOf", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "join",
        PropagatorSpec {
            dst: -1,
            src: &[-1],
        },
    ),
    ("repeat", PropagatorSpec { dst: -1, src: &[0] }),
    ("indent", PropagatorSpec { dst: -1, src: &[0] }),
    ("translateEscapes", PropagatorSpec { dst: -1, src: &[] }),
    ("chars", PropagatorSpec { dst: -1, src: &[] }),
    ("split", PropagatorSpec { dst: -1, src: &[0] }),
    ("stripIndent", PropagatorSpec { dst: -1, src: &[] }),
    // ── java.lang.StringBuilder / StringBuffer ────────────────────────────────
    ("append", PropagatorSpec { dst: -1, src: &[0] }),
    ("insert", PropagatorSpec { dst: -1, src: &[1] }),
    ("delete", PropagatorSpec { dst: -1, src: &[] }),
    ("deleteCharAt", PropagatorSpec { dst: -1, src: &[] }),
    ("reverse", PropagatorSpec { dst: -1, src: &[] }),
    ("setCharAt", PropagatorSpec { dst: -1, src: &[1] }),
    // ── java.util.List / Collection ───────────────────────────────────────────
    ("get", PropagatorSpec { dst: -1, src: &[] }),
    ("getOrDefault", PropagatorSpec { dst: -1, src: &[1] }),
    ("subList", PropagatorSpec { dst: -1, src: &[] }),
    ("toArray", PropagatorSpec { dst: -1, src: &[] }),
    // ── java.util.Optional ────────────────────────────────────────────────────
    ("orElse", PropagatorSpec { dst: -1, src: &[0] }),
    ("orElseGet", PropagatorSpec { dst: -1, src: &[] }),
    ("map", PropagatorSpec { dst: -1, src: &[] }),
    ("flatMap", PropagatorSpec { dst: -1, src: &[] }),
    ("filter", PropagatorSpec { dst: -1, src: &[] }),
    // ── String.format-style helpers (Apache Commons / Guava) ─────────────────
    (
        "format",
        PropagatorSpec {
            dst: -1,
            src: &[-1],
        },
    ),
    (
        "sprintf",
        PropagatorSpec {
            dst: -1,
            src: &[-1],
        },
    ),
    (
        "formatMessage",
        PropagatorSpec {
            dst: -1,
            src: &[-1],
        },
    ),
    // ── Jackson / JSON — propagate taint through serialized form ──────────────
    ("writeValueAsString", PropagatorSpec { dst: -1, src: &[0] }),
    ("toJson", PropagatorSpec { dst: -1, src: &[0] }),
    // ── java.util.Base64 — encoding does not sanitize taint ──────────────────
    ("encodeToString", PropagatorSpec { dst: -1, src: &[0] }),
    ("decode", PropagatorSpec { dst: -1, src: &[0] }),
    // ── java.net.URLEncoder / URLDecoder — taint passes through ───────────────
    ("encode", PropagatorSpec { dst: -1, src: &[0] }),
    ("decode", PropagatorSpec { dst: -1, src: &[0] }),
];

// =============================================================================
// Named sets (for rule-loader named-set references)
// =============================================================================

/// Servlet / Jakarta EE HTTP request sources.
pub const JAVA_HTTP_SOURCES: &[&str] = &[
    "getParameter",
    "getParameterValues",
    "getParameterMap",
    "getParameterNames",
    "getHeader",
    "getHeaders",
    "getHeaderNames",
    "getIntHeader",
    "getDateHeader",
    "getQueryString",
    "getRequestURI",
    "getRequestURL",
    "getPathInfo",
    "getPathTranslated",
    "getServletPath",
    "getContextPath",
    "getRemoteAddr",
    "getRemoteHost",
    "getRemoteUser",
    "getCookies",
    "getInputStream",
    "getReader",
    "getMethod",
    "getAuthType",
    "getValue", // Cookie.getValue
];

/// JDBC / JPA query methods — SQL injection sinks.
pub const JAVA_SQL_SINKS: &[&str] = &[
    "execute",
    "executeQuery",
    "executeUpdate",
    "executeLargeUpdate",
    "executeBatch",
    "addBatch",
    "prepareStatement",
    "prepareCall",
    "createQuery",
    "createNativeQuery",
    "createNamedQuery",
    "executeQuery",
];

/// OS command injection sinks.
pub const JAVA_EXEC_SINKS: &[&str] = &["exec", "start", "command"];

/// Reflection / class loading sinks.
pub const JAVA_REFLECTION_SINKS: &[&str] = &[
    "forName",
    "loadClass",
    "newInstance",
    "getMethod",
    "getDeclaredMethod",
    "getField",
    "getDeclaredField",
    "invoke",
];

/// Deserialization sources (return attacker-controlled object graph).
pub const JAVA_DESERIALIZATION_SOURCES: &[&str] = &[
    "readObject",
    "readUnshared",
    "readValue",
    "readTree",
    "fromJson",
];

/// HTTP response sinks (XSS / header injection / open redirect).
pub const JAVA_HTTP_RESPONSE_SINKS: &[&str] = &[
    "print",
    "println",
    "write",
    "sendRedirect",
    "setHeader",
    "addHeader",
    "addCookie",
    "setContentType",
    "forward",
    "include",
];

/// Log injection sinks (also JNDI via Log4j).
pub const JAVA_LOG_SINKS: &[&str] = &["debug", "info", "warn", "error", "fatal", "trace", "log"];

/// JNDI injection sinks.
pub const JAVA_JNDI_SINKS: &[&str] = &["lookup", "bind", "rebind"];

/// XPath injection sinks.
pub const JAVA_XPATH_SINKS: &[&str] = &["compile", "evaluate", "selectNodes", "selectSingleNode"];

/// LDAP injection sinks.
pub const JAVA_LDAP_SINKS: &[&str] = &["search", "searchSubtree"];

/// XXE sinks (JAXP).
pub const JAVA_XXE_SINKS: &[&str] = &["parse", "newSAXParser"];

/// Template injection sinks.
pub const JAVA_TEMPLATE_SINKS: &[&str] = &["process", "mergeTemplate", "render", "evaluate"];

/// SSRF sinks.
pub const JAVA_SSRF_SINKS: &[&str] = &[
    "getForObject",
    "getForEntity",
    "postForObject",
    "postForEntity",
    "exchange",
    "openConnection",
    "openStream",
    "execute",
];
