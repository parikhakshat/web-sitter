/// TypeScript-specific security patterns.
///
/// TypeScript shares all JavaScript patterns (same runtime, same CPG node
/// naming) so the JS tables are the primary reference.  This module adds
/// patterns specific to the TypeScript ecosystem:
///   - NestJS (decorators → HTTP handler parameters)
///   - TypeORM / Prisma (database access)
///   - Angular (XSS via DomSanitizer bypass, ElementRef.nativeElement)
///   - Type-safe HTTP clients (axios, superagent)
///   - tRPC / Zod (data coercion that passes taint through)

pub use super::javascript::{
    JS_TAINT_SOURCES, JS_TAINT_SINKS, JS_TAINT_PROPAGATORS,
    JS_DOM_XSS_SINKS, JS_EXEC_SINKS, JS_FILE_WRITE_SINKS, JS_DB_SINKS,
    JS_SSRF_SINKS, JS_EVAL_SINKS, JS_TEMPLATE_SINKS, JS_REDIRECT_SINKS,
    JS_DESERIALIZATION_SINKS, JS_LDAP_SINKS, JS_VM_SINKS,
};

use web_sitter::security_patterns::{SourceSpec, SinkSpec, PropagatorSpec};

// =============================================================================
// TypeScript-specific taint sources
// =============================================================================

/// Sources unique to the TypeScript / Node ecosystem.
pub const TS_TAINT_SOURCES: &[(&str, SourceSpec)] = &[
    // ── NestJS — decorator-injected HTTP request values ───────────────────────
    // @Body(), @Query(), @Param() are decorator factories that produce
    // parameters; the values they inject come from the HTTP request.
    // The decorator *functions* themselves appear as call expressions:
    (
        "Body",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Query",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Param",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Headers",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "Ip",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "HostParam",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // NestJS request helper (inject raw Request object)
    (
        "Req",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── Zod / Valibot — parse / safeParse return validated but still tainted ──
    (
        "safeParse",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── tRPC — procedure input ────────────────────────────────────────────────
    (
        "input",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── Angular — ActivatedRoute params / query params ────────────────────────
    // snapshot.paramMap.get / queryParamMap.get
    (
        "paramMap",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "queryParamMap",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── Node.js — readline interface ──────────────────────────────────────────
    (
        "question",
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
];

// =============================================================================
// TypeScript-specific taint sinks
// =============================================================================

pub const TS_TAINT_SINKS: &[(&str, SinkSpec)] = &[
    // ── TypeORM — raw query injection ─────────────────────────────────────────
    (
        "query",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "createQueryBuilder",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "where",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "andWhere",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "orWhere",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "having",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "select",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "orderBy",
        SinkSpec { sink_args: &[0] },
    ),
    // ── Prisma — $queryRaw / $executeRaw allow SQL injection with template ────
    (
        "$queryRaw",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "$executeRaw",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "$queryRawUnsafe",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "$executeRawUnsafe",
        SinkSpec { sink_args: &[0] },
    ),
    // ── Angular — DomSanitizer bypass — XSS ──────────────────────────────────
    (
        "bypassSecurityTrustHtml",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "bypassSecurityTrustScript",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "bypassSecurityTrustStyle",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "bypassSecurityTrustUrl",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "bypassSecurityTrustResourceUrl",
        SinkSpec { sink_args: &[0] },
    ),
    // ── axios / superagent / got — SSRF ──────────────────────────────────────
    (
        "axios",
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
        "patch",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "delete",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "request",
        SinkSpec { sink_args: &[0] },
    ),
    // ── NestJS — dynamic module loading (ClassSerializerInterceptor bypass) ───
    (
        "forRoot",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "forRootAsync",
        SinkSpec { sink_args: &[0] },
    ),
    // ── GraphQL — raw query strings ───────────────────────────────────────────
    (
        "gql",
        SinkSpec { sink_args: &[0] },
    ),
    // ── child_process (re-listed from JS for TS completeness) ─────────────────
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
    // ── eval / Function — code injection ──────────────────────────────────────
    (
        "eval",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Function",
        SinkSpec { sink_args: &[0] },
    ),
];

// =============================================================================
// TypeScript-specific propagators
// =============================================================================

pub const TS_TAINT_PROPAGATORS: &[(&str, PropagatorSpec)] = &[
    // Zod schema transforms — taint passes through
    (
        "transform",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "refine",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "parse",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // Angular Pipe.transform
    (
        "transform",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // String / Array from JS (inherited, but listed explicitly for TS tools)
    (
        "toString",
        PropagatorSpec { dst: -1, src: &[] },
    ),
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
    // Type assertions / casts — taint passes through unchanged at runtime
    (
        "as",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
];

// =============================================================================
// Named sets
// =============================================================================

/// TypeORM raw SQL sinks.
pub const TS_TYPEORM_SINKS: &[&str] = &[
    "query", "createQueryBuilder", "where", "andWhere", "orWhere",
    "having", "select", "orderBy",
];

/// Prisma unsafe raw sinks.
pub const TS_PRISMA_RAW_SINKS: &[&str] = &[
    "$queryRaw", "$executeRaw", "$queryRawUnsafe", "$executeRawUnsafe",
];

/// Angular DomSanitizer bypass sinks.
pub const TS_ANGULAR_BYPASS_SINKS: &[&str] = &[
    "bypassSecurityTrustHtml", "bypassSecurityTrustScript",
    "bypassSecurityTrustStyle", "bypassSecurityTrustUrl",
    "bypassSecurityTrustResourceUrl",
];

/// NestJS HTTP input decorator sources.
pub const TS_NESTJS_SOURCES: &[&str] = &[
    "Body", "Query", "Param", "Headers", "Ip", "HostParam", "Req",
];
