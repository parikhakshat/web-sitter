/*
 * Simplified lighttpd-style mod_rewrite module.
 * Demonstrates CWE-22 (Path Traversal) via unvalidated user input in
 * URL path concatenation, along with a function pointer callback pattern.
 *
 * Vulnerability: The rewritten URL path is appended to the docroot without
 * sanitizing ".." sequences, allowing an attacker to traverse outside the
 * web root.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_PATH_LEN 4096
#define DOCROOT      "/var/www/html"

/* ------------------------------------------------------------------ */
/* Callback types (function pointer pattern typical in lighttpd)       */
/* ------------------------------------------------------------------ */

typedef struct connection {
    char  uri_path[MAX_PATH_LEN];   /* raw path from HTTP request line */
    char  physical_path[MAX_PATH_LEN];
    int   http_status;
} connection;

typedef int (*rewrite_fn)(connection *con, void *plugin_data);

typedef struct plugin_data {
    char  docroot[MAX_PATH_LEN];
    char  rewrite_base[MAX_PATH_LEN];
    rewrite_fn  on_match;           /* user-registered callback */
} plugin_data;

/* ------------------------------------------------------------------ */
/* Utility helpers                                                     */
/* ------------------------------------------------------------------ */

/* Returns 1 if path contains a ".." component, 0 otherwise.
 * NOTE: This check is intentionally incomplete to model the real bug —
 * it only looks for literal "/../", missing "/.." at the end of path. */
static int path_contains_dotdot(const char *path) {
    return strstr(path, "/../") != NULL;
}

static void url_decode_inplace(char *buf, size_t buf_len) {
    /* Simplified: just NUL-terminate to buf_len */
    if (buf_len > 0)
        buf[buf_len - 1] = '\0';
}

/* ------------------------------------------------------------------ */
/* Core rewrite logic                                                  */
/* ------------------------------------------------------------------ */

/*
 * mod_rewrite_apply_rule:
 *   Rewrites con->uri_path according to a prefix rule.
 *   Stores result back in con->uri_path.
 *   Returns 0 on success, -1 if the path doesn't match the rule base.
 */
static int mod_rewrite_apply_rule(connection *con,
                                   const char *rule_base,
                                   const char *replacement) {
    size_t base_len = strlen(rule_base);

    if (strncmp(con->uri_path, rule_base, base_len) != 0)
        return -1;  /* rule doesn't apply */

    /* Build rewritten path: replacement + suffix after rule_base */
    const char *suffix = con->uri_path + base_len;
    snprintf(con->uri_path, MAX_PATH_LEN, "%s%s", replacement, suffix);
    return 0;
}

/*
 * mod_rewrite_build_physical_path:
 *   Concatenates docroot and the (rewritten) URI path to produce the
 *   on-disk file path.
 *
 *   VULNERABILITY (CWE-22): con->uri_path comes from the HTTP request.
 *   Although path_contains_dotdot() is called, it misses ".." at the
 *   end of the path (e.g. "/images/..").  An attacker can request
 *   "/images/.." to escape the docroot.
 */
static int mod_rewrite_build_physical_path(connection *con,
                                            plugin_data *pd) {
    /* Incomplete sanitization: only blocks /../ in the middle */
    if (path_contains_dotdot(con->uri_path)) {
        con->http_status = 403;
        return -1;
    }

    /* BUG: attacker-controlled uri_path appended to docroot without
     * full validation — path traversal possible via trailing ".." */
    snprintf(con->physical_path, MAX_PATH_LEN,
             "%s%s", pd->docroot, con->uri_path);   /* CWE-22 sink */

    return 0;
}

/*
 * mod_rewrite_handle_uri_raw:
 *   Entry point called by the lighttpd core for each request.
 *   Reads the raw URI from the network (attacker-controlled), applies
 *   rewrite rules, and builds the physical path.
 */
int mod_rewrite_handle_uri_raw(connection *con, plugin_data *pd) {
    if (!con || !pd)
        return -1;

    /* Attacker-supplied data enters here (source) */
    char raw_uri[MAX_PATH_LEN];
    if (fgets(raw_uri, sizeof(raw_uri), stdin) == NULL)
        return -1;

    /* Copy attacker input into connection object */
    strncpy(con->uri_path, raw_uri, MAX_PATH_LEN - 1);
    con->uri_path[MAX_PATH_LEN - 1] = '\0';

    /* URL-decode: %2e%2e becomes ".." — traverse bypass */
    url_decode_inplace(con->uri_path, MAX_PATH_LEN);

    /* Apply optional rewrite rule */
    mod_rewrite_apply_rule(con, pd->rewrite_base, "/static");

    /* Build physical path — vulnerability exercised here */
    if (mod_rewrite_build_physical_path(con, pd) != 0)
        return con->http_status;

    /* Invoke registered callback (function pointer pattern) */
    if (pd->on_match)
        pd->on_match(con, pd);

    return 200;
}

/* ------------------------------------------------------------------ */
/* Test harness                                                        */
/* ------------------------------------------------------------------ */

static int default_on_match(connection *con, void *data) {
    (void)data;
    printf("Serving: %s\n", con->physical_path);
    return 0;
}

int main(void) {
    connection con;
    memset(&con, 0, sizeof(con));

    plugin_data pd;
    memset(&pd, 0, sizeof(pd));
    strncpy(pd.docroot, DOCROOT, MAX_PATH_LEN - 1);
    strncpy(pd.rewrite_base, "/images", MAX_PATH_LEN - 1);
    pd.on_match = default_on_match;

    int status = mod_rewrite_handle_uri_raw(&con, &pd);
    printf("HTTP status: %d\n", status);
    return 0;
}
