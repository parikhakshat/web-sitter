/*
 * multi_variable_bfs_test.c
 *
 * Tests for per-variable BFS non-monotonicity fix.
 * When recv() writes to multiple buffers via separate calls, a shared
 * `visited` set must not block one variable from reaching its sink
 * via a node already visited by the other variable.
 */

#include <string.h>
#include <sys/socket.h>

/* ---- Regression 1: single recv — existing behaviour unchanged ---- */
void vuln_single_arg(int sock) {
    char buf[64];
    recv(sock, buf, sizeof(buf), 0);
    system(buf);                    /* sink */
}

/* ---- Regression 2: two independent buffers, non-overlapping paths ---- */
void vuln_two_args_independent(int sock) {
    char buf1[64], buf2[64];
    recv(sock, buf1, sizeof(buf1), 0);
    recv(sock, buf2, sizeof(buf2), 0);
    system(buf1);                   /* sink for buf1 */
    popen(buf2, "r");               /* sink for buf2 */
}

/* ---- Core bug: two buffers flowing through a SHARED intermediate ---- */
/*
 * Without the fix, whichever variable visits `tmp` first blocks the other
 * from traversing through `tmp` to reach its downstream sink.
 */
void vuln_two_args_shared_intermediate(int sock) {
    char buf1[64], buf2[64];
    recv(sock, buf1, sizeof(buf1), 0);
    recv(sock, buf2, sizeof(buf2), 0);

    char tmp[128];
    strncpy(tmp, buf1, sizeof(buf1));
    system(tmp);                    /* sink 1: buf1 -> tmp -> system */

    strncpy(tmp, buf2, sizeof(buf2));
    popen(tmp, "r");                /* sink 2: buf2 -> tmp -> popen */
}

/* ---- Guard regression: guarded paths must NOT produce findings ---- */
void safe_two_args_guarded(int sock) {
    char buf1[64], buf2[64];
    recv(sock, buf1, sizeof(buf1), 0);
    recv(sock, buf2, sizeof(buf2), 0);
    if (validate(buf1) && validate(buf2)) {
        system(buf1);
        popen(buf2, "r");
    }
}
