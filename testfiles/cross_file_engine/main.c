/* Hop 2 → sink: tainted buffer reaches system() */
#include <stdlib.h>
#include <string.h>

extern void fetch_command(char *out, int size);

void run_cross_file_vuln(void) {
    char cmd[256];
    fetch_command(cmd, sizeof(cmd));
    system(cmd);   /* CWE-78: tainted input reaches shell */
}

