/* Hop 1: wraps the tainted input, propagates to caller */
#include <string.h>

extern int read_input(char *buf, int size);

void fetch_command(char *out, int size) {
    read_input(out, size);
}
