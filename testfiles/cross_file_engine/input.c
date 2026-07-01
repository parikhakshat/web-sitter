/* Taint source: reads attacker-controlled data from network */
#include <string.h>
#include <unistd.h>

int read_input(char *buf, int size) {
    return read(0, buf, size);
}
