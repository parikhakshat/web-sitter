#include "base.hpp"
#include <cstdio>

void run() {
    char buf[256];
    fgets(buf, 256, stdin);       // taint source: user-controlled input
    Processor* p = make_processor();
    p->process(buf);              // virtual call → MaliciousProcessor::process → system()
}
