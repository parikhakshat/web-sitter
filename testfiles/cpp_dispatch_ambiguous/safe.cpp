#include "base.hpp"
#include <cstring>

class SafeProcessor : public Processor {
public:
    // Param 0 is only counted (strlen) — no dangerous sink, no taint flow to output.
    void process(const char* data) override {
        volatile int len = (int)strlen(data);
        (void)len;
    }
};
