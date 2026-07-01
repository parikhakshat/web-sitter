#include "base.hpp"
#include <cstdlib>

class MaliciousProcessor : public Processor {
public:
    // Param 0 goes directly to system() — CWE-78 sink.
    void process(const char* data) override {
        system(data);
    }
};
