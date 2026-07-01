#include "base.hpp"
#include <cstdlib>

class MaliciousProcessor : public Processor {
public:
    // Virtual override: data flows directly to system() — CWE-78 sink.
    void process(const char* data) override {
        system(data);
    }
};

Processor* make_processor() {
    return new MaliciousProcessor();
}
