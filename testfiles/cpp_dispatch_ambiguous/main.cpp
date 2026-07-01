#include "base.hpp"
#include <cstdio>

// Concrete MaliciousProcessor* receiver: CHA resolves only to MaliciousProcessor::process.
// Taint flows fgets → buf → system() via virtual dispatch → should fire CWE-78.
void run_malicious() {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    MaliciousProcessor p;
    p.process(buf);
}

// Concrete SafeProcessor receiver: CHA resolves only to SafeProcessor::process.
// SafeProcessor::process only calls fprintf — should NOT fire CWE-78.
void run_safe() {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    SafeProcessor p;
    p.process(buf);
}

class MaliciousProcessor : public Processor {
public:
    void process(const char* data) override;
};

class SafeProcessor : public Processor {
public:
    void process(const char* data) override;
};
