#pragma once

class Processor {
public:
    virtual void process(const char* data) = 0;
    virtual ~Processor() = default;
};

Processor* make_processor();
