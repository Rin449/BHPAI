#ifndef DECT_HPP
#define DECT_HPP

#include <vector>
#include <cstddef>
#include <cstdint>

struct ScanResult {
    int score = 0;
    bool upx = false;
    bool fsg = false;
    bool wwpack = false;
};

struct Pattern {
    const char* str;
    int score;
    size_t len;
};

ScanResult ScanBuffer(const std::vector<uint8_t>& buffer, size_t entry_point);

#endif