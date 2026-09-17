#pragma once
#include "PackCommon.hpp"
#include <vector>

class WWPackUnpacker {
public:
    static bool isWWPack(const std::vector<uint8_t>& buffer);
    static bool unpack(const std::vector<uint8_t>& packed, std::vector<uint8_t>& unpacked);
};
