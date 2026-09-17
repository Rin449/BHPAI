#pragma once
#include "PackCommon.hpp"
#include <vector>
#include <string>
#include <iostream>

class Logger {
public:
    static void debug(const std::string& msg) {
        std::cout << "[UPX-DEBUG] " << msg << std::endl;
    }
    static void error(const std::string& msg) {
        std::cerr << "\033[1;31m[UPX-ERROR] " << msg << "\033[0m" << std::endl;
    }
    static void success(const std::string& msg) {
        std::cout << "\033[1;32m[UPX-SUCCESS] " << msg << "\033[0m" << std::endl;
    }
};

inline bool upx_is_contained(const void* base, uint32_t size, const void* ptr, uint32_t len) {
    if (!base || !ptr) return false;
    uintptr_t b = reinterpret_cast<uintptr_t>(base);
    uintptr_t p = reinterpret_cast<uintptr_t>(ptr);
    return (p >= b && p + len <= b + size && p + len >= p);
}

inline uint32_t upx_read_int32(const void* ptr) {
    uint32_t val;
    std::memcpy(&val, ptr, 4);
    return val;
}

inline void upx_write_int32(void* ptr, uint32_t val) {
    std::memcpy(ptr, &val, 4);
}

inline void sar_shift(int32_t& val, int count) {
    val >>= count;
}

inline const char* mem_str(const char* haystack, uint32_t haystack_len, const char* needle, uint32_t needle_len) {
    if (needle_len > haystack_len) return nullptr;
    for (uint32_t i = 0; i <= haystack_len - needle_len; ++i) {
        if (std::memcmp(haystack + i, needle, needle_len) == 0) {
            return haystack + i;
        }
    }
    return nullptr;
}
uint32_t calculate_simple_hash(const char* data, uint32_t size);
int upx_inflate2b(const char* src, uint32_t ssize, char* dst, uint32_t* dsize, uint32_t upx0, uint32_t upx1, uint32_t ep);
int upx_inflate2d(const char* src, uint32_t ssize, char* dst, uint32_t* dsize, uint32_t upx0, uint32_t upx1, uint32_t ep);
int upx_inflate2e(const char* src, uint32_t ssize, char* dst, uint32_t* dsize, uint32_t upx0, uint32_t upx1, uint32_t ep);

class UPXUnpacker {
public:
    static bool isUPX(const std::vector<uint8_t>& buffer);
    static bool unpack(const std::vector<uint8_t>& packed, std::vector<uint8_t>& unpacked);
};
