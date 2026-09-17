#pragma once
#include <cstdint>
#include <cstring>

// Shared PE section descriptor used by all pack modules (UPX, WWPack, etc.)
struct ExeSection {
    uint32_t rva;   // Relative Virtual Address
    uint32_t vsz;   // Virtual Size
    uint32_t rsz;   // Raw Size
};

// --- Shared little-endian read/write utilities ---
inline uint32_t readInt32LE(const uint8_t* ptr) {
    return uint32_t(ptr[0]) | (uint32_t(ptr[1]) << 8) | (uint32_t(ptr[2]) << 16) | (uint32_t(ptr[3]) << 24);
}

inline void writeInt32LE(uint8_t* ptr, uint32_t val) {
    ptr[0] = val & 0xFF;
    ptr[1] = (val >> 8) & 0xFF;
    ptr[2] = (val >> 16) & 0xFF;
    ptr[3] = (val >> 24) & 0xFF;
}

// Safe boundary check — verifies [ptr, ptr+size) lies within [base, base+baseSz)
inline bool isContained(const uint8_t* base, size_t baseSz, const uint8_t* ptr, size_t size) {
    if (!base || !ptr) return false;
    if (ptr < base) return false;
    size_t offset = static_cast<size_t>(ptr - base);
    return (offset <= baseSz) && (size <= (baseSz - offset));
}
