#ifndef MEMORY_LIMIT_HPP
#define MEMORY_LIMIT_HPP

#include <iostream>
#include <stdexcept>
#include <unordered_map>
#include <vector>
#include <cstddef>

struct MemoryLimitExceeded : public std::runtime_error {
    MemoryLimitExceeded()
        : std::runtime_error("RAM usage limit exceeded (3GB limit) - Aborting analysis to prevent RAM overflow.") {}
    explicit MemoryLimitExceeded(const char* msg)
        : std::runtime_error(msg) {}
};

inline constexpr size_t MAX_SAFE_INSTRUCTION_COUNT = 500'000;
inline constexpr size_t MAX_HARD_INSTRUCTION_COUNT = 2'000'000;
inline constexpr size_t MAX_SAFE_CANDIDATE_COUNT = 500'000;
inline constexpr size_t MAX_SAFE_STRING_COUNT = 2'000'000;
inline constexpr size_t MAX_SAFE_TOTAL_STRING_LEN = 5'000'000;
inline constexpr size_t MAX_INSTRUCTION_PER_SECTION = 200'000;

void check_memory_limit();
inline bool check_instruction_limit(size_t count) {
    check_memory_limit();
    if (count > MAX_HARD_INSTRUCTION_COUNT) {
        std::cerr << "[WARN] Instruction count (" << count
                  << ") exceeds hard limit (" << MAX_HARD_INSTRUCTION_COUNT
                  << ") - truncating, analysis continues.\n";
        return false;
    }
    return true;
}

inline bool check_candidate_limit(size_t count) {
    check_memory_limit();
    if (count > MAX_SAFE_CANDIDATE_COUNT) {
        std::cerr << "[WARN] Candidate count (" << count
                  << ") exceeds limit (" << MAX_SAFE_CANDIDATE_COUNT
                  << ") - truncating, analysis continues.\n";
        return false;
    }
    return true;
}

inline bool check_string_limit(size_t string_count, size_t total_len) {
    check_memory_limit();
    if (string_count > MAX_SAFE_STRING_COUNT || total_len > MAX_SAFE_TOTAL_STRING_LEN) {
        std::cerr << "[WARN] String limit hit (count=" << string_count
                  << ", total_len=" << total_len
                  << ") - using collected strings only, analysis continues.\n";
        return false;
    }
    return true;
}

template<typename T>
void safe_reserve(std::vector<T>& v, size_t n) {
    check_memory_limit();
    if (n > 2'000'000) {
        std::cerr << "[WARN] safe_reserve clamped " << n
                  << " -> 2,000,000 to avoid RAM overflow.\n";
        n = 2'000'000;
    }
    v.reserve(n);
    check_memory_limit();
}

template<typename K, typename V>
void safe_reserve(std::unordered_map<K, V>& m, size_t n) {
    check_memory_limit();
    if (n > 2'000'000) {
        std::cerr << "[WARN] safe_reserve clamped " << n
                  << " -> 2,000,000 to avoid RAM overflow.\n";
        n = 2'000'000;
    }
    m.reserve(n);
    check_memory_limit();
}

#endif // MEMORY_LIMIT_HPP
