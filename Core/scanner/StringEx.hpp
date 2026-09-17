#ifndef STRINGEX_HPP
#define STRINGEX_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

bool looks_like_text(const std::string& s);
bool is_Caesar(const std::string& s);
bool is_printable_ascii(const uint8_t* data, size_t len, float threshold = 0.85f);
bool is_base64_fast(const std::string& s);
bool is_hex_fast(const std::string& s);

inline bool is_base64(const std::string& s) { return is_base64_fast(s); }
inline bool is_hex(const std::string& s) { return is_hex_fast(s); }

std::vector<uint8_t> decode_base64(const std::string& s);
std::vector<uint8_t> decode_hex(const std::string& s);
std::vector<uint8_t> decode_xor(const std::vector<uint8_t>& data, uint8_t key);

void init_printable();
void analyze_bytes(const std::vector<uint8_t>& data, int depth = 0);
void analyze_string(const std::string& s, int depth = 0);

void brute_xor_all(const std::vector<uint8_t>& data);
void brute_xor(const std::vector<uint8_t>& data, uint8_t key);

bool is_base64_strict(const std::string& s);

#endif