#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <cctype>
#include <cmath>
#include <immintrin.h>
#include <omp.h>

using namespace std;

alignas(64) static uint8_t printable[256];

vector<uint8_t> decode_xor(const vector<uint8_t>& data, uint8_t key) {
    vector<uint8_t> out;
    out.resize(data.size());

    for (size_t i = 0; i < data.size(); ++i)
        out[i] = data[i] ^ key;

    return out;
}

void init_printable() {
    for (int i = 0; i < 256; i++) {
        printable[i] = (i >= 32 && i <= 126) || i == '\n' || i == '\r' || i == '\t';
    }
}

void print_hex(const vector<uint8_t>& data) {
    for (size_t i=0; i<data.size(); ++i) {
        cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
        if ((i+1) % 16 == 0) cout << '\n';
    }
}

bool is_printable_ascii(const uint8_t* data, size_t len, float threshold = 0.85f) {
    size_t ok = 0;
    for (size_t i = 0; i < len; ++i)
        ok += printable[data[i]];

    return (float)ok / len >= threshold;
}

inline bool check_key_avx2(const uint8_t* p, size_t n, uint8_t key)
{
    const __m256i k = _mm256_set1_epi8((char)key);
    size_t i = 0;
    alignas(32) uint8_t tmp[32];

    while (i + 32 <= n) {
        __m256i x = _mm256_loadu_si256((const __m256i*)(p + i));
        x = _mm256_xor_si256(x, k);
        _mm256_store_si256((__m256i*)tmp, x);

        for (int j = 0; j < 32; j++)
            if (!printable[tmp[j]])
                return false;

        i += 32;
    }

    while (i < n) {
        if (!printable[p[i] ^ key])
            return false;
        i++;
    }

    return true;
}

bool is_base64_fast(const string& s) {
    if (s.size() < 8 || s.size() % 4 != 0) return false;

    for (char c : s) {
        unsigned char uc = (unsigned char)c;
        if (!(isalnum(uc) || c == '+' || c == '/' || c == '=')) return false;
    }
    return true;
}


bool is_hex_fast(const string& s) {
    if (s.size() < 4 || s.size() % 2 != 0) return false;

    for (char c : s) {
        if (!isxdigit((unsigned char)c)) return false;
    }
    return true;
}

inline uint8_t hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return c - 'A' + 10;
}

vector<uint8_t> decode_hex(const string& s) {
    vector<uint8_t> out;
    if (!is_hex_fast(s)) return out;

    out.reserve(s.size() / 2);

    for (size_t i = 0; i < s.size(); i += 2) {
        out.push_back((hex_val(s[i]) << 4) | hex_val(s[i + 1]));
    }
    return out;
}

vector<uint8_t> decode_base64(const string& in) {
    static const string tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    vector<uint8_t> out;
    int val = 0, valb = -8;

    for (uint8_t c : in) {
        if (c == '=') break;

        size_t idx = tbl.find(c);
        if (idx == string::npos) continue;

        val = (val << 6) + idx;
        valb += 6;

        if (valb >= 0) {
            out.push_back((uint8_t)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return out;
}


bool looks_like_text(const string& s) {
    if (s.size() < 20) return false;
    int cnt[26] = {0};
    int total = 0, vowels = 0;

    for (char c : s) {
        if (!isalpha((unsigned char)c)) continue;
        char ch = tolower((unsigned char)c);
        cnt[ch - 'a']++;
        total++;

        if (ch=='a'||ch=='e'||ch=='i'||ch=='o'||ch=='u')
            vowels++;
    }
    if (total < 15) return false;
    double vr = (double)vowels / total;
    if (vr < 0.25 || vr > 0.6) return false;
    int strong = 0;
    for (int i = 0; i < 26; ++i)
        if (cnt[i] * 100 / total >= 5) strong++;

    return strong >= 3;
}

bool is_Caesar(const string& s) {
    if (s.size() < 30) return false;

    for (int key = 0; key < 26; ++key) {
        int vowel = 0, total = 0;
        for (char c : s) {
            if (!isalpha((unsigned char)c)) continue;
            char d = (toupper((unsigned char)c) - 'A' - key + 26) % 26 + 'A';
            if (d=='A'||d=='E'||d=='I'||d=='O'||d=='U')
                vowel++;
            total++;
        }
        if (total > 0) {
            double r = (double)vowel / total;
            if (r > 0.25 && r < 0.6)
                return true;
        }
    }
    return false;
}

void brute_xor_all(const vector<uint8_t>& data) {
    if (data.size() < 8) return;

    const uint8_t* p = data.data();
    size_t n = data.size();

#ifdef _OPENMP
#pragma omp parallel for schedule(static)
#endif
    for (int key = 0; key < 256; key++) {
        if (!check_key_avx2(p, n, (uint8_t)key))
            continue;

#ifdef _OPENMP
#pragma omp critical
#endif
        {
            cout << "Key 0x"
                 << hex << setw(2) << setfill('0')
                 << key << " -> ";

            for (size_t i = 0; i < n; i++) {
                char c = p[i] ^ (uint8_t)key;
                cout << (printable[(uint8_t)c] ? c : '.');
            }

            cout << '\n';
        }
    }
}

void analyze_string(const string& s, int depth = 0);

void analyze_bytes(const vector<uint8_t>& data, int depth) {
    if (depth > 2) return;
    if (data.size() < 8) return;
    if (is_printable_ascii(data.data(), data.size())) {
        string s(data.begin(), data.end());
        analyze_string(s, depth + 1);
    }
    brute_xor_all(data);
}

void analyze_string(const string& s, int depth) {
    if (depth > 3 || s.empty()) return;

    cout << "[S] " << s << '\n';

    if (looks_like_text(s))
        cout << " -> TEXT\n";

    if (is_Caesar(s))
        cout << " -> CAESAR\n";

    if (is_base64_fast(s)) {
        cout << " -> BASE64\n";
        auto d = decode_base64(s);
        analyze_bytes(d, depth + 1);
    }

    if (is_hex_fast(s)) {
        cout << " -> HEX\n";
        auto d = decode_hex(s);
        analyze_bytes(d, depth + 1);
    }

    if (s.size() > 40)
        cout << " -> entropy check skipped (opt)\n";
}
