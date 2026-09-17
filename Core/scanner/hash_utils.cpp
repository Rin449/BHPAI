#include "pe_analyzer.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include "fuzzyhash.h"

#include <string>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <cmath>
#include <cstdio>
#include <algorithm>

// ────────────────────────────────────────────────

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t  buffer[64];
} MyMD5_CTX;

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define FF(a, b, c, d, x, s, ac) { \
    (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

#define GG(a, b, c, d, x, s, ac) { \
    (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

#define HH(a, b, c, d, x, s, ac) { \
    (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

#define II(a, b, c, d, x, s, ac) { \
    (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

static void MyMD5Transform(uint32_t state[4], const uint8_t block[64]);

static void MyMD5Init(MyMD5_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void MyMD5Update(MyMD5_CTX *ctx, const uint8_t *input, size_t inputLen) {
    size_t index = (ctx->count[0] >> 3) & 0x3F;
    uint64_t bitlen = (uint64_t)inputLen << 3;
    ctx->count[0] += (uint32_t)bitlen;
    if (ctx->count[0] < bitlen) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(bitlen >> 32);
    size_t partLen = 64 - index;
    size_t i = 0;
    if (inputLen >= partLen) {
        std::memcpy(&ctx->buffer[index], input, partLen);
        MyMD5Transform(ctx->state, ctx->buffer);
        i = partLen;
        while (i + 63 < inputLen) {
            MyMD5Transform(ctx->state, &input[i]);
            i += 64;
        }
        index = 0;
    }
    std::memcpy(&ctx->buffer[index], input + i, inputLen - i);
}

static void MyMD5Final(uint8_t digest[16], MyMD5_CTX *ctx) {
    uint8_t bits[8];
    size_t index, padLen;

    bits[0] = static_cast<uint8_t>(ctx->count[0]);
    bits[1] = static_cast<uint8_t>(ctx->count[0] >> 8);
    bits[2] = static_cast<uint8_t>(ctx->count[0] >> 16);
    bits[3] = static_cast<uint8_t>(ctx->count[0] >> 24);
    bits[4] = static_cast<uint8_t>(ctx->count[1]);
    bits[5] = static_cast<uint8_t>(ctx->count[1] >> 8);
    bits[6] = static_cast<uint8_t>(ctx->count[1] >> 16);
    bits[7] = static_cast<uint8_t>(ctx->count[1] >> 24);

    index = (ctx->count[0] >> 3) & 63;
    padLen = (index < 56) ? (56 - index) : (120 - index);

    static const uint8_t padding[64] = {
        0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    };

    MyMD5Update(ctx, padding, padLen);
    MyMD5Update(ctx, bits, 8);

    for (int i = 0; i < 4; ++i) {
        digest[i*4 + 0] = static_cast<uint8_t>(ctx->state[i]);
        digest[i*4 + 1] = static_cast<uint8_t>(ctx->state[i] >> 8);
        digest[i*4 + 2] = static_cast<uint8_t>(ctx->state[i] >> 16);
        digest[i*4 + 3] = static_cast<uint8_t>(ctx->state[i] >> 24);
    }
}

static void MyMD5Transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];

    for (int i = 0, j = 0; i < 16; ++i, j += 4) {
        x[i] = (block[j])     | (block[j+1] << 8) |
               (block[j+2] << 16) | (block[j+3] << 24);
    }

    // Round 1
    FF(a, b, c, d, x[ 0],  7, 0xd76aa478); FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
    FF(c, d, a, b, x[ 2], 17, 0x242070db); FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
    FF(a, b, c, d, x[ 4],  7, 0xf57c0faf); FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
    FF(c, d, a, b, x[ 6], 17, 0xa8304613); FF(b, c, d, a, x[ 7], 22, 0xfd469501);
    FF(a, b, c, d, x[ 8],  7, 0x698098d8); FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
    FF(c, d, a, b, x[10], 17, 0xffff5bb1); FF(b, c, d, a, x[11], 22, 0x895cd7be);
    FF(a, b, c, d, x[12],  7, 0x6b901122); FF(d, a, b, c, x[13], 12, 0xfd987193);
    FF(c, d, a, b, x[14], 17, 0xa679438e); FF(b, c, d, a, x[15], 22, 0x49b40821);

    // Round 2
    GG(a, b, c, d, x[ 1],  5, 0xf61e2562); GG(d, a, b, c, x[ 6],  9, 0xc040b340);
    GG(c, d, a, b, x[11], 14, 0x265e5a51); GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
    GG(a, b, c, d, x[ 5],  5, 0xd62f105d); GG(d, a, b, c, x[10],  9, 0x02441453);
    GG(c, d, a, b, x[15], 14, 0xd8a1e681); GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
    GG(a, b, c, d, x[ 9],  5, 0x21e1cde6); GG(d, a, b, c, x[14],  9, 0xc33707d6);
    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
    GG(a, b, c, d, x[13],  5, 0xa9e3e905); GG(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
    GG(c, d, a, b, x[ 7], 14, 0x676f02d9); GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    // Round 3
    HH(a, b, c, d, x[ 5],  4, 0xfffa3942); HH(d, a, b, c, x[ 8], 11, 0x8771f681);
    HH(c, d, a, b, x[11], 16, 0x6d9d6122); HH(b, c, d, a, x[14], 23, 0xfde5380c);
    HH(a, b, c, d, x[ 1],  4, 0xa4beea44); HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    HH(a, b, c, d, x[13],  4, 0x289b7ec6); HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); HH(b, c, d, a, x[ 6], 23, 0x04881d05);
    HH(a, b, c, d, x[ 9],  4, 0xd9d4d039); HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8); HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);

    // Round 4
    II(a, b, c, d, x[ 0],  6, 0xf4292244); II(d, a, b, c, x[ 7], 10, 0x432aff97);
    II(c, d, a, b, x[14], 15, 0xab9423a7); II(b, c, d, a, x[ 5], 21, 0xfc93a039);
    II(a, b, c, d, x[12],  6, 0x655b59c3); II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
    II(c, d, a, b, x[10], 15, 0xffeff47d); II(b, c, d, a, x[ 1], 21, 0x85845dd1);
    II(a, b, c, d, x[ 8],  6, 0x6fa87e4f); II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    II(c, d, a, b, x[ 6], 15, 0xa3014314); II(b, c, d, a, x[13], 21, 0x4e0811a1);
    II(a, b, c, d, x[ 4],  6, 0xf7537e82); II(d, a, b, c, x[11], 10, 0xbd3af235);
    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); II(b, c, d, a, x[ 9], 21, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

std::string MD5String(const std::string& input) {
    MyMD5_CTX ctx;
    uint8_t digest[16];

    MyMD5Init(&ctx);
    MyMD5Update(&ctx, reinterpret_cast<const uint8_t*>(input.data()), input.length());
    MyMD5Final(digest, &ctx);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        oss << std::setw(2) << static_cast<int>(digest[i]);
    }
    return oss.str();
}

// ────────────────────────────────────────────────
// Entropy calculation
// ────────────────────────────────────────────────

double calc_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    int hist[256] = {0};
    for (size_t i = 0; i < len; ++i) {
        hist[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (hist[i] == 0) continue;
        double p = static_cast<double>(hist[i]) / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// ────────────────────────────────────────────────

FileHashes compute_hashes(const std::vector<uint8_t>& buffer) {
    FileHashes res;

    {
        uint8_t digest[16];
        MyMD5_CTX ctx;
        MyMD5Init(&ctx);
        MyMD5Update(&ctx, buffer.data(), buffer.size());
        MyMD5Final(digest, &ctx);

        char md5_str[33]{};
        for (int i = 0; i < 16; ++i) {
            std::snprintf(md5_str + i*2, 3, "%02x", digest[i]);
        }
        res.md5 = md5_str;
    }

    // SHA256 (OpenSSL)
    {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx &&
            EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) &&
            EVP_DigestUpdate(ctx, buffer.data(), buffer.size()) &&
            EVP_DigestFinal_ex(ctx, digest, nullptr)) {
            char sha256_str[65]{};
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                std::snprintf(sha256_str + i*2, 3, "%02x", digest[i]);
            }
            res.sha256 = sha256_str;
        } else {
            res.sha256 = "(SHA256 computation failed)";
        }
        EVP_MD_CTX_free(ctx);
    }

    // Fuzzy hash
    {
        FuzzyHash fh{};
        int pieces = compute_fuzzy_hash(buffer.data(), buffer.size(), &fh);
        if (pieces > 0) {
            char fuzzy_buf[256] = {0};
            fuzzyhash_to_string(&fh, fuzzy_buf, sizeof(fuzzy_buf));
            res.fuzzy = fuzzy_buf;
        } else {
            res.fuzzy = "(fuzzy hash error or file too small)";
        }
    }
    return res;
}

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),[](unsigned char c){ return std::tolower(c); });
    return s;
}