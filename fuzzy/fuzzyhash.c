#include "fuzzyhash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define BASE 257ULL

static uint64_t fnv1a_64(const uint8_t* data, size_t len) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

typedef struct {
    uint64_t hash;
    uint64_t power;
} RollingHash64;

static void rolling_init(RollingHash64* r, const uint8_t* data, size_t window) {
    r->hash = 0;
    r->power = 1;

    for (size_t i = 0; i < window; i++) {
        r->hash = r->hash * BASE + data[i];
        if (i < window - 1) r->power *= BASE;
    }
}

static void rolling_update(RollingHash64* r, uint8_t out, uint8_t in) {
    r->hash = r->hash - (uint64_t)out * r->power;
    r->hash = r->hash * BASE + in;
}


static void hash_to_string(uint64_t val, char* out, size_t max_len) {
    int i = 0;

    if (val == 0) {
        out[0] = ALPHABET[0];
        out[1] = '\0';
        return;
    }

    while (val && i < (int)max_len - 1) {
        out[i++] = ALPHABET[val & 63];
        val >>= 6;
    }

    out[i] = '\0';

    if (i < 3) {
        memmove(out + 3 - i, out, i + 1);
        memset(out, ALPHABET[0], 3 - i);
    }
}

static int levenshtein_weighted(const char* s1, const char* s2) {
    int len1 = strlen(s1);
    int len2 = strlen(s2);
    if (len1 == 0) return len2 * 6;
    if (len2 == 0) return len1 * 6;
    int* prev = calloc(len2 + 1, sizeof(int));
    int* curr = calloc(len2 + 1, sizeof(int));
    if (!prev || !curr) {
        free(prev);
        free(curr);
        return 0;
    }
    for (int j = 0; j <= len2; j++)
        prev[j] = j * 6;
    for (int i = 1; i <= len1; i++) {
        curr[0] = i * 6;
        for (int j = 1; j <= len2; j++) {
            int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 6;
            int del = prev[j] + 6;
            int ins = curr[j - 1] + 6;
            int sub = prev[j - 1] + cost;
            int min = del < ins ? del : ins;
            curr[j] = min < sub ? min : sub;
        }
        int* tmp = prev;
        prev = curr;
        curr = tmp;
    }

    int dist = prev[len2];
    free(prev);
    free(curr);
    return dist;
}

int compute_fuzzy_hash(const uint8_t* data, size_t size, FuzzyHash* fh) {
    if (!data || !fh || size == 0) return -1;

    memset(fh, 0, sizeof(*fh));

    if (size < WINDOW_SIZE) {
        uint64_t h = fnv1a_64(data, size);
        hash_to_string(h, fh->hash1, PIECE_HASH_LEN);
        strcpy(fh->hash2, fh->hash1);
        fh->block_size = 3;
        return 1;
    }

    int block_size = 3;

    int limit = (int)size / (MAX_PIECES * 2);
    while (block_size < limit && block_size < (1 << 20)) {
        block_size <<= 1;
    }

    size_t b1 = block_size;
    size_t b2 = block_size * 2;

    char pieces1[MAX_PIECES][PIECE_HASH_LEN] = {{0}};
    char pieces2[MAX_PIECES][PIECE_HASH_LEN] = {{0}};
    size_t c1 = 0, c2 = 0;
    size_t start1 = 0, start2 = 0;
    RollingHash64 rf;
    rolling_init(&rf, data, WINDOW_SIZE);
    size_t pos = WINDOW_SIZE;
    while (pos < size) {
        uint64_t rh = rf.hash;

        if ((rh % b1) == (b1 - 1) && c1 < MAX_PIECES) {
            size_t len = pos - start1;
            if (len > 0) {
                hash_to_string(fnv1a_64(data + start1, len), pieces1[c1++], PIECE_HASH_LEN);
            }
            start1 = pos;
        }

        if ((rh % b2) == (b2 - 1) && c2 < MAX_PIECES) {
            size_t len = pos - start2;
            if (len > 0) {
                hash_to_string(fnv1a_64(data + start2, len), pieces2[c2++], PIECE_HASH_LEN);
            }
            start2 = pos;
        }
        rolling_update(&rf,data[pos - WINDOW_SIZE],data[pos]);
        pos++;
    }

    if (pos > start1 && c1 < MAX_PIECES) {
        hash_to_string(fnv1a_64(data + start1, pos - start1), pieces1[c1++], PIECE_HASH_LEN);
    }

    if (pos > start2 && c2 < MAX_PIECES) {
        hash_to_string(fnv1a_64(data + start2, pos - start2), pieces2[c2++], PIECE_HASH_LEN);
    }
    fh->block_size = b1;

    char* p1 = fh->hash1;
    char* p2 = fh->hash2;

    for (size_t i = 0; i < c1; i++) {
        p1 += snprintf(p1, PIECE_HASH_LEN - (p1 - fh->hash1), "%s", pieces1[i]);
    }

    for (size_t i = 0; i < c2; i++) {
        p2 += snprintf(p2, PIECE_HASH_LEN - (p2 - fh->hash2), "%s", pieces2[i]);
    }

    return c1 + c2;
}

int fuzzy_similarity(const FuzzyHash* a, const FuzzyHash* b) {
    if (!a || !b) return 0;

    int max_bs = a->block_size > b->block_size ? a->block_size : b->block_size;

    if (abs(a->block_size - b->block_size) > max_bs / 2 + 4) {
        return 0;
    }
    int d1 = levenshtein_weighted(a->hash1, b->hash1);
    int d2 = levenshtein_weighted(a->hash2, b->hash2);
    int l1 = strlen(a->hash1), l2 = strlen(b->hash1);
    int l3 = strlen(a->hash2), l4 = strlen(b->hash2);
    if (!l1 || !l2 || !l3 || !l4) return 0;
    int score1 = 100 - (d1 * 100 / (l1 * 6 + 1));
    int score2 = 100 - (d2 * 100 / (l3 * 6 + 1));
    int final = (score1 * 30 + score2 * 70) / 100;
    if (abs(a->block_size - b->block_size) <= 4) {
        final = final * 11 / 10;
    }
    if (final > 100) final = 100;
    if (final < 0) final = 0;

    return final;
}

uint8_t* read_file(const char* path, size_t* out_size) {
    if (!path || !out_size) return NULL;

    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0) {
        fclose(f);
        return NULL;
    }

    uint8_t* buf = malloc(sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_size = sz;
    return buf;
}

int fuzzyhash_to_string(const FuzzyHash* fh, char* buf, size_t bufsize) {
    if (!fh || !buf || bufsize < 16) return -1;

    return snprintf(buf, bufsize, "%d:%s:%s", fh->block_size, fh->hash1[0] ? fh->hash1 : "EMPTY", fh->hash2[0] ? fh->hash2 : "EMPTY");
}