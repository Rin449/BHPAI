#ifndef FUZZYHASH_H
#define FUZZYHASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PIECES      128
#define PIECE_HASH_LEN  64
#define WINDOW_SIZE     7
typedef struct {
    char hash1[PIECE_HASH_LEN + 1];
    char hash2[PIECE_HASH_LEN + 1];
    int  block_size;
} FuzzyHash;

int compute_fuzzy_hash(const uint8_t* data,size_t size,FuzzyHash* out_fh);
int fuzzy_similarity(const FuzzyHash* a, const FuzzyHash* b);
uint8_t* read_file(const char* path, size_t* out_size);
int fuzzyhash_to_string(const FuzzyHash* fh, char* buf, size_t bufsize);

#ifdef __cplusplus
}
#endif

#endif // FUZZYHASH_H