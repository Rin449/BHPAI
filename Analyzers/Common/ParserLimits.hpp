#ifndef BHPAI_PARSER_LIMITS_HPP
#define BHPAI_PARSER_LIMITS_HPP

#include <cstddef>
#include <cstdint>

namespace BHPAI {

struct ParserLimits {
    size_t max_file_size = 500ULL * 1024 * 1024;           // 500 MB
    size_t max_objects = 100000;                           // Max 100k objects
    size_t max_stream_size = 100ULL * 1024 * 1024;         // Max 100 MB per stream
    size_t max_decoded_stream_size = 250ULL * 1024 * 1024; // Max 250 MB decoded
    double max_decompression_ratio = 100.0;                 // Decompression bomb detection threshold
    uint32_t max_filter_depth = 6;                         // Max 6 filter chains
    uint32_t max_recursion_depth = 5;                      // Max 5 nested layers
};

} // namespace BHPAI

#endif // BHPAI_PARSER_LIMITS_HPP
