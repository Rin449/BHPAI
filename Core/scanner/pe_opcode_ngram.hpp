#ifndef PE_OPCODE_NGRAM_HPP
#define PE_OPCODE_NGRAM_HPP

#include "Disassembler.hpp"
#include "PeParser.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>

struct OpcodeFeature {
    std::string signature;
    uint32_t    count            = 0;
    uint64_t    first_va         = 0;
    double      weight           = 1.0;
    uint32_t    near_suspicious  = 0;
    std::vector<uint64_t> positions;
};

struct NgramConfig {
    size_t n               = 4;
    size_t context_radius  = 96;
    size_t max_features    = 300;
    double boost_multiplier = 3.0;
    bool   use_operand_type = true;
};

std::vector<OpcodeFeature> extract_suspicious_opcode_ngrams(
    const PeParser& parser,
    const std::unordered_set<std::string>& suspicious_apis,
    const NgramConfig& cfg = {},
    std::unordered_map<std::string, size_t>* semantic_histogram = nullptr
);

nlohmann::json opcode_features_to_json(
    const std::vector<OpcodeFeature>& features,
    size_t total_instructions = 0
);

#endif