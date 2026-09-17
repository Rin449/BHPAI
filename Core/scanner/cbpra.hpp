#pragma once
#include "PeParser.hpp"
#include "Disassembler.hpp"
#include <vector>
#include <cstdint>
#include <string>
#include <unordered_map>

struct PointerCandidate {
    uint64_t file_offset;
    uint64_t value;
    uint64_t target_rva;
    int size;
    bool is_cross_section = false;
    std::string src_section;
    std::string dst_section;
    bool is_reloc_target = false;
    bool is_iat_pointer = false;
    bool is_tls_pointer = false;
    bool is_pdata_pointer = false;
    bool points_to_code = false;
    bool is_aligned = false;
    bool inside_insn = false;
    double residual_entropy = 0.0;
    int chain_depth = 0; // 0: None, 1: Pointer->Code, 2: P->P->Code, 3+: P->P->P->Code
};

struct CbpraFeatures {
    size_t total_candidates = 0;
    size_t aligned_candidates = 0;
    size_t non_insn_candidates = 0;
    size_t low_entropy_candidates = 0;

    size_t reloc_confirmed = 0;
    size_t iat_confirmed = 0;
    size_t tls_confirmed = 0;
    size_t pdata_confirmed = 0;
    size_t points_to_executable = 0;

    size_t chain_depth1_count = 0;
    size_t chain_depth2_count = 0;
    size_t chain_depth3_plus_count = 0;
    size_t max_chain_depth = 0;
    size_t vtable_candidate_count = 0;
    size_t graph_node_count = 0;
    size_t graph_edge_count = 0;

    size_t cross_section_pointers = 0;
    double cross_section_ratio = 0.0;

    double aligned_ratio = 0.0;
    double reloc_ratio = 0.0;
    double code_pointer_ratio = 0.0;
    double chain_depth2_plus_ratio = 0.0;
    double residual_entropy_mean = 0.0;
    double residual_entropy_stddev = 0.0;

    std::unordered_map<std::string, size_t> section_pair_count;
};

CbpraFeatures extract_cbpra_features(const PeParser& parser, Disassembler& disasm);