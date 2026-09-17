#include "cbpra.hpp"
#include "MemoryLimit.hpp"
#include <cmath>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <unordered_set>

static double local_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    int hist[256] = {0};
    for (size_t i = 0; i < len; ++i) hist[data[i]]++;
    double ent = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (hist[i] == 0) continue;
        double p = static_cast<double>(hist[i]) / len;
        ent -= p * std::log2(p);
    }
    return ent;
}

static bool is_inside_instruction(Disassembler& disasm, const uint8_t* code, size_t size,uint64_t va, size_t check_offset, size_t ptr_size) {
    (void)ptr_size;
    size_t start = (check_offset > 16) ? check_offset - 16 : 0;
    size_t len = std::min<size_t>(48, size - start);

    auto insns = disasm.disassemble(code + start, len, va + start, 20);

    for (const auto& inst : insns) {
        uint64_t inst_start = inst.address;
        uint64_t inst_end = inst.address + inst.length;

        uint64_t ptr_va = va + check_offset;
        if (ptr_va > inst_start && ptr_va < inst_end) {
            return true;
        }
    }
    return false;
}

CbpraFeatures extract_cbpra_features(const PeParser& parser, Disassembler& disasm) {
    CbpraFeatures feats;
    if (!parser.is_valid()) return feats;

    const auto& buffer = parser.get_buffer();
    uint64_t image_base = parser.get_image_base();
    bool is64 = parser.is_64bit();
    int ptr_size = is64 ? 8 : 4;

    uint64_t image_size = parser.get_size_of_image();
    if (image_size == 0) image_size = buffer.size();

    std::vector<PointerCandidate> candidates;
    candidates.reserve(4096);

    std::unordered_map<uint64_t, size_t> rva_to_cand_idx;

    // Step 1: Candidate Generation & Structural Analysis
    size_t step = 4;
    for (size_t off = 0; off + ptr_size <= buffer.size(); off += step) {
        check_memory_limit();
        if (candidates.size() >= MAX_SAFE_CANDIDATE_COUNT) {
            std::cerr << "[CBPRA WARNING] Candidate limit reached (" << MAX_SAFE_CANDIDATE_COUNT << "). Early aborting candidate generation.\n";
            break;
        }

        // Skip initial headers
        if (off < 0x200) continue;

        uint64_t value = 0;
        if (ptr_size == 4) {
            value = *reinterpret_cast<const uint32_t*>(buffer.data() + off);
        } else {
            value = *reinterpret_cast<const uint64_t*>(buffer.data() + off);
        }

        if (value < image_base || value >= image_base + image_size) continue;

        uint64_t target_rva = value - image_base;
        uint64_t src_rva = parser.file_offset_to_rva(off);

        PointerCandidate c;
        c.file_offset = off;
        c.value = value;
        c.target_rva = target_rva;
        c.size = ptr_size;
        c.is_aligned = (off % ptr_size == 0);

        // Entropy residual
        size_t res_start = (off > 16) ? off - 16 : 0;
        size_t res_len = std::min<size_t>(32, buffer.size() - res_start);
        c.residual_entropy = local_entropy(buffer.data() + res_start, res_len);

        if (c.residual_entropy > 7.6) continue;

        // Check inside instruction
        const SectionInfo* src_sec = parser.find_section_by_offset(off);
        if (src_sec && src_sec->is_executable()) {
            size_t local_off = off - src_sec->raw_offset;
            c.inside_insn = is_inside_instruction(
                disasm,
                buffer.data() + src_sec->raw_offset,
                src_sec->raw_size,
                src_sec->virtual_address,
                local_off,
                ptr_size
            );
        } else {
            c.inside_insn = false;
        }
        const SectionInfo* dst_sec = parser.find_section_by_rva(target_rva);
        c.src_section = src_sec ? src_sec->name : "HEADER";
        c.dst_section = dst_sec ? dst_sec->name : "UNKNOWN";
        c.is_cross_section = (src_sec != nullptr && dst_sec != nullptr && src_sec->name != dst_sec->name);
        c.is_reloc_target = parser.is_reloc_rva(target_rva) || parser.is_reloc_rva(src_rva);
        c.is_iat_pointer = parser.is_iat_rva(src_rva) || parser.is_iat_rva(target_rva);
        c.is_tls_pointer = parser.is_tls_rva(src_rva) || parser.is_tls_rva(target_rva);
        c.is_pdata_pointer = parser.is_pdata_code_rva(target_rva);

        c.points_to_code = (dst_sec != nullptr && dst_sec->is_executable()) || c.is_pdata_pointer;

        size_t idx = candidates.size();
        candidates.push_back(c);
        if (src_rva != 0) {
            rva_to_cand_idx[src_rva] = idx;
        }
    }

    feats.total_candidates = candidates.size();
    if (candidates.empty()) return feats;
    std::unordered_set<uint64_t> unique_nodes;
    size_t graph_edges = 0;

    for (size_t i = 0; i < candidates.size(); ++i) {
        auto& c = candidates[i];
        uint64_t src_rva = parser.file_offset_to_rva(c.file_offset);
        unique_nodes.insert(src_rva);
        unique_nodes.insert(c.target_rva);
        graph_edges++;

        if (c.points_to_code) {
            c.chain_depth = 1;
        } else {
            auto it2 = rva_to_cand_idx.find(c.target_rva);
            if (it2 != rva_to_cand_idx.end()) {
                const auto& c2 = candidates[it2->second];
                if (c2.points_to_code) {
                    c.chain_depth = 2;
                } else {
                    auto it3 = rva_to_cand_idx.find(c2.target_rva);
                    if (it3 != rva_to_cand_idx.end()) {
                        const auto& c3 = candidates[it3->second];
                        if (c3.points_to_code) {
                            c.chain_depth = 3;
                        }
                    }
                }
            }
        }
    }

    size_t vtable_cand_count = 0;
    size_t contiguous_run = 0;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (candidates[i].is_aligned && candidates[i].chain_depth >= 1) {
            if (i > 0 && candidates[i].file_offset == candidates[i-1].file_offset + ptr_size) {
                contiguous_run++;
            } else {
                contiguous_run = 1;
            }
            if (contiguous_run >= 2) {
                vtable_cand_count++;
            }
        } else {
            contiguous_run = 0;
        }
    }

    double sum_ent = 0.0;
    std::vector<double> entropies;
    entropies.reserve(candidates.size());

    size_t max_depth = 0;

    for (const auto& c : candidates) {
        if (c.is_aligned) feats.aligned_candidates++;
        if (!c.inside_insn) feats.non_insn_candidates++;
        if (c.residual_entropy < 5.5) feats.low_entropy_candidates++;

        if (c.is_reloc_target) feats.reloc_confirmed++;
        if (c.is_iat_pointer) feats.iat_confirmed++;
        if (c.is_tls_pointer) feats.tls_confirmed++;
        if (c.is_pdata_pointer) feats.pdata_confirmed++;
        if (c.points_to_code) feats.points_to_executable++;

        if (c.chain_depth == 1) feats.chain_depth1_count++;
        else if (c.chain_depth == 2) feats.chain_depth2_count++;
        else if (c.chain_depth >= 3) feats.chain_depth3_plus_count++;

        if (static_cast<size_t>(c.chain_depth) > max_depth) {
            max_depth = c.chain_depth;
        }

        if (c.is_cross_section) {
            feats.cross_section_pointers++;
            std::string key = c.src_section + "->" + c.dst_section;
            feats.section_pair_count[key]++;
        }

        sum_ent += c.residual_entropy;
        entropies.push_back(c.residual_entropy);
    }

    feats.max_chain_depth = max_depth;
    feats.vtable_candidate_count = vtable_cand_count;
    feats.graph_node_count = unique_nodes.size();
    feats.graph_edge_count = graph_edges;

    double n = static_cast<double>(candidates.size());
    feats.aligned_ratio = static_cast<double>(feats.aligned_candidates) / n;
    feats.reloc_ratio = static_cast<double>(feats.reloc_confirmed) / n;
    feats.code_pointer_ratio = static_cast<double>(feats.points_to_executable) / n;
    feats.chain_depth2_plus_ratio = static_cast<double>(feats.chain_depth2_count + feats.chain_depth3_plus_count) / n;
    feats.cross_section_ratio = static_cast<double>(feats.cross_section_pointers) / n;

    feats.residual_entropy_mean = sum_ent / n;
    double var_sum = 0.0;
    for (double e : entropies) {
        double diff = e - feats.residual_entropy_mean;
        var_sum += diff * diff;
    }
    feats.residual_entropy_stddev = std::sqrt(var_sum / n);

    return feats;
}