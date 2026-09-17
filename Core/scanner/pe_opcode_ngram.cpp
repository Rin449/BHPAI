#include "pe_opcode_ngram.hpp"
#include "MemoryLimit.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <cctype>
#include <cmath>
#include <iostream>
#include <capstone/capstone.h>
#include <unordered_set>

struct RegTaint {
    bool tainted = false;
    std::string api_name;
    uint64_t suspected_va = 0;
};

extern DWORD RVAToOffset(const IMAGE_NT_HEADERS* nt, DWORD rva);
extern void check_memory_limit();

std::string get_semantic_group(unsigned int id, const cs_x86* x86 = nullptr) {
    (void)x86;
    switch (id) {
        case X86_INS_MOV: case X86_INS_MOVZX: case X86_INS_MOVSX:
        case X86_INS_MOVBE: case X86_INS_MOVAPS: case X86_INS_MOVD:
        case X86_INS_MOVQ:  case X86_INS_LEA:   case X86_INS_XCHG:
        case X86_INS_PUSH:  case X86_INS_POP:
            return "DATA_XFER";

        case X86_INS_ADD: case X86_INS_SUB: case X86_INS_MUL:
        case X86_INS_IMUL: case X86_INS_DIV: case X86_INS_IDIV:
        case X86_INS_INC:   case X86_INS_DEC:   case X86_INS_NEG:
        case X86_INS_ADC:   case X86_INS_SBB:
            return "ARITHMETIC";

        case X86_INS_AND:   case X86_INS_OR:    case X86_INS_XOR:
        case X86_INS_NOT:   case X86_INS_TEST:  case X86_INS_SHL:
        case X86_INS_SHR:   case X86_INS_SAR:   case X86_INS_ROL:
        case X86_INS_ROR:
            return "LOGIC";
        
        case X86_INS_CMP:
            return "CMP";

        case X86_INS_JMP:   case X86_INS_JE:    case X86_INS_JNE:
        case X86_INS_JA:    case X86_INS_JB:    case X86_INS_JG:
        case X86_INS_JL:    case X86_INS_JAE:   case X86_INS_JBE:
        case X86_INS_RET:   case X86_INS_RETF:  case X86_INS_CALL:
            return "CONTROL_FLOW";

        case X86_INS_VMOVDQA: case X86_INS_VMOVDQU: return "SIMD";
        case X86_INS_AESENC: case X86_INS_AESDEC: return "CRYPTO";

        case X86_INS_MOVSB: case X86_INS_MOVSW: case X86_INS_MOVSD:
        case X86_INS_STOSB: case X86_INS_LODSB: case X86_INS_CMPSB:
        case X86_INS_SCASB:
            return "STRING_OP";
        
        default:
            return "OTHER";
        
    }

}

bool is_load_from_iat(const cs_x86& x86, const cs_x86_op& op, uint64_t current_va, uint64_t image_base, const std::unordered_map<uint64_t, std::string>& iat_va_to_name) {
    (void)x86;
    (void)image_base;
    if (op.type != X86_OP_MEM) return false;

    uint64_t target_va = 0;
    if (op.mem.base == X86_REG_RIP) {
        target_va = current_va +  op.mem.disp +  op.size; // RIP-relative addressing
    } else if (op.mem.base != X86_REG_INVALID || op.mem.index != X86_REG_INVALID) {
        return false; // Not RIP-relative, likely not an import access
    } else {
        return false; // Not a memory operand we can analyze
    }

    if (target_va == 0) return false;

    auto it = iat_va_to_name.find(target_va);
    return it != iat_va_to_name.end();
}

std::string get_operand_type_shorthand(const cs_x86_op& op) {
    switch (op.type) {
        case X86_OP_REG:   return "r";
        case X86_OP_IMM:   return "imm";
        case X86_OP_MEM: {
            if (op.mem.base == X86_REG_RIP) return "[rip+imm]";
            if (op.mem.index != X86_REG_INVALID) return "[r+idx]";
            if (op.mem.base != X86_REG_INVALID) return "[r+disp]";
            return "[mem]";
        }
        case X86_OP_INVALID:
        default:           return "?";
    }
}

namespace {

std::string build_ngram_key(const Instruction& inst, bool use_op_type) {
    std::ostringstream oss;
    oss << inst.mnemonic;

    if (!use_op_type || !inst.has_detail) {
        return oss.str();
    }

    const cs_x86* x86 = &inst.x86;
    for (uint8_t i = 0; i < x86->op_count; ++i) {
        oss << "_" << get_operand_type_shorthand(x86->operands[i]);
    }
    return oss.str();
}

bool is_call_to_suspicious_import(
    const Instruction& inst,
    uint64_t va,
    [[maybe_unused]] uint64_t image_base,
    const std::unordered_map<uint64_t, std::string>& iat_va_to_name,
    const std::unordered_set<std::string>& suspicious_apis
) {
    if (inst.id != X86_INS_CALL || !inst.has_detail) return false;

    const cs_x86* x86 = &inst.x86;
    if (x86->op_count != 1) return false;

    const cs_x86_op& op = x86->operands[0];
    uint64_t target_va = 0;

    if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
        target_va = va + inst.length + op.mem.disp;
    }
    else if (op.type == X86_OP_IMM) {
        target_va = static_cast<uint64_t>(op.imm);
    }
    else {
        return false;
    }

    if (target_va == 0) return false;

    auto it = iat_va_to_name.find(target_va);
    if (it == iat_va_to_name.end()) return false;

    std::string api = it->second;
    std::transform(api.begin(), api.end(), api.begin(), [](unsigned char c){ return std::tolower(c); });

    return suspicious_apis.count(api) > 0;
}

} // anonymous namespace

std::vector<OpcodeFeature> extract_suspicious_opcode_ngrams(
    const PeParser& parser,
    const std::unordered_set<std::string>& suspicious_apis,
    const NgramConfig& cfg_in,
    std::unordered_map<std::string, size_t>* semantic_histogram
) {
    std::vector<OpcodeFeature> features;
    std::unordered_map<std::string, OpcodeFeature> feature_map;

    std::cout << "[BEGIN] Analyzing opcode n-gram\n";

    if (!parser.is_valid()) {
        std::cerr << "[ERROR] PeParser Not Valid: " << parser.get_error() << "\n";
        return features;
    }

    const auto& buffer = parser.get_buffer();
    std::cout << "[INFO] File size: " << buffer.size() << " bytes\n";

    if (buffer.size() < 0x200) {
        std::cerr << "[ERROR] Filesize too small (" << buffer.size() << " bytes)\n";
        return features;
    }

    Disassembler disasm;
    bool is64 = parser.is_64bit();
    std::cout << "[DEBUG] parser.is_64bit() Result: " << (is64 ? "true (x64)" : "false (x86)") << "\n";
    std::cout << "[INFO] File is " << (is64 ? "64-bit" : "32-bit") << "\n";

    if (!disasm.initialize(is64)) {
        std::cerr << "[ERROR] Failed to initialize Capstone\n";
        return features;
    }

    const auto& exec_sections = parser.get_executable_sections();
    std::cout << "[INFO] Number of executable sections: " << exec_sections.size() << "\n";

    if (exec_sections.empty()) {
        std::cerr << "[WARNING] No executable sections found\n";
        std::cerr << "[HINT] Check the Characteristics of sections in the PE file using CFF Explorer or PE-bear\n";
        return features;
    }

    for (const auto& sec : exec_sections) {
        std::cout << "[SECTION] " << sec.name 
                  << " | VA=0x" << std::hex << sec.virtual_address 
                  << " | Raw=0x" << sec.raw_offset << " + 0x" << sec.raw_size << std::dec << "\n";
    }

    NgramConfig cfg = cfg_in;
    if (cfg.n < 2) cfg.n = 4;
    std::cout << "[OPTION] n = " << cfg.n 
              << ", max_features = " << cfg.max_features 
              << ", boost = " << cfg.boost_multiplier << "\n";

    uint64_t image_base = parser.get_image_base();
    std::cout << "[INFO] ImageBase = 0x" << std::hex << image_base << std::dec << "\n";

    // ── Parse IAT ────────────────────────────────────────────────────────
    std::unordered_map<uint64_t, std::string> iat_va_to_name;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    if (dos->e_magic == IMAGE_DOS_SIGNATURE && 
        static_cast<size_t>(dos->e_lfanew) < buffer.size()) {
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + dos->e_lfanew);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            uint16_t mach = nt->FileHeader.Machine;
            std::cout << "[DEBUG] Machine trong PE header = 0x" << std::hex << mach << std::dec
                      << " -> " << (mach == 0x8664 ? "x64 (YES)" : 
                                    (mach == 0x014c ? "x86 (YES)" : 
                                    "NOT x86/x64!")) << "\n";
        }
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            const IMAGE_DATA_DIRECTORY* import_dir = nullptr;
            if (is64) {
                const auto& opt = nt->OptionalHeader;
                if (opt.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                    opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                    import_dir = &opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                }
            } else {
                const auto& opt = nt->OptionalHeader;
                if (opt.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                    opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                    import_dir = &opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                }
            }

            if (import_dir && import_dir->VirtualAddress && import_dir->Size) {
                DWORD off = RVAToOffset(nt, import_dir->VirtualAddress);
                if (off != 0 && off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= buffer.size()) {
                    const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(buffer.data() + off);
                    while (desc->Name && desc->FirstThunk) {
                        DWORD thunk_rva = desc->FirstThunk;
                        DWORD thunk_off = RVAToOffset(nt, thunk_rva);
                        if (thunk_off == 0 || thunk_off >= buffer.size()) {
                            ++desc; continue;
                        }

                        const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(buffer.data() + thunk_off);
                        while (thunk->u1.AddressOfData) {
                            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                                DWORD name_rva = static_cast<DWORD>(thunk->u1.AddressOfData);
                                DWORD name_off = RVAToOffset(nt, name_rva);
                                if (name_off && name_off + 4 < buffer.size()) {
                                    const uint8_t* ptr = buffer.data() + name_off + 2; // skip hint
                                    std::string name;
                                    while (*ptr && ptr < buffer.data() + buffer.size() - 1) {
                                        name += static_cast<char>(*ptr++);
                                    }
                                    if (!name.empty() && name.size() < 512) {
                                        uint64_t iat_va = image_base + thunk_rva;
                                        iat_va_to_name[iat_va] = std::move(name);
                                    }
                                }
                            }
                            thunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(
                                reinterpret_cast<const uint8_t*>(thunk) + sizeof(IMAGE_THUNK_DATA));
                            thunk_rva += sizeof(IMAGE_THUNK_DATA);
                        }
                        ++desc;
                    }
                }
            }
        }
    }



    size_t total_ins = 0;
    size_t total_ngram_counted = 0;

    for (const auto& sec : exec_sections) {
        check_memory_limit();
        if (sec.raw_size == 0 || sec.raw_offset + sec.raw_size > buffer.size()) {
            std::cerr << "[ERROR] Section " << sec.name << " has invalid raw offset/size\n";
            continue;
        }

        std::cout << "[DISASM] Disassembling section " << sec.name << " ...\n";

        auto insns = disasm.disassemble(
            buffer.data() + sec.raw_offset,
            sec.raw_size,
            sec.virtual_address,
            MAX_INSTRUCTION_PER_SECTION
        );

        if (!check_instruction_limit(insns.size())) {
            insns.resize(MAX_HARD_INSTRUCTION_COUNT);
        }

        std::vector<std::string> block_keys;
        std::vector<bool> block_susp;
        std::vector<uint64_t> block_addrs;

        safe_reserve(block_keys, insns.size());
        safe_reserve(block_susp, insns.size());
        safe_reserve(block_addrs, insns.size());

        std::cout << "[DISASM] Section " << sec.name 
                  << " -> found " << insns.size() << " instructions\n";

        if (insns.empty()) {
            std::cerr << "[WARNING] No instructions disassembled in section " << sec.name << "\n";
            std::cerr << "[POSSIBLE REASONS] Incorrect bitness, section contains data rather than code, or anti-disassembly techniques\n";
            continue;
        }

        total_ins += insns.size();

        std::unordered_map<x86_reg, RegTaint> reg_taint;

        for (size_t i = 0; i < insns.size(); ++i) {
            const auto& inst = insns[i];
            uint64_t va = inst.address;

            if (semantic_histogram != nullptr) {
                ++(*semantic_histogram)[get_semantic_group(
                    inst.id, inst.has_detail ? &inst.x86 : nullptr)];
            }

            if (!inst.has_detail) {
                std::cerr << "[WARN] Instruction at 0x" << std::hex << va 
                          << " has no detail (detail = null)\n";
                continue;
            }

            const cs_x86* x86 = &inst.x86;

            bool is_suspicious = false;

            if (inst.id == X86_INS_CALL || inst.id == X86_INS_RET ||
                inst.id == X86_INS_JMP) {
                reg_taint.clear();
            }

            if (x86->op_count == 2 &&
                x86->operands[0].type == X86_OP_REG &&
                x86->operands[1].type == X86_OP_MEM &&
                is_load_from_iat(*x86, x86->operands[1], va, image_base, iat_va_to_name)) {

                x86_reg dst = x86->operands[0].reg;
                reg_taint[dst].tainted = true;
            }

            if (inst.id == X86_INS_MOV &&
                x86->op_count == 2 &&
                x86->operands[0].type == X86_OP_REG &&
                x86->operands[1].type == X86_OP_REG) {
                reg_taint[x86->operands[0].reg] = reg_taint[x86->operands[1].reg];
            }

            if (inst.id == X86_INS_CALL && x86->op_count == 1) {
                const auto& op = x86->operands[0];
                if (op.type == X86_OP_REG) {
                    auto it = reg_taint.find(op.reg);
                    if (it != reg_taint.end() && it->second.tainted) {
                        is_suspicious = true;
                    }
                }
                else if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
                    is_suspicious = is_call_to_suspicious_import(
                        inst, va, image_base, iat_va_to_name, suspicious_apis);
                }
            }

            std::string key = build_ngram_key(inst, cfg.use_operand_type);
            if (key.empty()) continue;

            check_memory_limit();
            block_keys.push_back(std::move(key));
            block_addrs.push_back(va);
            block_susp.push_back(is_suspicious);

            bool end_of_block =
                inst.id == X86_INS_JMP ||
                inst.id == X86_INS_RET ||
                inst.id == X86_INS_CALL ||
                (inst.id >= X86_INS_JO && inst.id <= X86_INS_JP) ||  // conditional jumps
                i == insns.size() - 1;

            if (end_of_block) {
                if (block_keys.size() >= cfg.n) {
                    for (size_t j = 0; j + cfg.n <= block_keys.size(); ++j) {
                        std::string ngram = block_keys[j];
                        for (size_t k = 1; k < cfg.n; ++k)
                            ngram += "," + block_keys[j + k];

                        uint32_t susp_count = 0;
                        for (size_t k = j; k < j + cfg.n; ++k)
                            if (block_susp[k]) ++susp_count;

                        check_memory_limit();
                        auto& feat = feature_map[ngram];
                        feat.signature = ngram;
                        ++feat.count;
                        if (feat.first_va == 0) feat.first_va = block_addrs[j];

                        if (susp_count > 0) {
                            feat.near_suspicious += susp_count;
                            double w = 1.0 + cfg.boost_multiplier * static_cast<double>(susp_count);
                            if (w > feat.weight) feat.weight = w;
                        }

                        if (feat.positions.size() < 8)
                            feat.positions.push_back(block_addrs[j]);
                    }
                }

                // Reset block
                block_keys.clear();
                block_susp.clear();
                block_addrs.clear();
            }
        }
    }

    check_memory_limit();
    features.reserve(feature_map.size());
    for (auto& p : feature_map) {
        features.push_back(std::move(p.second));
    }

    std::sort(features.begin(), features.end(), [](const OpcodeFeature& a, const OpcodeFeature& b) {
        if (std::fabs(a.weight - b.weight) > 1e-6) return a.weight > b.weight;
        return a.count > b.count;
    });

    if (features.size() > cfg.max_features)
        features.resize(cfg.max_features);

    std::cout << "\n[RESULTS]\n";
    std::cout << "  Total instructions disassembled  : " << total_ins << "\n";
    std::cout << "  Total n-grams counted            : " << total_ngram_counted << "\n";
    std::cout << "  Unique n-grams after filtering   : " << features.size() << "\n";
    std::cout << "  Final number of features returned: " << features.size() << "\n";

    if (features.empty()) {
        std::cerr << "[CONCLUSION] No n-grams found → possible reasons:\n";
        std::cerr << "  1. No executable sections\n";
        std::cerr << "  2. Disassembled 0 instructions\n";
        std::cerr << "  3. Blocks too short (< n = " << cfg.n << " instructions)\n";
        std::cerr << "  4. No basic blocks long enough\n";
    }

    return features;
}

nlohmann::json opcode_features_to_json(
    const std::vector<OpcodeFeature>& features,
    size_t total_instructions
) {
    nlohmann::json j = nlohmann::json::array();

    for (const auto& f : features) {
        nlohmann::json item;
        item["sig"]        = f.signature;
        item["count"]      = f.count;
        item["weight"]     = f.weight;
        item["near_sus"]   = f.near_suspicious;
        item["first_va"]   = "0x" + std::to_string(f.first_va);
        if (!f.positions.empty()) {
            auto& arr = item["sample_positions"] = nlohmann::json::array();
            for (auto va : f.positions) {
                arr.push_back("0x" + std::to_string(va));
            }
        }
        j.push_back(item);
    }

    nlohmann::json root;
    root["opcode_ngrams"] = std::move(j);
    root["total_ngrams_found"] = features.size();
    root["approx_instructions_analyzed"] = total_instructions;

    return root;
}