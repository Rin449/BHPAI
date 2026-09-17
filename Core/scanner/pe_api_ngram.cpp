#include "pe_api_ngram.hpp"
#include "MemoryLimit.hpp"
#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <cstring>
#include <windows.h>

extern DWORD RVAToOffset(const IMAGE_NT_HEADERS* nt, DWORD rva);

static bool is_load_from_iat_api(
    const cs_x86_op& op,
    uint64_t current_va,
    uint64_t inst_len,
    const std::unordered_map<uint64_t, std::string>& iat_va_to_name,
    std::string& resolved_name
) {
    if (op.type != X86_OP_MEM) return false;

    uint64_t target_va = 0;
    if (op.mem.base == X86_REG_RIP) {
        target_va = current_va + inst_len + op.mem.disp;
    } else if (op.mem.base == X86_REG_INVALID && op.mem.index == X86_REG_INVALID) {
        target_va = static_cast<uint64_t>(op.mem.disp);
    } else {
        return false;
    }

    auto it = iat_va_to_name.find(target_va);
    if (it != iat_va_to_name.end()) {
        resolved_name = it->second;
        return true;
    }
    return false;
}

ApiCallSequenceResult extract_api_call_sequence(const PeParser& parser) {
    ApiCallSequenceResult result;

    if (!parser.is_valid()) {
        result.error = API_PARSE_INVALID_PE;
        return result;
    }

    const auto& buffer = parser.get_buffer();
    if (buffer.size() < 0x200) {
        result.error = API_PARSE_FILE_TOO_SMALL;
        return result;
    }

    Disassembler disasm;
    bool is64 = parser.is_64bit();
    if (!disasm.initialize(is64)) {
        result.error = API_PARSE_DISASM_INIT_FAIL;
        return result;
    }

    uint64_t image_base = parser.get_image_base();

    // ── Parse IAT ──
    std::unordered_map<uint64_t, std::string> iat_va_to_name;
    safe_reserve(iat_va_to_name, 1024);
    bool import_table_found = false;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    if (dos->e_magic == IMAGE_DOS_SIGNATURE && static_cast<size_t>(dos->e_lfanew) < buffer.size()) {
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + dos->e_lfanew);
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
                import_table_found = true;
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

    if (!import_table_found) {
        result.error = API_PARSE_IMPORT_TABLE_MISSING;
        return result;
    }

    const auto& exec_sections = parser.get_executable_sections();
    if (exec_sections.empty()) {
        result.error = API_PARSE_NO_EXEC_SECTIONS;
        return result;
    }

    // Keep track of register values containing function pointers
    struct RegTaint {
        bool tainted = false;
        std::string api_name;
    };
    std::unordered_map<x86_reg, RegTaint> reg_taint;
    safe_reserve(reg_taint, 64);

    for (const auto& sec : exec_sections) {
        if (sec.raw_size == 0 || sec.raw_offset + sec.raw_size > buffer.size()) {
            continue;
        }

        auto insns = disasm.disassemble(
            buffer.data() + sec.raw_offset,
            sec.raw_size,
            sec.virtual_address,
            MAX_INSTRUCTION_PER_SECTION
        );

        if (insns.empty()) continue;

        for (size_t i = 0; i < insns.size(); ++i) {
            const auto& inst = insns[i];
            uint64_t va = inst.address;

            if (!inst.has_detail) continue;

            const cs_x86* x86 = &inst.x86;

            // Clear registers taint on flow changes to avoid false taint propagation
            if (inst.id == X86_INS_CALL || inst.id == X86_INS_RET || inst.id == X86_INS_JMP) {
                reg_taint.clear();
            }

            // mov reg, [iat_address]
            if (inst.id == X86_INS_MOV && x86->op_count == 2 &&
                x86->operands[0].type == X86_OP_REG &&
                x86->operands[1].type == X86_OP_MEM) {
                
                std::string resolved_name;
                if (is_load_from_iat_api(x86->operands[1], va, inst.length, iat_va_to_name, resolved_name)) {
                    x86_reg dst = x86->operands[0].reg;
                    reg_taint[dst].tainted = true;
                    reg_taint[dst].api_name = std::move(resolved_name);
                }
            }

            // mov reg_a, reg_b
            if (inst.id == X86_INS_MOV && x86->op_count == 2 &&
                x86->operands[0].type == X86_OP_REG &&
                x86->operands[1].type == X86_OP_REG) {
                x86_reg dst = x86->operands[0].reg;
                x86_reg src = x86->operands[1].reg;
                reg_taint[dst] = reg_taint[src];
            }

            // Check if call target is resolved API
            if (inst.id == X86_INS_CALL && x86->op_count == 1) {
                const auto& op = x86->operands[0];
                std::string resolved_api;

                if (op.type == X86_OP_REG) {
                    auto it = reg_taint.find(op.reg);
                    if (it != reg_taint.end() && it->second.tainted) {
                        resolved_api = it->second.api_name;
                    }
                }
                else if (op.type == X86_OP_MEM) {
                    is_load_from_iat_api(op, va, inst.length, iat_va_to_name, resolved_api);
                }
                else if (op.type == X86_OP_IMM) {
                    // Call to thunk or direct address
                    uint64_t target_va = static_cast<uint64_t>(op.imm);
                    auto it = iat_va_to_name.find(target_va);
                    if (it != iat_va_to_name.end()) {
                        resolved_api = it->second;
                    }
                }

                if (!resolved_api.empty()) {
                    result.sequence.push_back(resolved_api);
                }
            }
        }
    }

    // Parser ran to completion — mark success even if sequence is empty
    // (empty sequence with success=true means the file genuinely has no resolved API calls)
    result.success = true;
    result.error   = API_PARSE_OK;
    return result;
}

std::unordered_map<std::string, uint32_t> generate_api_ngrams(
    const std::vector<std::string>& api_sequence
) {
    std::unordered_map<std::string, uint32_t> ngrams;
    if (api_sequence.size() < 2) {
        return ngrams;
    }
    safe_reserve(ngrams, std::min<size_t>(api_sequence.size() * 2, 2'000'000));

    // 2-grams
    for (size_t i = 0; i + 1 < api_sequence.size(); ++i) {
        std::string key = api_sequence[i] + "->" + api_sequence[i+1];
        ngrams[key]++;
    }

    // 3-grams
    if (api_sequence.size() >= 3) {
        for (size_t i = 0; i + 2 < api_sequence.size(); ++i) {
            std::string key = api_sequence[i] + "->" + api_sequence[i+1] + "->" + api_sequence[i+2];
            ngrams[key]++;
        }
    }

    return ngrams;
}
