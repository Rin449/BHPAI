#include "Disassembler.hpp"
#include "MemoryLimit.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>

extern bool g_safe_run;

Disassembler::Disassembler() = default;

Disassembler::~Disassembler() {
    if (initialized_) {
        cs_close(&handle_);
    }
}

bool Disassembler::initialize(bool is_64bit)
{
    cs_mode mode = is_64bit ? CS_MODE_64 : CS_MODE_32;
    cs_err err = cs_open(CS_ARCH_X86, mode, &handle_);
    
    if (err != CS_ERR_OK) {
        std::cerr << "[CAPSTONE ERROR] cs_open failed: " << cs_strerror(err) << "\n";
        return false;
    }

    err = cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    if (err != CS_ERR_OK) {
        std::cerr << "[CAPSTONE ERROR] Failed to enable CS_OPT_DETAIL: " << cs_strerror(err) << "\n";
        std::cerr << "[CAPSTONE ERROR] Common cause: Capstone built in diet/reduced mode → no detail support\n";
        cs_close(&handle_);
        return false;
    }

    cs_option(handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    initialized_ = true;
    std::cout << "[CAPSTONE OK] Initialization successful - Mode: " 
              << (is_64bit ? "64-bit" : "32-bit") 
              << " | Detail: ON\n";
    return true;
}

std::vector<Instruction> Disassembler::disassemble(
    const uint8_t* code,
    size_t size,
    uint64_t start_address,
    size_t max_count)
{
    std::vector<Instruction> result;

    if (!initialized_) return result;

    if (g_safe_run) {
        if (max_count == 0 || max_count > MAX_SAFE_INSTRUCTION_COUNT) {
            max_count = MAX_SAFE_INSTRUCTION_COUNT;
        }
    } else {
        if (max_count == 0 || max_count > MAX_HARD_INSTRUCTION_COUNT) {
            max_count = MAX_HARD_INSTRUCTION_COUNT;
        }
    }

    cs_insn* insn = nullptr;
    check_memory_limit();
    size_t count = cs_disasm(handle_, code, size, start_address, max_count, &insn);
    check_memory_limit();

    if (count == 0) {
        return result;
    }

    if (!check_instruction_limit(count)) {
        count = MAX_HARD_INSTRUCTION_COUNT;
    }

    try {
        for (size_t i = 0; i < count; ++i) {
            check_memory_limit();
            Instruction inst;
            inst.address  = insn[i].address;
            inst.id       = insn[i].id;
            inst.length   = std::min<size_t>(insn[i].size, 32);
            if (inst.length == 0) inst.length = 1;
            inst.has_detail = insn[i].detail != nullptr;
            inst.op_count  = inst.has_detail ? insn[i].detail->x86.op_count : 0;
            inst.mnemonic  = insn[i].mnemonic;
            inst.operands  = insn[i].op_str;
            inst.bytes.assign(insn[i].bytes, insn[i].bytes + inst.length);
            if (inst.has_detail) {
                inst.x86 = insn[i].detail->x86;
            }

            result.push_back(std::move(inst));
        }
    } catch (...) {
        cs_free(insn, count);
        throw;
    }

    cs_free(insn, count);
    return result;
}

std::string Disassembler::format_instruction(const Instruction& inst, bool /*color*/) const {
    std::ostringstream oss;

    oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << inst.address << "  ";

    size_t max_bytes_show = std::min(inst.bytes.size(), size_t(24));
    for (size_t i = 0; i < max_bytes_show; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(inst.bytes[i]) << " ";
    }

    size_t bytes_len = max_bytes_show * 3;
    if (bytes_len < 24) {
        oss << std::string(24 - bytes_len, ' ');
    } else if (inst.bytes.size() > 24) {
        oss << "... ";
    }

    oss << inst.mnemonic;
    if (!inst.operands.empty()) {
        oss << " " << inst.operands;
    }

    return oss.str();
}