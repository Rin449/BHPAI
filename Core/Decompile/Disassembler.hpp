#ifndef DISASSEMBLER_HPP
#define DISASSEMBLER_HPP

#include <capstone/capstone.h>
#include <string>
#include <vector>
#include <cstdint>

struct Instruction {
    uint64_t address;
    unsigned int id;
    size_t length;
    bool has_detail;
    uint8_t op_count;

    std::string mnemonic;
    std::string operands;
    std::vector<uint8_t> bytes;
    cs_x86 x86;
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    bool initialize(bool is_64bit);
    std::vector<Instruction> disassemble(
        const uint8_t* code,
        size_t size,
        uint64_t start_address,
        size_t max_count = 0
    );

    std::string format_instruction(const Instruction& inst, bool color = false) const;

private:
    csh handle_ = 0;
    bool initialized_ = false;
};

#endif // DISASSEMBLER_HPP