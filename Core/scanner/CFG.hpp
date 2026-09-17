#ifndef CFG_HPP
#define CFG_HPP

#include "Disassembler.hpp"
#include <map>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <nlohmann/json.hpp>

struct BasicBlock {
    uint64_t start_addr = 0;
    uint64_t end_addr = 0;
    std::vector<Instruction> instructions;
    
    std::vector<uint64_t> successors;
    std::vector<uint64_t> predecessors;
    
    bool is_entry = false;
    bool is_exit = false;
    bool has_call = false;
    bool has_indirect_jump = false;
    bool has_indirect_call = false;
};

class ControlFlowGraph {
public:
    bool build(const std::vector<Instruction>& instructions, uint64_t base_addr = 0);
    
    size_t cyclomatic_complexity() const;
    size_t count_loops() const;
    size_t count_unreachable() const;
    double avg_block_size() const;

    nlohmann::json to_json() const;
    nlohmann::json extract_features() const;

    const std::unordered_map<uint64_t, BasicBlock>& get_blocks() const { return blocks; }

private:
    std::unordered_map<uint64_t, BasicBlock> blocks;
    std::vector<uint64_t> sorted_block_addresses;
    std::unordered_set<uint64_t> leaders;

    void add_edge(uint64_t from, uint64_t to);

    void find_leaders(const std::vector<Instruction>& insns);
    void build_blocks(const std::vector<Instruction>& insns);
    void connect_edges();
    bool is_terminator(const Instruction& inst) const;
};

#endif