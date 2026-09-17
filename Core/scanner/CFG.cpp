#include <algorithm>
#include <functional>
#include <queue>
#include <unordered_set>
#include "CFG.hpp"

static bool is_branch(const Instruction& inst) {
    return inst.id == X86_INS_JMP || (inst.id >= X86_INS_JO && inst.id <= X86_INS_JP);
}
static bool is_conditional_branch(const Instruction& inst) {
    return (inst.id >= X86_INS_JO && inst.id <= X86_INS_JP);
}

bool ControlFlowGraph::build(const std::vector<Instruction>& instructions, uint64_t base_addr) {
    (void)base_addr;
    if (instructions.empty()) return false;
    
    blocks.clear();
    sorted_block_addresses.clear();
    leaders.clear();
    blocks.reserve(std::max<size_t>(16, instructions.size() / 8));
    leaders.reserve(std::max<size_t>(16, instructions.size() / 8));

    find_leaders(instructions);
    build_blocks(instructions);
    std::sort(sorted_block_addresses.begin(), sorted_block_addresses.end());
    connect_edges();

    // Mark entry point
    if (!blocks.empty()) {
        blocks.begin()->second.is_entry = true;
    }
    return true;
}

void ControlFlowGraph::find_leaders(const std::vector<Instruction>& insns) {
    if (insns.empty()) return;
    
    leaders.reserve(std::max<size_t>(16, insns.size() / 8));
    leaders.insert(insns[0].address);

    for (size_t i = 0; i < insns.size(); ++i) {
        const auto& inst = insns[i];
        
        if (is_branch(inst) && inst.has_detail) {
            for (uint8_t j = 0; j < inst.x86.op_count; ++j) {
                const cs_x86_op& op = inst.x86.operands[j];
                if (op.type == X86_OP_IMM) {
                    leaders.insert(static_cast<uint64_t>(op.imm));
                }
            }
        }

        if (is_conditional_branch(inst) && i + 1 < insns.size()) {
            leaders.insert(insns[i + 1].address);
        }
        
        if ((inst.id == X86_INS_JMP || inst.id == X86_INS_RET) && i + 1 < insns.size()) {
            leaders.insert(insns[i + 1].address);
        }
    }
}

void ControlFlowGraph::add_edge(uint64_t from, uint64_t to)
{
    auto fromIt = blocks.find(from);
    auto toIt   = blocks.find(to);

    if (fromIt == blocks.end() || toIt == blocks.end())
        return;

    auto& succ = fromIt->second.successors;

    if (std::find(succ.begin(), succ.end(), to) == succ.end())
    {
        succ.push_back(to);
        toIt->second.predecessors.push_back(from);
    }
}

void ControlFlowGraph::build_blocks(const std::vector<Instruction>& insns)
{
    BasicBlock* current = nullptr;
    const Instruction* lastInst = nullptr;

    for (const auto& inst : insns)
    {
        if (leaders.count(inst.address))
        {
            if (current && lastInst)
            {
                current->end_addr = lastInst->address + lastInst->length - 1;
            }
            auto [it, inserted] = blocks.try_emplace(inst.address);
            if (inserted) {
                sorted_block_addresses.push_back(inst.address);
            }
            current = &it->second;
            current->start_addr = inst.address;
        }

        if (current) {
            current->instructions.push_back(inst);
        }
        lastInst = &inst;

        if (inst.id == X86_INS_CALL)
            current->has_call = true;

        if (inst.id == X86_INS_CALL && inst.x86.op_count > 0)
        {
            auto& op = inst.x86.operands[0];
            if (op.type == X86_OP_MEM || op.type == X86_OP_REG)
            {
                current->has_indirect_call = true;
            }
        }

        if (is_branch(inst) &&
            inst.x86.op_count > 0 &&
            inst.x86.operands[0].type != X86_OP_IMM)
        {
            current->has_indirect_jump = true;
        }
    }

    if (current && lastInst) {
        current->end_addr = lastInst->address + lastInst->length - 1;
    }
    for (auto& [addr, bb] : blocks) {
        if (!bb.instructions.empty() && bb.instructions.back().id == X86_INS_RET) {
            bb.is_exit = true;
        }
    }
}

void ControlFlowGraph::connect_edges()
{
    for (size_t index = 0; index < sorted_block_addresses.size(); ++index)
    {
        uint64_t addr = sorted_block_addresses[index];
        auto& bb = blocks[addr];
        if (bb.instructions.empty())
            continue;
        const Instruction& last = bb.instructions.back();
        if (index + 1 < sorted_block_addresses.size())
        {
            uint64_t next_addr = sorted_block_addresses[index + 1];
            if (is_conditional_branch(last))
            {
                add_edge(addr, next_addr);
            }
            else if (last.id != X86_INS_JMP &&
                     last.id != X86_INS_RET)
            {
                add_edge(addr, next_addr);
            }
        }
        if (is_branch(last) && last.has_detail)
        {
            for (uint8_t i = 0; i < last.x86.op_count; i++)
            {
                const auto& op = last.x86.operands[i];

                if (op.type != X86_OP_IMM)
                    continue;

                uint64_t target = static_cast<uint64_t>(op.imm);

                add_edge(addr, target);
            }
        }
    }
}

bool ControlFlowGraph::is_terminator(const Instruction& inst) const {
    return inst.id == X86_INS_JMP || inst.id == X86_INS_RET;
}

size_t ControlFlowGraph::cyclomatic_complexity() const {
    if (blocks.empty()) return 0;

    size_t nodes = blocks.size();
    size_t edges = 0;
    for (const auto& kv : blocks) {
        edges += kv.second.successors.size();
    }
    size_t P = 0;
    std::unordered_set<uint64_t> visited;
    visited.reserve(blocks.size());

    std::unordered_map<uint64_t, std::vector<uint64_t>> undirected_adj;
    undirected_adj.reserve(blocks.size() * 2);
    for (const auto& kv : blocks) {
        const auto& addr = kv.first;
        const auto& bb = kv.second;
        for (uint64_t succ : bb.successors) {
            undirected_adj[addr].push_back(succ);
            undirected_adj[succ].push_back(addr);
        }
        for (uint64_t pred : bb.predecessors) {
            undirected_adj[addr].push_back(pred);
            undirected_adj[pred].push_back(addr);
        }
    }

    for (const auto& kv : blocks) {
        const uint64_t addr = kv.first;
        if (visited.find(addr) == visited.end()) {
            P++;
            std::queue<uint64_t> q;
            q.push(addr);
            visited.insert(addr);

            while (!q.empty()) {
                uint64_t curr = q.front();
                q.pop();

                for (uint64_t neighbor : undirected_adj[curr]) {
                    if (visited.find(neighbor) == visited.end()) {
                        visited.insert(neighbor);
                        q.push(neighbor);
                    }
                }
            }
        }
    }

   return std::max<uint64_t>(1, static_cast<uint64_t>(edges) - static_cast<uint64_t>(nodes) + 2 * static_cast<uint64_t>(P));
}

nlohmann::json ControlFlowGraph::extract_features() const {
    nlohmann::json j;
    j["cyclomatic_complexity"] = cyclomatic_complexity();
    j["num_basic_blocks"] = blocks.size();

    size_t edges = 0, indirect = 0, calls = 0, indirect_calls = 0, branch_instructions = 0, jump_instructions = 0, total_instructions = 0;
    size_t max_out_degree = 0;
    double total_out_degree = 0.0;
    double total_in_degree = 0.0;
    size_t max_in_degree = 0;
    size_t back_edges = 0;

    for (const auto& [_, bb] : blocks) {
        edges += bb.successors.size();
        total_out_degree += bb.successors.size();
        total_in_degree += bb.predecessors.size();
        max_out_degree = std::max(max_out_degree, bb.successors.size());
        max_in_degree = std::max(max_in_degree, bb.predecessors.size());
        if (bb.has_indirect_jump) indirect++;
        if (bb.has_indirect_call) indirect++;
        if (bb.has_call) calls++;
        if (bb.has_indirect_call) indirect_calls++;

        for (const auto& inst : bb.instructions) {
            total_instructions++;
            if (inst.id == X86_INS_JMP || (inst.id >= X86_INS_JO && inst.id <= X86_INS_JP)) {
                branch_instructions++;
            }
            if (inst.id == X86_INS_JMP || inst.id == X86_INS_CALL || inst.id == X86_INS_RET ||
                (inst.id >= X86_INS_JO && inst.id <= X86_INS_JP)) {
                jump_instructions++;
            }
        }

        for (uint64_t succ : bb.successors) {
            if (succ < bb.start_addr) {
                back_edges++;
            }
        }
    }

    std::unordered_set<uint64_t> visited;
    std::function<size_t(uint64_t, std::unordered_set<uint64_t>)> max_depth = [&](uint64_t start, std::unordered_set<uint64_t> path) {
        if (path.count(start)) {
            return static_cast<size_t>(0);
        }
        path.insert(start);

        const auto it = blocks.find(start);
        if (it == blocks.end()) {
            return static_cast<size_t>(0);
        }

        size_t depth = it->second.has_call ? 1 : 0;
        for (uint64_t succ : it->second.successors) {
            depth = std::max(depth, (it->second.has_call ? 1 : 0) + max_depth(succ, path));
        }
        return depth;
    };

    size_t max_call_depth = 0;
    if (!blocks.empty()) {
        max_call_depth = max_depth(blocks.begin()->first, {});
    }

    size_t recursive_function_count = 0;
    std::unordered_set<uint64_t> seen;
    for (const auto& [addr, bb] : blocks) {
        if (seen.count(addr)) continue;
        for (uint64_t succ : bb.successors) {
            if (succ == addr || seen.count(succ)) {
                recursive_function_count++;
                break;
            }
        }
        seen.insert(addr);
    }

    j["num_edges"] = edges;
    j["average_out_degree"] = blocks.empty() ? 0.0 : total_out_degree / blocks.size();
    j["average_in_degree"] = blocks.empty() ? 0.0 : total_in_degree / blocks.size();
    j["max_out_degree"] = max_out_degree;
    j["max_call_depth"] = max_call_depth;
    j["recursive_function_count"] = recursive_function_count;
    j["back_edge_ratio"] = edges == 0 ? 0.0 : static_cast<double>(back_edges) / edges;
    j["jump_density"] = total_instructions == 0 ? 0.0 : static_cast<double>(jump_instructions) / total_instructions;
    j["branch_density"] = total_instructions == 0 ? 0.0 : static_cast<double>(branch_instructions) / total_instructions;
    j["indirect_control_flow"] = indirect;
    j["indirect_call_ratio"] = calls == 0 ? 0.0 : static_cast<double>(indirect_calls) / calls;
    j["call_count"] = calls;
    j["avg_block_size"] = avg_block_size();
    j["has_loops"] = count_loops() > 0;
    j["unreachable_blocks"] = count_unreachable();

    return j;
}

double ControlFlowGraph::avg_block_size() const {
    if (blocks.empty()) return 0.0;
    double total = 0;
    for (const auto& [_, bb] : blocks) {
        total += bb.instructions.size();
    }
    return total / blocks.size();
}

size_t ControlFlowGraph::count_loops() const {
    size_t loops = 0;
    for (const auto& [addr, bb] : blocks) {
        for (uint64_t succ : bb.successors) {
            if (succ < addr) loops++; 
        }
    }
    return loops;
}


size_t ControlFlowGraph::count_unreachable() const {
    if (blocks.empty()) return 0;
    std::set<uint64_t> visited;
    std::queue<uint64_t> q;
    
    q.push(blocks.begin()->first);
    visited.insert(blocks.begin()->first);

    while (!q.empty()) {
        uint64_t curr = q.front(); q.pop();
        auto it = blocks.find(curr);
        if (it == blocks.end()) continue;
        
        for (uint64_t succ : it->second.successors) {
            if (visited.find(succ) == visited.end()) {
                visited.insert(succ);
                q.push(succ);
            }
        }
    }
    return blocks.size() - visited.size();
}