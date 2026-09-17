#include "BehavioralGraph.hpp"
#include "MemoryLimit.hpp"
#include <algorithm>
#include <cmath>
#include <capstone/capstone.h>

extern std::string get_semantic_group(unsigned int id, const cs_x86* x86 = nullptr);
extern void check_memory_limit();

nlohmann::json GraphNode::to_json() const {
    nlohmann::json j;
    j["id"] = id;
    j["type"] = type_name;

    if (type == NodeType::BASIC_BLOCK) {
        j["start_addr"] = start_addr;
        j["end_addr"] = end_addr;
        j["instruction_count"] = instruction_count;
        j["byte_entropy"] = byte_entropy;
        j["has_call"] = has_call;
        j["has_indirect_call"] = has_indirect_call;
        j["has_indirect_jump"] = has_indirect_jump;
        j["is_entry"] = is_entry;
        j["is_exit"] = is_exit;
        j["is_loop_header"] = is_loop_header;
        j["distance_to_entry"] = distance_to_entry;
        j["semantic_histogram"] = semantic_histogram;
    } else if (type == NodeType::API_NODE || type == NodeType::API) {
        j["api_name"] = api_name;
        j["dll_category"] = dll_category;
        j["is_suspicious"] = is_suspicious;
        j["call_count"] = call_count;
    } else if (type == NodeType::MEMORY_REGION) {
        j["section_name"] = section_name;
        j["byte_entropy"] = byte_entropy;
        j["characteristics"] = characteristics;
    } else if (type == NodeType::PROCESS) {
        j["pid"] = pid;
        j["label"] = label;
        j["file_path"] = file_path;
    } else if (type == NodeType::FILE) {
        j["file_path"] = file_path;
        j["extension"] = extension;
        j["byte_entropy"] = byte_entropy;
    } else if (type == NodeType::CRYPTO_KEY) {
        j["label"] = label;
        j["metadata"] = metadata;
    } else if (type == NodeType::NETWORK) {
        j["ip_port"] = ip_port;
    } else if (type == NodeType::REGISTRY) {
        j["reg_key"] = reg_key;
    }
    return j;
}

nlohmann::json GraphEdge::to_json() const {
    nlohmann::json j;
    j["source"] = source;
    j["target"] = target;
    j["type"] = type_name;
    j["addr_dist"] = addr_dist;
    j["taint_strength"] = taint_strength;
    if (!metadata_str.empty()) {
        j["metadata"] = metadata_str;
    }
    return j;
}

std::string BehavioralGraphBuilder::categorize_dll(const std::string& api_name) const {
    std::string lower = api_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower.rfind("virtual", 0) == 0 || lower.rfind("createprocess", 0) == 0 ||
        lower.rfind("thread", 0) != std::string::npos || lower.rfind("memory", 0) != std::string::npos ||
        lower.find("loadlibrary") != std::string::npos || lower.find("getprocaddress") != std::string::npos) {
        return "kernel32";
    }
    if (lower.rfind("nt", 0) == 0 || lower.rfind("zw", 0) == 0 || lower.rfind("rtl", 0) == 0) {
        return "ntdll";
    }
    if (lower.find("internet") != std::string::npos || lower.find("http") != std::string::npos ||
        lower.find("socket") != std::string::npos || lower.find("recv") != std::string::npos || lower.find("send") != std::string::npos) {
        return "wininet_net";
    }
    if (lower.find("reg") != std::string::npos || lower.find("advapi") != std::string::npos || lower.find("crypt") != std::string::npos) {
        return "advapi32_security";
    }
    if (lower.find("window") != std::string::npos || lower.find("message") != std::string::npos || lower.find("user") != std::string::npos) {
        return "user32_gui";
    }
    return "other";
}

double BehavioralGraphBuilder::calculate_bytes_entropy(const uint8_t* data, size_t size) const {
    if (size == 0 || data == nullptr) return 0.0;
    std::unordered_map<uint8_t, size_t> counts;
    for (size_t i = 0; i < size; ++i) {
        counts[data[i]]++;
    }
    double entropy = 0.0;
    for (const auto& [byte_val, count] : counts) {
        double p = static_cast<double>(count) / size;
        entropy -= p * (std::log(p) / std::log(2.0));
    }
    return entropy;
}

extern DWORD RVAToOffset(const IMAGE_NT_HEADERS* nt, DWORD rva);

bool BehavioralGraphBuilder::build(
    const PeParser& parser,
    const PeHeaderFeatures& feats,
    const std::vector<uint8_t>& buffer,
    const std::unordered_set<std::string>& suspicious_apis
) {
    nodes_.clear();
    edges_.clear();
    block_addr_to_node_id_.clear();
    api_name_to_node_id_.clear();

    // Extract IAT VA to Name mapping
    std::unordered_map<uint64_t, std::string> iat_va_to_name;
    uint64_t image_base = parser.get_image_base();
    bool is64 = parser.is_64bit();

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
                                    const uint8_t* ptr = buffer.data() + name_off + 2;
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

    const auto& exec_sections = parser.get_executable_sections();
    if (exec_sections.empty()) {
        return false;
    }

    Disassembler disasm;
    if (!disasm.initialize(feats.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
        return false;
    }

    uint64_t entry_va = feats.image_base + feats.address_of_entry_point;

    // 1. Add MemoryRegion nodes for executable sections
    for (const auto& sec : exec_sections) {
        if (sec.raw_size == 0 || sec.raw_offset + sec.raw_size > buffer.size()) continue;

        GraphNode node;
        node.id = static_cast<uint32_t>(nodes_.size());
        node.type = NodeType::MEMORY_REGION;
        node.type_name = "MemoryRegion";
        node.section_name = sec.name;
        node.byte_entropy = calculate_bytes_entropy(buffer.data() + sec.raw_offset, sec.raw_size);
        node.characteristics = sec.characteristics;
        nodes_.push_back(node);
    }

    // 2. Extract instructions and build CFG across executable sections
    std::vector<Instruction> all_instructions;
    for (const auto& sec : exec_sections) {
        if (sec.raw_size == 0 || sec.raw_offset + sec.raw_size > buffer.size()) continue;
        auto insns = disasm.disassemble(
            buffer.data() + sec.raw_offset,
            sec.raw_size,
            sec.virtual_address,
            MAX_INSTRUCTION_PER_SECTION
        );
        all_instructions.insert(all_instructions.end(), insns.begin(), insns.end());
    }

    if (all_instructions.empty()) {
        return false;
    }

    ControlFlowGraph cfg;
    if (!cfg.build(all_instructions, entry_va)) {
        return false;
    }

    const auto& blocks = cfg.get_blocks();

    // Register Taint Tracking helper
    struct RegTaint {
        bool tainted = false;
        std::string api_name;
        uint32_t source_node_id = 0;
    };
    std::unordered_map<x86_reg, RegTaint> reg_taint;

    // 3. Create BasicBlock nodes
    std::vector<uint64_t> sorted_block_addrs;
    sorted_block_addrs.reserve(blocks.size());

    for (const auto& [start_addr, bb] : blocks) {
        sorted_block_addrs.push_back(start_addr);

        GraphNode node;
        node.id = static_cast<uint32_t>(nodes_.size());
        node.type = NodeType::BASIC_BLOCK;
        node.type_name = "BasicBlock";
        node.start_addr = bb.start_addr;
        node.end_addr = bb.end_addr;
        node.instruction_count = bb.instructions.size();
        node.has_call = bb.has_call;
        node.has_indirect_call = bb.has_indirect_call;
        node.has_indirect_jump = bb.has_indirect_jump;
        node.is_entry = bb.is_entry;
        node.is_exit = bb.is_exit;
        node.distance_to_entry = static_cast<int64_t>(bb.start_addr) - static_cast<int64_t>(entry_va);

        // Compute byte entropy of basic block bytes if available
        if (bb.end_addr >= bb.start_addr) {
            size_t approx_size = static_cast<size_t>(bb.end_addr - bb.start_addr);
            node.byte_entropy = calculate_bytes_entropy(
                buffer.data() + std::min(bb.start_addr, (uint64_t)buffer.size()),
                std::min(approx_size, buffer.size() - std::min(bb.start_addr, (uint64_t)buffer.size()))
            );
        }

        // Semantic instruction histogram
        for (const auto& inst : bb.instructions) {
            const cs_x86* x86_detail = inst.has_detail ? &inst.x86 : nullptr;
            std::string group = get_semantic_group(inst.id, x86_detail);
            node.semantic_histogram[group]++;
        }

        block_addr_to_node_id_[start_addr] = node.id;
        nodes_.push_back(node);
    }

    std::sort(sorted_block_addrs.begin(), sorted_block_addrs.end());

    // 4. Iterate over blocks to process call targets, API nodes, and taint edges
    for (const auto& [start_addr, bb] : blocks) {
        check_memory_limit();
        uint32_t bb_node_id = block_addr_to_node_id_[start_addr];

        for (const auto& inst : bb.instructions) {
            if (!inst.has_detail) continue;
            const cs_x86* x86 = &inst.x86;
            uint64_t va = inst.address;

            // Clear taint on control flow jumps/returns
            if (inst.id == X86_INS_CALL || inst.id == X86_INS_RET || inst.id == X86_INS_JMP) {
                reg_taint.clear();
            }

            // Detect API calls from memory or register
            if (inst.id == X86_INS_CALL && x86->op_count == 1) {
                const auto& op = x86->operands[0];
                std::string resolved_api;

                if (op.type == X86_OP_REG) {
                    auto it = reg_taint.find(op.reg);
                    if (it != reg_taint.end() && it->second.tainted) {
                        resolved_api = it->second.api_name;

                        // Add Taint edge from source node to current BB node
                        GraphEdge taint_edge;
                        taint_edge.source = it->second.source_node_id;
                        taint_edge.target = bb_node_id;
                        taint_edge.type = EdgeType::TAINT_EDGE;
                        taint_edge.type_name = "taint";
                        taint_edge.taint_strength = 1.0;
                        edges_.push_back(taint_edge);
                    }
                } else if (op.type == X86_OP_MEM) {
                    if (op.mem.base == X86_REG_RIP) {
                        uint64_t target_va = va + op.mem.disp + inst.length;
                        auto it = iat_va_to_name.find(target_va);
                        if (it != iat_va_to_name.end()) {
                            resolved_api = it->second;
                        }
                    }
                }

                if (!resolved_api.empty()) {
                    // Check if API node already exists
                    uint32_t api_node_id = 0;
                    auto api_it = api_name_to_node_id_.find(resolved_api);
                    if (api_it == api_name_to_node_id_.end()) {
                        GraphNode api_node;
                        api_node.id = static_cast<uint32_t>(nodes_.size());
                        api_node.type = NodeType::API_NODE;
                        api_node.type_name = "API";
                        api_node.api_name = resolved_api;
                        api_node.dll_category = categorize_dll(resolved_api);

                        std::string lower_api = resolved_api;
                        std::transform(lower_api.begin(), lower_api.end(), lower_api.begin(), ::tolower);
                        api_node.is_suspicious = (suspicious_apis.find(lower_api) != suspicious_apis.end());
                        api_node.call_count = 1;

                        api_node_id = api_node.id;
                        api_name_to_node_id_[resolved_api] = api_node_id;
                        nodes_.push_back(api_node);
                    } else {
                        api_node_id = api_it->second;
                        nodes_[api_node_id].call_count++;
                    }

                    // Create CALL edge from BasicBlock to API node
                    GraphEdge call_edge;
                    call_edge.source = bb_node_id;
                    call_edge.target = api_node_id;
                    call_edge.type = EdgeType::CALL_EDGE;
                    call_edge.type_name = "call";
                    edges_.push_back(call_edge);
                }
            }

            // Register MOV taint tracking
            if (inst.id == X86_INS_MOV && x86->op_count == 2) {
                if (x86->operands[0].type == X86_OP_REG && x86->operands[1].type == X86_OP_MEM) {
                    if (x86->operands[1].mem.base == X86_REG_RIP) {
                        uint64_t target_va = va + x86->operands[1].mem.disp + inst.length;
                        auto it = iat_va_to_name.find(target_va);
                        if (it != iat_va_to_name.end()) {
                            x86_reg dst = x86->operands[0].reg;
                            reg_taint[dst].tainted = true;
                            reg_taint[dst].api_name = it->second;
                            reg_taint[dst].source_node_id = bb_node_id;
                        }
                    }
                } else if (x86->operands[0].type == X86_OP_REG && x86->operands[1].type == X86_OP_REG) {
                    x86_reg dst = x86->operands[0].reg;
                    x86_reg src = x86->operands[1].reg;
                    reg_taint[dst] = reg_taint[src];
                }
            }
        }
    }

    // 5. Build Control-Flow Edges & Sequential Edges
    for (const auto& [start_addr, bb] : blocks) {
        uint32_t src_node_id = block_addr_to_node_id_[start_addr];

        for (uint64_t succ_addr : bb.successors) {
            auto succ_it = block_addr_to_node_id_.find(succ_addr);
            if (succ_it != block_addr_to_node_id_.end()) {
                GraphEdge cf_edge;
                cf_edge.source = src_node_id;
                cf_edge.target = succ_it->second;
                cf_edge.type = EdgeType::CONTROL_FLOW;
                cf_edge.type_name = "control_flow";
                cf_edge.addr_dist = static_cast<int64_t>(succ_addr) - static_cast<int64_t>(start_addr);
                edges_.push_back(cf_edge);
            }
        }
    }

    for (size_t i = 0; i + 1 < sorted_block_addrs.size(); ++i) {
        uint32_t src_node_id = block_addr_to_node_id_[sorted_block_addrs[i]];
        uint32_t dst_node_id = block_addr_to_node_id_[sorted_block_addrs[i + 1]];

        GraphEdge seq_edge;
        seq_edge.source = src_node_id;
        seq_edge.target = dst_node_id;
        seq_edge.type = EdgeType::SEQUENTIAL_EDGE;
        seq_edge.type_name = "sequential";
        seq_edge.addr_dist = static_cast<int64_t>(sorted_block_addrs[i + 1]) - static_cast<int64_t>(sorted_block_addrs[i]);
        edges_.push_back(seq_edge);
    }

    return true;
}

nlohmann::json BehavioralGraphBuilder::to_json() const {
    nlohmann::json j;
    nlohmann::json nodes_json = nlohmann::json::array();
    nlohmann::json edges_json = nlohmann::json::array();

    for (const auto& node : nodes_) {
        nodes_json.push_back(node.to_json());
    }
    for (const auto& edge : edges_) {
        edges_json.push_back(edge.to_json());
    }

    j["num_nodes"] = nodes_.size();
    j["num_edges"] = edges_.size();
    j["nodes"] = std::move(nodes_json);
    j["edges"] = std::move(edges_json);
    return j;
}

nlohmann::json RansomwareGraphPatternMatch::to_json() const {
    nlohmann::json j;
    j["matched"] = matched;
    j["process_pid"] = process_pid;
    j["process_name"] = process_name;
    j["file_read_count"] = file_read_count;
    j["file_write_count"] = file_write_count;
    j["file_rename_count"] = file_rename_count;
    j["crypto_operation_count"] = crypto_operation_count;
    j["common_target_extension"] = common_target_extension;
    j["confidence_score"] = confidence_score;
    j["involved_node_ids"] = involved_node_ids;
    j["pattern_description"] = pattern_description;
    return j;
}

uint32_t BehavioralEvidenceGraph::add_or_get_node(NodeType type, const std::string& label, uint32_t pid, const std::string& path_or_info) {
    std::string key = std::to_string(static_cast<int>(type)) + ":" + label + ":" + std::to_string(pid) + ":" + path_or_info;
    auto it = key_to_node_id_.find(key);
    if (it != key_to_node_id_.end()) {
        return it->second;
    }

    uint32_t new_id = static_cast<uint32_t>(nodes_.size() + 1);
    GraphNode node;
    node.id = new_id;
    node.type = type;
    node.label = label;
    node.pid = pid;

    switch (type) {
        case NodeType::PROCESS:
            node.type_name = "Process";
            node.file_path = path_or_info;
            break;
        case NodeType::FILE: {
            node.type_name = "File";
            node.file_path = path_or_info.empty() ? label : path_or_info;
            size_t dot_pos = node.file_path.rfind('.');
            if (dot_pos != std::string::npos) {
                node.extension = node.file_path.substr(dot_pos);
            }
            break;
        }
        case NodeType::CRYPTO_KEY:
            node.type_name = "CryptoKey";
            node.metadata["info"] = path_or_info;
            break;
        case NodeType::API:
        case NodeType::API_NODE:
            node.type_name = "API";
            node.api_name = label;
            break;
        case NodeType::NETWORK:
            node.type_name = "Network";
            node.ip_port = path_or_info.empty() ? label : path_or_info;
            break;
        case NodeType::REGISTRY:
            node.type_name = "Registry";
            node.reg_key = path_or_info.empty() ? label : path_or_info;
            break;
        case NodeType::MEMORY_REGION:
            node.type_name = "MemoryRegion";
            node.section_name = label;
            break;
        default:
            node.type_name = "Generic";
            break;
    }

    nodes_.push_back(node);
    key_to_node_id_[key] = new_id;
    return new_id;
}

void BehavioralEvidenceGraph::add_edge(uint32_t source_id, uint32_t target_id, EdgeType type, double weight, const std::string& meta) {
    GraphEdge edge;
    edge.source = source_id;
    edge.target = target_id;
    edge.type = type;
    edge.taint_strength = weight;
    edge.metadata_str = meta;

    switch (type) {
        case EdgeType::CREATED: edge.type_name = "created"; break;
        case EdgeType::READ: edge.type_name = "read"; break;
        case EdgeType::WROTE: edge.type_name = "wrote"; break;
        case EdgeType::ENCRYPTED: edge.type_name = "encrypted"; break;
        case EdgeType::RENAMED: edge.type_name = "renamed"; break;
        case EdgeType::GENERATED: edge.type_name = "generated"; break;
        case EdgeType::RESOLVED: edge.type_name = "resolved"; break;
        case EdgeType::CONNECTED: edge.type_name = "connected"; break;
        case EdgeType::CALL_EDGE: edge.type_name = "call"; break;
        case EdgeType::TAINT_EDGE: edge.type_name = "taint"; break;
        case EdgeType::CONTROL_FLOW: edge.type_name = "control_flow"; break;
        case EdgeType::SEQUENTIAL_EDGE: edge.type_name = "sequential"; break;
        default: edge.type_name = "associated"; break;
    }

    edges_.push_back(edge);
}

RansomwareGraphPatternMatch BehavioralEvidenceGraph::detect_ransomware_attack_pattern() const {
    RansomwareGraphPatternMatch best_match;
    best_match.matched = false;

    std::unordered_map<uint32_t, const GraphNode*> node_map;
    for (const auto& n : nodes_) {
        node_map[n.id] = &n;
    }

    for (const auto& proc_node : nodes_) {
        if (proc_node.type != NodeType::PROCESS) continue;

        std::set<uint32_t> read_file_ids;
        std::set<uint32_t> written_file_ids;
        std::set<uint32_t> renamed_file_ids;
        std::set<uint32_t> crypto_node_ids;
        std::map<std::string, size_t> target_extension_counts;
        std::vector<uint32_t> involved;
        involved.push_back(proc_node.id);

        for (const auto& edge : edges_) {
            if (edge.source != proc_node.id) continue;

            auto it = node_map.find(edge.target);
            if (it == node_map.end()) continue;
            const GraphNode* target_node = it->second;

            if (edge.type == EdgeType::READ && target_node->type == NodeType::FILE) {
                read_file_ids.insert(target_node->id);
                involved.push_back(target_node->id);
            } else if ((edge.type == EdgeType::WROTE || edge.type == EdgeType::ENCRYPTED) && target_node->type == NodeType::FILE) {
                written_file_ids.insert(target_node->id);
                involved.push_back(target_node->id);
                if (!target_node->extension.empty()) {
                    target_extension_counts[target_node->extension]++;
                }
            } else if (edge.type == EdgeType::RENAMED && target_node->type == NodeType::FILE) {
                renamed_file_ids.insert(target_node->id);
                involved.push_back(target_node->id);
                if (!target_node->extension.empty()) {
                    target_extension_counts[target_node->extension]++;
                }
            } else if (edge.type == EdgeType::GENERATED || edge.type == EdgeType::CALL_EDGE ||
                       target_node->type == NodeType::CRYPTO_KEY || target_node->type == NodeType::API) {
                crypto_node_ids.insert(target_node->id);
                involved.push_back(target_node->id);
            }
        }

        std::string dominant_ext;
        size_t max_ext_count = 0;
        for (const auto& [ext, cnt] : target_extension_counts) {
            if (cnt > max_ext_count) {
                max_ext_count = cnt;
                dominant_ext = ext;
            }
        }

        bool has_many_reads = (read_file_ids.size() >= 3);
        bool has_crypto = (!crypto_node_ids.empty());
        bool has_many_writes = (written_file_ids.size() >= 3);
        bool has_uniform_renames = (renamed_file_ids.size() >= 2 && max_ext_count >= 2);

        if ((has_many_reads && has_crypto && has_many_writes && has_uniform_renames) ||
            (has_many_writes && max_ext_count >= 4 && has_crypto)) {
            RansomwareGraphPatternMatch m;
            m.matched = true;
            m.process_pid = proc_node.pid;
            m.process_name = proc_node.label;
            m.file_read_count = read_file_ids.size();
            m.file_write_count = written_file_ids.size();
            m.file_rename_count = renamed_file_ids.size();
            m.crypto_operation_count = crypto_node_ids.size();
            m.common_target_extension = dominant_ext;
            m.confidence_score = std::min(0.99, 0.70 + (written_file_ids.size() * 0.02) + (crypto_node_ids.size() * 0.05));
            m.involved_node_ids = involved;
            m.pattern_description = "PROCESS (" + proc_node.label + ") -> " +
                                  std::to_string(m.file_read_count) + " FILE READS -> " +
                                  std::to_string(m.crypto_operation_count) + " CRYPTO OPS -> " +
                                  std::to_string(m.file_write_count) + " FILE WRITES -> " +
                                  std::to_string(m.file_rename_count) + " RENAMES (" + dominant_ext + ")";

            if (!best_match.matched || m.confidence_score > best_match.confidence_score) {
                best_match = m;
            }
        }
    }

    return best_match;
}

nlohmann::json BehavioralEvidenceGraph::to_json() const {
    nlohmann::json j;
    nlohmann::json nodes_arr = nlohmann::json::array();
    nlohmann::json edges_arr = nlohmann::json::array();

    for (const auto& n : nodes_) {
        nodes_arr.push_back(n.to_json());
    }
    for (const auto& e : edges_) {
        edges_arr.push_back(e.to_json());
    }

    j["num_nodes"] = nodes_.size();
    j["num_edges"] = edges_.size();
    j["nodes"] = std::move(nodes_arr);
    j["edges"] = std::move(edges_arr);

    auto pattern = detect_ransomware_attack_pattern();
    j["ransomware_pattern_match"] = pattern.to_json();

    return j;
}

void BehavioralEvidenceGraph::clear() {
    nodes_.clear();
    edges_.clear();
    key_to_node_id_.clear();
}

