#ifndef BEHAVIORAL_GRAPH_HPP
#define BEHAVIORAL_GRAPH_HPP

#include "CFG.hpp"
#include "PeParser.hpp"
#include "Disassembler.hpp"
#include "pe_analyzer.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <nlohmann/json.hpp>

enum class NodeType {
    BASIC_BLOCK,
    API_NODE,
    MEMORY_REGION,
    PROCESS,
    FILE,
    CRYPTO_KEY,
    API,
    NETWORK,
    REGISTRY
};

enum class EdgeType {
    CONTROL_FLOW,
    CALL_EDGE,
    TAINT_EDGE,
    SEQUENTIAL_EDGE,
    CREATED,
    READ,
    WROTE,
    ENCRYPTED,
    RENAMED,
    GENERATED,
    RESOLVED,
    CONNECTED
};

struct GraphNode {
    uint32_t id = 0;
    NodeType type = NodeType::BASIC_BLOCK;
    std::string type_name; // "BasicBlock", "API", "MemoryRegion", "Process", "File", "CryptoKey", "Network", "Registry"

    // Node features
    uint64_t start_addr = 0;
    uint64_t end_addr = 0;
    size_t instruction_count = 0;
    double byte_entropy = 0.0;
    bool has_call = false;
    bool has_indirect_call = false;
    bool has_indirect_jump = false;
    bool is_entry = false;
    bool is_exit = false;
    bool is_loop_header = false;
    int64_t distance_to_entry = 0;
    std::unordered_map<std::string, uint32_t> semantic_histogram;

    // API specific
    std::string api_name;
    std::string dll_category;
    bool is_suspicious = false;
    uint32_t call_count = 0;

    // Memory region specific
    std::string section_name;
    uint32_t characteristics = 0;

    // Dynamic entity specific
    std::string label;
    uint32_t pid = 0;
    std::string file_path;
    std::string extension;
    std::string ip_port;
    std::string reg_key;
    uint64_t timestamp = 0;
    std::unordered_map<std::string, std::string> metadata;

    nlohmann::json to_json() const;
};

struct GraphEdge {
    uint32_t source = 0;
    uint32_t target = 0;
    EdgeType type = EdgeType::CONTROL_FLOW;
    std::string type_name; // "control_flow", "call", "taint", "sequential", "created", "read", "wrote", "encrypted", "renamed", "generated", "resolved", "connected"
    int64_t addr_dist = 0;
    double taint_strength = 1.0;
    std::string metadata_str;

    nlohmann::json to_json() const;
};

struct RansomwareGraphPatternMatch {
    bool matched = false;
    uint32_t process_pid = 0;
    std::string process_name;
    size_t file_read_count = 0;
    size_t file_write_count = 0;
    size_t file_rename_count = 0;
    size_t crypto_operation_count = 0;
    std::string common_target_extension;
    double confidence_score = 0.0;
    std::vector<uint32_t> involved_node_ids;
    std::string pattern_description;

    nlohmann::json to_json() const;
};

class BehavioralEvidenceGraph {
public:
    BehavioralEvidenceGraph() = default;

    uint32_t add_or_get_node(NodeType type, const std::string& label, uint32_t pid = 0, const std::string& path_or_info = "");
    void add_edge(uint32_t source_id, uint32_t target_id, EdgeType type, double weight = 1.0, const std::string& meta = "");

    const std::vector<GraphNode>& get_nodes() const { return nodes_; }
    const std::vector<GraphEdge>& get_edges() const { return edges_; }

    RansomwareGraphPatternMatch detect_ransomware_attack_pattern() const;
    nlohmann::json to_json() const;
    void clear();

private:
    std::vector<GraphNode> nodes_;
    std::vector<GraphEdge> edges_;
    std::unordered_map<std::string, uint32_t> key_to_node_id_;
};

class BehavioralGraphBuilder {
public:
    BehavioralGraphBuilder() = default;

    bool build(
        const PeParser& parser,
        const PeHeaderFeatures& feats,
        const std::vector<uint8_t>& buffer,
        const std::unordered_set<std::string>& suspicious_apis
    );

    nlohmann::json to_json() const;

    const std::vector<GraphNode>& get_nodes() const { return nodes_; }
    const std::vector<GraphEdge>& get_edges() const { return edges_; }

private:
    std::vector<GraphNode> nodes_;
    std::vector<GraphEdge> edges_;
    std::unordered_map<uint64_t, uint32_t> block_addr_to_node_id_;
    std::unordered_map<std::string, uint32_t> api_name_to_node_id_;

    std::string categorize_dll(const std::string& api_name) const;
    double calculate_bytes_entropy(const uint8_t* data, size_t size) const;
};

#endif // BEHAVIORAL_GRAPH_HPP
