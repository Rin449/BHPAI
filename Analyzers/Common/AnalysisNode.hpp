#ifndef BHPAI_ANALYSIS_NODE_HPP
#define BHPAI_ANALYSIS_NODE_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>
#include "FileRouter.hpp"

namespace BHPAI {

struct Finding {
    std::string rule_id;
    std::string category;
    int severity = 1; // 0: Info, 1: Low, 2: Medium, 3: High, 4: Critical
    std::string description;
};

struct AttackMapping {
    std::string technique_id;
    std::string technique_name;
    std::string tactic;
    double confidence = 0.0; // 0.0 to 1.0
    std::vector<std::string> evidence;
};

struct AnalysisNode {
    std::string node_id;
    std::string filename;
    std::string sha256;
    std::string md5;
    FileFormat format = FileFormat::UNKNOWN;
    std::string format_name = "Unknown";
    std::string mime_type = "application/octet-stream";
    uint64_t file_size = 0;
    int depth = 0;

    double heuristic_score = 0.0; // 0.0 to 100.0
    double ml_score = -1.0;        // -1.0: not evaluated, 0.0 to 1.0
    std::string verdict = "CLEAN";
    std::string risk_label = "Clean Document";

    std::vector<Finding> findings;
    std::vector<AttackMapping> mitre_attacks;
    std::vector<AnalysisNode> children;
    nlohmann::json details;

    nlohmann::json ToJson() const;
};

} // namespace BHPAI

#endif // BHPAI_ANALYSIS_NODE_HPP
