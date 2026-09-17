#include "AnalysisNode.hpp"

namespace BHPAI {

nlohmann::json AnalysisNode::ToJson() const {
    nlohmann::json j;
    j["node_id"] = node_id;
    j["file"] = {
        {"name", filename},
        {"sha256", sha256},
        {"md5", md5},
        {"format", format_name},
        {"mime_type", mime_type},
        {"size_bytes", file_size},
        {"depth", depth}
    };

    j["analysis"] = {
        {"risk_score", heuristic_score},
        {"verdict", verdict},
        {"risk_label", risk_label},
        {"heuristic_score", heuristic_score},
        {"ml_score", ml_score >= 0.0 ? ml_score : 0.0}
    };

    nlohmann::json f_arr = nlohmann::json::array();
    for (const auto& f : findings) {
        f_arr.push_back({
            {"rule_id", f.rule_id},
            {"category", f.category},
            {"severity", f.severity},
            {"description", f.description}
        });
    }
    j["findings"] = f_arr;

    nlohmann::json m_arr = nlohmann::json::array();
    for (const auto& m : mitre_attacks) {
        m_arr.push_back({
            {"technique_id", m.technique_id},
            {"technique_name", m.technique_name},
            {"tactic", m.tactic},
            {"confidence", m.confidence},
            {"evidence", m.evidence}
        });
    }
    j["mitre_attack"] = m_arr;

    nlohmann::json c_arr = nlohmann::json::array();
    for (const auto& child : children) {
        c_arr.push_back(child.ToJson());
    }
    j["children"] = c_arr;
    j["details"] = details;

    return j;
}

} // namespace BHPAI
