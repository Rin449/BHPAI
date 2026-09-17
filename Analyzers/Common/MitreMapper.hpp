#ifndef BHPAI_MITRE_MAPPER_HPP
#define BHPAI_MITRE_MAPPER_HPP

#include <string>
#include <vector>
#include "AnalysisNode.hpp"

namespace BHPAI {

class MitreMapper {
public:
    static std::vector<AttackMapping> EvaluateTechniques(
        bool has_openaction,
        bool has_launch,
        bool has_embedded_exe,
        bool has_javascript,
        int eval_count,
        int unescape_count,
        double obfuscation_score,
        int dangerous_api_count,
        bool suspicious_filter_chain,
        double js_entropy,
        const std::vector<std::string>& uris,
        bool has_xfa
    );
};

} // namespace BHPAI

#endif // BHPAI_MITRE_MAPPER_HPP
