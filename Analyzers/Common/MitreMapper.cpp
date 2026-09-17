#include "MitreMapper.hpp"

namespace BHPAI {

std::vector<AttackMapping> MitreMapper::EvaluateTechniques(
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
) {
    std::vector<AttackMapping> mappings;

    // 1. T1204.002 - User Execution: Malicious File
    if (has_openaction || has_launch) {
        AttackMapping m;
        m.technique_id = "T1204.002";
        m.technique_name = "User Execution: Malicious File";
        m.tactic = "Execution";

        if (has_openaction && has_embedded_exe) {
            m.confidence = 0.95;
            m.evidence.push_back("Document triggers /OpenAction automatically upon open");
            m.evidence.push_back("Embedded executable binary detected as target payload");
        } else if (has_launch) {
            m.confidence = 0.90;
            m.evidence.push_back("Contains /Launch action configured to execute local system commands or applications");
        } else if (has_openaction && has_javascript && obfuscation_score >= 0.35) {
            m.confidence = 0.88;
            m.evidence.push_back("Triggers /OpenAction pointing to obfuscated JavaScript payload");
        } else {
            m.confidence = 0.45;
            m.evidence.push_back("Contains standard /OpenAction or view state trigger");
        }
        mappings.push_back(std::move(m));
    }

    // 2. T1059.007 - Command and Scripting Interpreter: JavaScript
    if (has_javascript) {
        AttackMapping m;
        m.technique_id = "T1059.007";
        m.technique_name = "Command and Scripting Interpreter: JavaScript";
        m.tactic = "Execution";

        if (eval_count > 0 || unescape_count > 0 || dangerous_api_count > 0 || obfuscation_score >= 0.35) {
            m.confidence = 0.92;
            if (eval_count > 0) m.evidence.push_back("JavaScript calls eval() for dynamic runtime code generation");
            if (unescape_count > 0) m.evidence.push_back("JavaScript calls unescape() to decode packed hex buffers");
            if (dangerous_api_count > 0) m.evidence.push_back("Invokes dangerous Acrobat APIs (launchURL/util.printf/Collab)");
            if (obfuscation_score >= 0.35) m.evidence.push_back("JavaScript obfuscation score exceeds 0.35 threshold");
        } else {
            m.confidence = 0.30;
            m.evidence.push_back("Standard non-obfuscated JavaScript forms logic present");
        }
        mappings.push_back(std::move(m));
    }

    // 3. T1027 - Obfuscated Files or Information
    if (obfuscation_score >= 0.35 || suspicious_filter_chain || js_entropy > 5.5) {
        AttackMapping m;
        m.technique_id = "T1027";
        m.technique_name = "Obfuscated Files or Information";
        m.tactic = "Defense Evasion";

        double conf = 0.60;
        if (suspicious_filter_chain) {
            conf += 0.20;
            m.evidence.push_back("Multi-layer stream compression/filter chain or decode anomaly detected");
        }
        if (obfuscation_score >= 0.40) {
            conf += 0.15;
            m.evidence.push_back("High density of hex/unicode escape sequences in script body");
        }
        if (js_entropy > 5.5) {
            conf += 0.10;
            m.evidence.push_back("Script entropy exceeds 5.5 bits/byte (packed/encrypted buffer indicator)");
        }
        m.confidence = std::min(0.98, conf);
        mappings.push_back(std::move(m));
    }

    // 4. T1027.009 - Embedded Payload / Dropper
    if (has_embedded_exe) {
        AttackMapping m;
        m.technique_id = "T1027.009";
        m.technique_name = "Embedded Payloads";
        m.tactic = "Defense Evasion";
        m.confidence = 0.96;
        m.evidence.push_back("Embedded Windows PE executable or DLL binary stored inside document stream");
        mappings.push_back(std::move(m));
    }

    // 5. T1105 - Ingress Tool Transfer
    if (!uris.empty() || has_embedded_exe) {
        AttackMapping m;
        m.technique_id = "T1105";
        m.technique_name = "Ingress Tool Transfer";
        m.tactic = "Command and Control";

        if (dangerous_api_count > 0 && !uris.empty()) {
            m.confidence = 0.85;
            m.evidence.push_back("Acrobat network launch APIs configured with remote destination URIs");
            for (size_t i = 0; i < std::min<size_t>(uris.size(), 3); ++i) {
                m.evidence.push_back("External URI: " + uris[i]);
            }
        } else if (has_embedded_exe) {
            m.confidence = 0.75;
            m.evidence.push_back("Pre-packaged binary payload carried internally within container");
        } else {
            m.confidence = 0.40;
            m.evidence.push_back("External URI references present in document structure");
        }
        mappings.push_back(std::move(m));
    }

    // 6. T1203 - Exploitation for Client Execution
    if (has_xfa) {
        AttackMapping m;
        m.technique_id = "T1203";
        m.technique_name = "Exploitation for Client Execution";
        m.tactic = "Execution";
        m.confidence = 0.70;
        m.evidence.push_back("XML Forms Architecture (/XFA) active, expanding XML parser exploit surface");
        mappings.push_back(std::move(m));
    }

    return mappings;
}

} // namespace BHPAI
