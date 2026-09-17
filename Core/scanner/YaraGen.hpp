#ifndef YARA_GENERATOR_HPP
#define YARA_GENERATOR_HPP

#include "pe_analyzer.hpp"
#include "pe_opcode_ngram.hpp"
#include <string>
#include <vector>
#include <unordered_set>
#include <map>
#include <cstdint>

enum class SignalStrength {
    Weak,
    Medium,
    Strong,
    Critical
};

enum class CandidateType {
    URL,
    IP,
    Domain,
    Mutex,
    Registry,
    Crypto,
    RansomKeyword,
    SuspiciousText,
    HexPattern,
    OpcodeNgram
};

struct StringCandidate {
    std::string value;
    std::string normalized_key;
    CandidateType type = CandidateType::SuspiciousText;
    SignalStrength strength = SignalStrength::Weak;
    double entropy = 0.0;
    int relevance_score = 0;
    std::string label; // e.g. "ioc_url_0", "generic_0", "pattern_0"
    bool is_raw_hex = false;
};

struct CompilerProfile {
    bool is_rust = false;
    bool is_go = false;
    bool is_dotnet = false;
    bool is_mingw = false;
    bool is_msvc = false;
    std::string name = "Generic/Unknown";
};

struct BehaviorProfile {
    int process_injection_score = 0;
    int process_discovery_score = 0;
    int credential_access_score = 0;
    int persistence_score = 0;
    int anti_analysis_score = 0;
    int network_c2_score = 0;
    int crypto_ransom_score = 0;

    std::vector<std::string> injection_clauses;
    std::vector<std::string> discovery_clauses;
    std::vector<std::string> credential_clauses;
    std::vector<std::string> persistence_clauses;
    std::vector<std::string> anti_analysis_clauses;
    std::vector<std::string> network_clauses;
    std::vector<std::string> crypto_clauses;
};

struct RuleQualityMetrics {
    double specificity = 0.0;
    double uniqueness = 0.0;
    double portability = 1.0;
    double expected_fp_risk = 0.0;
    double expected_fn_risk = 0.0;
    std::string confidence = "MEDIUM";
};

struct RuleValidationResult {
    bool is_valid = true;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

struct YaraRule {
    std::string name;
    std::string description;
    std::string author = "BHPAI-AutoAnalyzer";
    int score = 0;
    std::string rule_text;
    std::vector<std::string> tags;
    CompilerProfile compiler;
    BehaviorProfile behavior;
    RuleQualityMetrics quality;
    RuleValidationResult validation;
};

struct MalwareTraits {
    bool has_injection = false;
    bool has_persistence = false;
    bool has_credential_theft = false;
    bool has_anti_debug = false;
    bool has_anti_vm = false;
    bool has_networking = false;

    bool api_VirtualAllocEx = false;
    bool api_WriteProcessMemory = false;
    bool api_CreateRemoteThread = false;
    bool api_NtMapViewOfSection = false;
    bool api_QueueUserAPC = false;
    
    bool api_IsDebuggerPresent = false;
    bool api_CheckRemoteDebuggerPresent = false;
    
    bool api_MiniDumpWriteDump = false;
    bool api_LsaEnumerateLogonSessions = false;

    std::vector<std::string> found_pdb_paths;
    std::vector<std::string> found_registry_keys;
    std::vector<std::string> found_urls;
};

class YaraGenerator {
public:
    YaraRule generate(const std::string& filepath, 
                      const PeHeaderFeatures& feats, 
                      const ImportStats& imports, 
                      const std::vector<OpcodeFeature>& ngrams, 
                      const std::vector<std::string>& strings, 
                      const InterestingStrings& interesting_strings,
                      const std::vector<uint8_t>& entry_point_bytes,
                      const FileHashes& hashes,
                      const std::string& packer_name = "");

    std::string generate_rule_string(const YaraRule& rule);

    static CompilerProfile detect_compiler(const std::vector<std::string>& strings, 
                                           const ImportStats& imports, 
                                           const PeHeaderFeatures& feats);

    static BehaviorProfile build_behavior_profile(const ImportStats& imports, 
                                                  const PeHeaderFeatures& feats);

    static int score_candidate(const StringCandidate& c, const CompilerProfile& compiler);

    static std::string normalize_string(const std::string& s);

    static std::string generate_entry_point_pattern(const std::vector<uint8_t>& entry_point_bytes, bool is_64bit);

    static std::vector<std::string> generate_opcode_patterns(const std::vector<OpcodeFeature>& ngrams, size_t max_patterns = 3);

    static RuleQualityMetrics calculate_quality_metrics(const std::vector<StringCandidate>& selected_candidates, 
                                                        const BehaviorProfile& behavior, 
                                                        const PeHeaderFeatures& feats);

    static RuleValidationResult validate_and_optimize_rule(std::string& rule_text, 
                                                           const std::vector<StringCandidate>& candidates, 
                                                           const BehaviorProfile& behavior);

private:
    std::string generate_strings_section(const std::vector<StringCandidate>& selected_candidates,
                                         const std::vector<std::string>& opcode_patterns,
                                         const std::string& ep_pattern,
                                         const std::string& packer_name,
                                         const PeHeaderFeatures& feats,
                                         const ImportStats& imports);
                                         
    std::string generate_condition(const PeHeaderFeatures& feats, 
                                   const ImportStats& imports, 
                                   const std::vector<StringCandidate>& selected_candidates,
                                   const BehaviorProfile& behavior,
                                   const std::string& ep_pattern,
                                   const std::vector<std::string>& opcode_patterns,
                                   const std::string& packer_name);

    static std::string escape_string(const std::string& s);
    static bool is_printable(const std::string& s);
    static std::string to_hex_string(const std::string& s);
};

#endif // YARA_GENERATOR_HPP