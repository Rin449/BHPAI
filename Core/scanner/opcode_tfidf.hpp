#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <utility>
#include <nlohmann/json.hpp>

struct TfidfConfig {
    bool use_bigrams = true;
    size_t max_features = 5000;
    size_t max_instructions_per_file = 50000;

    double min_df = 0.0001;
    double max_df = 0.95;
};

struct OpcodeTfidfVector {
    std::unordered_map<std::string, double> sparse;
    std::vector<std::pair<std::string, double>> top_terms;

    nlohmann::json to_json(size_t limit = 50) const;
};

class PeParser; // forward

class OpcodeTfidfVectorizer {
public:
    OpcodeTfidfVectorizer();
    explicit OpcodeTfidfVectorizer(const TfidfConfig& cfg);

    void fit(const std::vector<std::vector<std::string>>& corpus);

    OpcodeTfidfVector transform(const std::vector<std::string>& opcodes) const;

    OpcodeTfidfVector extract_and_vectorize(const PeParser& parser);

private:
    TfidfConfig config;

    size_t total_docs = 0;

    std::vector<std::string> vocabulary;
    std::unordered_map<std::string, double> idf_map;

private:
    std::vector<std::string> extract_opcodes(const PeParser& parser);

    std::vector<std::string> generate_ngrams(const std::vector<std::string>& opcodes) const;
};