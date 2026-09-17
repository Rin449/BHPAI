#include "opcode_tfidf.hpp"
#include <algorithm>
#include <iostream>
#include <unordered_set>
#include <cmath>
#include "PeParser.hpp"
#include "Disassembler.hpp"

OpcodeTfidfVectorizer::OpcodeTfidfVectorizer() : OpcodeTfidfVectorizer(TfidfConfig{}) {}

OpcodeTfidfVectorizer::OpcodeTfidfVectorizer(const TfidfConfig& cfg) : config(cfg) {}

std::vector<std::string>
OpcodeTfidfVectorizer::extract_opcodes(const PeParser& parser)
{
    std::vector<std::string> opcodes;
    Disassembler disasm;

    if (!disasm.initialize(parser.is_64bit())) {
        std::cerr << "[TF-IDF] disassembler init failed\n";
        return opcodes;
    }

    const auto& buffer = parser.get_buffer();

    for (const auto& sec : parser.get_executable_sections()) {
        if (sec.raw_size == 0) continue;

        auto instructions = disasm.disassemble(
            buffer.data() + sec.raw_offset,
            sec.raw_size,
            sec.virtual_address,
            config.max_instructions_per_file - opcodes.size()
        );

        for (const auto& inst : instructions) {
            opcodes.push_back(inst.mnemonic);

            if (opcodes.size() >= config.max_instructions_per_file)
                return opcodes;
        }
    }

    return opcodes;
}

std::vector<std::string>
OpcodeTfidfVectorizer::generate_ngrams(const std::vector<std::string>& opcodes) const
{
    if (!config.use_bigrams || opcodes.size() < 2)
        return opcodes;

    std::vector<std::string> ngrams;
    ngrams.reserve(opcodes.size());

    for (size_t i = 0; i + 1 < opcodes.size(); ++i) {
        ngrams.emplace_back(opcodes[i] + "_" + opcodes[i + 1]);
    }

    return ngrams;
}

void OpcodeTfidfVectorizer::fit(
    const std::vector<std::vector<std::string>>& corpus)
{
    total_docs = corpus.size();
    if (total_docs == 0) return;

    std::unordered_map<std::string, size_t> doc_freq;

    for (const auto& doc : corpus) {
        auto ngrams = generate_ngrams(doc);

        std::unordered_set<std::string> unique_terms(
            ngrams.begin(), ngrams.end()
        );

        for (const auto& term : unique_terms) {
            doc_freq[term]++;
        }
    }

    std::vector<std::pair<std::string, double>> scored;
    scored.reserve(doc_freq.size());

    for (const auto& [term, df_count] : doc_freq) {
        double df_ratio = static_cast<double>(df_count) / total_docs;

        if (df_ratio < config.min_df || df_ratio > config.max_df)
            continue;

        double idf = std::log(1.0 + total_docs / (1.0 + df_count));
        scored.emplace_back(term, idf);
    }

    std::sort(scored.begin(), scored.end(),
        [](const auto& a, const auto& b) {
            return a.second > b.second;
        });

    if (scored.size() > config.max_features)
        scored.resize(config.max_features);

    vocabulary.clear();
    idf_map.clear();
    vocabulary.reserve(scored.size());

    for (const auto& [term, idf] : scored) {
        vocabulary.push_back(term);
        idf_map[term] = idf;
    }

    std::cout << "[TF-IDF] vocab size = "
              << vocabulary.size()
              << " docs = " << total_docs << "\n";
}

OpcodeTfidfVector
OpcodeTfidfVectorizer::transform(const std::vector<std::string>& opcodes) const
{
    OpcodeTfidfVector vec;

    if (vocabulary.empty() || opcodes.empty())
        return vec;

    auto ngrams = generate_ngrams(opcodes);

    std::unordered_map<std::string, int> term_count;
    term_count.reserve(ngrams.size());

    for (const auto& t : ngrams)
        term_count[t]++;

    const double total_terms = static_cast<double>(ngrams.size());
    if (total_terms == 0) return vec;

    std::vector<std::pair<std::string, double>> scores;

    for (const auto& [term, count] : term_count) {
        auto it = idf_map.find(term);
        if (it == idf_map.end()) continue;

        double tf = 1.0 + std::log(count);
        double tfidf = tf * it->second;

        if (tfidf > 1e-8) {
            vec.sparse[term] = tfidf;
            scores.emplace_back(term, tfidf);
        }
    }

    std::sort(scores.begin(), scores.end(),
        [](const auto& a, const auto& b) {
            return a.second > b.second;
        });

    vec.top_terms = std::move(scores);

    return vec;
}

OpcodeTfidfVector
OpcodeTfidfVectorizer::extract_and_vectorize(const PeParser& parser)
{
    std::cout << "[TF-IDF] extract_and_vectorize: start\n";
    auto opcodes = extract_opcodes(parser);
    std::cout << "[TF-IDF] extract_and_vectorize: extracted " << opcodes.size() << " opcodes\n";
    auto vec = transform(opcodes);
    std::cout << "[TF-IDF] extract_and_vectorize: transform complete, " << vec.top_terms.size() << " top terms\n";
    return vec;
}

nlohmann::json OpcodeTfidfVector::to_json(size_t limit) const
{
    nlohmann::json arr = nlohmann::json::array();
    const size_t count = std::min(limit, top_terms.size());

    for (size_t i = 0; i < count; ++i) {
        const auto& [term, score] = top_terms[i];
        arr.push_back(nlohmann::json{{"term", term}, {"score", score}});
    }

    return arr;
}