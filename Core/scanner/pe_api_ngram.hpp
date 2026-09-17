#ifndef PE_API_NGRAM_HPP
#define PE_API_NGRAM_HPP

#include "PeParser.hpp"
#include "Disassembler.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

// ── Error codes for API sequence extraction ──────────────────────────────────
enum ApiParserError {
    API_PARSE_OK                   = 0,
    API_PARSE_INVALID_PE           = 1,
    API_PARSE_FILE_TOO_SMALL       = 2,
    API_PARSE_DISASM_INIT_FAIL     = 3,
    API_PARSE_IMPORT_TABLE_MISSING = 4,
    API_PARSE_NO_EXEC_SECTIONS     = 5,
    API_PARSE_EXCEPTION            = 6,
};

// ── Structured result from API sequence extraction ───────────────────────────
struct ApiCallSequenceResult {
    bool                          success  = false;
    ApiParserError                error    = API_PARSE_OK;
    std::vector<std::string>      sequence;
};

// Extracts the sequence of resolved API calls in order of appearance in executable sections.
// Returns a structured result with success/error info instead of a bare vector.
ApiCallSequenceResult extract_api_call_sequence(const PeParser& parser);

// Generates 2-gram and 3-gram counts from the API sequence
std::unordered_map<std::string, uint32_t> generate_api_ngrams(
    const std::vector<std::string>& api_sequence
);

#endif // PE_API_NGRAM_HPP
