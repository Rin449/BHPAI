#ifndef BHPAI_ANALYSIS_BUDGET_HPP
#define BHPAI_ANALYSIS_BUDGET_HPP

#include <cstdint>
#include <cstddef>
#include <chrono>
#include <string>

namespace BHPAI {

class AnalysisBudget {
public:
    uint64_t max_input_bytes = 500ULL * 1024 * 1024;      // 500 MB
    uint64_t max_extracted_bytes = 250ULL * 1024 * 1024;  // 250 MB
    uint64_t max_decoded_bytes = 250ULL * 1024 * 1024;    // 250 MB
    uint32_t max_child_files = 50;
    uint32_t max_recursion_depth = 5;
    uint32_t max_analysis_ms = 30000;                     // 30 seconds

    uint64_t current_extracted_bytes = 0;
    uint64_t current_decoded_bytes = 0;
    uint32_t current_child_count = 0;

    AnalysisBudget();

    bool CanRecurse(int current_depth) const;
    bool CanAddChild() const;
    bool ConsumeExtractedBytes(size_t bytes);
    bool ConsumeDecodedBytes(size_t bytes);
    bool IsTimeExpired() const;
    bool IsBudgetExceeded() const { return m_exceeded; }
    std::string GetExceededReason() const { return m_exceeded_reason; }

    void SetExceeded(const std::string& reason);

private:
    std::chrono::steady_clock::time_point m_start_time;
    bool m_exceeded = false;
    std::string m_exceeded_reason;
};

} // namespace BHPAI

#endif // BHPAI_ANALYSIS_BUDGET_HPP
