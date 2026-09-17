#include "AnalysisBudget.hpp"

namespace BHPAI {

AnalysisBudget::AnalysisBudget()
    : m_start_time(std::chrono::steady_clock::now()) {
}

bool AnalysisBudget::CanRecurse(int current_depth) const {
    if (m_exceeded) return false;
    if (current_depth >= static_cast<int>(max_recursion_depth)) return false;
    return !IsTimeExpired();
}

bool AnalysisBudget::CanAddChild() const {
    if (m_exceeded) return false;
    if (current_child_count >= max_child_files) return false;
    return !IsTimeExpired();
}

bool AnalysisBudget::ConsumeExtractedBytes(size_t bytes) {
    if (m_exceeded) return false;
    if (current_extracted_bytes + bytes > max_extracted_bytes) {
        SetExceeded("Max extracted payload budget exceeded (" + std::to_string(max_extracted_bytes) + " bytes)");
        return false;
    }
    current_extracted_bytes += bytes;
    current_child_count++;
    return true;
}

bool AnalysisBudget::ConsumeDecodedBytes(size_t bytes) {
    if (m_exceeded) return false;
    if (current_decoded_bytes + bytes > max_decoded_bytes) {
        SetExceeded("Max decoded stream budget exceeded (" + std::to_string(max_decoded_bytes) + " bytes)");
        return false;
    }
    current_decoded_bytes += bytes;
    return true;
}

bool AnalysisBudget::IsTimeExpired() const {
    if (m_exceeded) return true;
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - m_start_time).count();
    if (elapsed > static_cast<long long>(max_analysis_ms)) {
        const_cast<AnalysisBudget*>(this)->SetExceeded("Analysis timeout exceeded (" + std::to_string(max_analysis_ms) + " ms)");
        return true;
    }
    return false;
}

void AnalysisBudget::SetExceeded(const std::string& reason) {
    m_exceeded = true;
    m_exceeded_reason = reason;
}

} // namespace BHPAI
