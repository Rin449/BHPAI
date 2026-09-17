#ifndef BHPAI_IOC_EXTRACTOR_HPP
#define BHPAI_IOC_EXTRACTOR_HPP

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace BHPAI {

struct IOCReport {
    std::vector<std::string> raw_urls;
    std::vector<std::string> defanged_urls;
    std::vector<std::string> domains;
    std::vector<std::string> ipv4_addresses;
    std::vector<std::string> email_addresses;

    nlohmann::json ToJson() const;
};

class IOCExtractor {
public:
    static IOCReport ExtractFromText(const std::string& text);
    static std::string DefangURL(const std::string& url);
    static std::string DefangIP(const std::string& ip);
    static std::string DefangDomain(const std::string& domain);
    static std::string ExtractDomainFromURL(const std::string& url);
    static bool IsValidIPv4(const std::string& ip);
    static bool IsBenignVendorDomain(const std::string& domain);
};

} // namespace BHPAI

#endif // BHPAI_IOC_EXTRACTOR_HPP
