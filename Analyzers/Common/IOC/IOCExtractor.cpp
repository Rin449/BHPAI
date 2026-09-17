#include "IOCExtractor.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <regex>

namespace BHPAI {

nlohmann::json IOCReport::ToJson() const {
    nlohmann::json j;
    j["urls"] = defanged_urls;
    j["domains"] = domains;
    j["ipv4"] = ipv4_addresses;
    j["emails"] = email_addresses;
    return j;
}

std::string IOCExtractor::DefangURL(const std::string& url) {
    std::string defanged = url;
    // Replace http:// with hxxp://
    if (defanged.find("https://") == 0) {
        defanged.replace(0, 8, "hxxps://");
    } else if (defanged.find("http://") == 0) {
        defanged.replace(0, 7, "hxxp://");
    }

    // Replace dots with [.] in host portion
    size_t proto_pos = defanged.find("://");
    size_t host_start = (proto_pos != std::string::npos) ? proto_pos + 3 : 0;
    size_t path_pos = defanged.find('/', host_start);
    size_t host_len = (path_pos != std::string::npos) ? path_pos - host_start : defanged.size() - host_start;

    std::string host = defanged.substr(host_start, host_len);
    std::string defanged_host;
    for (char c : host) {
        if (c == '.') defanged_host += "[.]";
        else defanged_host += c;
    }

    if (path_pos != std::string::npos) {
        return defanged.substr(0, host_start) + defanged_host + defanged.substr(path_pos);
    } else {
        return defanged.substr(0, host_start) + defanged_host;
    }
}

std::string IOCExtractor::DefangIP(const std::string& ip) {
    std::string res;
    for (char c : ip) {
        if (c == '.') res += "[.]";
        else res += c;
    }
    return res;
}

std::string IOCExtractor::DefangDomain(const std::string& domain) {
    std::string res;
    for (char c : domain) {
        if (c == '.') res += "[.]";
        else res += c;
    }
    return res;
}

std::string IOCExtractor::ExtractDomainFromURL(const std::string& url) {
    size_t proto = url.find("://");
    size_t start = (proto != std::string::npos) ? proto + 3 : 0;
    size_t end = url.find_first_of("/:?#", start);
    if (end == std::string::npos) end = url.size();
    return url.substr(start, end - start);
}

bool IOCExtractor::IsBenignVendorDomain(const std::string& domain) {
    std::string lower = domain;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    static const std::vector<std::string> benign = {
        "adobe.com", "w3.org", "microsoft.com", "apple.com", "google.com",
        "ns.adobe.com", "xml.apache.org", "purl.org", "iptc.org", "schema.org"
    };

    for (const auto& b : benign) {
        if (lower == b || (lower.size() > b.size() && lower.substr(lower.size() - b.size() - 1) == "." + b)) {
            return true;
        }
    }
    return false;
}

bool IOCExtractor::IsValidIPv4(const std::string& ip) {
    std::stringstream ss(ip);
    std::string segment;
    int count = 0;
    while (std::getline(ss, segment, '.')) {
        if (segment.empty() || segment.size() > 3) return false;
        for (char c : segment) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
        int val = std::stoi(segment);
        if (val < 0 || val > 255) return false;
        count++;
    }
    return (count == 4);
}

IOCReport IOCExtractor::ExtractFromText(const std::string& text) {
    IOCReport rep;
    if (text.empty()) return rep;

    // 1. Extract URLs: http:// or https://
    size_t p = 0;
    while ((p = text.find("http", p)) != std::string::npos) {
        if (p == 0 || !std::isalnum(static_cast<unsigned char>(text[p-1]))) {
            size_t end = p;
            while (end < text.size() &&
                   !std::isspace(static_cast<unsigned char>(text[end])) &&
                   text[end] != '"' && text[end] != '\'' && text[end] != '>' &&
                   text[end] != ')' && text[end] != ']' && text[end] != '<') {
                end++;
            }
            std::string url = text.substr(p, end - p);
            if (url.find("http://") == 0 || url.find("https://") == 0) {
                if (std::find(rep.raw_urls.begin(), rep.raw_urls.end(), url) == rep.raw_urls.end()) {
                    rep.raw_urls.push_back(url);
                    rep.defanged_urls.push_back(DefangURL(url));

                    std::string domain = ExtractDomainFromURL(url);
                    if (!domain.empty() && !IsBenignVendorDomain(domain)) {
                        std::string defanged_dom = DefangDomain(domain);
                        if (std::find(rep.domains.begin(), rep.domains.end(), defanged_dom) == rep.domains.end()) {
                            rep.domains.push_back(defanged_dom);
                        }
                    }
                }
            }
            p = end;
        } else {
            p++;
        }
    }

    // 2. Extract IPv4 addresses: regex [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
    try {
        std::regex ip_regex(R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)");
        auto words_begin = std::sregex_iterator(text.begin(), text.end(), ip_regex);
        auto words_end = std::sregex_iterator();

        for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
            std::string ip = i->str();
            if (ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "255.255.255.255") {
                std::string def_ip = DefangIP(ip);
                if (std::find(rep.ipv4_addresses.begin(), rep.ipv4_addresses.end(), def_ip) == rep.ipv4_addresses.end()) {
                    rep.ipv4_addresses.push_back(def_ip);
                }
            }
        }
    } catch (...) {}

    return rep;
}

} // namespace BHPAI
