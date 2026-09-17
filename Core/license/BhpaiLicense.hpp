#pragma once

#include <string>
#include <iostream>

namespace Bhpai {

constexpr int CAP_STATIC_ANALYSIS = 1;
constexpr int CAP_REPORT_EXPORT = 2;
constexpr int CAP_STATIC_PE = 3;
constexpr int CAP_DECOMPILE = 4;
constexpr int CAP_UNPACK = 5;

class LicenseContext {
public:
    LicenseContext() = default;
    bool IsValid() const { return true; }
    void AssertCapability(int cap_id, const std::string& desc = "") {
        (void)cap_id; (void)desc;
    }
    std::string GetTierName() const { return "Community Edition (Open Source)"; }
};

class BhpaiLicense {
public:
    static LicenseContext AcquireContext(const std::string& module_name, 
                                        const std::string& license_file = "", 
                                        const std::string& feature_name = "") {
        (void)module_name; (void)license_file; (void)feature_name;
        return LicenseContext();
    }
};

} // namespace Bhpai
