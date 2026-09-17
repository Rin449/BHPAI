#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include "detect.hpp"
using namespace std;

static const Pattern patterns[] = {
    {"cmstp.exe", 10, 9},
    {"/au", 15, 3},
    {"[RunPreSetupCommandsSection]", 50, 28},
    {"AdvancedINF=2.5", 30, 15},
    {"[DefaultInstall]", 15, 16},
    {"CustomDestination", 10, 18},
    {"ProfileInstallPath", 20, 18},
    {"CMMGR32.EXE", 25, 11},
    {"taskkill /IM cmstp.exe", 25, 23},
    {".inf", 5, 4}
};

static const size_t PATTERN_COUNT = sizeof(patterns) / sizeof(Pattern);

static const uint8_t fsg_sig[] = {
    0x03,0xDE,0xEB,0x01,0xF8,0xB8,0x80,0x00,0x42,0x00,
    0xEB,0x02,0xCD,0x20,0x68,0x17,0xA0,0xB3,0xAB,
    0xEB,0x01,0xE8,0x59,0x0F,0xB6,0xDB,0x68,0x0B,0xA1,0xB3
};

static const char fsg_mask[] =
"xxxxxxx?xxxxxxxxxxxxxxxxxxxxxxx";

static inline bool match_fsg(const uint8_t* data) {
    for (size_t i = 0; i < sizeof(fsg_sig); ++i) {
        if (fsg_mask[i] == 'x' && data[i] != fsg_sig[i])
            return false;
    }
    return true;
}
ScanResult ScanBuffer(const vector<uint8_t>& buffer, size_t entry_point) {
    ScanResult result;
    const uint8_t* data = buffer.data();
    size_t size = buffer.size();
    for (size_t i = 0; i < size; ++i) {
        if (!result.upx && i + 4 <= size) {
            if (memcmp(data + i, "UPX!", 4) == 0) {
                result.upx = true;
            }
        }
        if (!result.wwpack) {
            if (i + 0x2a1 < size && memcmp(data + i, "\x8B\x44\x24\x04\x8B\x4C\x24\x08", 8) == 0) {
                result.wwpack = true;
                result.score += 40;
            }
        }
        if (!result.fsg && i == entry_point) {
            if (i + sizeof(fsg_sig) <= size) {
                if (match_fsg(data + i)) {
                    result.fsg = true;
                }
            }
        }
        for (size_t p = 0; p < PATTERN_COUNT; ++p) {
            const Pattern& pat = patterns[p];
            if (i + pat.len <= size) {
                if (memcmp(data + i, pat.str, pat.len) == 0) {
                    result.score += pat.score;
                }
            }
        }
    }
    return result;
}