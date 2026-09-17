#include "YaraGen.hpp"
#include "StringEx.hpp"
#include "Disassembler.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <regex>

namespace {

// Helper: check if string contains substring case-insensitively
bool contains_ci(const std::string& haystack, const std::string& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](unsigned char ch1, unsigned char ch2) {
            return std::tolower(ch1) == std::tolower(ch2);
        }
    );
    return it != haystack.end();
}

// Clean string by removing non-printable/control chars for safe YARA quoting
std::string sanitize_for_yara(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= 32 && uc <= 126) {
            out += c;
        } else if (c == '\t') {
            out += ' ';
        }
    }
    return out;
}

} // anonymous namespace

bool YaraGenerator::is_printable(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (!std::isprint(uc) && c != '\r' && c != '\n' && c != '\t') {
            return false;
        }
    }
    return true;
}

std::string YaraGenerator::to_hex_string(const std::string& s) {
    std::ostringstream oss;
    for (size_t i = 0; i < s.length(); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(static_cast<unsigned char>(s[i])) & 0xFF) << " ";
    }
    std::string res = oss.str();
    if (!res.empty() && res.back() == ' ') res.pop_back();
    return res;
}

std::string YaraGenerator::escape_string(const std::string& s) {
    std::string cleaned = sanitize_for_yara(s);
    std::string escaped;
    escaped.reserve(cleaned.length() * 2);
    for (char c : cleaned) {
        if (c == '\\') escaped += "\\\\";
        else if (c == '"')  escaped += "\\\"";
        else if (c == '\n') escaped += "\\n";
        else if (c == '\r') escaped += "\\r";
        else if (c == '\t') escaped += "\\t";
        else escaped += c;
    }
    if (escaped.length() > 120) {
        escaped = escaped.substr(0, 120);
    }
    return escaped;
}

std::string YaraGenerator::normalize_string(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && (std::isspace(static_cast<unsigned char>(s[start])) || s[start] == '"' || s[start] == '\'')) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && (std::isspace(static_cast<unsigned char>(s[end - 1])) || s[end - 1] == '"' || s[end - 1] == '\'')) {
        --end;
    }
    std::string trimmed = s.substr(start, end - start);
    std::string norm;
    norm.reserve(trimmed.size());
    for (char c : trimmed) {
        norm += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (norm.rfind("http://", 0) == 0 || norm.rfind("https://", 0) == 0) {
        while (!norm.empty() && norm.back() == '/') norm.pop_back();
    }
    return norm;
}

CompilerProfile YaraGenerator::detect_compiler(const std::vector<std::string>& strings, 
                                               const ImportStats& imports, 
                                               const PeHeaderFeatures& feats) 
{
    CompilerProfile prof;
    int rust_signals = 0;
    int go_signals = 0;
    int dotnet_signals = 0;
    int mingw_signals = 0;
    int msvc_signals = 0;

    for (const auto& s : strings) {
        if (s.find("/rustc/") != std::string::npos || s.find("panicking.rs") != std::string::npos ||
            s.find("alloc::raw_vec") != std::string::npos || s.find("library\\std\\src") != std::string::npos ||
            s.find("core::fmt::Arguments") != std::string::npos) {
            rust_signals++;
        }
        if (s.find("runtime.gopanic") != std::string::npos || s.find("go.buildid") != std::string::npos ||
            s.find("Go buildinf") != std::string::npos || s.find("runtime.main") != std::string::npos) {
            go_signals++;
        }
        if (s.find("_CorExeMain") != std::string::npos || s.find("mscorlib") != std::string::npos ||
            s.find("System.Runtime") != std::string::npos) {
            dotnet_signals++;
        }
        if (s.find("__register_frame_info") != std::string::npos || s.find("libgcc") != std::string::npos ||
            s.find("mingw_init") != std::string::npos || s.find("__emutls_get_address") != std::string::npos) {
            mingw_signals++;
        }
        if (s.find("MSVCR") != std::string::npos || s.find("VCRUNTIME") != std::string::npos ||
            s.find("api-ms-win-crt") != std::string::npos) {
            msvc_signals++;
        }
    }

    if (feats.rich_header.entries.size() > 0) {
        msvc_signals += 3;
    }

    for (const auto& dll_pair : imports.dll_to_functions) {
        std::string dll_lower = dll_pair.first;
        std::transform(dll_lower.begin(), dll_lower.end(), dll_lower.begin(), [](unsigned char c) { return std::tolower(c); });
        if (dll_lower.find("mscoree.dll") != std::string::npos) dotnet_signals += 5;
        if (dll_lower.find("msvcr") != std::string::npos || dll_lower.find("vcruntime") != std::string::npos) msvc_signals += 2;
    }

    if (rust_signals >= 2) {
        prof.is_rust = true;
        prof.name = "Rust";
    } else if (go_signals >= 2) {
        prof.is_go = true;
        prof.name = "Go";
    } else if (dotnet_signals >= 2) {
        prof.is_dotnet = true;
        prof.name = ".NET";
    } else if (mingw_signals >= 2) {
        prof.is_mingw = true;
        prof.name = "MinGW/GCC";
    } else if (msvc_signals >= 2) {
        prof.is_msvc = true;
        prof.name = "MSVC";
    }

    return prof;
}

BehaviorProfile YaraGenerator::build_behavior_profile(const ImportStats& imports, const PeHeaderFeatures& feats) {
    (void)feats;
    BehaviorProfile bp;

    auto has_func = [&](const std::string& target_dll, const std::string& target_func) -> bool {
        for (const auto& [dll, funcs] : imports.dll_to_functions) {
            if (contains_ci(dll, target_dll)) {
                for (const auto& f : funcs) {
                    if (contains_ci(f, target_func)) return true;
                }
            }
        }
        return false;
    };

    // 1. Process Injection
    bool has_va = imports.has_VirtualAllocEx || has_func("kernel32", "VirtualAllocEx");
    bool has_wpm = imports.has_WriteProcessMemory || has_func("kernel32", "WriteProcessMemory");
    bool has_crt = imports.has_CreateRemoteThread || has_func("kernel32", "CreateRemoteThread");
    bool has_nt_alloc = imports.has_NtAllocateVirtualMemory || has_func("ntdll", "NtAllocateVirtualMemory");
    bool has_nt_write = imports.has_NtWriteVirtualMemory || has_func("ntdll", "NtWriteVirtualMemory");
    bool has_nt_map = imports.has_NtMapViewOfSection || has_func("ntdll", "NtMapViewOfSection");

    if (has_va && has_wpm) {
        bp.process_injection_score += 40;
        bp.injection_clauses.push_back("pe.imports(\"kernel32.dll\", \"VirtualAllocEx\") and pe.imports(\"kernel32.dll\", \"WriteProcessMemory\")");
    }
    if (has_nt_alloc && has_nt_write) {
        bp.process_injection_score += 45;
        bp.injection_clauses.push_back("pe.imports(\"ntdll.dll\", \"NtAllocateVirtualMemory\") and pe.imports(\"ntdll.dll\", \"NtWriteVirtualMemory\")");
    }
    if (has_crt) {
        bp.process_injection_score += 25;
        bp.injection_clauses.push_back("pe.imports(\"kernel32.dll\", \"CreateRemoteThread\")");
    }
    if (has_nt_map) {
        bp.process_injection_score += 20;
        bp.injection_clauses.push_back("pe.imports(\"ntdll.dll\", \"NtMapViewOfSection\")");
    }

    // 2. Process Discovery
    bool has_toolhelp = has_func("kernel32", "CreateToolhelp32Snapshot");
    bool has_p32 = has_func("kernel32", "Process32First") || has_func("kernel32", "Process32Next");
    bool has_openproc = has_func("kernel32", "OpenProcess");
    if (has_toolhelp && has_p32) {
        bp.process_discovery_score += 25;
        bp.discovery_clauses.push_back("pe.imports(\"kernel32.dll\", \"CreateToolhelp32Snapshot\") and pe.imports(\"kernel32.dll\", \"Process32First\")");
    } else if (has_openproc) {
        bp.process_discovery_score += 10;
        bp.discovery_clauses.push_back("pe.imports(\"kernel32.dll\", \"OpenProcess\")");
    }

    // 3. Credential Access
    bool has_minidump = has_func("dbghelp", "MiniDumpWriteDump");
    bool has_cryptunprotect = has_func("crypt32", "CryptUnprotectData");
    bool has_credenumerate = has_func("advapi32", "CredEnumerate");
    if (has_minidump) {
        bp.credential_access_score += 35;
        bp.credential_clauses.push_back("pe.imports(\"dbghelp.dll\", \"MiniDumpWriteDump\")");
    }
    if (has_cryptunprotect) {
        bp.credential_access_score += 25;
        bp.credential_clauses.push_back("pe.imports(\"crypt32.dll\", \"CryptUnprotectData\")");
    }
    if (has_credenumerate) {
        bp.credential_access_score += 20;
        bp.credential_clauses.push_back("pe.imports(\"advapi32.dll\", \"CredEnumerateA\") or pe.imports(\"advapi32.dll\", \"CredEnumerateW\")");
    }

    // 4. Persistence
    bool has_regset = has_func("advapi32", "RegSetValueEx");
    bool has_createsvc = has_func("advapi32", "CreateService");
    if (has_regset) {
        bp.persistence_score += 15;
        bp.persistence_clauses.push_back("pe.imports(\"advapi32.dll\", \"RegSetValueExA\") or pe.imports(\"advapi32.dll\", \"RegSetValueExW\")");
    }
    if (has_createsvc) {
        bp.persistence_score += 20;
        bp.persistence_clauses.push_back("pe.imports(\"advapi32.dll\", \"CreateServiceA\") or pe.imports(\"advapi32.dll\", \"CreateServiceW\")");
    }

    // 5. Anti-Analysis
    bool has_isdbg = has_func("kernel32", "IsDebuggerPresent");
    bool has_remotedbg = has_func("kernel32", "CheckRemoteDebuggerPresent");
    if (has_isdbg && has_remotedbg) {
        bp.anti_analysis_score += 20;
        bp.anti_analysis_clauses.push_back("pe.imports(\"kernel32.dll\", \"IsDebuggerPresent\") and pe.imports(\"kernel32.dll\", \"CheckRemoteDebuggerPresent\")");
    } else if (has_isdbg) {
        bp.anti_analysis_score += 10;
        bp.anti_analysis_clauses.push_back("pe.imports(\"kernel32.dll\", \"IsDebuggerPresent\")");
    }

    // 6. Network / C2
    bool has_inet = imports.has_InternetOpen || has_func("wininet", "InternetOpen");
    bool has_winhttp = imports.has_WinHttpOpen || has_func("winhttp", "WinHttpOpen");
    bool has_socket = has_func("ws2_32", "socket") || has_func("ws2_32", "connect");
    if (has_inet) {
        bp.network_c2_score += 15;
        bp.network_clauses.push_back("pe.imports(\"wininet.dll\", \"InternetOpenA\") or pe.imports(\"wininet.dll\", \"InternetOpenW\")");
    }
    if (has_winhttp) {
        bp.network_c2_score += 15;
        bp.network_clauses.push_back("pe.imports(\"winhttp.dll\", \"WinHttpOpen\")");
    }
    if (has_socket) {
        bp.network_c2_score += 10;
        bp.network_clauses.push_back("pe.imports(\"ws2_32.dll\", \"socket\") or pe.imports(\"ws2_32.dll\", \"connect\")");
    }

    // 7. Cryptographic routines
    if (imports.has_CryptEncrypt || imports.has_BCryptEncrypt) {
        bp.crypto_ransom_score += 15;
        bp.crypto_clauses.push_back("pe.imports(\"advapi32.dll\", \"CryptEncrypt\") or pe.imports(\"bcrypt.dll\", \"BCryptEncrypt\")");
    }

    return bp;
}

int YaraGenerator::score_candidate(const StringCandidate& c, const CompilerProfile& compiler) {
    // 1. Filter mangled C++ symbols and compiler metadata
    if (c.value.rfind("_Z", 0) == 0 || c.value.rfind("__Z", 0) == 0 ||
        c.value.rfind("__tcf_", 0) == 0 || c.value.rfind("_GLOBAL__", 0) == 0 ||
        c.value.rfind(".pdata", 0) == 0 || c.value.rfind(".xdata", 0) == 0 ||
        c.value.rfind(".rdata", 0) == 0 || c.value.rfind(".text$", 0) == 0 ||
        c.value.rfind("??_", 0) == 0 || c.value.rfind("?analyze", 0) == 0) {
        return -100;
    }

    if (c.value.find("nlohmann::json") != std::string::npos ||
        c.value.find("basic_string<") != std::string::npos ||
        c.value.find("basic_json<") != std::string::npos ||
        c.value.find("std::__cxx11") != std::string::npos ||
        c.value.find("std::vector<") != std::string::npos) {
        return -100;
    }

    // 2. Noise Filter
    static const std::vector<std::string> global_blacklist = {
        "!This program cannot be run in DOS mode",
        "Rich",
        ".rdata", ".data", ".text", ".rsrc", ".reloc",
        "KERNEL32.dll", "ADVAPI32.dll", "USER32.dll", "ntdll.dll", "WS2_32.dll",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "ExitProcess",
        "GetLastError", "CloseHandle", "Sleep",
        "invalid string position", "string too long", "vector too long",
        "bad allocation", "unknown error"
    };

    for (const auto& noise : global_blacklist) {
        if (contains_ci(c.value, noise)) return -100;
    }

    if (compiler.is_rust) {
        static const std::vector<std::string> rust_noise = {
            "panicking.rs", "Option::unwrap", "attempt to divide by zero",
            "index out of bounds", "char boundary", "slice index", "raw_vec",
            "capacity overflow", "library/std", "fmt::write", "core::result",
            "assertion failed", "called `Option::unwrap()` on a `None` value"
        };
        for (const auto& noise : rust_noise) {
            if (c.value.find(noise) != std::string::npos) return -100;
        }
    }

    if (compiler.is_go) {
        static const std::vector<std::string> go_noise = {
            "runtime/", "sync/atomic", "os/exec", "syscall/", "internal/",
            "net/http/", "math/rand/", "reflect.Value", "runtime.gopanic"
        };
        for (const auto& noise : go_noise) {
            if (c.value.find(noise) != std::string::npos) return -100;
        }
    }

    // Check for local file paths with drive letters (e.g. C:\Users\...) - low portability
    if (c.value.find(":\\Users\\") != std::string::npos || c.value.find(":\\Users/") != std::string::npos ||
        c.value.find(":\\Windows\\") != std::string::npos) {
        return -50;
    }

    int score = 0;
    switch (c.type) {
        case CandidateType::URL:           score += 30; break;
        case CandidateType::IP:            score += 25; break;
        case CandidateType::Mutex:         score += 20; break;
        case CandidateType::Registry:      score += 15; break;
        case CandidateType::RansomKeyword: score += 25; break;
        case CandidateType::Crypto:        score += 10; break;
        case CandidateType::HexPattern:    score += 15; break;
        case CandidateType::OpcodeNgram:   score += 18; break;
        case CandidateType::Domain:        score += 20; break;
        case CandidateType::SuspiciousText:score += 5;  break;
    }

    // Length bonuses
    if (c.value.size() >= 32) score += 8;
    else if (c.value.size() >= 16) score += 5;
    else if (c.value.size() < 10 && c.type != CandidateType::IP && c.type != CandidateType::Mutex) score -= 5;

    // Entropy bonuses (Sweet spot: 4.0 - 6.2 for obfuscated tokens / meaningful text)
    if (c.entropy >= 4.0 && c.entropy <= 6.2) {
        score += 4;
    } else if (c.entropy > 7.4 && !c.is_raw_hex) {
        score -= 10; // High entropy raw noise
    } else if (c.entropy < 2.5) {
        score -= 8; // Low entropy repetitive padding
    }

    // Semantic keyword bonuses
    if (c.value.find("/api/") != std::string::npos || c.value.find("gate.php") != std::string::npos ||
        c.value.find("panel") != std::string::npos || c.value.find("/upload.php") != std::string::npos) {
        score += 12;
    }

    if (contains_ci(c.value, "decrypt") || contains_ci(c.value, "ransom") || contains_ci(c.value, "bitcoin") ||
        contains_ci(c.value, ".locked") || contains_ci(c.value, "wallet") || contains_ci(c.value, "restore-my-files")) {
        score += 15;
    }

    if (c.value.find("powershell.exe") != std::string::npos || c.value.find("cmd.exe") != std::string::npos ||
        c.value.find("wscript.exe") != std::string::npos || c.value.find("rundll32.exe") != std::string::npos) {
        score += 12;
    }

    if (c.value.rfind("Global\\", 0) == 0 || c.value.rfind("Local\\", 0) == 0) {
        score += 8;
    }

    return score;
}

std::string YaraGenerator::generate_entry_point_pattern(const std::vector<uint8_t>& entry_point_bytes, bool is_64bit) {
    if (entry_point_bytes.size() < 8) return "";

    Disassembler disasm;
    if (!disasm.initialize(is_64bit)) {
        return "";
    }

    auto insts = disasm.disassemble(entry_point_bytes.data(), std::min<size_t>(entry_point_bytes.size(), 32), 0x1000, 8);
    if (insts.empty()) return "";

    // Check for standard compiler entry prologue
    // 32-bit: push ebp; mov ebp, esp; sub esp, XX
    // 64-bit: sub rsp, XX; mov ...
    bool starts_with_prologue = false;
    if (!is_64bit && insts.size() >= 2 && insts[0].mnemonic == "push" && insts[1].mnemonic == "mov") {
        starts_with_prologue = true;
    } else if (is_64bit && insts[0].mnemonic == "sub" && insts[0].bytes.size() >= 4 && insts[0].bytes[0] == 0x48) {
        starts_with_prologue = true;
    }

    std::ostringstream oss;
    size_t masked_instructions = 0;
    bool has_distinctive = false;

    for (const auto& inst : insts) {
        if (inst.bytes.empty()) continue;

        // Check if relative call or jmp
        bool is_relative_call_jmp = (inst.mnemonic == "call" || inst.mnemonic == "jmp" || inst.mnemonic.rfind("j", 0) == 0) &&
                                    (inst.bytes[0] == 0xE8 || inst.bytes[0] == 0xE9);

        // Check RIP-relative displacement
        bool is_rip_relative = false;
        if (inst.has_detail && is_64bit) {
            for (uint8_t i = 0; i < inst.x86.op_count; ++i) {
                if (inst.x86.operands[i].type == X86_OP_MEM && inst.x86.operands[i].mem.base == X86_REG_RIP) {
                    is_rip_relative = true;
                    break;
                }
            }
        }

        if (is_relative_call_jmp && inst.bytes.size() == 5) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(inst.bytes[0]) << " ?? ?? ?? ?? ";
        } else if (is_rip_relative && inst.bytes.size() >= 5) {
            for (size_t b = 0; b < inst.bytes.size() - 4; ++b) {
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(inst.bytes[b]) << " ";
            }
            oss << "?? ?? ?? ?? ";
        } else {
            for (uint8_t b : inst.bytes) {
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
            }
            if (inst.mnemonic != "push" && inst.mnemonic != "mov" && inst.mnemonic != "sub") {
                has_distinctive = true;
            }
        }

        masked_instructions++;
        if (masked_instructions >= 5 || oss.str().size() >= 48) break;
    }

    // If it's merely a standard 2-instruction prologue without distinctive pattern, reject it
    if (starts_with_prologue && !has_distinctive && masked_instructions <= 2) {
        return "";
    }

    std::string result = oss.str();
    while (!result.empty() && result.back() == ' ') result.pop_back();
    return result;
}

std::vector<std::string> YaraGenerator::generate_opcode_patterns(const std::vector<OpcodeFeature>& ngrams, size_t max_patterns) {
    std::vector<std::string> patterns;
    if (ngrams.empty()) return patterns;

    std::vector<OpcodeFeature> sorted_ngrams = ngrams;
    std::sort(sorted_ngrams.begin(), sorted_ngrams.end(), [](const OpcodeFeature& a, const OpcodeFeature& b) {
        double score_a = a.weight * (1.0 + a.near_suspicious);
        double score_b = b.weight * (1.0 + b.near_suspicious);
        return score_a > score_b;
    });

    for (const auto& feat : sorted_ngrams) {
        if (feat.weight < 1.8 && feat.near_suspicious == 0) continue;
        if (feat.signature.empty()) continue;

        // Convert signature (e.g. "push_imm_call_imm_xor_r_r") into opcode comments & metadata
        patterns.push_back(feat.signature);
        if (patterns.size() >= max_patterns) break;
    }

    return patterns;
}

RuleQualityMetrics YaraGenerator::calculate_quality_metrics(const std::vector<StringCandidate>& selected_candidates, 
                                                            const BehaviorProfile& behavior, 
                                                            const PeHeaderFeatures& feats) 
{
    RuleQualityMetrics q;
    size_t ioc_count = 0;
    size_t generic_count = 0;

    for (const auto& c : selected_candidates) {
        if (c.type == CandidateType::URL || c.type == CandidateType::IP || 
            c.type == CandidateType::Mutex || c.type == CandidateType::Registry ||
            c.type == CandidateType::RansomKeyword) {
            ioc_count++;
        } else if (c.type == CandidateType::SuspiciousText) {
            generic_count++;
        }
    }

    double total = static_cast<double>(selected_candidates.size() + 1);
    q.specificity = std::clamp(static_cast<double>(ioc_count * 2) / total, 0.0, 1.0);
    q.uniqueness = std::clamp(static_cast<double>(ioc_count + (behavior.process_injection_score > 0 ? 2 : 0)) / 4.0, 0.2, 1.0);
    q.portability = 1.0;

    // Estimate FP risk
    int behavior_count = static_cast<int>(behavior.injection_clauses.size() + behavior.discovery_clauses.size() + 
                                          behavior.credential_clauses.size() + behavior.persistence_clauses.size());

    if (ioc_count >= 2) {
        q.expected_fp_risk = 0.08;
    } else if (ioc_count == 1 && behavior_count >= 1) {
        q.expected_fp_risk = 0.15;
    } else if (behavior_count >= 2) {
        q.expected_fp_risk = 0.20;
    } else if (generic_count >= 3 && behavior_count >= 1) {
        q.expected_fp_risk = 0.35;
    } else {
        q.expected_fp_risk = 0.65;
    }

    if (feats.digital_signature_valid) {
        q.expected_fp_risk += 0.20; // Valid signed binaries have higher FP risk if targeted by heuristics
    }
    q.expected_fp_risk = std::clamp(q.expected_fp_risk, 0.0, 1.0);

    if (q.expected_fp_risk <= 0.20) {
        q.confidence = "HIGH";
    } else if (q.expected_fp_risk <= 0.45) {
        q.confidence = "MEDIUM";
    } else {
        q.confidence = "LOW";
    }

    return q;
}

RuleValidationResult YaraGenerator::validate_and_optimize_rule(std::string& rule_text, 
                                                               const std::vector<StringCandidate>& candidates, 
                                                               const BehaviorProfile& behavior) 
{
    (void)behavior;
    RuleValidationResult res;
    res.is_valid = true;

    // 1. Bracket balance check
    int brace_count = 0;
    int paren_count = 0;
    for (char ch : rule_text) {
        if (ch == '{') brace_count++;
        else if (ch == '}') brace_count--;
        else if (ch == '(') paren_count++;
        else if (ch == ')') paren_count--;
    }

    if (brace_count != 0) {
        res.is_valid = false;
        res.errors.push_back("Unbalanced braces in YARA rule.");
    }
    if (paren_count != 0) {
        res.is_valid = false;
        res.errors.push_back("Unbalanced parentheses in condition.");
    }

    // 2. Identify active string prefixes
    bool has_ioc = false;
    bool has_generic = false;
    bool has_crypto = false;
    bool has_pattern = false;

    for (const auto& c : candidates) {
        if (c.label.rfind("ioc_", 0) == 0) has_ioc = true;
        if (c.label.rfind("generic_", 0) == 0) has_generic = true;
        if (c.label.rfind("crypto_", 0) == 0) has_crypto = true;
        if (c.label.rfind("pattern_", 0) == 0 || c.label.rfind("ep_code", 0) == 0) has_pattern = true;
    }

    // 3. Condition reference safety verification:
    // If condition references $ioc_* but has_ioc is false, warn or flag
    if (rule_text.find("($ioc_*)") != std::string::npos && !has_ioc) {
        res.warnings.push_back("Condition references $ioc_* but no IOC strings were generated.");
    }
    if (rule_text.find("($generic_*)") != std::string::npos && !has_generic) {
        res.warnings.push_back("Condition references $generic_* but no generic strings were generated.");
    }
    if (rule_text.find("($crypto_*)") != std::string::npos && !has_crypto) {
        res.warnings.push_back("Condition references $crypto_* but no crypto strings were generated.");
    }
    if (rule_text.find("$ep_code") != std::string::npos && !has_pattern) {
        res.warnings.push_back("Condition references $ep_code but no pattern/ep_code was generated.");
    }

    return res;
}

std::string YaraGenerator::generate_strings_section(const std::vector<StringCandidate>& selected_candidates,
                                                     const std::vector<std::string>& opcode_patterns,
                                                     const std::string& ep_pattern,
                                                     const std::string& packer_name,
                                                     const PeHeaderFeatures& feats,
                                                     const ImportStats& imports) 
{
    std::ostringstream oss;
    oss << "    strings:\n";

    for (const auto& c : selected_candidates) {
        if (c.is_raw_hex) {
            oss << "        $" << c.label << " = { " << c.value << " }\n";
        } else {
            oss << "        $" << c.label << " = \"" << escape_string(c.value) << "\" ascii wide xor(0x01-0x20)\n";
        }
    }

    if (!ep_pattern.empty()) {
        oss << "        $ep_code = { " << ep_pattern << " }\n";
    }

    // Optional regex signatures for POS card scraping
    if (feats.likely_pos_scraper || imports.pos_specific_count > 0) {
        oss << "        $pos_track1 = /((4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14}))/ ascii wide\n";
        oss << "        $pos_track2 = /=[0-9]{14,20}/ ascii wide\n";
    }

    // Opcode pattern metadata comments
    if (!opcode_patterns.empty()) {
        for (size_t i = 0; i < opcode_patterns.size(); ++i) {
            oss << "        // opcode_pattern_" << i << ": " << opcode_patterns[i] << "\n";
        }
    }

    if (!packer_name.empty()) {
        oss << "        // packer_signature: " << packer_name << "\n";
    }

    return oss.str();
}

std::string YaraGenerator::generate_condition(const PeHeaderFeatures& feats, 
                                               const ImportStats& imports, 
                                               const std::vector<StringCandidate>& selected_candidates,
                                               const BehaviorProfile& behavior,
                                               const std::string& ep_pattern,
                                               const std::vector<std::string>& opcode_patterns,
                                               const std::string& packer_name) 
{
    (void)opcode_patterns;
    std::ostringstream oss;
    oss << "    condition:\n";
    oss << "        uint16(0) == 0x5A4D and\n";
    oss << "        uint32(0x3C) < filesize - 4 and\n";
    oss << "        uint32(uint32(0x3C)) == 0x4550 and\n";
    oss << "        filesize < 52428800 and\n"; // 50MB adaptive limit
    oss << "        (\n";

    size_t ioc_count = 0;
    size_t generic_count = 0;
    size_t crypto_count = 0;
    for (const auto& c : selected_candidates) {
        if (c.label.rfind("ioc_", 0) == 0) ioc_count++;
        else if (c.label.rfind("generic_", 0) == 0) generic_count++;
        else if (c.label.rfind("crypto_", 0) == 0) crypto_count++;
    }

    std::vector<std::string> clauses;

    // Clause 1: High-fidelity IOC match
    if (ioc_count >= 2) {
        clauses.push_back("2 of ($ioc_*)");
    } else if (ioc_count == 1) {
        clauses.push_back("1 of ($ioc_*)");
    }

    // Clause 2: Behavior clauses paired with generic text or structural traits
    if (!behavior.injection_clauses.empty()) {
        std::string inj_clause = "(" + behavior.injection_clauses[0] + ")";
        if (generic_count >= 2) {
            clauses.push_back(inj_clause + " and 2 of ($generic_*)");
        } else if (generic_count == 1) {
            clauses.push_back(inj_clause + " and 1 of ($generic_*)");
        } else {
            clauses.push_back(inj_clause);
        }
    }

    if (!behavior.discovery_clauses.empty() && !behavior.injection_clauses.empty()) {
        clauses.push_back("(" + behavior.discovery_clauses[0] + " and " + behavior.injection_clauses[0] + ")");
    }

    if (!behavior.credential_clauses.empty()) {
        clauses.push_back("(" + behavior.credential_clauses[0] + ")");
    }

    // Clause 3: Entry point code match
    if (!ep_pattern.empty()) {
        if (generic_count >= 1) {
            clauses.push_back("$ep_code and 1 of ($generic_*)");
        } else {
            clauses.push_back("$ep_code and pe.entry_point_raw > 0");
        }
    }

    // Clause 4: High Section Entropy + Generic
    if (feats.code_section_entropy > 7.2) {
        if (generic_count >= 2) {
            clauses.push_back("for any i in (0..pe.number_of_sections - 1) : (pe.sections[i].entropy > 7.2) and 2 of ($generic_*)");
        } else if (crypto_count >= 1) {
            clauses.push_back("for any i in (0..pe.number_of_sections - 1) : (pe.sections[i].entropy > 7.2) and 1 of ($crypto_*)");
        }
    }

    // Clause 5: Packer structural verification
    if (packer_name == "upx") {
        if (ioc_count >= 1) {
            clauses.push_back("(for any i in (0..pe.number_of_sections - 1) : (pe.sections[i].name == \".UPX0\" or pe.sections[i].name == \"UPX0\")) and 1 of ($ioc_*)");
        } else if (generic_count >= 2) {
            clauses.push_back("(for any i in (0..pe.number_of_sections - 1) : (pe.sections[i].name == \".UPX0\" or pe.sections[i].name == \"UPX0\")) and 2 of ($generic_*)");
        }
    }

    // Clause 6: POS Scraper patterns
    if (feats.likely_pos_scraper || imports.pos_specific_count > 0) {
        clauses.push_back("1 of ($pos_track*)");
    }

    // Fallback if no specific clauses formed
    if (clauses.empty()) {
        if (generic_count >= 3) {
            clauses.push_back("3 of ($generic_*) and pe.number_of_sections >= 3");
        } else if (generic_count >= 1) {
            clauses.push_back("1 of ($generic_*) and pe.number_of_sections >= 3");
        } else {
            clauses.push_back("pe.number_of_sections >= 4 and pe.is_32bit()");
        }
    }

    for (size_t i = 0; i < clauses.size(); ++i) {
        oss << "            " << clauses[i];
        if (i + 1 < clauses.size()) {
            oss << " or\n";
        }
    }

    oss << "\n        )\n";
    return oss.str();
}

YaraRule YaraGenerator::generate(const std::string& filepath, 
                                  const PeHeaderFeatures& feats, 
                                  const ImportStats& imports, 
                                  const std::vector<OpcodeFeature>& ngrams, 
                                  const std::vector<std::string>& strings, 
                                  const InterestingStrings& interesting_strings,
                                  const std::vector<uint8_t>& entry_point_bytes,
                                  const FileHashes& hashes,
                                  const std::string& packer_name) 
{
    YaraRule rule;
    rule.name = "malware_heuristic_" + hashes.md5.substr(0, 16);
    rule.description = "Auto-generated refined behavioral heuristic rule for " + filepath;
    rule.tags = {"malware", "pe"};

    // 1. Detect Compiler Profile
    rule.compiler = detect_compiler(strings, imports, feats);
    if (!rule.compiler.name.empty() && rule.compiler.name != "Generic/Unknown") {
        rule.tags.push_back(rule.compiler.is_rust ? "rust" : (rule.compiler.is_go ? "go" : (rule.compiler.is_dotnet ? "dotnet" : "msvc")));
    }

    // 2. Build Behavior Profile
    rule.behavior = build_behavior_profile(imports, feats);
    if (rule.behavior.process_injection_score > 0) rule.tags.push_back("injection");
    if (rule.behavior.credential_access_score > 0) rule.tags.push_back("credential_theft");
    if (rule.behavior.persistence_score > 0) rule.tags.push_back("persistence");
    if (rule.behavior.anti_analysis_score > 0) rule.tags.push_back("anti_analysis");
    if (feats.has_tls) rule.tags.push_back("has_tls");
    if (feats.likely_pos_scraper) rule.tags.push_back("pos_scraper");

    // 3. Calculate Heuristic Malware Score (Behavioral & Structural, NOT compiler penalty)
    int score = 0;
    score += rule.behavior.process_injection_score;
    score += rule.behavior.credential_access_score;
    score += rule.behavior.persistence_score;
    score += rule.behavior.anti_analysis_score;
    score += rule.behavior.network_c2_score;
    score += rule.behavior.crypto_ransom_score;

    if (feats.has_tls) score += 10;
    if (feats.code_section_entropy > 7.4) score += 20;
    if (feats.code_ratio > 0.0 && feats.code_ratio < 0.10) score += 15;
    if (feats.has_signature) score -= 35;
    if (feats.digital_signature_valid) score -= 25;
    if (!packer_name.empty()) score += 10;

    rule.score = std::clamp(score, 0, 100);

    // 4. Phase 1: Candidate Gathering & Deduplication
    std::unordered_set<std::string> seen_keys;
    std::vector<StringCandidate> candidates;
    candidates.reserve(strings.size() + 64);

    auto add_candidate_dedup = [&](const std::string& val, CandidateType type, bool is_raw_hex = false) {
        if (val.size() < 4 || val.size() > 512) return;

        // Skip mangled compiler symbols & section headers
        if (val.rfind("_Z", 0) == 0 || val.rfind("__Z", 0) == 0 ||
            val.rfind("__tcf_", 0) == 0 || val.rfind("_GLOBAL__", 0) == 0 ||
            val.rfind(".pdata", 0) == 0 || val.rfind(".xdata", 0) == 0 ||
            val.rfind(".rdata", 0) == 0 || val.rfind(".text$", 0) == 0 ||
            val.find(".weak.") != std::string::npos || val.find(".refptr.") != std::string::npos ||
            val.rfind("??_", 0) == 0 || val.rfind("?analyze", 0) == 0) {
            return;
        }

        std::string key = normalize_string(val);
        if (key.empty()) return;
        // Truncate key to 80 chars for dedup so identical prefixes aren't emitted as duplicates
        std::string dedup_key = (key.size() > 80) ? key.substr(0, 80) : key;
        if (!seen_keys.insert(dedup_key).second) return; // Deduplicated!

        StringCandidate cand;
        cand.value = val;
        cand.normalized_key = key;
        cand.type = type;
        cand.is_raw_hex = is_raw_hex;
        cand.entropy = calc_entropy(reinterpret_cast<const uint8_t*>(val.data()), val.size());
        candidates.push_back(cand);
    };

    // Extract from strings
    for (const auto& s : strings) {
        if (candidates.size() >= 5000) break; // High safety ceiling
        if (s.size() < 6) continue;

        if (s.rfind("http://", 0) == 0 || s.rfind("https://", 0) == 0) {
            add_candidate_dedup(s, CandidateType::URL);
        } else if (s.find("\\Registry\\") != std::string::npos || s.find("\\Software\\") != std::string::npos || s.find("HKEY_") != std::string::npos) {
            add_candidate_dedup(s, CandidateType::Registry);
        } else if (s.rfind("Global\\", 0) == 0 || s.rfind("Local\\", 0) == 0 || s.find("Mutex") != std::string::npos) {
            add_candidate_dedup(s, CandidateType::Mutex);
        } else if (contains_ci(s, "decrypt") || contains_ci(s, "ransom") || contains_ci(s, "bitcoin") || contains_ci(s, ".locked") || contains_ci(s, "restore-my-files")) {
            add_candidate_dedup(s, CandidateType::RansomKeyword);
        } else if (contains_ci(s, "base64") || contains_ci(s, "aes") || contains_ci(s, "sha256") || contains_ci(s, "crypt")) {
            add_candidate_dedup(s, CandidateType::Crypto);
        } else if (looks_like_text(s)) {
            add_candidate_dedup(s, CandidateType::SuspiciousText);
        }
    }

    // Extract from interesting_strings
    for (const auto& u : interesting_strings.urls) add_candidate_dedup(u, CandidateType::URL);
    for (const auto& ip : interesting_strings.ips) add_candidate_dedup(ip, CandidateType::IP);
    for (const auto& d : interesting_strings.domains) add_candidate_dedup(d, CandidateType::Domain);
    for (const auto& m : interesting_strings.mutexes) add_candidate_dedup(m, CandidateType::Mutex);
    for (const auto& r : interesting_strings.registry_paths) add_candidate_dedup(r, CandidateType::Registry);
    for (const auto& c : interesting_strings.crypto_constants) add_candidate_dedup(c, CandidateType::Crypto);

    // 5. Phase 2: Scoring Candidates
    std::vector<StringCandidate> scored_candidates;
    scored_candidates.reserve(candidates.size());

    for (auto& cand : candidates) {
        cand.relevance_score = score_candidate(cand, rule.compiler);
        if (cand.relevance_score <= 0) continue; // Filter out noise / non-positive

        if (cand.relevance_score >= 30) cand.strength = SignalStrength::Strong;
        else if (cand.relevance_score >= 15) cand.strength = SignalStrength::Medium;
        else cand.strength = SignalStrength::Weak;

        scored_candidates.push_back(cand);
    }

    // 6. Phase 3: Sorting Candidates
    std::sort(scored_candidates.begin(), scored_candidates.end(), [](const StringCandidate& a, const StringCandidate& b) {
        if (a.relevance_score != b.relevance_score) return a.relevance_score > b.relevance_score;
        // Secondary: proximity of entropy to 5.0
        double dist_a = std::abs(a.entropy - 5.0);
        double dist_b = std::abs(b.entropy - 5.0);
        if (dist_a != dist_b) return dist_a < dist_b;
        return a.value.size() > b.value.size();
    });

    // 7. Phase 4: Stratified Selection (Top N with quota)
    std::vector<StringCandidate> selected;
    size_t ioc_count = 0;
    size_t crypto_count = 0;
    size_t generic_count = 0;

    for (auto& cand : scored_candidates) {
        if (cand.type == CandidateType::URL || cand.type == CandidateType::IP || 
            cand.type == CandidateType::Mutex || cand.type == CandidateType::Registry ||
            cand.type == CandidateType::RansomKeyword || cand.type == CandidateType::Domain) {
            if (ioc_count < 8) {
                cand.label = "ioc_" + std::to_string(ioc_count++);
                selected.push_back(cand);
            }
        } else if (cand.type == CandidateType::Crypto || cand.type == CandidateType::HexPattern) {
            if (crypto_count < 4) {
                cand.label = "crypto_" + std::to_string(crypto_count++);
                selected.push_back(cand);
            }
        } else {
            if (generic_count < 6) {
                cand.label = "generic_" + std::to_string(generic_count++);
                selected.push_back(cand);
            }
        }
        if (selected.size() >= 18) break;
    }

    // 8. Opcode N-grams & Entry Point Signatures
    bool is_64bit = (feats.magic == 0x20B);
    std::string ep_pattern = generate_entry_point_pattern(entry_point_bytes, is_64bit);
    std::vector<std::string> opcode_patterns = generate_opcode_patterns(ngrams, 3);

    // 9. Calculate Quality Metrics
    rule.quality = calculate_quality_metrics(selected, rule.behavior, feats);

    // 10. Synthesize Rule Text
    std::ostringstream oss;
    oss << "import \"pe\"\n";
    oss << "rule " << rule.name;
    if (!rule.tags.empty()) {
        oss << " : ";
        for (size_t i = 0; i < rule.tags.size(); ++i) {
            oss << rule.tags[i] << (i == rule.tags.size() - 1 ? "" : " ");
        }
    }
    oss << "\n{\n";
    oss << "    meta:\n";
    oss << "        description = \"" << rule.description << "\"\n";
    oss << "        author = \"" << rule.author << "\"\n";
    oss << "        calculated_malware_score = " << rule.score << "\n";
    oss << "        threat_level = \"" << (rule.score >= 70 ? "HIGH" : (rule.score >= 40 ? "MEDIUM" : "LOW")) << "\"\n";
    oss << "        compiler_profile = \"" << rule.compiler.name << "\"\n";
    oss << "        quality_specificity = \"" << std::fixed << std::setprecision(2) << rule.quality.specificity << "\"\n";
    oss << "        expected_fp_risk = \"" << (rule.quality.expected_fp_risk <= 0.25 ? "LOW" : (rule.quality.expected_fp_risk <= 0.5 ? "MEDIUM" : "HIGH")) << "\"\n";
    oss << "        confidence = \"" << rule.quality.confidence << "\"\n";
    oss << "        md5 = \"" << hashes.md5 << "\"\n";
    oss << "\n";

    oss << generate_strings_section(selected, opcode_patterns, ep_pattern, packer_name, feats, imports);
    oss << "\n";
    oss << generate_condition(feats, imports, selected, rule.behavior, ep_pattern, opcode_patterns, packer_name);
    oss << "}\n";

    rule.rule_text = oss.str();

    // 11. Validation and Self-Optimization Loop
    rule.validation = validate_and_optimize_rule(rule.rule_text, selected, rule.behavior);

    return rule;
}

std::string YaraGenerator::generate_rule_string(const YaraRule& rule) {
    return rule.rule_text;
}