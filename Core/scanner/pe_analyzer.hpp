#ifndef PE_ANALYZER_HPP
#define PE_ANALYZER_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <windows.h>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include "MemoryLimit.hpp"

#pragma pack(push, 1)
struct DosHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct PeHeader {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct SectionHeader {
    char     Name[8];
    union {
        uint32_t VirtualSize;
        uint32_t Misc_VirtualSize;
    };
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
#pragma pack(pop)

struct ResourceStats {
    bool     exists             = false;
    uint32_t size               = 0;

    // per-type leaf counts
    int total_resources         = 0;
    int icon_count              = 0;
    int cursor_count            = 0;
    int bitmap_count            = 0;
    int dialog_count            = 0;
    int menu_count              = 0;
    int stringtable_count       = 0;
    int accelerator_count       = 0;
    int manifest_count          = 0;
    int version_count           = 0;
    int rcdata_count            = 0;
    int other_count             = 0;

    // per-leaf entropy statistics
    double entropy_mean         = 0.0;
    double entropy_max          = 0.0;
    double entropy_std          = 0.0;

    // manifest payload (parsed from RT_MANIFEST)
    bool     manifest_present        = false;
    uint32_t manifest_size           = 0;
    double   manifest_entropy        = 0.0;
    int      dependency_count        = 0;
    // execution level: 0=none/unknown, 1=asInvoker, 2=highestAvailable, 3=requireAdministrator
    int      execution_level         = 0;
    bool     uiaccess                = false;
    bool     auto_elevate            = false;
    // requested privilege: 0=normal, 1=admin, 2=system
    int      requested_privilege     = 0;
    bool     has_dpi                 = false;
    bool     has_com                 = false;
    bool     has_dependencies        = false;
};

struct VersionInfoFeats {
    bool has_version_info           = false;
    int  company_name_length        = 0;
    int  product_name_length        = 0;
    int  description_length         = 0;
    int  original_filename_length   = 0;
    int  product_version_length     = 0;
};

struct RichHeaderEntry {
    uint16_t prod_id   = 0;   // compiler/tool ID
    uint16_t build_id  = 0;   // build number
    uint32_t count     = 0;   // usage count
};

struct RichHeaderFeats {
    bool     present        = false;
    int      entry_count    = 0;
    bool     has_vs2015     = false;  // ProdID 0x00DC-0x00EF range
    bool     has_vs2017     = false;  // ProdID 0x00F0-0x0100 range
    bool     has_vs2019     = false;  // ProdID 0x0101-0x010F range
    bool     has_vs2022     = false;  // ProdID 0x0110+ range
    bool     has_masm       = false;  // tool 0x60 (MASM)
    bool     has_cvtres     = false;  // tool 0x53 (CVTRES)
    uint32_t checksum       = 0;
    std::vector<RichHeaderEntry> entries;
};

struct FileHashes {
    std::string md5;
    std::string sha256;
    std::string fuzzy;
};

struct PeHeaderFeatures {
    // DOS
    bool     is_invalid_dos         = true;
    uint32_t e_lfanew               = 0;
    bool     e_lfanew_too_large     = false;
    bool     e_lfanew_not_aligned   = false;

    // File Header
    uint16_t machine                = 0;
    uint16_t number_of_sections     = 0;
    uint32_t time_date_stamp        = 0;
    uint16_t size_of_optional_header= 0;
    uint16_t characteristics        = 0;
    bool     is_dll                 = false;

    bool     likely_pos_scraper             = false;
    int      pos_malware_score              = 0;
    bool     has_track_pattern_strings      = false;
    bool     has_luhn_or_cc_validation      = false;
    bool     has_memory_scraping_apis       = false;
    bool     has_child_process_injection    = false;
    bool     has_mutex_persistence          = false;
    bool     has_http_post_exfil            = false;
    bool     has_base64_xor_routines        = false;
    size_t   suspicious_pos_apis_count      = 0;
    double   code_section_entropy           = 0.0;

    // Optional Header
    uint16_t magic                  = 0;
    uint8_t  major_linker_version   = 0;
    uint8_t  minor_linker_version   = 0;
    uint32_t size_of_code           = 0;
    uint32_t size_of_initialized_data = 0;
    uint32_t size_of_uninitialized_data = 0;
    uint32_t address_of_entry_point = 0;
    uint32_t base_of_code           = 0;
    uint64_t image_base             = 0;
    uint32_t section_alignment      = 0;
    uint32_t file_alignment         = 0;
    uint16_t major_os_version       = 0;
    uint16_t minor_os_version       = 0;
    uint16_t major_subsystem_version= 0;
    uint16_t minor_subsystem_version= 0;
    uint32_t size_of_image          = 0;
    uint32_t size_of_headers        = 0;
    uint32_t checksum               = 0;
    uint16_t subsystem              = 0;
    uint16_t dll_characteristics    = 0;

    // Derived flags
    bool     timestamp_zero_or_future = false;
    bool     checksum_zero            = false;
    bool     os_version_low           = false;
    bool     alignment_weird          = false;
    bool     is_gui                   = false;
    bool     is_console               = false;
    bool     aslr_enabled             = false;
    bool     nx_enabled               = false;
    bool     cfg_enabled              = false;

    // Data Directories
    uint32_t import_rva    = 0;
    uint32_t import_size   = 0;
    uint32_t export_rva    = 0;
    uint32_t export_size   = 0;
    uint32_t resource_rva  = 0;
    uint32_t resource_size = 0;
    uint32_t num_resources = 0;       // kept for backward compat
    double   resource_entropy = 0.0;  // kept for backward compat (= entropy_mean)
    uint32_t tls_rva       = 0;
    uint32_t tls_size      = 0;
    uint32_t debug_rva     = 0;
    uint32_t debug_size    = 0;
    uint32_t security_rva  = 0;   // file offset to certificate table (not an RVA)
    uint32_t security_size = 0;

    bool     has_tls       = false;
    bool     has_debug     = false;
    bool     has_signature = false;
    bool     digital_signature_valid = false;
    double   code_ratio    = 0.0;
    bool     no_imports    = false;

    uint32_t delay_import_rva  = 0;
    uint32_t delay_import_size = 0;
    bool     no_delay_imports  = true;

    // --- Extended resource features ---
    ResourceStats resource_stats;   // full per-type + per-leaf-entropy breakdown

    // --- Certificate ---
    bool     certificate_present = false;
    int      certificate_count   = 0;

    // --- Version Info ---
    VersionInfoFeats version_info;

    // --- Rich Header ---
    RichHeaderFeats rich_header;
};

struct ImportStats {
    size_t total_functions = 0;
    size_t suspicious_count = 0;
    size_t pos_specific_count = 0;
    size_t dll_count = 0;
    double imports_per_dll = 0.0;
    double dll_entropy = 0.0;
    size_t largest_import_dll = 0;
    double import_graph_density = 0.0;
    std::map<std::string, std::vector<std::string>> dll_to_functions;
    bool has_memory_scraping_apis = false;
    bool has_VirtualAllocEx = false;
    bool has_VirtualAlloc = false;
    bool has_VirtualProtect = false;
    bool has_WriteProcessMemory = false;
    bool has_ReadProcessMemory = false;
    bool has_CreateRemoteThread = false;
    bool has_NtMapViewOfSection = false;
    bool has_QueueUserAPC = false;
    bool has_WinExec = false;
    bool has_ShellExecute = false;
    bool has_LoadLibrary = false;
    bool has_GetProcAddress = false;
    bool has_InternetOpen = false;
    bool has_WinHttpOpen = false;
    bool has_CryptEncrypt = false;
    bool has_BCryptEncrypt = false;
    bool has_NtAllocateVirtualMemory = false;
    bool has_NtWriteVirtualMemory = false;
    bool has_NtProtectVirtualMemory = false;
    std::vector<std::string> imported_function_names;
    std::string imphash;
};

struct DelayImportStats {
    size_t delay_import_count = 0;
    size_t delay_import_dlls = 0;
    size_t delay_import_functions = 0;
    std::map<std::string, std::vector<std::string>> dll_to_functions;
};

struct ByteLevelFeatures {
    std::vector<double> byte_histogram;            // 256 normalized bins
    double zero_byte_ratio = 0.0;
    std::vector<double> byte_entropy_histogram;     // 16 normalized windowed entropy bins
    std::vector<double> byte_entropy_matrix;        // 256 normalized (16x16) joint byte-entropy bins
    double windowed_entropy_mean = 0.0;
    double windowed_entropy_max = 0.0;
    double windowed_entropy_min = 0.0;
    double windowed_entropy_std = 0.0;
    std::vector<double> nibble_transition_matrix;   // 256 normalized (16x16) nibble markov matrix bins
    double markov_matrix_entropy = 0.0;
};

struct ExportStats {
    size_t export_count = 0;
    size_t export_named_count = 0;
    size_t export_ordinal_only_count = 0;
    double export_name_entropy_mean = 0.0;
    double export_name_entropy_max = 0.0;
    double export_name_entropy_min = 0.0;
    double export_name_entropy_std = 0.0;
    std::string export_name_hash;
    std::vector<std::string> export_names;
};

struct StringStats {
    size_t total_strings = 0;
    size_t ascii_strings = 0;
    size_t unicode_strings = 0;
    double avg_length = 0.0;
    double median_length = 0.0;
    double avg_entropy = 0.0;
    double printable_ratio = 0.0;
    double unicode_ratio = 0.0;
};

struct InterestingStrings {
    std::vector<std::string> ips;
    std::vector<std::string> domains;
    std::vector<std::string> urls;
    std::vector<std::string> registry_paths;
    std::vector<std::string> mutexes;
    std::vector<std::string> file_paths;
    std::vector<std::string> emails;
    std::vector<std::string> crypto_constants;
};

double calc_entropy(const uint8_t* data, size_t len);
VersionInfoFeats ExtractVersionInfo(const std::string& filepath);
RichHeaderFeats  ParseRichHeader(const std::vector<uint8_t>& buffer, uint32_t e_lfanew);
FileHashes compute_hashes(const std::vector<uint8_t>& buffer);

extern bool g_safe_run;
void check_memory_limit();

bool analyze_pe(std::string filepath, const std::string& label = "unknown");
void ParseImports(LPBYTE lpBase);
DWORD RVAToOffset(const IMAGE_NT_HEADERS* nt, DWORD rva);
std::string ToLower(std::string s);
std::string MD5String(const std::string& input);

PeHeaderFeatures extract_pe_header_features(const std::vector<uint8_t>& buffer);
ImportStats GetImportStats(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats);
DelayImportStats GetDelayImportStats(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats);
size_t GetTLSCallbackCount(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats);
bool VerifyDigitalSignature(const std::wstring& filePath);
ByteLevelFeatures extract_byte_level_features(const std::vector<uint8_t>& buffer);
ExportStats GetExportStats(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats);
StringStats ComputeStringStatistics(const std::vector<std::string>& ascii_strings,
                                    const std::vector<std::string>& unicode_strings);
InterestingStrings ExtractInterestingStrings(const std::vector<std::string>& strings);
std::string ComputeImpHash(const std::map<std::string, std::vector<std::string>>& dll_to_functions);

nlohmann::json features_to_json(
    const PeHeaderFeatures& feats,
    const FileHashes& hashes,
    const std::string& filepath,
    size_t filesize,
    const ImportStats& import_stats,
    const DelayImportStats& delay_import_stats,
    size_t tls_callbacks,
    double reloc_entropy,
    size_t overlay_size,
    bool signature_valid,
    const ByteLevelFeatures& byte_feats = ByteLevelFeatures(),
    const ExportStats& export_stats = ExportStats()
);

nlohmann::json features_to_json(const PeHeaderFeatures& feats, const FileHashes& hashes, 
                                const std::string& filepath, size_t filesize);

PeHeaderFeatures extract_pe_header_features(const std::vector<uint8_t>& buffer);

void scan_for_pos_indicators(
    const std::vector<uint8_t>& buffer,
    PeHeaderFeatures& feats
    //const std::vector<SectionHeader>& sections
);

#endif