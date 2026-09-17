#define NOMINMAX
#include <windows.h>

#include "pe_analyzer.hpp"

#include <wintrust.h>
#include <softpub.h>
#include <set>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cctype>
#include <string>
#include <cmath>
#include <numeric>
#include <regex>

#if defined(_MSC_VER)
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "version.lib")
#endif

#ifndef IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#endif

#if !defined(__MINGW32__) && !defined(__MINGW64__)
typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
    DWORD AllAttributes;
    DWORD DllNameRVA;
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;
    DWORD ImportNameTableRVA;
    DWORD BoundImportAddressTableRVA;
    DWORD UnloadInformationTableRVA;
    DWORD TimeDateStamp;
} IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;
#endif

static std::string read_cstring_at(const std::vector<uint8_t>& buffer, size_t offset, size_t max_len = 256) {
    if (offset >= buffer.size()) return {};
    std::string s;
    for (size_t i = 0; i < max_len && offset + i < buffer.size(); ++i) {
        char c = static_cast<char>(buffer[offset + i]);
        if (c == '\0') break;
        s += c;
    }
    return s;
}

[[maybe_unused]] static void finalize_import_graph_metrics(ImportStats& stats) {
    stats.dll_count = stats.dll_to_functions.size();
    if (stats.dll_count == 0) return;

    std::vector<size_t> per_dll_counts;
    per_dll_counts.reserve(stats.dll_count);
    for (const auto& [dll, funcs] : stats.dll_to_functions) {
        (void)dll;
        per_dll_counts.push_back(funcs.size());
    }

    double sum = std::accumulate(per_dll_counts.begin(), per_dll_counts.end(), 0.0);
    stats.imports_per_dll = sum / static_cast<double>(stats.dll_count);

    auto max_it = std::max_element(per_dll_counts.begin(), per_dll_counts.end());
    stats.largest_import_dll = (max_it != per_dll_counts.end()) ? *max_it : 0;

    stats.dll_entropy = 0.0;
    if (stats.total_functions > 0) {
        for (size_t c : per_dll_counts) {
            double p = static_cast<double>(c) / static_cast<double>(stats.total_functions);
            if (p > 0.0) {
                stats.dll_entropy -= p * std::log2(p);
            }
        }
    }

    std::set<std::string> unique_functions(
        stats.imported_function_names.begin(), stats.imported_function_names.end());
    if (!unique_functions.empty()) {
        stats.import_graph_density =
            static_cast<double>(stats.total_functions) /
            (static_cast<double>(stats.dll_count) * static_cast<double>(unique_functions.size()));
    }
}

[[maybe_unused]] static nlohmann::json import_graph_to_json(const std::map<std::string, std::vector<std::string>>& graph) {
    nlohmann::json j = nlohmann::json::object();
    for (const auto& [dll, funcs] : graph) {
        j[dll] = funcs;
    }
    return j;
}

[[maybe_unused]] static bool parse_import_thunks(
    const std::vector<uint8_t>& buffer,
    const IMAGE_NT_HEADERS* nt,
    DWORD thunk_rva,
    const std::function<void(const std::string&)>& on_function)
{
    if (thunk_rva == 0) return false;

    DWORD thunk_off = RVAToOffset(nt, thunk_rva);
    if (thunk_off == 0 || thunk_off + 8 > buffer.size()) return false;

    const size_t thunk_size = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);

    size_t cursor = thunk_off;
    while (cursor + thunk_size <= buffer.size()) {
        ULONGLONG address_of_data = 0;
        if (thunk_size == sizeof(IMAGE_THUNK_DATA64)) {
            auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(buffer.data() + cursor);
            address_of_data = thunk->u1.AddressOfData;
            if (address_of_data == 0) break;
            if (address_of_data & IMAGE_ORDINAL_FLAG64) {
                cursor += thunk_size;
                continue;
            }
        } else {
            auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA32*>(buffer.data() + cursor);
            address_of_data = thunk->u1.AddressOfData;
            if (address_of_data == 0) break;
            if (address_of_data & IMAGE_ORDINAL_FLAG32) {
                cursor += thunk_size;
                continue;
            }
        }

        DWORD name_off = RVAToOffset(nt, static_cast<DWORD>(address_of_data) + 2);
        if (name_off != 0 && name_off + 64 <= buffer.size()) {
            std::string func_name = read_cstring_at(buffer, name_off);
            if (!func_name.empty()) {
                on_function(func_name);
            }
        }
        cursor += thunk_size;
    }
    return true;
}

static const std::set<std::string> suspicious_apis = {
    "CreateRemoteThread",      "WriteProcessMemory",     "VirtualAllocEx",
    "NtCreateSection",         "NtMapViewOfSection",     "ZwCreateSection",
    "LoadLibraryA",            "GetProcAddress",         "VirtualProtect",
    "IsDebuggerPresent",       "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess","ZwQueryInformationProcess",
    "HeapCreate",              "RtlMoveMemory",           "memcpy", "memmove",
    "VirtualAlloc",            "HeapAlloc",

    "ReadProcessMemory",       "CreateToolhelp32Snapshot","Process32First",
    "Process32Next",           "EnumProcesses",           "OpenProcess",
    "DuplicateHandle",         "GetLastInputInfo",

    "InternetOpenA",           "InternetConnectA",        "HttpOpenRequestA",
    "HttpSendRequestA",

    "RegNotifyChangeKeyValue", "RegSetValueExA",          "CreateMutexA",
    "RegSetValueExA",         "RegCreateKeyExA",         "RegOpenKeyExA"
};

static const uint8_t* my_memmem(
    const uint8_t* haystack,
    size_t haystack_len,
    const uint8_t* needle,
    size_t needle_len)
{
    if (!needle || needle_len == 0) {
        return haystack;
    }
    if (needle_len > haystack_len) {
        return nullptr;
    }

    auto first = haystack;
    auto last  = haystack + haystack_len;

    auto it = std::search(first, last, needle, needle + needle_len);
    return (it != last) ? it : nullptr;
}

// ─────────────────────────────────────────────────────────
// Manifest XML helper: count occurrences of a substring
static int CountXmlOccurrences(const std::string& xml, const std::string& tag) {
    int count = 0;
    size_t pos = 0;
    while ((pos = xml.find(tag, pos)) != std::string::npos) {
        ++count;
        pos += tag.size();
    }
    return count;
}

static std::string XmlAttrValue(const std::string& xml, const std::string& attr) {
    std::string needle = attr + "=\"";
    size_t pos = xml.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    size_t end = xml.find('"', pos);
    if (end == std::string::npos) return {};
    return xml.substr(pos, end - pos);
}

static bool XmlAttrIsTrue(const std::string& xml, const std::string& attr) {
    std::string val = XmlAttrValue(xml, attr);
    for (char& c : val) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return val == "true" || val == "1";
}

static void ParseManifestXml(const std::string& xml, ResourceStats& stats) {
    stats.dependency_count = CountXmlOccurrences(xml, "<dependency");
    stats.has_dependencies = stats.dependency_count > 0;

    stats.has_dpi = (xml.find("dpiAware") != std::string::npos ||
                     xml.find("dpiAwareness") != std::string::npos);
    stats.has_com = (xml.find("<com:") != std::string::npos ||
                     xml.find("comInterface") != std::string::npos ||
                     xml.find("com:Interface") != std::string::npos);

    stats.uiaccess = XmlAttrIsTrue(xml, "uiAccess");
    stats.auto_elevate = XmlAttrIsTrue(xml, "autoElevate") ||
                         xml.find("<autoElevate>true</autoElevate>") != std::string::npos;

    std::string level = XmlAttrValue(xml, "level");
    for (char& c : level) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (level == "asinvoker") {
        stats.execution_level = 1;
        stats.requested_privilege = 0;
    } else if (level == "highestavailable") {
        stats.execution_level = 2;
        stats.requested_privilege = 1;
    } else if (level == "requireadministrator") {
        stats.execution_level = 3;
        stats.requested_privilege = 1;
    } else if (level == "system") {
        stats.execution_level = 0;
        stats.requested_privilege = 2;
    } else if (xml.find("requestedExecutionLevel") != std::string::npos) {
        stats.execution_level = 1;
        stats.requested_privilege = 0;
    }
}

// ─────────────────────────────────────────────────────────
// Count WIN_CERTIFICATE entries in the security directory
static int CountCertificates(
    const std::vector<uint8_t>& buffer,
    uint32_t security_offset,
    uint32_t security_size)
{
    if (security_offset == 0 || security_size < 8) return 0;
    if (static_cast<uint64_t>(security_offset) + security_size > buffer.size()) return 0;

    int count = 0;
    uint32_t offset = security_offset;
    const uint32_t end = security_offset + security_size;

    while (offset + 8 <= end && offset + 8 <= buffer.size()) {
        uint32_t dwLength = 0;
        std::memcpy(&dwLength, buffer.data() + offset, sizeof(dwLength));
        if (dwLength < 8 || offset + dwLength > end) break;
        ++count;
        uint32_t aligned = (dwLength + 7u) & ~7u;
        if (aligned == 0) break;
        offset += aligned;
    }
    return count;
}

// ─────────────────────────────────────────────────────────
// Resource tree walker
// depth=0 → Type node; depth=1 → Name node; depth=2 → Language/leaf node
static void WalkResourceTree(
    const uint8_t*  rsrc_base,
    size_t          rsrc_size,
    uint32_t        dir_offset,
    int             depth,
    int             type_id,          // RT_* at depth 0
    std::set<uint32_t>& visited,
    ResourceStats&  stats,
    std::vector<double>& leaf_entropies,
    const uint8_t*  file_base,        // full file buffer start
    size_t          file_size,
    uint32_t        rsrc_section_rva, // VirtualAddress of .rsrc section
    uint32_t        rsrc_raw_start)   // PointerToRawData of .rsrc section
{
    if (depth > 4) return;
    if (visited.count(dir_offset)) return;
    visited.insert(dir_offset);

    if (dir_offset + sizeof(IMAGE_RESOURCE_DIRECTORY) > rsrc_size) return;

    auto* dir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(rsrc_base + dir_offset);
    uint16_t total = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    uint32_t entries_off = dir_offset + sizeof(IMAGE_RESOURCE_DIRECTORY);

    if (entries_off + total * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > rsrc_size) return;
    auto* entries = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(rsrc_base + entries_off);

    for (uint16_t i = 0; i < total; ++i) {
        const auto& entry = entries[i];

        if (entry.OffsetToData & 0x80000000u) {
            // subdirectory
            uint32_t sub_off = entry.OffsetToData & 0x7FFFFFFFu;
            int child_type = type_id;
            if (depth == 0) {
                // at root level the ID is the RT_ type
                child_type = (entry.NameIsString == 0) ? static_cast<int>(entry.Id) : 0;
            }
            WalkResourceTree(rsrc_base, rsrc_size, sub_off, depth + 1,
                             child_type, visited, stats,
                             leaf_entropies, file_base, file_size,
                             rsrc_section_rva, rsrc_raw_start);
        } else {
            // leaf data entry
            stats.total_resources++;

            // classify by type_id (which was captured at depth 0)
            switch (type_id) {
                case  1: stats.cursor_count++;      break;  // RT_CURSOR
                case  2: stats.bitmap_count++;      break;  // RT_BITMAP
                case  3: stats.icon_count++;        break;  // RT_ICON
                case  4: stats.menu_count++;        break;  // RT_MENU
                case  5: stats.dialog_count++;      break;  // RT_DIALOG
                case  6: stats.stringtable_count++; break;  // RT_STRING
                case  9: stats.accelerator_count++; break;  // RT_ACCELERATOR
                case 10: stats.rcdata_count++;      break;  // RT_RCDATA
                case 16: stats.version_count++;     break;  // RT_VERSION
                case 24: stats.manifest_count++;    break;  // RT_MANIFEST
                default: stats.other_count++;       break;
            }

            // Read IMAGE_RESOURCE_DATA_ENTRY at entry.OffsetToData
            uint32_t data_entry_off = entry.OffsetToData;
            if (data_entry_off + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > rsrc_size) continue;

            auto* rde = reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(rsrc_base + data_entry_off);
            // RDE.OffsetToData is an RVA into the PE
            uint32_t rva = rde->OffsetToData;
            uint32_t leaf_size = rde->Size;

            // Convert RVA → file offset via .rsrc section mapping
            if (rva < rsrc_section_rva) continue;
            uint32_t off_in_section = rva - rsrc_section_rva;
            uint32_t file_off = rsrc_raw_start + off_in_section;

            if (leaf_size == 0 || file_off >= file_size ||
                static_cast<uint64_t>(file_off) + leaf_size > file_size) continue;

            const uint8_t* leaf_data = file_base + file_off;
            double ent = calc_entropy(leaf_data, leaf_size);
            leaf_entropies.push_back(ent);

            // Capture manifest bytes for XML parsing
            if (type_id == 24 && !stats.manifest_present) {
                stats.manifest_present = true;
                stats.manifest_size    = leaf_size;
                stats.manifest_entropy = ent;

                // Simple XML text search – no heavy parser needed
                std::string xml(reinterpret_cast<const char*>(leaf_data),
                                std::min<uint32_t>(leaf_size, 8192));
                ParseManifestXml(xml, stats);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────
static ResourceStats ComputeResourceStats(
    const std::vector<uint8_t>& buffer,
    const IMAGE_NT_HEADERS* nt,
    uint32_t resource_rva)
{
    ResourceStats stats;
    if (resource_rva == 0) return stats;

    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (resource_rva >= section->VirtualAddress &&
            resource_rva <  section->VirtualAddress + section->Misc.VirtualSize) {

            uint32_t off_in_sec = resource_rva - section->VirtualAddress;
            uint32_t raw_start  = section->PointerToRawData + off_in_sec;
            if (raw_start >= buffer.size()) return stats;

            size_t rsrc_size = std::min(
                static_cast<size_t>(section->SizeOfRawData - off_in_sec),
                buffer.size() - static_cast<size_t>(raw_start));
            if (rsrc_size == 0) return stats;

            stats.exists = true;
            stats.size   = static_cast<uint32_t>(rsrc_size);

            const uint8_t* rsrc_base = buffer.data() + raw_start;
            std::set<uint32_t> visited;
            std::vector<double> leaf_entropies;

            WalkResourceTree(
                rsrc_base, rsrc_size,
                0, 0, 0,
                visited, stats, leaf_entropies,
                buffer.data(), buffer.size(),
                section->VirtualAddress,
                section->PointerToRawData);

            // Compute per-leaf entropy statistics
            if (!leaf_entropies.empty()) {
                double sum = std::accumulate(leaf_entropies.begin(), leaf_entropies.end(), 0.0);
                stats.entropy_mean = sum / leaf_entropies.size();
                stats.entropy_max  = *std::max_element(leaf_entropies.begin(), leaf_entropies.end());

                double sq_sum = 0.0;
                for (double e : leaf_entropies)
                    sq_sum += (e - stats.entropy_mean) * (e - stats.entropy_mean);
                stats.entropy_std = (leaf_entropies.size() > 1)
                    ? std::sqrt(sq_sum / (leaf_entropies.size() - 1))
                    : 0.0;
            }

            return stats;
        }
    }
    return stats;
}


PeHeaderFeatures extract_pe_header_features(const std::vector<uint8_t>& buffer) {
    PeHeaderFeatures feats{};

    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
        return feats;
    }

    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, buffer.data(), sizeof(dos));

    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        feats.is_invalid_dos = true;
        return feats;
    }

    feats.is_invalid_dos = false;
    feats.e_lfanew = dos.e_lfanew;

    if (feats.e_lfanew < 64 || feats.e_lfanew > buffer.size() - 4 || feats.e_lfanew % 8 != 0) {
        feats.e_lfanew_not_aligned = true;
    }
    feats.e_lfanew_too_large = (feats.e_lfanew > 0x2000);

    if (feats.e_lfanew + sizeof(IMAGE_NT_HEADERS32) > buffer.size()) {
        return feats;
    }

    IMAGE_NT_HEADERS32 nt32{};
    std::memcpy(&nt32, buffer.data() + feats.e_lfanew, sizeof(IMAGE_NT_HEADERS32));

    if (nt32.Signature != IMAGE_NT_SIGNATURE) {
        return feats;
    }

    bool is_64bit = (nt32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    feats.machine                 = nt32.FileHeader.Machine;
    feats.number_of_sections      = nt32.FileHeader.NumberOfSections;
    feats.time_date_stamp         = nt32.FileHeader.TimeDateStamp;
    feats.size_of_optional_header = nt32.FileHeader.SizeOfOptionalHeader;
    feats.characteristics         = nt32.FileHeader.Characteristics;
    feats.is_dll                  = (feats.characteristics & IMAGE_FILE_DLL) != 0;

    size_t nt_size = is_64bit ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
    if (feats.e_lfanew + nt_size > buffer.size()) {
        return feats;
    }

    IMAGE_NT_HEADERS64 nt64{};
    if (is_64bit) {
        std::memcpy(&nt64, buffer.data() + feats.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
    }

    if (is_64bit) {
        const auto& opt = nt64.OptionalHeader;
        feats.magic                  = opt.Magic;
        feats.image_base             = opt.ImageBase;
        feats.section_alignment      = opt.SectionAlignment;
        feats.file_alignment         = opt.FileAlignment;
        feats.major_linker_version   = opt.MajorLinkerVersion;
        feats.minor_linker_version   = opt.MinorLinkerVersion;
        feats.major_os_version       = opt.MajorOperatingSystemVersion;
        feats.minor_os_version       = opt.MinorOperatingSystemVersion;
        feats.major_subsystem_version= opt.MajorSubsystemVersion;
        feats.minor_subsystem_version= opt.MinorSubsystemVersion;
        feats.size_of_code           = opt.SizeOfCode;
        feats.size_of_initialized_data = opt.SizeOfInitializedData;
        feats.size_of_uninitialized_data = opt.SizeOfUninitializedData;
        feats.address_of_entry_point = opt.AddressOfEntryPoint;
        feats.base_of_code           = opt.BaseOfCode;
        feats.size_of_image          = opt.SizeOfImage;
        feats.size_of_headers        = opt.SizeOfHeaders;
        feats.checksum               = opt.CheckSum;
        feats.subsystem              = opt.Subsystem;
        feats.dll_characteristics    = opt.DllCharacteristics;

        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            feats.import_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            feats.import_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            feats.export_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            feats.export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            feats.resource_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            feats.resource_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
            auto* nt_ptr = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + feats.e_lfanew);
            ResourceStats rs = ComputeResourceStats(buffer, nt_ptr, feats.resource_rva);
            feats.resource_stats   = rs;
            feats.num_resources    = static_cast<uint32_t>(rs.total_resources);
            feats.resource_entropy = rs.entropy_mean;  // backward-compat alias
            feats.resource_size    = rs.size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
            feats.tls_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            feats.tls_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
            feats.has_tls  = (feats.tls_rva != 0 && feats.tls_size > 0);
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            feats.debug_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            feats.debug_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
            feats.has_debug  = (feats.debug_rva != 0 && feats.debug_size > 0);
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            feats.security_rva        = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            feats.security_size       = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            feats.has_signature       = (feats.security_size > 0);
            feats.certificate_present = feats.has_signature;
            feats.certificate_count   = CountCertificates(buffer, feats.security_rva, feats.security_size);
        }
    } else {
        const auto& opt = nt32.OptionalHeader;
        feats.magic                  = opt.Magic;
        feats.image_base             = opt.ImageBase;
        feats.section_alignment      = opt.SectionAlignment;
        feats.file_alignment         = opt.FileAlignment;
        feats.major_linker_version   = opt.MajorLinkerVersion;
        feats.minor_linker_version   = opt.MinorLinkerVersion;
        feats.major_os_version       = opt.MajorOperatingSystemVersion;
        feats.minor_os_version       = opt.MinorOperatingSystemVersion;
        feats.major_subsystem_version= opt.MajorSubsystemVersion;
        feats.minor_subsystem_version= opt.MinorSubsystemVersion;
        feats.size_of_code           = opt.SizeOfCode;
        feats.size_of_initialized_data = opt.SizeOfInitializedData;
        feats.size_of_uninitialized_data = opt.SizeOfUninitializedData;
        feats.address_of_entry_point = opt.AddressOfEntryPoint;
        feats.base_of_code           = opt.BaseOfCode;
        feats.size_of_image          = opt.SizeOfImage;
        feats.size_of_headers        = opt.SizeOfHeaders;
        feats.checksum               = opt.CheckSum;
        feats.subsystem              = opt.Subsystem;
        feats.dll_characteristics    = opt.DllCharacteristics;

        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            feats.import_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            feats.import_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            feats.export_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            feats.export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            feats.resource_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            feats.resource_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
            auto* nt_ptr = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + feats.e_lfanew);
            ResourceStats rs = ComputeResourceStats(buffer, nt_ptr, feats.resource_rva);
            feats.resource_stats   = rs;
            feats.num_resources    = static_cast<uint32_t>(rs.total_resources);
            feats.resource_entropy = rs.entropy_mean;  // backward-compat alias
            feats.resource_size    = rs.size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
            feats.tls_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            feats.tls_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
            feats.has_tls  = (feats.tls_rva != 0 && feats.tls_size > 0);
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            feats.debug_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            feats.debug_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
            feats.has_debug  = (feats.debug_rva != 0 && feats.debug_size > 0);
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            feats.security_rva        = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            feats.security_size       = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            feats.has_signature       = (feats.security_size > 0);
            feats.certificate_present = feats.has_signature;
            feats.certificate_count   = CountCertificates(buffer, feats.security_rva, feats.security_size);
        }
    }

    feats.no_imports = (feats.import_size == 0);

    // Rich Header – parsed from DOS stub region
    feats.rich_header = ParseRichHeader(buffer, feats.e_lfanew);

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    feats.timestamp_zero_or_future = (feats.time_date_stamp == 0 ||
                                     static_cast<uint64_t>(feats.time_date_stamp) > static_cast<uint64_t>(now) + 86400ULL * 365 * 2);
    feats.checksum_zero            = (feats.checksum == 0);
    feats.os_version_low           = (feats.major_os_version < 6);
    feats.alignment_weird          = (feats.section_alignment < feats.file_alignment && feats.section_alignment != 0);

    feats.is_gui    = (feats.subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI);
    feats.is_console= (feats.subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI);

    feats.aslr_enabled = (feats.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    feats.nx_enabled   = (feats.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    feats.cfg_enabled  = (feats.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;

    std::vector<SectionHeader> sections;
    scan_for_pos_indicators(buffer, feats);

    return feats;
}

// ───────────────────────────────────────────────
void scan_for_pos_indicators(
    const std::vector<uint8_t>& buffer,
    PeHeaderFeatures& feats)
{
    static const char* pos_signatures[] = {
        "response=", "&ump=", "&opt=", "varUID", "varDumps",
        "IsValidCC", "DigitsLen", "IsEndDataValid", "Track3",
        "WindowsResilienceServiceMutex", "Software\\Resilience Software",
        "Luhn", "check digit", "card number", "^.{1,79}^", ";\\d{13,19}=",
        nullptr
    };

    int score = 0;

    const uint8_t* data = buffer.data();
    size_t size = buffer.size();

    feats.code_section_entropy = calc_entropy(data, size);
    if (feats.code_section_entropy > 7.1) score += 10;

    for (int i = 0; pos_signatures[i]; ++i) {
        const char* sig = pos_signatures[i];
        size_t sig_len = std::strlen(sig);

        if (my_memmem(data, size, reinterpret_cast<const uint8_t*>(sig), sig_len)) {
            feats.has_track_pattern_strings = true;
            score += 15;

            if (std::strstr(sig, "response=") || std::strstr(sig, "&ump=")) {
                feats.has_http_post_exfil = true;
                score += 20;
            }
            if (std::strstr(sig, "IsValidCC") || std::strstr(sig, "Luhn")) {
                feats.has_luhn_or_cc_validation = true;
                score += 25;
            }
            if (std::strstr(sig, "Mutex") || std::strstr(sig, "Resilience")) {
                feats.has_mutex_persistence = true;
                score += 10;
            }
        }
    }

    feats.pos_malware_score = std::min(100, score);
    feats.likely_pos_scraper = (feats.pos_malware_score >= 55);
}

// ────────────────────────────────────────────────
ImportStats GetImportStats(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats) {
    ImportStats stats{};

    if (feats.import_rva == 0 || feats.import_size == 0) return stats;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + feats.e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return stats;

    DWORD import_offset = RVAToOffset(nt, feats.import_rva);
    if (import_offset == 0 || import_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > buffer.size()) {
        return stats;
    }

    auto* import_desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(buffer.data() + import_offset);

    auto mark_api = [&](const std::string& func_name) {
        std::string lower_api = func_name;
        std::transform(lower_api.begin(), lower_api.end(), lower_api.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });

        auto set_flag = [&](const char* api_name, bool& flag) {
            if (lower_api == api_name) {
                flag = true;
            }
        };

        set_flag("virtualalloc", stats.has_VirtualAlloc);
        set_flag("virtualprotect", stats.has_VirtualProtect);
        set_flag("writeprocessmemory", stats.has_WriteProcessMemory);
        set_flag("readprocessmemory", stats.has_ReadProcessMemory);
        set_flag("createremotethread", stats.has_CreateRemoteThread);
        set_flag("ntmapviewofsection", stats.has_NtMapViewOfSection);
        set_flag("queueuserapc", stats.has_QueueUserAPC);
    };

    while (import_desc->Name && (import_desc->OriginalFirstThunk || import_desc->FirstThunk)) {
        DWORD thunk_rva = import_desc->OriginalFirstThunk ? import_desc->OriginalFirstThunk : import_desc->FirstThunk;
        DWORD thunk_off = RVAToOffset(nt, thunk_rva);
        if (thunk_off == 0 || thunk_off + 8 > buffer.size()) break;

        DWORD dll_name_off = RVAToOffset(nt, import_desc->Name);
        std::string dll_name;
        if (dll_name_off != 0 && dll_name_off < buffer.size()) {
            dll_name = read_cstring_at(buffer, dll_name_off, 256);
        }

        auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(buffer.data() + thunk_off);

        while (thunk->u1.AddressOfData) {
            stats.total_functions++;

            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                DWORD name_rva = static_cast<DWORD>(thunk->u1.AddressOfData);
                DWORD name_off = RVAToOffset(nt, name_rva + 2); // skip hint/ordinal
                if (name_off != 0 && name_off + 64 <= buffer.size()) {
                    std::string func_name(reinterpret_cast<const char*>(buffer.data() + name_off));
                    stats.imported_function_names.push_back(func_name);
                    if (!dll_name.empty()) {
                        stats.dll_to_functions[dll_name].push_back(func_name);
                    }
                    if (func_name == "VirtualAllocEx")          stats.has_VirtualAllocEx = true;
                    if (func_name == "VirtualAlloc")            stats.has_VirtualAlloc = true;
                    if (func_name == "VirtualProtect")          stats.has_VirtualProtect = true;
                    if (func_name == "WriteProcessMemory")      stats.has_WriteProcessMemory = true;
                    if (func_name == "ReadProcessMemory")       stats.has_ReadProcessMemory = true;
                    if (func_name == "CreateRemoteThread")      stats.has_CreateRemoteThread = true;
                    if (func_name == "NtMapViewOfSection")      stats.has_NtMapViewOfSection = true;
                    if (func_name == "QueueUserAPC")            stats.has_QueueUserAPC = true;
                    if (func_name == "WinExec")                 stats.has_WinExec = true;
                    if (func_name == "ShellExecuteA" || func_name == "ShellExecuteW") stats.has_ShellExecute = true;
                    if (func_name == "LoadLibraryA" || func_name == "LoadLibraryW") stats.has_LoadLibrary = true;
                    if (func_name == "GetProcAddress")          stats.has_GetProcAddress = true;
                    if (func_name == "InternetOpenA" || func_name == "InternetOpenW") stats.has_InternetOpen = true;
                    if (func_name == "WinHttpOpen")             stats.has_WinHttpOpen = true;
                    if (func_name == "CryptEncrypt")            stats.has_CryptEncrypt = true;
                    if (func_name == "BCryptEncrypt")          stats.has_BCryptEncrypt = true;
                    if (func_name == "NtAllocateVirtualMemory") stats.has_NtAllocateVirtualMemory = true;
                    if (func_name == "NtWriteVirtualMemory")    stats.has_NtWriteVirtualMemory = true;
                    if (func_name == "NtProtectVirtualMemory")  stats.has_NtProtectVirtualMemory = true;
                    mark_api(func_name);
                    if (suspicious_apis.find(func_name) != suspicious_apis.end()) {
                        stats.suspicious_count++;
                    }
                }
            } else {
                if (!dll_name.empty()) {
                    DWORD ord = static_cast<DWORD>(thunk->u1.Ordinal & 0xFFFF);
                    stats.dll_to_functions[dll_name].push_back("ord" + std::to_string(ord));
                }
            }
            ++thunk;
        }
        ++import_desc;
    }
    for (const auto& api : suspicious_apis) {
        if (my_memmem(buffer.data(), buffer.size(),
                      reinterpret_cast<const uint8_t*>(api.c_str()), api.size())) {
            stats.pos_specific_count++;
        }
    }

    stats.has_memory_scraping_apis = (stats.pos_specific_count >= 3);
    stats.imphash = ComputeImpHash(stats.dll_to_functions);

    return stats;
}

// ────────────────────────────────────────────────
std::string ComputeImpHash(const std::map<std::string, std::vector<std::string>>& dll_to_functions) {
    if (dll_to_functions.empty()) return "";

    std::string formatted_imports;
    bool first = true;

    for (const auto& [dll, funcs] : dll_to_functions) {
        std::string lib_name = dll;
        std::transform(lib_name.begin(), lib_name.end(), lib_name.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });

        size_t last_dot = lib_name.rfind('.');
        if (last_dot != std::string::npos) {
            std::string ext = lib_name.substr(last_dot);
            if (ext == ".dll" || ext == ".drv" || ext == ".sys" || ext == ".ocx" || ext == ".exe" || ext == ".cpl" || ext == ".acm") {
                lib_name = lib_name.substr(0, last_dot);
            }
        }

        for (const auto& func : funcs) {
            if (!first) {
                formatted_imports += ",";
            }
            first = false;
            std::string func_name = func;
            std::transform(func_name.begin(), func_name.end(), func_name.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            formatted_imports += lib_name + "." + func_name;
        }
    }

    if (formatted_imports.empty()) return "";
    return MD5String(formatted_imports);
}

// ────────────────────────────────────────────────
ByteLevelFeatures extract_byte_level_features(const std::vector<uint8_t>& buffer) {
    ByteLevelFeatures feats;
    feats.byte_histogram.assign(256, 0.0);
    feats.byte_entropy_histogram.assign(16, 0.0);
    feats.byte_entropy_matrix.assign(256, 0.0);
    feats.nibble_transition_matrix.assign(256, 0.0);

    const size_t total_bytes = buffer.size();
    if (total_bytes == 0) return feats;

    // 1. Byte Histogram (256 bins)
    std::vector<uint64_t> byte_counts(256, 0);
    for (uint8_t b : buffer) {
        byte_counts[b]++;
    }

    for (int i = 0; i < 256; ++i) {
        feats.byte_histogram[i] = static_cast<double>(byte_counts[i]) / static_cast<double>(total_bytes);
    }
    feats.zero_byte_ratio = feats.byte_histogram[0];

    // 2. Windowed Entropy & Joint Byte-Entropy Histogram (2D: 16x16)
    const size_t window_size = 2048;
    const size_t step_size = 1024;
    std::vector<double> window_entropies;

    if (total_bytes <= window_size) {
        double ent = calc_entropy(buffer.data(), total_bytes);
        window_entropies.push_back(ent);

        int ent_bin = std::min(15, static_cast<int>(std::floor((ent / 8.0) * 16.0)));
        feats.byte_entropy_histogram[ent_bin] += 1.0;

        for (uint8_t b : buffer) {
            int byte_bin = b / 16;
            feats.byte_entropy_matrix[byte_bin * 16 + ent_bin] += 1.0;
        }
    } else {
        size_t window_count = 0;
        for (size_t offset = 0; offset + window_size <= total_bytes; offset += step_size) {
            double ent = calc_entropy(buffer.data() + offset, window_size);
            window_entropies.push_back(ent);
            window_count++;

            int ent_bin = std::min(15, static_cast<int>(std::floor((ent / 8.0) * 16.0)));
            feats.byte_entropy_histogram[ent_bin] += 1.0;

            for (size_t i = 0; i < window_size; ++i) {
                uint8_t b = buffer[offset + i];
                int byte_bin = b / 16;
                feats.byte_entropy_matrix[byte_bin * 16 + ent_bin] += 1.0;
            }
        }

        if (window_count > 0) {
            for (int i = 0; i < 16; ++i) {
                feats.byte_entropy_histogram[i] /= static_cast<double>(window_count);
            }
        }
    }

    double matrix_sum = 0.0;
    for (double v : feats.byte_entropy_matrix) matrix_sum += v;
    if (matrix_sum > 0.0) {
        for (int i = 0; i < 256; ++i) {
            feats.byte_entropy_matrix[i] /= matrix_sum;
        }
    }

    if (!window_entropies.empty()) {
        feats.windowed_entropy_min = window_entropies[0];
        feats.windowed_entropy_max = window_entropies[0];
        double sum_ent = 0.0;
        for (double ent : window_entropies) {
            sum_ent += ent;
            feats.windowed_entropy_min = std::min(feats.windowed_entropy_min, ent);
            feats.windowed_entropy_max = std::max(feats.windowed_entropy_max, ent);
        }
        feats.windowed_entropy_mean = sum_ent / static_cast<double>(window_entropies.size());

        double var_ent = 0.0;
        for (double ent : window_entropies) {
            double diff = ent - feats.windowed_entropy_mean;
            var_ent += diff * diff;
        }
        feats.windowed_entropy_std = std::sqrt(var_ent / static_cast<double>(window_entropies.size()));
    }

    // 3. Markov Transition Matrix on 4-bit Nibbles (16x16 matrix = 256 bins)
    std::vector<uint64_t> nibble_trans_counts(256, 0);
    uint64_t total_transitions = 0;

    uint8_t prev_nibble = buffer[0] >> 4;
    uint8_t curr_nibble = buffer[0] & 0x0F;
    nibble_trans_counts[prev_nibble * 16 + curr_nibble]++;
    total_transitions++;
    prev_nibble = curr_nibble;

    for (size_t i = 1; i < total_bytes; ++i) {
        curr_nibble = buffer[i] >> 4;
        nibble_trans_counts[prev_nibble * 16 + curr_nibble]++;
        total_transitions++;
        prev_nibble = curr_nibble;

        curr_nibble = buffer[i] & 0x0F;
        nibble_trans_counts[prev_nibble * 16 + curr_nibble]++;
        total_transitions++;
        prev_nibble = curr_nibble;
    }

    if (total_transitions > 0) {
        for (int i = 0; i < 256; ++i) {
            feats.nibble_transition_matrix[i] = static_cast<double>(nibble_trans_counts[i]) / static_cast<double>(total_transitions);
        }

        double markov_ent = 0.0;
        for (int i = 0; i < 256; ++i) {
            double p = feats.nibble_transition_matrix[i];
            if (p > 0.0) {
                markov_ent -= p * std::log2(p);
            }
        }
        feats.markov_matrix_entropy = markov_ent;
    }

    return feats;
}

// ────────────────────────────────────────────────
ExportStats GetExportStats(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats) {
    ExportStats stats;
    if (feats.export_rva == 0 || feats.export_size == 0 ||
        feats.e_lfanew > buffer.size() ||
        sizeof(IMAGE_NT_HEADERS32) > buffer.size() - feats.e_lfanew) {
        return stats;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + feats.e_lfanew);
    DWORD export_off = RVAToOffset(nt, feats.export_rva);
    if (export_off == 0 || export_off >= buffer.size() ||
        sizeof(IMAGE_EXPORT_DIRECTORY) > buffer.size() - export_off) {
        return stats;
    }

    const auto* exp_dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(buffer.data() + export_off);

    stats.export_count = exp_dir->NumberOfFunctions;
    stats.export_named_count = exp_dir->NumberOfNames;
    stats.export_ordinal_only_count = (exp_dir->NumberOfFunctions > exp_dir->NumberOfNames)
                                       ? (exp_dir->NumberOfFunctions - exp_dir->NumberOfNames)
                                       : 0;

    DWORD names_off = RVAToOffset(nt, exp_dir->AddressOfNames);
    if (names_off != 0 && names_off < buffer.size() && exp_dir->NumberOfNames > 0) {
        size_t num_names = std::min<size_t>(exp_dir->NumberOfNames, 4096);
        if (num_names <= (buffer.size() - names_off) / sizeof(DWORD)) {
            const auto* name_rvas = reinterpret_cast<const DWORD*>(buffer.data() + names_off);
            stats.export_names.reserve(num_names);
            std::vector<double> entropies;

            for (size_t i = 0; i < num_names; ++i) {
                DWORD name_off = RVAToOffset(nt, name_rvas[i]);
                if (name_off != 0) {
                    std::string exp_name = read_cstring_at(buffer, name_off, 256);
                    if (!exp_name.empty()) {
                        stats.export_names.push_back(exp_name);
                        double ent = calc_entropy(reinterpret_cast<const uint8_t*>(exp_name.data()), exp_name.size());
                        entropies.push_back(ent);
                    }
                }
            }

            if (!entropies.empty()) {
                stats.export_name_entropy_min = entropies[0];
                stats.export_name_entropy_max = entropies[0];
                double sum = 0.0;
                for (double e : entropies) {
                    sum += e;
                    stats.export_name_entropy_min = std::min(stats.export_name_entropy_min, e);
                    stats.export_name_entropy_max = std::max(stats.export_name_entropy_max, e);
                }
                stats.export_name_entropy_mean = sum / static_cast<double>(entropies.size());

                double var = 0.0;
                for (double e : entropies) {
                    double diff = e - stats.export_name_entropy_mean;
                    var += diff * diff;
                }
                stats.export_name_entropy_std = std::sqrt(var / static_cast<double>(entropies.size()));
            }
        }
    }

    if (!stats.export_names.empty()) {
        std::vector<std::string> sorted_names = stats.export_names;
        std::sort(sorted_names.begin(), sorted_names.end());
        std::string concat;
        for (size_t i = 0; i < sorted_names.size(); ++i) {
            if (i > 0) concat += ",";
            concat += sorted_names[i];
        }
        stats.export_name_hash = MD5String(concat);
    }

    return stats;
}

StringStats ComputeStringStatistics(
    const std::vector<std::string>& ascii_strings,
    const std::vector<std::string>& unicode_strings) {
    StringStats stats;
    stats.ascii_strings = ascii_strings.size();
    stats.unicode_strings = unicode_strings.size();
    stats.total_strings = stats.ascii_strings + stats.unicode_strings;
    if (stats.total_strings == 0) return stats;

    std::vector<size_t> lengths;
    lengths.reserve(stats.total_strings);
    double entropy_sum = 0.0;
    double printable_ratio_sum = 0.0;

    auto process = [&](const std::vector<std::string>& strings) {
        for (const auto& value : strings) {
            lengths.push_back(value.size());
            entropy_sum += calc_entropy(
                reinterpret_cast<const uint8_t*>(value.data()), value.size());

            size_t printable = 0;
            for (unsigned char c : value) {
                if (c >= 32 && c <= 126) ++printable;
            }
            if (!value.empty()) {
                printable_ratio_sum += static_cast<double>(printable) / value.size();
            }
        }
    };

    process(ascii_strings);
    process(unicode_strings);

    stats.avg_length = std::accumulate(lengths.begin(), lengths.end(), 0.0) /
                       static_cast<double>(lengths.size());
    std::sort(lengths.begin(), lengths.end());
    if (lengths.size() % 2 == 0) {
        stats.median_length = (static_cast<double>(lengths[lengths.size() / 2 - 1]) +
                               static_cast<double>(lengths[lengths.size() / 2])) / 2.0;
    } else {
        stats.median_length = static_cast<double>(lengths[lengths.size() / 2]);
    }
    stats.avg_entropy = entropy_sum / static_cast<double>(stats.total_strings);
    stats.printable_ratio = printable_ratio_sum / static_cast<double>(stats.total_strings);
    stats.unicode_ratio = static_cast<double>(stats.unicode_strings) /
                          static_cast<double>(stats.total_strings);
    return stats;
}

InterestingStrings ExtractInterestingStrings(const std::vector<std::string>& strings) {
    InterestingStrings result;
    static const std::regex re_ip(
        R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)");
    static const std::regex re_url(R"((https?|ftp)://[^\s/$.?#].[^\s]*)", std::regex::icase);
    static const std::regex re_email(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)");
    static const std::regex re_domain(
        R"(\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|info|biz|xyz|ru|cn|tk|top|club|online|site|io|gov|edu)\b)",
        std::regex::icase);
    static const std::regex re_registry(R"(hkey_[a-z_\\]+)", std::regex::icase);
    static const std::regex re_file_path(R"([a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*)");
    static const std::vector<std::string> crypto_markers = {
        "aes", "rsa", "rc4", "salsa20", "chacha", "sha1", "sha256", "md5",
        "base64", "rijndael", "blowfish", "twofish", "serpent",
        "cryptacquirecontext", "cryptencrypt", "cryptdecrypt",
        "bcryptencrypt", "bcryptdecrypt", "nte_bad_algid"
    };

    for (const auto& value : strings) {
        if (value.size() < 6) continue;
        std::string lower = value;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (std::regex_search(value, re_ip)) result.ips.push_back(value);
        if (std::regex_search(value, re_url)) result.urls.push_back(value);
        if (std::regex_search(value, re_email)) {
            result.emails.push_back(value);
        } else if (std::regex_search(value, re_domain)) {
            result.domains.push_back(value);
        }
        if (std::regex_search(lower, re_registry) ||
            lower.find("\\currentversion\\run") != std::string::npos ||
            lower.find("\\windows\\currentversion\\") != std::string::npos) {
            result.registry_paths.push_back(value);
        }
        if (std::regex_search(value, re_file_path) ||
            lower.find("\\temp\\") != std::string::npos ||
            lower.find("\\appdata\\") != std::string::npos) {
            result.file_paths.push_back(value);
        }
        if (lower.find("mutex") != std::string::npos ||
            lower.find("global\\") != std::string::npos ||
            lower.find("local\\") != std::string::npos ||
            lower.find("session\\") != std::string::npos) {
            result.mutexes.push_back(value);
        }
        for (const auto& marker : crypto_markers) {
            if (lower.find(marker) != std::string::npos) {
                result.crypto_constants.push_back(value);
                break;
            }
        }
    }
    return result;
}

// ────────────────────────────────────────────────
size_t GetTLSCallbackCount(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats) {
    if (!feats.has_tls || feats.tls_rva == 0 || feats.tls_size < sizeof(IMAGE_TLS_DIRECTORY)) {
        return 0;
    }

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + feats.e_lfanew);
    if (!nt) return 0;

    DWORD tls_off = RVAToOffset(nt, feats.tls_rva);
    if (tls_off == 0 || tls_off + sizeof(IMAGE_TLS_DIRECTORY) > buffer.size()) {
        return 0;
    }

    auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(buffer.data() + tls_off);
    if (tls->AddressOfCallBacks == 0) return 0;

    DWORD cb_rva = static_cast<DWORD>(tls->AddressOfCallBacks);
    DWORD cb_off = RVAToOffset(nt, cb_rva);
    if (cb_off == 0) return 0;

    size_t count = 0;
    const ULONGLONG* ptr = reinterpret_cast<const ULONGLONG*>(buffer.data() + cb_off);
    const uint8_t* buffer_end = buffer.data() + buffer.size();

    while (ptr && *ptr != 0 && count < 1024) {
        ++count;
        ++ptr;

        if (reinterpret_cast<const uint8_t*>(ptr) + sizeof(ULONGLONG) > buffer_end) {
            break;
        }
    }
    return count;
}

// ────────────────────────────────────────────────
bool VerifyDigitalSignature(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct       = sizeof(fileInfo);
    fileInfo.pcwszFilePath  = filePath.c_str();
    fileInfo.hFile          = INVALID_HANDLE_VALUE;
    fileInfo.pgKnownSubject = nullptr;

    WINTRUST_DATA winTrustData{};
    winTrustData.cbStruct            = sizeof(winTrustData);
    winTrustData.dwUIChoice          = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    winTrustData.dwUnionChoice       = WTD_CHOICE_FILE;
    winTrustData.pFile               = &fileInfo;
    winTrustData.dwStateAction       = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG result = WinVerifyTrust(nullptr, &action, &winTrustData);

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &winTrustData);

    return (result == 0);
}


// ────────────────────────────────────────────────
DWORD RVAToOffset(const IMAGE_NT_HEADERS* nt, DWORD rva) {
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->Misc.VirtualSize) {
            return section->PointerToRawData + (rva - section->VirtualAddress);
        }
    }
    return 0;
}

// ────────────────────────────────────────────────
nlohmann::json features_to_json(const PeHeaderFeatures& feats, const FileHashes& hashes,
                                const std::string& filepath, size_t filesize,
                                const ImportStats& import_stats,
                                const DelayImportStats& delay_import_stats,
                                size_t tls_callbacks,
                                double reloc_entropy,
                                size_t overlay_size,
                                bool signature_valid,
                                const ByteLevelFeatures& byte_feats,
                                const ExportStats& export_stats) {
    nlohmann::json j;

    j["file"]          = filepath;
    j["size_bytes"]    = filesize;
    j["md5"]           = hashes.md5;
    j["sha256"]        = hashes.sha256;
    j["fuzzy_hash"]    = hashes.fuzzy;
    j["imphash"]       = import_stats.imphash;

    j["is_invalid_dos"]         = feats.is_invalid_dos;
    j["e_lfanew"]               = feats.e_lfanew;
    j["e_lfanew_too_large"]     = feats.e_lfanew_too_large;
    j["e_lfanew_not_aligned"]   = feats.e_lfanew_not_aligned;

    j["machine"]                = feats.machine;
    j["num_sections"]           = feats.number_of_sections;
    j["time_date_stamp"]        = feats.time_date_stamp;
    j["is_dll"]                 = feats.is_dll;

    j["magic"]                  = feats.magic;
    j["image_base"]             = feats.image_base;
    j["entry_point_rva"]        = feats.address_of_entry_point;
    j["size_of_image"]          = feats.size_of_image;
    j["size_of_headers"]        = feats.size_of_headers;
    j["section_alignment"]      = feats.section_alignment;
    j["file_alignment"]         = feats.file_alignment;

    j["major_linker_version"]   = feats.major_linker_version;
    j["minor_linker_version"]   = feats.minor_linker_version;

    j["timestamp_zero_or_future"]= feats.timestamp_zero_or_future;
    j["checksum_zero"]          = feats.checksum_zero;
    j["os_version_low"]         = feats.os_version_low;
    j["alignment_weird"]        = feats.alignment_weird;
    j["is_gui"]                 = feats.is_gui;
    j["is_console"]             = feats.is_console;
    j["aslr_enabled"]           = feats.aslr_enabled;
    j["nx_enabled"]             = feats.nx_enabled;
    j["cfg_enabled"]            = feats.cfg_enabled;

    j["has_tls"]                = feats.has_tls;
    j["has_debug"]              = feats.has_debug;
    j["has_signature"]          = feats.has_signature;
    j["no_imports"]             = feats.no_imports;

    j["import_rva"]             = feats.import_rva;
    j["import_size"]            = feats.import_size;
    j["resource_size"]          = feats.resource_size;
    j["resource_ratio"]         = (filesize > 0) ? static_cast<double>(feats.resource_size) / filesize : 0.0;
    j["num_resources"]          = feats.num_resources;
    j["resource_entropy"]       = feats.resource_entropy;
    j["tls_size"]               = feats.tls_size;
    j["security_size"]          = feats.security_size;

    j["import_function_count"]     = import_stats.total_functions;
    j["suspicious_api_count"]      = import_stats.suspicious_count;
    j["suspicious_api_ratio"]      = import_stats.total_functions > 0 ?
                                     static_cast<double>(import_stats.suspicious_count) / import_stats.total_functions : 0.0;
    j["has_VirtualAlloc"]          = import_stats.has_VirtualAlloc;
    j["has_VirtualProtect"]        = import_stats.has_VirtualProtect;
    j["has_WriteProcessMemory"]    = import_stats.has_WriteProcessMemory;
    j["has_ReadProcessMemory"]     = import_stats.has_ReadProcessMemory;
    j["has_CreateRemoteThread"]    = import_stats.has_CreateRemoteThread;
    j["has_NtMapViewOfSection"]    = import_stats.has_NtMapViewOfSection;
    j["has_QueueUserAPC"]          = import_stats.has_QueueUserAPC;
    j["has_WinExec"]               = import_stats.has_WinExec;
    j["has_ShellExecute"]          = import_stats.has_ShellExecute;
    j["has_LoadLibrary"]           = import_stats.has_LoadLibrary;
    j["has_GetProcAddress"]        = import_stats.has_GetProcAddress;
    j["has_InternetOpen"]          = import_stats.has_InternetOpen;
    j["has_WinHttpOpen"]           = import_stats.has_WinHttpOpen;
    j["has_CryptEncrypt"]          = import_stats.has_CryptEncrypt;
    j["has_BCryptEncrypt"]         = import_stats.has_BCryptEncrypt;
    j["has_memory_scraping_apis"]  = import_stats.has_memory_scraping_apis;
    j["delay_import_count"]        = delay_import_stats.delay_import_count;
    j["delay_import_dlls"]         = delay_import_stats.delay_import_dlls;
    j["delay_import_functions"]    = delay_import_stats.delay_import_functions;
    j["no_delay_imports"]          = feats.no_delay_imports;
    j["tls_callback_count"]        = tls_callbacks;
    j["relocation_entropy"]        = reloc_entropy;
    j["overlay_size_bytes"]        = overlay_size;
    j["digital_signature_valid"]   = signature_valid;

    j["likely_pos_scraper"]          = feats.likely_pos_scraper;
    j["pos_malware_score"]           = feats.pos_malware_score;
    j["has_track_pattern_strings"]   = feats.has_track_pattern_strings;
    j["has_luhn_or_cc_validation"]   = feats.has_luhn_or_cc_validation;
    j["has_http_post_exfil"]         = feats.has_http_post_exfil;
    j["has_mutex_persistence"]       = feats.has_mutex_persistence;
    j["code_section_entropy"]        = feats.code_section_entropy;

    if (feats.size_of_image > 0) {
        j["code_ratio"] = static_cast<double>(feats.size_of_code) / feats.size_of_image;
    } else {
        j["code_ratio"] = 0.0;
    }

    // ── Byte-level features ────────────────────────────────────
    j["byte_histogram"]            = byte_feats.byte_histogram;
    j["zero_byte_ratio"]           = byte_feats.zero_byte_ratio;
    j["byte_entropy_histogram"]    = byte_feats.byte_entropy_histogram;
    j["byte_entropy_matrix"]       = byte_feats.byte_entropy_matrix;
    j["windowed_entropy_mean"]     = byte_feats.windowed_entropy_mean;
    j["windowed_entropy_max"]      = byte_feats.windowed_entropy_max;
    j["windowed_entropy_min"]      = byte_feats.windowed_entropy_min;
    j["windowed_entropy_std"]      = byte_feats.windowed_entropy_std;
    j["nibble_transition_matrix"]  = byte_feats.nibble_transition_matrix;
    j["markov_matrix_entropy"]     = byte_feats.markov_matrix_entropy;

    // ── Export table features ──────────────────────────────────
    j["export_count"]              = export_stats.export_count;
    j["export_named_count"]        = export_stats.export_named_count;
    j["export_ordinal_only_count"]  = export_stats.export_ordinal_only_count;
    j["export_name_entropy_mean"]   = export_stats.export_name_entropy_mean;
    j["export_name_entropy_max"]    = export_stats.export_name_entropy_max;
    j["export_name_entropy_min"]    = export_stats.export_name_entropy_min;
    j["export_name_entropy_std"]    = export_stats.export_name_entropy_std;
    j["export_name_hash"]          = export_stats.export_name_hash;
    j["export_names"]              = export_stats.export_names;

    // ── Resource count (per-type) ───────────────────────────────
    const auto& rs = feats.resource_stats;
    j["resource_total"]           = rs.total_resources;
    j["resource_icon_count"]      = rs.icon_count;
    j["resource_cursor_count"]    = rs.cursor_count;
    j["resource_bitmap_count"]    = rs.bitmap_count;
    j["resource_dialog_count"]    = rs.dialog_count;
    j["resource_menu_count"]      = rs.menu_count;
    j["resource_stringtable_count"] = rs.stringtable_count;
    j["resource_accelerator_count"] = rs.accelerator_count;
    j["resource_manifest_count"]  = rs.manifest_count;
    j["resource_version_count"]   = rs.version_count;
    j["resource_rcdata_count"]    = rs.rcdata_count;
    j["resource_other_count"]     = rs.other_count;

    // ── Resource entropy (per-leaf stats) ──────────────────────
    j["resource_entropy_mean"]    = rs.entropy_mean;
    j["resource_entropy_max"]     = rs.entropy_max;
    j["resource_entropy_std"]     = rs.entropy_std;

    // ── Manifest ───────────────────────────────────────────────
    j["manifest_present"]            = rs.manifest_present;
    j["manifest_size"]               = rs.manifest_size;
    j["manifest_entropy"]            = rs.manifest_entropy;
    j["manifest_execution_level"]    = rs.execution_level;
    j["manifest_uiaccess"]           = rs.uiaccess;
    j["manifest_auto_elevate"]       = rs.auto_elevate;
    j["manifest_requested_privilege"]= rs.requested_privilege;
    j["manifest_has_dpi"]            = rs.has_dpi;
    j["manifest_has_com"]            = rs.has_com;
    j["manifest_has_dependencies"]   = rs.has_dependencies;
    j["manifest_dependency_count"]   = rs.dependency_count;

    // ── Certificate ────────────────────────────────────────────
    j["certificate_present"]         = feats.certificate_present;
    j["certificate_count"]           = feats.certificate_count;

    // ── Version Info ───────────────────────────────────────────
    const auto& vi = feats.version_info;
    j["has_version_info"]              = vi.has_version_info;
    j["version_company_name_length"]   = vi.company_name_length;
    j["version_product_name_length"]   = vi.product_name_length;
    j["version_description_length"]    = vi.description_length;
    j["version_original_filename_len"] = vi.original_filename_length;
    j["version_product_version_len"]   = vi.product_version_length;

    const auto& rh = feats.rich_header;
    j["rich_header_present"]   = rh.present;
    j["rich_header_entries"]   = rh.entry_count;
    j["rich_has_vs2015"]       = rh.has_vs2015;
    j["rich_has_vs2017"]       = rh.has_vs2017;
    j["rich_has_vs2019"]       = rh.has_vs2019;
    j["rich_has_vs2022"]       = rh.has_vs2022;
    j["rich_has_masm"]         = rh.has_masm;
    j["rich_has_cvtres"]       = rh.has_cvtres;
    j["rich_checksum"]         = rh.checksum;

    return j;
}
RichHeaderFeats ParseRichHeader(const std::vector<uint8_t>& buffer, uint32_t e_lfanew) {
    RichHeaderFeats feats;

    // Rich header lives between offset 0x80 and e_lfanew
    if (e_lfanew < 0x80 || e_lfanew > buffer.size()) return feats;

    const uint8_t* stub     = buffer.data() + 0x80;
    size_t         stub_len = e_lfanew - 0x80;

    // Search for "Rich" signature (0x68636952) working backwards from e_lfanew
    // More robustly: scan forward for "Rich" DWORD
    int rich_offset = -1;
    for (size_t i = 0; i + 8 <= stub_len; i += 4) {
        uint32_t dw;
        std::memcpy(&dw, stub + i, 4);
        if (dw == 0x68636952u) {  // "Rich"
            rich_offset = static_cast<int>(i);
            break;
        }
    }
    if (rich_offset < 0) return feats;

    // XOR key is the DWORD immediately after "Rich"
    uint32_t xor_key = 0;
    std::memcpy(&xor_key, stub + rich_offset + 4, 4);
    feats.checksum = xor_key;

    // Find "DanS" (XOR-encoded as xor_key ^ 0x536E6144) before Rich
    uint32_t dans_encoded = xor_key ^ 0x536E6144u;
    int dans_offset = -1;
    for (int i = 0; i < rich_offset; i += 4) {
        uint32_t dw;
        std::memcpy(&dw, stub + i, 4);
        if (dw == dans_encoded) {
            dans_offset = i;
            break;
        }
    }
    if (dans_offset < 0) return feats;

    // Entries start after DanS + 3 padding DWORDs (total 16 bytes = 4 DWORDs)
    int entries_start = dans_offset + 16;
    int entries_end   = rich_offset;

    if (entries_start >= entries_end) return feats;

    feats.present = true;

    // Decode each 8-byte entry: [CompID(4)] [Count(4)] both XOR'd with xor_key
    for (int i = entries_start; i + 8 <= entries_end; i += 8) {
        uint32_t comp_raw, count_raw;
        std::memcpy(&comp_raw,  stub + i,     4);
        std::memcpy(&count_raw, stub + i + 4, 4);

        uint32_t comp  = comp_raw  ^ xor_key;
        uint32_t count = count_raw ^ xor_key;

        uint16_t prod_id  = static_cast<uint16_t>(comp >> 16);
        uint16_t build_id = static_cast<uint16_t>(comp & 0xFFFF);

        RichHeaderEntry entry;
        entry.prod_id  = prod_id;
        entry.build_id = build_id;
        entry.count    = count;
        feats.entries.push_back(entry);
        feats.entry_count++;

        // Classify by ProdID ranges (documented community research)
        // VS2015: 0x00DC–0x00EF  (build ~23506–23918)
        // VS2017: 0x00F0–0x0100  (build ~25017–25834)
        // VS2019: 0x0101–0x010F  (build ~27508–29395)
        // VS2022: 0x0110+        (build ~30319+)
        if (prod_id >= 0x00DC && prod_id <= 0x00EF) feats.has_vs2015 = true;
        else if (prod_id >= 0x00F0 && prod_id <= 0x0100) feats.has_vs2017 = true;
        else if (prod_id >= 0x0101 && prod_id <= 0x010F) feats.has_vs2019 = true;
        else if (prod_id >= 0x0110) feats.has_vs2022 = true;

        // Tool detection by low byte of prod_id (common convention)
        uint8_t tool = static_cast<uint8_t>(prod_id & 0xFF);
        if (tool == 0x60) feats.has_masm   = true;  // MASM / ML
        if (tool == 0x53) feats.has_cvtres = true;  // CVTRES
    }

    return feats;
}

VersionInfoFeats ExtractVersionInfo(const std::string& filepath) {
    VersionInfoFeats vi;

    DWORD dummy = 0;
    DWORD info_size = GetFileVersionInfoSizeA(filepath.c_str(), &dummy);
    if (info_size == 0) return vi;

    std::vector<uint8_t> info_buf(info_size);
    if (!GetFileVersionInfoA(filepath.c_str(), 0, info_size, info_buf.data()))
        return vi;

    vi.has_version_info = true;

    // Try common translation blocks
    struct LangCodepage { WORD language; WORD codepage; };
    LangCodepage* translations = nullptr;
    UINT trans_len = 0;

    if (VerQueryValueA(info_buf.data(), "\\VarFileInfo\\Translation",
                       reinterpret_cast<LPVOID*>(&translations), &trans_len)
        && trans_len >= sizeof(LangCodepage))
    {
        char sub_block[64];
        UINT val_len = 0;
        void* val = nullptr;

        auto query = [&](const char* name, int& out_len) {
            snprintf(sub_block, sizeof(sub_block),
                     "\\StringFileInfo\\%04X%04X\\%s",
                     translations[0].language,
                     translations[0].codepage,
                     name);
            if (VerQueryValueA(info_buf.data(), sub_block, &val, &val_len) && val_len > 0) {
                out_len = static_cast<int>(strnlen(static_cast<const char*>(val), val_len));
            }
        };

        query("CompanyName",      vi.company_name_length);
        query("ProductName",      vi.product_name_length);
        query("FileDescription",  vi.description_length);
        query("OriginalFilename", vi.original_filename_length);
        query("ProductVersion",   vi.product_version_length);
    }

    return vi;
}
