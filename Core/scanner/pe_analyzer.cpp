#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "pe_analyzer.hpp"
#include "Disassembler.hpp"
#include "PeParser.hpp"
#include "StringEx.hpp"
#include "pe_opcode_ngram.hpp"
#include "YaraGen.hpp"
#include "detect.hpp"
#include "opcode_tfidf.hpp"
#include "WWPack.hpp"
#include "UPX.hpp"
#include "CFG.hpp"
#include "pe_api_ngram.hpp"
#include "BehavioralGraph.hpp"
#include "cbpra.hpp"
#include "BhpaiLicense.hpp"
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <unordered_set>
#include <chrono>

bool g_safe_run = false;
static Bhpai::LicenseContext g_license_context;

void check_memory_limit() {
    if (!g_safe_run) return;
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        // 3 GB = 3221225472 bytes
        if (pmc.WorkingSetSize > 3221225472ULL || pmc.PagefileUsage > 3221225472ULL) {
            throw MemoryLimitExceeded();
        }
    }
}

std::unordered_set<std::string> get_suspicious_apis_lowercase() {
    static const std::vector<std::string> apis = {
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "NtCreateSection", "NtMapViewOfSection", "ZwCreateSection",
        "LoadLibraryA", "GetProcAddress", "VirtualProtect",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "ZwQueryInformationProcess",
        "HeapCreate", "RtlMoveMemory", "memcpy", "memmove",
        "VirtualAlloc", "HeapAlloc",
        "ReadProcessMemory", "CreateToolhelp32Snapshot", "Process32First",
        "Process32Next", "EnumProcesses", "OpenProcess",
        "DuplicateHandle", "GetLastInputInfo",
        "InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
        "HttpSendRequestA",
        "RegNotifyChangeKeyValue", "RegSetValueExA", "CreateMutexA"
    };

    std::unordered_set<std::string> s;
    for (const auto& api : apis) {
        std::string lower = api;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        s.insert(std::move(lower));
    }
    return s;
}


std::vector<Instruction> PDAR(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats, uint32_t rva, size_t how_many_bytes = 1024, size_t max_instructions = 400)
{
    std::vector<Instruction> instructions;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<uint8_t*>(buffer.data() + feats.e_lfanew));
    auto* section = IMAGE_FIRST_SECTION(nt);

    uint64_t image_base = feats.image_base;
    if (image_base == 0 && feats.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        image_base = 0x400000;
    }
    uint64_t va         = image_base + rva;
    DWORD raw_offset    = 0;

    bool found = false;
    for (WORD i = 0; i < feats.number_of_sections; ++i, ++section)
    {
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->Misc.VirtualSize)
        {
            DWORD offset_in_section = rva - section->VirtualAddress;
            if (offset_in_section >= section->SizeOfRawData)
            {
                std::cerr << "[!] RVA 0x" << std::hex << rva
                          << " Section: " << section->Name << "\n";
                return instructions;
            }

            raw_offset = section->PointerToRawData + offset_in_section;
            found = true;
            break;
        }
    }

    if (!found)
    {
        std::cerr << "[!] Not found: 0x" << std::hex << rva << "\n";
        return instructions;
    }

    if (raw_offset == 0 || raw_offset >= buffer.size())
    {
        std::cerr << "[ERROR] Invalid file offset: 0x" << std::hex << raw_offset << "\n";
        return instructions;
    }

    Disassembler disasm;
    bool is_64bit = (feats.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if (!disasm.initialize(is_64bit))
    {
        std::cerr << "[ERROR] Failed to initialize Capstone disassembler\n";
        return instructions;
    }

    size_t bytes_available = buffer.size() - raw_offset;
    size_t bytes_to_disasm = std::min(how_many_bytes, bytes_available);

    instructions = disasm.disassemble(
        buffer.data() + raw_offset,
        bytes_to_disasm,
        va,  
        max_instructions
    );

    if (instructions.empty())
    {
        std::cout << "[!] No instructions disassembled at RVA 0x" << std::hex << rva << "\n";
        return instructions;
    }

    std::cout << "\n=== Disassembly at RVA 0x" << std::hex << std::setw(8) << std::setfill('0') << rva;
    if (is_64bit) {
        std::cout << " (VA 0x" << std::hex << va << ")";
    }
    std::cout << "  ── " << instructions.size() << " instructions / "
              << bytes_to_disasm << " bytes ===\n";

    for (const auto& inst : instructions)
    {
        std::cout << disasm.format_instruction(inst, true) << "\n";
    }

    if (instructions.size() >= max_instructions || bytes_to_disasm >= how_many_bytes)
    {
        std::cout << "   ... (truncated – increase how_many_bytes or max_instructions if needed)\n";
    }
    std::cout << std::dec << "\n";

    return instructions;
}

std::vector<std::string> capture_disassembly_for_json(
    const std::vector<uint8_t>& buffer,
    const PeHeaderFeatures& feats,
    uint32_t rva,
    size_t how_many_bytes = 768,
    size_t max_instructions = 220)
{
    std::vector<std::string> result;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<uint8_t*>(buffer.data() + feats.e_lfanew));
    auto* section = IMAGE_FIRST_SECTION(nt);

    uint64_t image_base = feats.image_base;
    if (image_base == 0 && feats.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        image_base = 0x400000;
    }

    uint64_t va = image_base + rva;
    DWORD raw_offset = 0;
    bool found = false;

    for (WORD i = 0; i < feats.number_of_sections; ++i, ++section)
    {
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->Misc.VirtualSize)
        {
            DWORD offset_in_section = rva - section->VirtualAddress;
            if (offset_in_section < section->SizeOfRawData)
            {
                raw_offset = section->PointerToRawData + offset_in_section;
                found = true;
                break;
            }
        }
    }

    if (!found || raw_offset == 0 || raw_offset >= buffer.size()) {
        return result; // trả về mảng rỗng
    }

    Disassembler disasm;
    bool is_64bit = (feats.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if (!disasm.initialize(is_64bit)) {
        return result;
    }

    size_t bytes_available = buffer.size() - raw_offset;
    size_t bytes_to_disasm = std::min(how_many_bytes, bytes_available);

    auto instructions = disasm.disassemble(
        buffer.data() + raw_offset,
        bytes_to_disasm,
        va,
        max_instructions
    );

    for (const auto& inst : instructions) {
        result.push_back(disasm.format_instruction(inst, true));
    }

    return result;
}

bool analyze_pe(std::string filepath, const std::string& label)
{
    try {
        PeParser initial_parser(filepath);
    if (!initial_parser.is_valid()) {
        std::cerr << "[ERROR] " << initial_parser.get_error() << "\n";
        return false;
    }

    std::vector<uint8_t> active_buffer = initial_parser.get_buffer();
    uint32_t entry_rva = initial_parser.get_entry_point_rva();
    bool was_unpacked = false;
    bool was_upx_unpacked = false;

    ScanResult initial_scan = ScanBuffer(active_buffer, entry_rva);
    if (initial_scan.wwpack || WWPackUnpacker::isWWPack(active_buffer)) {
        std::cout << "[+] Detected WWPack packer. Attempting to unpack...\n";
        std::vector<uint8_t> unpacked_buffer;
        if (WWPackUnpacker::unpack(active_buffer, unpacked_buffer)) {
            std::cout << "[+] Unpack successful! New size: " << unpacked_buffer.size() << " bytes\n";
            active_buffer = std::move(unpacked_buffer);
            was_unpacked = true;
            
            std::string unpacked_path = filepath + ".unpacked.exe";
            std::ofstream out_file(unpacked_path, std::ios::binary);
            if (out_file.is_open()) {
                out_file.write(reinterpret_cast<const char*>(active_buffer.data()), active_buffer.size());
                out_file.close();
                std::cout << "[+] Unpacked binary written to: " << unpacked_path << "\n";
                filepath = unpacked_path;
            }
        } else {
            std::cerr << "[WARNING] WWPack unpacking failed. Proceeding with packed binary.\n";
        }
    }

    // --- UPX Unpacking ---
    if (!was_unpacked && (initial_scan.upx || UPXUnpacker::isUPX(active_buffer))) {
        std::cout << "[+] Detected UPX packer. Attempting to unpack...\n";
        std::vector<uint8_t> unpacked_buffer;
        if (UPXUnpacker::unpack(active_buffer, unpacked_buffer)) {
            std::cout << "[+] UPX Unpack successful! New size: " << unpacked_buffer.size() << " bytes\n";
            active_buffer = std::move(unpacked_buffer);
            was_unpacked = true;
            was_upx_unpacked = true;

            std::string unpacked_path = filepath + ".unpacked.exe";
            std::ofstream out_file(unpacked_path, std::ios::binary);
            if (out_file.is_open()) {
                out_file.write(reinterpret_cast<const char*>(active_buffer.data()), active_buffer.size());
                out_file.close();
                std::cout << "[+] Unpacked binary written to: " << unpacked_path << "\n";
                filepath = unpacked_path;
            }
        } else {
            std::cerr << "[WARNING] UPX unpacking failed. Proceeding with packed binary.\n";
        }
    }
 
    g_license_context.AssertCapability(Bhpai::CAP_STATIC_ANALYSIS, "PE Dissector");

    PeParser parser(active_buffer, filepath);
    if (!parser.is_valid()) {
        std::cerr << "[ERROR] " << parser.get_error() << "\n";
        return false;
    }

    MalwareTraits traits;

    const auto& buffer = parser.get_buffer();
    size_t filesize = buffer.size();

    if (filesize < 0x40) {
        std::cerr << "[ERROR] File too small to be a PE file\n";
        return false;
    }

    auto hashes        = compute_hashes(buffer);
    auto feats         = extract_pe_header_features(buffer);
    feats.version_info = ExtractVersionInfo(filepath);   // Win32 VerQueryValue
    ImportStats import_stats = GetImportStats(buffer, feats);
    DelayImportStats delay_import_stats{};
    size_t tls_callbacks = GetTLSCallbackCount(buffer, feats);

    std::wstring wpath(filepath.begin(), filepath.end());
    bool sig_valid = VerifyDigitalSignature(wpath);
    feats.digital_signature_valid = sig_valid;
    feats.code_ratio = (feats.size_of_image > 0) ? static_cast<double>(feats.size_of_code) / feats.size_of_image : 0.0;

    size_t pe_end = 0;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<uint8_t*>(buffer.data()) + feats.e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < feats.number_of_sections; ++i) {
        size_t sec_end = static_cast<size_t>(sections[i].PointerToRawData) + sections[i].SizeOfRawData;
        pe_end = std::max(pe_end, sec_end);
    }
    size_t overlay_size = (pe_end < filesize) ? filesize - pe_end : 0;

    // === Reloc entropy ===
    double reloc_entropy = 0.0;
    size_t section_table_offset = feats.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (feats.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? sizeof(IMAGE_OPTIONAL_HEADER64) - sizeof(IMAGE_OPTIONAL_HEADER32) : 0);

    for (WORD i = 0; i < feats.number_of_sections; ++i) {
        size_t sec_off = section_table_offset + i * sizeof(IMAGE_SECTION_HEADER);
        if (sec_off + sizeof(IMAGE_SECTION_HEADER) > filesize) break;

        IMAGE_SECTION_HEADER sec{};
        memcpy(&sec, buffer.data() + sec_off, sizeof(sec));

        std::string name(reinterpret_cast<char*>(sec.Name), 8);
        name.erase(std::find(name.begin(), name.end(), '\0'), name.end());

        if (name == ".reloc" && sec.PointerToRawData && sec.SizeOfRawData) {
            size_t raw_size = std::min(static_cast<size_t>(sec.SizeOfRawData),
                                       filesize - static_cast<size_t>(sec.PointerToRawData));
            reloc_entropy = calc_entropy(buffer.data() + sec.PointerToRawData, raw_size);
            break;
        }
    }

    entry_rva = parser.get_entry_point_rva();
    uint64_t image_base = parser.get_image_base();

    ScanResult scan_result = ScanBuffer(buffer, entry_rva);
    if (was_unpacked) {
        if (was_upx_unpacked) {
            scan_result.upx = true;
        } else {
            scan_result.wwpack = true;
        }
        scan_result.score += 40;
    }

    // === API n-grams ===
    ApiCallSequenceResult api_result;
    std::unordered_map<std::string, uint32_t> api_ngrams;
    try {
        api_result = extract_api_call_sequence(parser);
        if (api_result.success) {
            api_ngrams = generate_api_ngrams(api_result.sequence);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[WARNING] API call sequence/n-gram extraction failed: " << e.what() << "\n";
        api_result.success = false;
        api_result.error = API_PARSE_EXCEPTION;
    }

    g_license_context.AssertCapability(Bhpai::CAP_STATIC_ANALYSIS, "Disassembly & Opcode Feature Engine");

    // === Opcode n-grams ===
    std::vector<OpcodeFeature> opcode_features;
    std::unordered_map<std::string, size_t> semantic_histogram;
    try {
        auto suspicious_apis = get_suspicious_apis_lowercase();

        NgramConfig ngram_cfg;
        ngram_cfg.n                = 4;
        ngram_cfg.use_operand_type = true;
        ngram_cfg.max_features     = 250;
        ngram_cfg.boost_multiplier = 4.0;
        ngram_cfg.context_radius   = 96;

        opcode_features = extract_suspicious_opcode_ngrams(
            parser, suspicious_apis, ngram_cfg, &semantic_histogram);
    }
    catch (const std::exception& e) {
        std::cerr << "[WARNING] Opcode n-gram extraction failed: " << e.what() << "\n";
        opcode_features.clear();
    }
    catch (...) {
        std::cerr << "[WARNING] Opcode n-gram extraction failed with unknown error\n";
        opcode_features.clear();
    }
    
    std::cout << "\n=== PE Analysis Report ===\n";
    std::cout << "File:       " << filepath << "\n";
    std::cout << "Size:       " << filesize << " bytes\n";
    std::cout << "MD5:        " << hashes.md5 << "\n";
    std::cout << "SHA256:     " << hashes.sha256 << "\n";
    std::cout << "Fuzzy:      " << hashes.fuzzy << "\n\n";

    std::cout << "Entry Point RVA: 0x" << std::hex << entry_rva << std::dec << "\n";
    std::cout << "Image Base:      0x" << std::hex << image_base << std::dec << "\n";
    std::cout << "VA EP:           0x" << std::hex << (image_base + entry_rva) << std::dec << "\n\n";

    std::cout << "Machine:              0x" << std::hex << feats.machine << std::dec << "\n";
    std::cout << "Number of sections:   " << feats.number_of_sections << "\n";
    std::cout << "Imports:              " << import_stats.total_functions 
              << " functions (" << import_stats.suspicious_count << " suspicious)\n";
    std::cout << "TLS callbacks:        " << tls_callbacks << "\n";
    std::cout << "Overlay:              " << overlay_size << " bytes\n";
    std::cout << "Digital signature:    " << (sig_valid ? "VALID" : "INVALID / NONE") << "\n";

    std::cout << "\n=== API Call Sequence (first 25) ===\n";
    if (api_result.success) {
        for (size_t i = 0; i < std::min<size_t>(25, api_result.sequence.size()); ++i) {
            std::cout << "  " << api_result.sequence[i] << "\n";
        }
        if (api_result.sequence.size() > 25) {
            std::cout << "   ... (" << (api_result.sequence.size() - 25) << " more)\n";
        }
    } else {
        std::cout << "  [!] API parser failed (error=" << static_cast<int>(api_result.error) << ")\n";
    }

    std::cout << "\n=== Top suspicious opcode n-grams (top 15) ===\n";
    size_t show_count = std::min<size_t>(15, opcode_features.size());
    for (size_t i = 0; i < show_count; ++i) {
        const auto& f = opcode_features[i];
        std::cout << std::left << std::setw(60) << f.signature
                  << " count=" << std::setw(6) << f.count
                  << " weight=" << std::fixed << std::setprecision(2) << f.weight
                  << " near_sus=" << f.near_suspicious;
        if (f.first_va != 0) {
            std::cout << "  first@0x" << std::hex << f.first_va;
        }
        std::cout << "\n";
    }
    if (opcode_features.size() > show_count) {
        std::cout << "   ... (" << (opcode_features.size() - show_count) << " more)\n";
    }

    std::cout << "\n=== TF-IDF Opcode Vectorization ===\n";
    static OpcodeTfidfVectorizer tfidf_vectorizer;
    auto tfidf_result = tfidf_vectorizer.extract_and_vectorize(parser);
    std::cout << "Top TF-IDF terms:\n";
    for (size_t i = 0; i < std::min<size_t>(15, tfidf_result.top_terms.size()); ++i) {
        const auto& p = tfidf_result.top_terms[i];
        std::cout << "  " << p.first << " = " << std::fixed << std::setprecision(4) << p.second << "\n";
    }

    std::cout << "\n=== STRING & ENCODING ANALYSIS ===\n";

    nlohmann::json string_analysis = nlohmann::json::object();
    nlohmann::json interesting_strings = nlohmann::json::array();
    nlohmann::json decoded_results = nlohmann::json::array();

    std::vector<std::string> ascii_strings;
    std::vector<std::string> unicode_strings;
    std::vector<std::string> strings;
    std::string current;
    size_t total_string_len = 0;

    // ASCII strings
    check_memory_limit();
    for (uint8_t byte : buffer) {
        if (byte >= 32 && byte <= 126) {
            current += static_cast<char>(byte);
        } else {
            if (current.length() >= 8) {
                total_string_len += current.length();
                ascii_strings.push_back(std::move(current));
                if (ascii_strings.size() >= MAX_SAFE_STRING_COUNT || total_string_len >= MAX_SAFE_TOTAL_STRING_LEN) {
                    current.clear();
                    break;
                }
            }
            current.clear();
        }
    }
    if (current.length() >= 8 && ascii_strings.size() < MAX_SAFE_STRING_COUNT && total_string_len < MAX_SAFE_TOTAL_STRING_LEN) {
        total_string_len += current.length();
        ascii_strings.push_back(std::move(current));
    }
    current.clear();

    // Unicode strings (wide)
    for (size_t i = 0; i + 1 < buffer.size(); i += 2) {
        if (buffer[i] >= 32 && buffer[i] <= 126 && buffer[i + 1] == 0) {
            current += static_cast<char>(buffer[i]);
        } else {
            if (current.length() >= 8) {
                total_string_len += current.length();
                unicode_strings.push_back(std::move(current));
                if (ascii_strings.size() + unicode_strings.size() >= MAX_SAFE_STRING_COUNT || total_string_len >= MAX_SAFE_TOTAL_STRING_LEN) {
                    current.clear();
                    break;
                }
            }
            current.clear();
        }
    }
    if (current.length() >= 8 && (ascii_strings.size() + unicode_strings.size()) < MAX_SAFE_STRING_COUNT && total_string_len < MAX_SAFE_TOTAL_STRING_LEN) {
        total_string_len += current.length();
        unicode_strings.push_back(std::move(current));
    }
    current.clear();

    if (!check_string_limit(ascii_strings.size() + unicode_strings.size(), total_string_len)) {
        std::cerr << "[WARN] String collection was truncated at limit - continuing with "
                  << (ascii_strings.size() + unicode_strings.size()) << " strings.\n";
    }

    safe_reserve(strings, ascii_strings.size() + unicode_strings.size());
    strings.insert(strings.end(), ascii_strings.begin(), ascii_strings.end());
    strings.insert(strings.end(), unicode_strings.begin(), unicode_strings.end());

    StringStats string_stats = ComputeStringStatistics(ascii_strings, unicode_strings);
    InterestingStrings selected_strings = ExtractInterestingStrings(strings);

    std::cout << "Found " << strings.size() << " strings (length >= 8)\n";
    check_memory_limit();

    size_t analyzed = 0;
    const size_t max_analyze = 50;

    for (const auto& s : strings) {
        if (analyzed >= max_analyze) break;
        if (s.length() < 12) continue;

        nlohmann::json str_obj;
        str_obj["string"]   = (s.length() > 200 ? s.substr(0, 197) + "..." : s);
        str_obj["length"]   = s.length();
        str_obj["entropy"]  = calc_entropy(reinterpret_cast<const uint8_t*>(s.data()), s.size());

        str_obj["looks_like_text"] = looks_like_text(s);
        str_obj["is_caesar"]       = is_Caesar(s);
        str_obj["is_base64"]       = is_base64(s);
        str_obj["is_hex"]          = is_hex(s);

        if (is_base64(s)) {
            auto dec_data = decode_base64(s);
            if (!dec_data.empty() && is_printable_ascii(dec_data.data(), dec_data.size())) {
                std::string dec_str(dec_data.begin(), dec_data.end());
                nlohmann::json dec;
                dec["type"] = "base64";
                dec["original"] = s.length() > 150 ? s.substr(0,147)+"..." : s;
                dec["decoded"]  = dec_str;
                dec["length"]   = dec_data.size();
                decoded_results.push_back(dec);
            }
        }
        else if (is_hex(s)) {
            auto dec_data = decode_hex(s);
            if (!dec_data.empty() && is_printable_ascii(dec_data.data(), dec_data.size())) {
                std::string dec_str(dec_data.begin(), dec_data.end());
                nlohmann::json dec;
                dec["type"] = "hex";
                dec["original"] = s.length() > 150 ? s.substr(0,147)+"..." : s;
                dec["decoded"]  = dec_str;
                dec["length"]   = dec_data.size();
                decoded_results.push_back(dec);
            }
        }

        interesting_strings.push_back(str_obj);

        std::cout << "String [" << s.length() << "]: "
                  << (s.length() > 100 ? s.substr(0,97)+"..." : s) << "\n";
        analyze_string(s, 0);
        std::cout << "────────────────────────────────────\n";

        analyzed++;
        check_memory_limit();
    }

    nlohmann::json cfg_json = nlohmann::json::object();
    if (feats.address_of_entry_point != 0) {
        std::cout << "\nBuilding Control Flow Graph near Entry Point...\n";
        auto instructions = PDAR(buffer, feats, feats.address_of_entry_point, 768, 220);
        ControlFlowGraph cfg;
        if (cfg.build(instructions, feats.image_base + feats.address_of_entry_point)) {
            size_t unreachable_count = cfg.count_unreachable();
            size_t loop_count = cfg.count_loops();
            std::cout << "CFG analysis: " << cfg.get_blocks().size() << " basic blocks, "
                      << unreachable_count << " unreachable, "
                      << loop_count << " loops detected.\n";
            cfg_json = cfg.extract_features();
            cfg_json["build_success"] = true;
        } else {
            std::cout << "[!] Failed to build CFG.\n";
            cfg_json["build_success"] = false;
            cfg_json["error"] = "CFG build failed";
        }
    }

    nlohmann::json behavioral_graph_json = nlohmann::json::object();
    try {
        BehavioralGraphBuilder bg_builder;
        auto susp_apis = get_suspicious_apis_lowercase();
        if (bg_builder.build(parser, feats, buffer, susp_apis)) {
            behavioral_graph_json = bg_builder.to_json();
            behavioral_graph_json["build_success"] = true;
        } else {
            behavioral_graph_json["build_success"] = false;
        }
    } catch (const std::exception& ex) {
        std::cerr << "[!] Exception building BehavioralGraph: " << ex.what() << "\n";
        behavioral_graph_json["build_success"] = false;
    }

    // === CBPRA: Cross-Binary Pointer Resolution Analysis ===
    nlohmann::json cbpra_json = nlohmann::json::object();
    try {
        Disassembler cbpra_disasm;
        if (cbpra_disasm.initialize(parser.is_64bit())) {
            auto cbpra = extract_cbpra_features(parser, cbpra_disasm);
            cbpra_json["total_candidates"]       = cbpra.total_candidates;
            cbpra_json["aligned_candidates"]     = cbpra.aligned_candidates;
            cbpra_json["non_insn_candidates"]    = cbpra.non_insn_candidates;
            cbpra_json["low_entropy_candidates"]  = cbpra.low_entropy_candidates;

            cbpra_json["reloc_confirmed"]         = cbpra.reloc_confirmed;
            cbpra_json["iat_confirmed"]           = cbpra.iat_confirmed;
            cbpra_json["tls_confirmed"]           = cbpra.tls_confirmed;
            cbpra_json["pdata_confirmed"]         = cbpra.pdata_confirmed;
            cbpra_json["points_to_code"]          = cbpra.points_to_executable;

            cbpra_json["chain_depth1_count"]      = cbpra.chain_depth1_count;
            cbpra_json["chain_depth2_count"]      = cbpra.chain_depth2_count;
            cbpra_json["chain_depth3_plus_count"] = cbpra.chain_depth3_plus_count;
            cbpra_json["max_chain_depth"]         = cbpra.max_chain_depth;
            cbpra_json["vtable_candidate_count"]  = cbpra.vtable_candidate_count;
            cbpra_json["graph_node_count"]        = cbpra.graph_node_count;
            cbpra_json["graph_edge_count"]        = cbpra.graph_edge_count;

            cbpra_json["cross_section"]           = cbpra.cross_section_pointers;
            cbpra_json["cross_ratio"]             = cbpra.cross_section_ratio;
            cbpra_json["aligned_ratio"]           = cbpra.aligned_ratio;
            cbpra_json["reloc_ratio"]             = cbpra.reloc_ratio;
            cbpra_json["code_pointer_ratio"]      = cbpra.code_pointer_ratio;
            cbpra_json["chain_depth2_plus_ratio"] = cbpra.chain_depth2_plus_ratio;
            cbpra_json["residual_entropy_mean"]   = cbpra.residual_entropy_mean;
            cbpra_json["residual_entropy_stddev"] = cbpra.residual_entropy_stddev;
            cbpra_json["section_pairs"]           = cbpra.section_pair_count;
            cbpra_json["build_success"]          = true;

            std::cout << "\n=== CBPRA Analysis ==="
                      << "\n  Total candidates:      " << cbpra.total_candidates
                      << "\n  Reloc confirmed:       " << cbpra.reloc_confirmed
                      << "\n  IAT confirmed:         " << cbpra.iat_confirmed
                      << "\n  TLS confirmed:         " << cbpra.tls_confirmed
                      << "\n  .pdata confirmed:      " << cbpra.pdata_confirmed
                      << "\n  Points to code:        " << cbpra.points_to_executable
                      << "\n  Chain depth 1 (P->Code):" << cbpra.chain_depth1_count
                      << "\n  Chain depth 2 (P->P->C):" << cbpra.chain_depth2_count
                      << "\n  Chain depth 3+ (P...C):" << cbpra.chain_depth3_plus_count
                      << "\n  VTable candidates:     " << cbpra.vtable_candidate_count
                      << "\n  Graph nodes/edges:     " << cbpra.graph_node_count << " / " << cbpra.graph_edge_count
                      << "\n  Cross-section:         " << cbpra.cross_section_pointers
                      << "\n  Residual entropy mean: " << cbpra.residual_entropy_mean
                      << "\n";
        } else {
            cbpra_json["build_success"] = false;
            cbpra_json["error"] = "Disassembler init failed";
        }
    } catch (const std::exception& ex) {
        std::cerr << "[!] Exception in CBPRA: " << ex.what() << "\n";
        cbpra_json["build_success"] = false;
        cbpra_json["error"] = ex.what();
    }

    string_analysis["total_strings_found"] = strings.size();
    string_analysis["analyzed"]            = analyzed;
    string_analysis["interesting_strings"] = std::move(interesting_strings);
    string_analysis["string_stats"] = {
        {"total", string_stats.total_strings},
        {"ascii_count", string_stats.ascii_strings},
        {"unicode_count", string_stats.unicode_strings},
        {"avg_length", string_stats.avg_length},
        {"median_length", string_stats.median_length},
        {"avg_entropy", string_stats.avg_entropy},
        {"printable_ratio", string_stats.printable_ratio},
        {"unicode_ratio", string_stats.unicode_ratio}
    };
    string_analysis["selected_strings"] = {
        {"ips", selected_strings.ips},
        {"domains", selected_strings.domains},
        {"urls", selected_strings.urls},
        {"registry_paths", selected_strings.registry_paths},
        {"mutexes", selected_strings.mutexes},
        {"file_paths", selected_strings.file_paths},
        {"emails", selected_strings.emails},
        {"crypto_constants", selected_strings.crypto_constants}
    };
    if (!decoded_results.empty()) {
        string_analysis["decoded_results"] = std::move(decoded_results);
    }

    if (overlay_size > 64) {
        std::cout << "\n[!] Overlay detected (" << overlay_size 
                  << " bytes). Running brute-force XOR scan...\n";
        std::vector<uint8_t> overlay(buffer.begin() + pe_end, buffer.end());
        brute_xor_all(overlay);
    }

    std::cout << "\n=== STRING ANALYSIS COMPLETED ===\n";

    std::cout << "\nSections:\n";
    std::cout << std::left << std::setw(12) << "Name"
              << std::setw(14) << "Entropy"
              << std::setw(14) << "Raw Size"
              << "Status\n";

    double max_ent = 0.0;
    std::vector<nlohmann::json> section_list;
    std::set<std::string> seen_names;
    WORD num_sec = static_cast<WORD>(std::min<size_t>(feats.number_of_sections, 96));

    for (WORD i = 0; i < num_sec; ++i) {
        size_t sec_off = section_table_offset + i * sizeof(IMAGE_SECTION_HEADER);
        if (sec_off + sizeof(IMAGE_SECTION_HEADER) > filesize) break;

        IMAGE_SECTION_HEADER sec{};
        memcpy(&sec, buffer.data() + sec_off, sizeof(sec));

        std::string name(reinterpret_cast<char*>(sec.Name), 8);
        name.erase(std::find(name.begin(), name.end(), '\0'), name.end());
        if (name.empty()) name = "(no name)";

        std::string status;
        if (seen_names.count(name)) status += "duplicate ";
        seen_names.insert(name);

        if (name.length() > 8 || name.find_first_not_of("._-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != std::string::npos) {
            status += "invalid_chars ";
        }

        size_t raw_start = sec.PointerToRawData;
        if (raw_start >= filesize || sec.SizeOfRawData == 0) {
            std::cout << std::left << std::setw(12) << name
                      << std::setw(14) << "-" << std::setw(14) << "0"
                      << "No raw data" << (status.empty() ? "" : " [" + status + "]") << "\n";
            continue;
        }

        size_t raw_size = std::min(static_cast<size_t>(sec.SizeOfRawData),
                                   filesize - static_cast<size_t>(raw_start));

        double ent = calc_entropy(buffer.data() + raw_start, raw_size);
        max_ent = std::max(max_ent, ent);

        nlohmann::json sec_json;
        sec_json["name"]          = name;
        sec_json["entropy"]       = ent;
        sec_json["raw_size"]      = raw_size;
        sec_json["virtual_size"]  = sec.Misc.VirtualSize;
        sec_json["characteristics"] = sec.Characteristics;
        section_list.push_back(sec_json);

        std::cout << std::left << std::setw(12) << name
                  << std::fixed << std::setprecision(3) << std::setw(14) << ent
                  << std::setw(14) << raw_size;

        if (ent > 7.2) std::cout << " HIGH ENTROPY (possible packing/obfuscation)";
        if (!status.empty()) std::cout << " [" << status << "]";
        std::cout << "\n";
    }

    if (max_ent > 7.3)
        std::cout << "\n[!] High entropy section(s) detected → may indicate packing, compression, or encryption\n";
    if (overlay_size > 1024 * 1024)
        std::cout << "[!] Large overlay detected (" << overlay_size << " bytes) → possible appended data / dropper\n";
    if (tls_callbacks > 3)
        std::cout << "[!] Unusual number of TLS callbacks (" << tls_callbacks << ") → often used in protectors / anti-debug\n";

    if (feats.address_of_entry_point != 0) {
        std::cout << "\nDisassembling near Entry Point...\n";
        PDAR(buffer, feats, feats.address_of_entry_point, 768, 220);
    }

    for (const auto& api : import_stats.imported_function_names) {
        std::string lower_api = api;
        std::transform(lower_api.begin(), lower_api.end(), lower_api.begin(), ::tolower);

        if (lower_api == "virtualallocex") { traits.api_VirtualAllocEx = true; traits.has_injection = true; }
        if (lower_api == "writeprocessmemory") { traits.api_WriteProcessMemory = true; traits.has_injection = true; }
        if (lower_api == "createremotethread") { traits.api_CreateRemoteThread = true; traits.has_injection = true; }
        if (lower_api == "ntmapviewofsection") { traits.api_NtMapViewOfSection = true; traits.has_injection = true; }
        if (lower_api == "isdebuggerpresent") { traits.api_IsDebuggerPresent = true; traits.has_anti_debug = true; }
        if (lower_api == "checkremotedebuggerpresent") { traits.api_CheckRemoteDebuggerPresent = true; traits.has_anti_debug = true; }
        if (lower_api == "minidumpwritedump") { traits.api_MiniDumpWriteDump = true; traits.has_credential_theft = true; }
    }

    for (const auto& s : strings) {
        if (s.find(".pdb") != std::string::npos && (s.find(":\\") != std::string::npos || s.find("/") != std::string::npos)) {
            traits.found_pdb_paths.push_back(s);
        }
        if (s.find("Software\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos) {
            traits.found_registry_keys.push_back(s);
            traits.has_persistence = true;
        }
        if (s.rfind("http://", 0) == 0 || s.rfind("https://", 0) == 0) {
            traits.found_urls.push_back(s);
            traits.has_networking = true;
        }   
    }

    check_memory_limit();
    try {
        std::string packer_name;
        if (scan_result.upx) {
            packer_name = "upx";
        } else if (scan_result.wwpack) {
            packer_name = "wwpack";
        } else if (scan_result.fsg) {
            packer_name = "fsg";
        }

        std::vector<uint8_t> entry_point_bytes;
        if (feats.address_of_entry_point != 0) {
            uint64_t entry_va = feats.image_base + feats.address_of_entry_point;
            for (const auto& sec : parser.get_executable_sections()) {
                if (entry_va >= sec.virtual_address && entry_va < sec.virtual_address + sec.raw_size) {
                    size_t offset = static_cast<size_t>(sec.raw_offset + (entry_va - sec.virtual_address));
                    size_t avail = std::min<size_t>(32, buffer.size() > offset ? buffer.size() - offset : 0);
                    entry_point_bytes.insert(entry_point_bytes.end(), buffer.begin() + offset, buffer.begin() + offset + avail);
                    break;
                }
            }
        }

        YaraGenerator yara_gen;
        YaraRule yara_rule = yara_gen.generate(filepath, feats, import_stats, opcode_features, strings, selected_strings, entry_point_bytes, hashes, packer_name);
        std::string yara_text = yara_gen.generate_rule_string(yara_rule);
        std::string yara_filename = filepath + ".yar";
        std::ofstream yara_file(yara_filename);
        if (yara_file.is_open()) {
            yara_file << yara_text << "\n";
            yara_file.close();
            std::cout << "YARA rule written to: " << yara_filename << "\n";
        } else {
            std::cerr << "[ERROR] Failed to write YARA rule: " << yara_filename << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception occurred while generating YARA rule: " << e.what() << "\n";
    }
    std::cout << "\n=== ANALYSIS COMPLETED ===\n";

    auto byte_feats = extract_byte_level_features(buffer);
    auto export_stats = GetExportStats(buffer, feats);

    auto json_out = features_to_json(feats, hashes, filepath, filesize,
                                     import_stats, delay_import_stats,
                                     tls_callbacks, reloc_entropy,
                                     overlay_size, sig_valid,
                                     byte_feats, export_stats);

    json_out["opcode_ngrams"]     = opcode_features_to_json(opcode_features, 0);
    json_out["semantic_group_histogram"] = semantic_histogram;
    json_out["CFG"] = std::move(cfg_json);
    json_out["behavioral_graph"] = std::move(behavioral_graph_json);
    json_out["cbpra"] = std::move(cbpra_json);

    // === BHPAI-SE: Native C++ Symbolic Execution Engine (Enterprise Feature) ===
    nlohmann::json se_json = nlohmann::json::object();
    se_json["enabled"] = false;
    se_json["execution_status"] = "community_edition_standalone";
    json_out["se"] = se_json;
    json_out["symbolic_execution"] = se_json; // backward compatibility

    // === API parser metadata & derived features ===
    json_out["api_parser_success"] = api_result.success;
    json_out["api_parser_error"]   = static_cast<int>(api_result.error);

    if (api_result.success) {
        json_out["api_seq_length"] = static_cast<int>(api_result.sequence.size());
        json_out["api_sequence"]   = api_result.sequence;

        // api_unique_calls
        std::unordered_set<std::string> unique_apis(
            api_result.sequence.begin(), api_result.sequence.end());
        int unique_count = static_cast<int>(unique_apis.size());
        int total_count  = static_cast<int>(api_result.sequence.size());
        json_out["api_unique_calls"] = unique_count;

        // api_repeat_ratio = 1 - unique / total
        double repeat_ratio = 1.0 - static_cast<double>(unique_count) / std::max(1, total_count);
        json_out["api_repeat_ratio"] = repeat_ratio;
    } else {
        json_out["api_seq_length"]   = -1;
        json_out["api_sequence"]     = nlohmann::json::array();
        json_out["api_unique_calls"] = -1;
        json_out["api_repeat_ratio"] = -1.0;
    }

    nlohmann::json api_ngrams_json = nlohmann::json::object();
    for (const auto& [ngram, count] : api_ngrams) {
        api_ngrams_json[ngram] = count;
    }
    json_out["api_ngrams"] = api_ngrams_json;

    nlohmann::json top_ngrams = nlohmann::json::array();
    for (size_t i = 0; i < std::min<size_t>(30, opcode_features.size()); ++i) {
        const auto& f = opcode_features[i];
        nlohmann::json ngram;
        ngram["signature"]      = f.signature;
        ngram["count"]          = f.count;
        ngram["weight"]         = f.weight;
        ngram["near_suspicious"] = f.near_suspicious;
        ngram["first_va"]       = f.first_va;
        top_ngrams.push_back(ngram);
    }
    json_out["top_suspicious_ngrams"] = std::move(top_ngrams);
    json_out["opcode_tfidf"] = tfidf_result.to_json(50);
    json_out["disassembly_near_ep"] = capture_disassembly_for_json(buffer, feats, feats.address_of_entry_point, 768, 220);
    json_out["string_stats"] = string_analysis["string_stats"];
    json_out["interesting_strings"] = string_analysis["selected_strings"];
    json_out["string_analysis"]   = std::move(string_analysis);
    json_out["sections"]          = std::move(section_list);
    json_out["label"]             = label;                    // "malware" or "benign"
    json_out["analysis_timestamp"]= std::time(nullptr);
    json_out["filename"]          = filepath;
    json_out["is_upx"]            = scan_result.upx;
    json_out["is_fsg"]            = scan_result.fsg;
    json_out["is_wwpack"]         = scan_result.wwpack;
    json_out["score"]             = scan_result.score;

    g_license_context.AssertCapability(Bhpai::CAP_REPORT_EXPORT, "JSON Telemetry Export");

    std::string json_str = json_out.dump(2);

    std::cerr << json_str << "\n";

    std::string json_filename = filepath + ".json";
    std::ofstream json_file(json_filename);
    if (json_file.is_open()) {
        json_file << json_str << "\n";
        json_file.close();
        std::cout << "Clean JSON written to: " << json_filename << "\n";
    } else {
        std::cerr << "[ERROR] Failed to write JSON: " << json_filename << "\n";
    }

    return true;
    } catch (const MemoryLimitExceeded& e) {
        std::cerr << "\n[!] " << e.what() << "\n";
        return false;
    }
}

int main(int argc, char** argv)
{
    g_license_context = Bhpai::BhpaiLicense::AcquireContext("pe_analyzer", "", "BHPAI PE Static Analyzer");

    std::string filepath;
    std::string label = "unknown";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--safe-run") {
            g_safe_run = true;
        } else if (filepath.empty()) {
            filepath = arg;
        } else if (label == "unknown") {
            label = arg;
        }
    }

    if (filepath.empty()) {
        std::cerr << "Usage: pe_analyzer <path_to_pe_file> [label] [--safe-run]\n";
        std::cerr << "Example: pe_analyzer sample.exe malware --safe-run\n";
        return 1;
    }

    std::cout << "-----------------------------------------\n";
    std::cout << "Analyzing: " << filepath << " (label: " << label << ")";
    if (g_safe_run) {
        std::cout << " [SAFE-RUN MODE ENABLED]";
    }
    std::cout << "\n-----------------------------------------\n";
    init_printable();
    if (!analyze_pe(filepath, label)) {
        return 1;
    }

    return 0;
}