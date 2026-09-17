#include "FileRouter.hpp"
#include <fstream>
#include <algorithm>
#include <cstring>
#include <cctype>

namespace BHPAI {

static std::string GetFileExtension(const std::string& filename) {
    auto pos = filename.find_last_of('.');
    if (pos == std::string::npos) return "";
    std::string ext = filename.substr(pos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext;
}

std::string FileRouter::FormatToString(FileFormat fmt) {
    switch (fmt) {
        case FileFormat::PE: return "PE Executable (Windows)";
        case FileFormat::PDF: return "PDF Document";
        case FileFormat::OOXML_DOCX: return "Microsoft Word Document (DOCX)";
        case FileFormat::OOXML_XLSX: return "Microsoft Excel Spreadsheet (XLSX)";
        case FileFormat::OOXML_PPTX: return "Microsoft PowerPoint Presentation (PPTX)";
        case FileFormat::OLE2: return "OLE2 Compound Document (DOC/XLS/PPT)";
        case FileFormat::SCRIPT_POWERSHELL: return "PowerShell Script";
        case FileFormat::SCRIPT_VBSCRIPT: return "VBScript Payload";
        case FileFormat::SCRIPT_JAVASCRIPT: return "JavaScript / JScript Payload";
        case FileFormat::SCRIPT_BATCH: return "Windows Batch Script";
        case FileFormat::SCRIPT_HTA: return "HTML Application (HTA)";
        case FileFormat::SCRIPT_SHELL: return "Unix Shell Script";
        case FileFormat::ARCHIVE_ZIP: return "ZIP Archive";
        case FileFormat::ARCHIVE_7Z: return "7-Zip Archive";
        case FileFormat::ARCHIVE_RAR: return "RAR Archive";
        case FileFormat::ARCHIVE_TAR: return "TAR Archive";
        default: return "Unknown";
    }
}

// -----------------------------------------------------------------------------
// Stage 1: Fast Magic Byte Detection
// -----------------------------------------------------------------------------
FileFormatInfo FileRouter::Stage1_MagicDetection(const uint8_t* data, size_t size) {
    FileFormatInfo info;
    if (!data || size < 2) return info;

    // 1. PDF: %PDF- (with 1024-byte tolerance for preamble/BOM)
    size_t pdf_limit = std::min<size_t>(size, 1024);
    for (size_t i = 0; i + 4 < pdf_limit; ++i) {
        if (data[i] == '%' && data[i+1] == 'P' && data[i+2] == 'D' && data[i+3] == 'F' && data[i+4] == '-') {
            info.format = FileFormat::PDF;
            info.format_name = "PDF Document";
            info.mime_type = "application/pdf";
            info.detected_magic = "%PDF-";
            info.magic_offset = i;
            return info;
        }
    }

    // 2. PE: MZ
    if (data[0] == 'M' && data[1] == 'Z') {
        bool is_pe = true;
        if (size >= 64) {
            uint32_t pe_offset = *reinterpret_cast<const uint32_t*>(data + 0x3C);
            if (pe_offset + 4 <= size) {
                is_pe = (data[pe_offset] == 'P' && data[pe_offset+1] == 'E' &&
                         data[pe_offset+2] == 0 && data[pe_offset+3] == 0);
            }
        }
        if (is_pe) {
            info.format = FileFormat::PE;
            info.format_name = "PE Executable (Windows)";
            info.mime_type = "application/x-dosexec";
            info.detected_magic = "MZ";
            info.magic_offset = 0;
            return info;
        }
    }

    // 3. PK ZIP container: PK\x03\x04
    if (size >= 4 && data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04) {
        info.format = FileFormat::ARCHIVE_ZIP;
        info.format_name = "ZIP Archive Container";
        info.mime_type = "application/zip";
        info.detected_magic = "PK\\x03\\x04";
        info.magic_offset = 0;
        return info;
    }

    // 4. OLE2 Compound File: \xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1
    if (size >= 8 &&
        data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0 &&
        data[4] == 0xA1 && data[5] == 0xB1 && data[6] == 0x1A && data[7] == 0xE1) {
        info.format = FileFormat::OLE2;
        info.format_name = "OLE2 Compound Document (DOC/XLS/PPT)";
        info.mime_type = "application/x-ole-storage";
        info.detected_magic = "\\xD0\\xCF\\x11\\xE0";
        info.magic_offset = 0;
        return info;
    }

    // 5. 7-Zip: 7z\xBC\xAF\x27\x1C
    if (size >= 6 && data[0] == '7' && data[1] == 'z' && data[2] == 0xBC &&
        data[3] == 0xAF && data[4] == 0x27 && data[5] == 0x1C) {
        info.format = FileFormat::ARCHIVE_7Z;
        info.format_name = "7-Zip Archive";
        info.mime_type = "application/x-7z-compressed";
        info.detected_magic = "7z";
        info.magic_offset = 0;
        return info;
    }

    // 6. RAR: Rar!\x1A\x07
    if (size >= 7 && data[0] == 'R' && data[1] == 'a' && data[2] == 'r' &&
        data[3] == '!' && data[4] == 0x1A && data[5] == 0x07) {
        info.format = FileFormat::ARCHIVE_RAR;
        info.format_name = "RAR Archive";
        info.mime_type = "application/x-rar-compressed";
        info.detected_magic = "Rar!";
        info.magic_offset = 0;
        return info;
    }

    // 7. Shebang: #!
    if (size >= 2 && data[0] == '#' && data[1] == '!') {
        info.format = FileFormat::SCRIPT_SHELL;
        info.format_name = "Unix Shell Script";
        info.mime_type = "text/x-shellscript";
        info.detected_magic = "#!";
        info.magic_offset = 0;
        return info;
    }

    return info;
}

// -----------------------------------------------------------------------------
// Stage 2: Container Inspection (Parsing Local Headers & Central Directory)
// -----------------------------------------------------------------------------
FileFormatInfo FileRouter::Stage2_ContainerInspection(const uint8_t* data, size_t size, FileFormatInfo current_info) {
    if (current_info.format != FileFormat::ARCHIVE_ZIP || size < 30) {
        return current_info;
    }

    std::vector<std::string> entries;
    size_t offset = 0;
    size_t max_scan = std::min<size_t>(size, 500000); // Scan first 500KB of ZIP headers

    // Parse local file headers: PK\x03\x04
    while (offset + 30 <= max_scan && entries.size() < 100) {
        if (data[offset] == 0x50 && data[offset+1] == 0x4B &&
            data[offset+2] == 0x03 && data[offset+3] == 0x04) {
            uint16_t name_len = *reinterpret_cast<const uint16_t*>(data + offset + 26);
            uint16_t extra_len = *reinterpret_cast<const uint16_t*>(data + offset + 28);

            if (offset + 30 + name_len <= size) {
                std::string entry_name(reinterpret_cast<const char*>(data + offset + 30), name_len);
                entries.push_back(entry_name);
                offset += 30 + name_len + extra_len;
                continue;
            }
        }
        offset++;
    }

    current_info.container_entries = entries;

    // Check for OOXML entry paths
    bool has_content_types = false;
    bool has_word = false;
    bool has_xl = false;
    bool has_ppt = false;

    for (const auto& entry : entries) {
        std::string lower = entry;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower.find("[content_types].xml") != std::string::npos) has_content_types = true;
        if (lower.find("word/document.xml") != std::string::npos || lower.find("word/") == 0) has_word = true;
        if (lower.find("xl/workbook.xml") != std::string::npos || lower.find("xl/") == 0) has_xl = true;
        if (lower.find("ppt/presentation.xml") != std::string::npos || lower.find("ppt/") == 0) has_ppt = true;
    }

    if (has_word) {
        current_info.format = FileFormat::OOXML_DOCX;
        current_info.format_name = "Microsoft Word Document (DOCX)";
        current_info.mime_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    } else if (has_xl) {
        current_info.format = FileFormat::OOXML_XLSX;
        current_info.format_name = "Microsoft Excel Spreadsheet (XLSX)";
        current_info.mime_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    } else if (has_ppt) {
        current_info.format = FileFormat::OOXML_PPTX;
        current_info.format_name = "Microsoft PowerPoint Presentation (PPTX)";
        current_info.mime_type = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    } else if (has_content_types) {
        current_info.format = FileFormat::OOXML_DOCX; // Default OOXML container
        current_info.format_name = "Office Open XML Container";
        current_info.mime_type = "application/vnd.openxmlformats-officedocument";
    }

    return current_info;
}

// -----------------------------------------------------------------------------
// Stage 3: Content-Based Script Classifier (For Scripts Without Shebangs)
// -----------------------------------------------------------------------------
FileFormatInfo FileRouter::Stage3_ContentClassifier(const uint8_t* data, size_t size, const std::string& filename) {
    FileFormatInfo info;
    if (!data || size == 0) return info;

    std::string ext = GetFileExtension(filename);

    // Sample first 8KB of text
    size_t sample_len = std::min<size_t>(size, 8192);
    // Check if data is text (majority printable or whitespace)
    size_t printable = 0;
    for (size_t i = 0; i < sample_len; ++i) {
        if (std::isprint(data[i]) || std::isspace(data[i])) printable++;
    }
    double text_ratio = static_cast<double>(printable) / static_cast<double>(sample_len);
    if (text_ratio < 0.85) {
        return info; // Likely binary, not a script
    }

    std::string content(reinterpret_cast<const char*>(data), sample_len);
    std::string lower = content;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // 1. HTA Detection
    if (lower.find("<hta:application") != std::string::npos ||
        (lower.find("<html") != std::string::npos && lower.find("<script") != std::string::npos && ext == ".hta")) {
        info.format = FileFormat::SCRIPT_HTA;
        info.format_name = "HTML Application (HTA)";
        info.mime_type = "application/hta";
        info.detected_script_type = "HTA";
        return info;
    }

    // 2. PowerShell Detection
    if (lower.find("invoke-expression") != std::string::npos ||
        lower.find("downloadstring") != std::string::npos ||
        lower.find("-executionpolicy") != std::string::npos ||
        lower.find("powershell.exe") != std::string::npos ||
        lower.find("[convert]::frombase64string") != std::string::npos ||
        lower.find("new-object net.webclient") != std::string::npos ||
        ext == ".ps1" || ext == ".psm1") {
        info.format = FileFormat::SCRIPT_POWERSHELL;
        info.format_name = "PowerShell Script";
        info.mime_type = "application/x-powershell";
        info.detected_script_type = "PowerShell";
        return info;
    }

    // 3. VBScript Detection
    if (lower.find("wscript.shell") != std::string::npos ||
        lower.find("createobject(\"wscript") != std::string::npos ||
        lower.find("on error resume next") != std::string::npos ||
        lower.find("wscript.sleep") != std::string::npos ||
        ext == ".vbs" || ext == ".vbe") {
        info.format = FileFormat::SCRIPT_VBSCRIPT;
        info.format_name = "VBScript Payload";
        info.mime_type = "text/vbscript";
        info.detected_script_type = "VBScript";
        return info;
    }

    // 4. JScript / JavaScript Detection
    if (lower.find("activexobject") != std::string::npos ||
        lower.find("wscript.createobject") != std::string::npos ||
        (lower.find("eval(") != std::string::npos && lower.find("unescape(") != std::string::npos) ||
        ext == ".js" || ext == ".jse") {
        info.format = FileFormat::SCRIPT_JAVASCRIPT;
        info.format_name = "JavaScript / JScript Payload";
        info.mime_type = "application/javascript";
        info.detected_script_type = "JavaScript";
        return info;
    }

    // 5. Windows Batch Script Detection
    if (lower.find("@echo off") != std::string::npos ||
        lower.find("setlocal") != std::string::npos ||
        (lower.find("cmd.exe") != std::string::npos && lower.find("%") != std::string::npos) ||
        ext == ".bat" || ext == ".cmd") {
        info.format = FileFormat::SCRIPT_BATCH;
        info.format_name = "Windows Batch Script";
        info.mime_type = "application/x-bat";
        info.detected_script_type = "Batch";
        return info;
    }

    return info;
}

FileFormatInfo FileRouter::DetectFormat(const uint8_t* data, size_t size, const std::string& filename) {
    FileFormatInfo info;
    if (!data || size == 0) return info;

    std::string ext = GetFileExtension(filename);

    // Stage 1: Magic byte inspection
    info = Stage1_MagicDetection(data, size);

    // Stage 2: Container inspection if ZIP
    if (info.format == FileFormat::ARCHIVE_ZIP) {
        info = Stage2_ContainerInspection(data, size, info);
    }

    // Stage 3: Content-based script classifier if unknown or text
    if (info.format == FileFormat::UNKNOWN || info.format == FileFormat::SCRIPT_SHELL) {
        FileFormatInfo script_info = Stage3_ContentClassifier(data, size, filename);
        if (script_info.format != FileFormat::UNKNOWN) {
            info = script_info;
        }
    }

    // Extension mismatch check
    if (!ext.empty()) {
        if (info.format == FileFormat::PE && ext != ".exe" && ext != ".dll" && ext != ".sys" && ext != ".scr" && ext != ".ocx") {
            info.extension_mismatch = true;
        } else if (info.format == FileFormat::PDF && ext != ".pdf") {
            info.extension_mismatch = true;
        } else if (info.format == FileFormat::OOXML_DOCX && ext != ".docx" && ext != ".docm") {
            info.extension_mismatch = true;
        }
    }

    return info;
}

FileFormatInfo FileRouter::DetectFormatFromFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        FileFormatInfo err;
        err.format_name = "File Not Found";
        return err;
    }

    std::vector<uint8_t> buffer(65536); // Read up to 64KB for container and magic inspection
    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    std::streamsize bytes_read = file.gcount();
    buffer.resize(static_cast<size_t>(bytes_read));

    return DetectFormat(buffer.data(), buffer.size(), filepath);
}

} // namespace BHPAI
