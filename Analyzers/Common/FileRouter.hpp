#ifndef BHPAI_FILE_ROUTER_HPP
#define BHPAI_FILE_ROUTER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace BHPAI {

enum class FileFormat {
    UNKNOWN = 0,
    PE,
    PDF,
    OOXML_DOCX,
    OOXML_XLSX,
    OOXML_PPTX,
    OLE2,
    SCRIPT_POWERSHELL,
    SCRIPT_VBSCRIPT,
    SCRIPT_JAVASCRIPT,
    SCRIPT_BATCH,
    SCRIPT_HTA,
    SCRIPT_SHELL,
    ARCHIVE_ZIP,
    ARCHIVE_7Z,
    ARCHIVE_RAR,
    ARCHIVE_TAR
};

struct FileFormatInfo {
    FileFormat format = FileFormat::UNKNOWN;
    std::string format_name = "Unknown";
    std::string mime_type = "application/octet-stream";
    std::string detected_magic;
    size_t magic_offset = 0;
    bool extension_mismatch = false;
    std::vector<std::string> container_entries;
    std::string detected_script_type;
};

class FileRouter {
public:
    static FileFormatInfo DetectFormat(const uint8_t* data, size_t size, const std::string& filename = "");
    static FileFormatInfo DetectFormatFromFile(const std::string& filepath);
    static std::string FormatToString(FileFormat fmt);

private:
    // 3-Stage Pipeline
    static FileFormatInfo Stage1_MagicDetection(const uint8_t* data, size_t size);
    static FileFormatInfo Stage2_ContainerInspection(const uint8_t* data, size_t size, FileFormatInfo current_info);
    static FileFormatInfo Stage3_ContentClassifier(const uint8_t* data, size_t size, const std::string& filename);
};

} // namespace BHPAI

#endif // BHPAI_FILE_ROUTER_HPP
