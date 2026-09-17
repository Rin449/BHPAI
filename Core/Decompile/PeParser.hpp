#ifndef PE_PARSER_HPP
#define PE_PARSER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <unordered_set>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#else
#pragma pack(push, 1)

struct IMAGE_DOS_HEADER {
    uint16_t e_magic;           // MZ
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

#define IMAGE_NT_SIGNATURE          0x00004550  // "PE\0\0"

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

#define IMAGE_FILE_MACHINE_I386     0x014c
#define IMAGE_FILE_MACHINE_AMD64    0x8664

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;                     // 0x10B
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;                     // 0x20B
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_SECTION_HEADER {
    uint8_t  Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
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

#endif // _WIN32

#pragma pack(push, 1)
struct PeBaseRelocation {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
};

struct PeRuntimeFunction {
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t UnwindInfoAddress;
};

struct PeImportDescriptor {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

struct PeTlsDirectory32 {
    uint32_t StartAddressOfRawData;
    uint32_t EndAddressOfRawData;
    uint32_t AddressOfIndex;
    uint32_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

struct PeTlsDirectory64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};
#pragma pack(pop)

#ifndef IMAGE_SCN_CNT_CODE
#define IMAGE_SCN_CNT_CODE                  0x00000020
#define IMAGE_SCN_MEM_EXECUTE               0x20000000
#define IMAGE_SCN_MEM_READ                  0x40000000
#define IMAGE_SCN_MEM_WRITE                 0x80000000
#endif

#ifndef IMAGE_DIRECTORY_ENTRY_EXPORT
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define IMAGE_DIRECTORY_ENTRY_TLS             9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
#endif

struct SectionInfo {
    std::string name;
    uint64_t    virtual_address;     // RVA + ImageBase
    uint64_t    raw_offset;
    uint64_t    raw_size;
    uint32_t    virtual_size;        // Virtual size in memory
    uint32_t    characteristics;
    bool        is_executable() const;
};

class PeParser {
public:
    explicit PeParser(const std::string& filepath);
    PeParser(const std::vector<uint8_t>& buffer, const std::string& filepath);
    ~PeParser() = default;

    bool is_valid() const { return valid_; }
    std::string get_error() const { return error_msg_; }

    bool is_64bit() const { return is_64bit_; }
    uint64_t get_image_base() const { return image_base_; }
    uint32_t get_entry_point_rva() const { return entry_point_rva_; }
    uint32_t get_size_of_image() const { return size_of_image_; }

    const std::vector<SectionInfo>& get_all_sections() const {
        return all_sections_;
    }

    const std::vector<SectionInfo>& get_executable_sections() const {
        return executable_sections_;
    }

    const std::vector<uint8_t>& get_buffer() const { return buffer_; }

    // Table queries
    bool is_reloc_rva(uint64_t rva) const;
    bool is_iat_rva(uint64_t rva) const;
    bool is_tls_rva(uint64_t rva) const;
    bool is_pdata_code_rva(uint64_t rva) const;

    const SectionInfo* find_section_by_rva(uint64_t rva) const;
    const SectionInfo* find_section_by_offset(uint64_t offset) const;
    uint64_t rva_to_file_offset(uint64_t rva) const;
    uint64_t file_offset_to_rva(uint64_t offset) const;

    const std::unordered_set<uint64_t>& get_reloc_rvas() const { return reloc_rvas_; }
    const std::unordered_set<uint64_t>& get_iat_rvas() const { return iat_rvas_; }
    const std::unordered_set<uint64_t>& get_tls_rvas() const { return tls_rvas_; }
    const std::vector<std::pair<uint32_t, uint32_t>>& get_pdata_functions() const { return pdata_functions_; }

private:
    bool parse();
    void parse_data_directories(const IMAGE_DATA_DIRECTORY* data_dirs, uint32_t count);

    std::string filepath_;
    std::vector<uint8_t> buffer_;
    bool valid_ = false;
    std::string error_msg_;

    bool is_64bit_ = false;
    uint64_t image_base_ = 0;
    uint32_t entry_point_rva_ = 0;
    uint32_t size_of_image_ = 0;

    std::vector<SectionInfo> all_sections_;
    std::vector<SectionInfo> executable_sections_;

    std::unordered_set<uint64_t> reloc_rvas_;
    std::unordered_set<uint64_t> iat_rvas_;
    std::unordered_set<uint64_t> tls_rvas_;
    std::vector<std::pair<uint32_t, uint32_t>> pdata_functions_;
};

#endif // PE_PARSER_HPP