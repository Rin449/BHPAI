#include "PeParser.hpp"
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <cstring>

bool SectionInfo::is_executable() const {
    return (characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0;
}

PeParser::PeParser(const std::string& filepath) : filepath_(filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        error_msg_ = "Cannot open file: " + filepath;
        return;
    }

    size_t size = file.tellg();
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        error_msg_ = "File too small";
        return;
    }

    buffer_.resize(size);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer_.data()), size);
    file.close();

    valid_ = parse();
}

PeParser::PeParser(const std::vector<uint8_t>& buffer, const std::string& filepath)
    : filepath_(filepath), buffer_(buffer) {
    valid_ = parse();
}

bool PeParser::parse() {
    if (buffer_.size() < sizeof(IMAGE_DOS_HEADER)) {
        error_msg_ = "File too small for DOS header";
        return false;
    }

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer_.data());
    if (dos->e_magic != 0x5A4D) { // MZ
        error_msg_ = "Not a DOS MZ executable";
        return false;
    }

    if (dos->e_lfanew < 0 || static_cast<size_t>(dos->e_lfanew) >= buffer_.size() - sizeof(uint32_t)) {
        error_msg_ = "Invalid e_lfanew offset";
        return false;
    }

    auto* nt_sig = reinterpret_cast<const uint32_t*>(buffer_.data() + dos->e_lfanew);
    if (*nt_sig != IMAGE_NT_SIGNATURE) {
        error_msg_ = "Not a PE file (missing PE signature)";
        return false;
    }

    size_t nt_offset = dos->e_lfanew;
    auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(buffer_.data() + nt_offset + 4);

    is_64bit_ = (file_hdr->Machine == IMAGE_FILE_MACHINE_AMD64);

    if (file_hdr->Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "[DEBUG] Machine type: 0x" << std::hex << file_hdr->Machine << std::dec << "\n";
    }
    const size_t opt_offset = nt_offset + 4 + sizeof(IMAGE_FILE_HEADER);
    if (opt_offset + file_hdr->SizeOfOptionalHeader > buffer_.size()) {
        error_msg_ = "Optional header out of bounds";
        return false;
    }

    const uint16_t* magic = reinterpret_cast<const uint16_t*>(buffer_.data() + opt_offset);

    uint64_t image_base = 0;
    uint32_t entry_point_rva = 0;

    uint32_t raw_size_of_image = 0;
    const IMAGE_DATA_DIRECTORY* data_dirs = nullptr;
    uint32_t num_data_dirs = 0;

    if (*magic == 0x10B) { 
        if (!is_64bit_) {
            const auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
                buffer_.data() + opt_offset);
            if (opt->Magic != 0x10B) {
                error_msg_ = "Magic PE32 not matched";
                return false;
            }
            image_base        = opt->ImageBase;
            entry_point_rva   = opt->AddressOfEntryPoint;
            raw_size_of_image = opt->SizeOfImage;
            data_dirs         = opt->DataDirectory;
            num_data_dirs     = opt->NumberOfRvaAndSizes;
        } else {
            error_msg_ = "Machine is x64 but Optional Header is PE32";
            return false;
        }
    }
    else if (*magic == 0x20B) {
        if (is_64bit_) {
            const auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
                buffer_.data() + opt_offset);
            if (opt->Magic != 0x20B) {
                error_msg_ = "Magic PE32+ not matched";
                return false;
            }
            image_base        = opt->ImageBase;
            entry_point_rva   = opt->AddressOfEntryPoint;
            raw_size_of_image = opt->SizeOfImage;
            data_dirs         = opt->DataDirectory;
            num_data_dirs     = opt->NumberOfRvaAndSizes;
        } else {
            error_msg_ = "Machine is x86 but Optional Header is PE32+";
            return false;
        }
    }
    else {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "Optional Header magic is invalid: 0x%04x", *magic);
        error_msg_ = buffer;
        return false;
    }

    image_base_       = image_base;
    entry_point_rva_  = entry_point_rva;

    const size_t section_offset = opt_offset + file_hdr->SizeOfOptionalHeader;
    if (section_offset + file_hdr->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > buffer_.size()) {
        error_msg_ = "Section table extends beyond file boundaries";
        return false;
    }

    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        buffer_.data() + section_offset);

    uint32_t max_sec_end_rva = 0;
    for (int i = 0; i < file_hdr->NumberOfSections; ++i) {
        const auto& sec = sections[i];

        SectionInfo info;
        info.name = std::string(reinterpret_cast<const char*>(sec.Name), 8);
        auto it = std::find(info.name.c_str(), info.name.c_str() + info.name.size(), '\0');
        info.name.erase(it - info.name.c_str());

        info.virtual_address = image_base + sec.VirtualAddress;
        info.raw_offset      = sec.PointerToRawData;
        info.raw_size        = sec.SizeOfRawData;
        info.virtual_size    = sec.Misc.VirtualSize;
        info.characteristics = sec.Characteristics;

        uint32_t sec_end_rva = sec.VirtualAddress + std::max(sec.SizeOfRawData, sec.Misc.VirtualSize);
        if (sec_end_rva > max_sec_end_rva) {
            max_sec_end_rva = sec_end_rva;
        }

        all_sections_.push_back(info);
        if (info.is_executable() && info.raw_size > 0) {
            executable_sections_.push_back(info);
        }
    }

    if (raw_size_of_image > 0 && raw_size_of_image >= max_sec_end_rva) {
        size_of_image_ = raw_size_of_image;
    } else {
        size_of_image_ = max_sec_end_rva > 0 ? max_sec_end_rva : static_cast<uint32_t>(buffer_.size());
    }

    if (data_dirs && num_data_dirs > 0) {
        parse_data_directories(data_dirs, num_data_dirs);
    }

    return true;
}

void PeParser::parse_data_directories(const IMAGE_DATA_DIRECTORY* data_dirs, uint32_t count) {
    // 1. Base Relocations
    if (count > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        uint32_t reloc_rva = data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        uint32_t reloc_size = data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        uint64_t file_off = rva_to_file_offset(reloc_rva);
        if (reloc_rva != 0 && reloc_size > 0 && file_off != 0 && file_off + reloc_size <= buffer_.size()) {
            size_t offset = file_off;
            size_t end_offset = file_off + reloc_size;
            while (offset + sizeof(PeBaseRelocation) <= end_offset) {
                auto* header = reinterpret_cast<const PeBaseRelocation*>(buffer_.data() + offset);
                if (header->SizeOfBlock < sizeof(PeBaseRelocation) || offset + header->SizeOfBlock > end_offset) {
                    break;
                }
                uint32_t page_rva = header->VirtualAddress;
                size_t num_entries = (header->SizeOfBlock - sizeof(PeBaseRelocation)) / sizeof(uint16_t);
                const uint16_t* entries = reinterpret_cast<const uint16_t*>(buffer_.data() + offset + sizeof(PeBaseRelocation));
                for (size_t i = 0; i < num_entries; ++i) {
                    uint16_t type = entries[i] >> 12;
                    uint16_t reloc_off = entries[i] & 0x0FFF;
                    if (type != 0) { // Not ABSOLUTE padding
                        uint64_t loc_rva = page_rva + reloc_off;
                        reloc_rvas_.insert(loc_rva);
                    }
                }
                offset += header->SizeOfBlock;
            }
        }
    }

    // 2. IAT / Import Directory
    if (count > IMAGE_DIRECTORY_ENTRY_IAT) {
        uint32_t iat_rva = data_dirs[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
        uint32_t iat_size = data_dirs[IMAGE_DIRECTORY_ENTRY_IAT].Size;
        if (iat_rva != 0 && iat_size > 0) {
            size_t step = is_64bit_ ? 8 : 4;
            for (uint32_t cur = iat_rva; cur + step <= iat_rva + iat_size; cur += step) {
                iat_rvas_.insert(cur);
            }
        }
    }
    if (count > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        uint32_t imp_rva = data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        uint32_t imp_size = data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        uint64_t file_off = rva_to_file_offset(imp_rva);
        if (imp_rva != 0 && imp_size > 0 && file_off != 0 && file_off + sizeof(PeImportDescriptor) <= buffer_.size()) {
            const auto* imp = reinterpret_cast<const PeImportDescriptor*>(buffer_.data() + file_off);
            while (imp->FirstThunk != 0 && reinterpret_cast<const uint8_t*>(imp) + sizeof(PeImportDescriptor) <= buffer_.data() + buffer_.size()) {
                uint32_t thunk_rva = imp->FirstThunk;
                uint64_t thunk_off = rva_to_file_offset(thunk_rva);
                size_t step = is_64bit_ ? 8 : 4;
                while (thunk_off != 0 && thunk_off + step <= buffer_.size()) {
                    uint64_t val = 0;
                    if (is_64bit_) {
                        val = *reinterpret_cast<const uint64_t*>(buffer_.data() + thunk_off);
                    } else {
                        val = *reinterpret_cast<const uint32_t*>(buffer_.data() + thunk_off);
                    }
                    if (val == 0) break;
                    iat_rvas_.insert(thunk_rva);
                    thunk_rva += step;
                    thunk_off += step;
                }
                imp++;
            }
        }
    }

    // 3. TLS Directory
    if (count > IMAGE_DIRECTORY_ENTRY_TLS) {
        uint32_t tls_rva = data_dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        uint32_t tls_size = data_dirs[IMAGE_DIRECTORY_ENTRY_TLS].Size;
        uint64_t file_off = rva_to_file_offset(tls_rva);
        if (tls_rva != 0 && tls_size > 0 && file_off != 0) {
            uint64_t callbacks_va = 0;
            if (is_64bit_ && file_off + sizeof(PeTlsDirectory64) <= buffer_.size()) {
                const auto* tls64 = reinterpret_cast<const PeTlsDirectory64*>(buffer_.data() + file_off);
                callbacks_va = tls64->AddressOfCallBacks;
            } else if (!is_64bit_ && file_off + sizeof(PeTlsDirectory32) <= buffer_.size()) {
                const auto* tls32 = reinterpret_cast<const PeTlsDirectory32*>(buffer_.data() + file_off);
                callbacks_va = tls32->AddressOfCallBacks;
            }
            if (callbacks_va >= image_base_) {
                uint64_t callbacks_rva = callbacks_va - image_base_;
                uint64_t cb_off = rva_to_file_offset(callbacks_rva);
                size_t step = is_64bit_ ? 8 : 4;
                while (cb_off != 0 && cb_off + step <= buffer_.size()) {
                    uint64_t cb_va = is_64bit_ ? *reinterpret_cast<const uint64_t*>(buffer_.data() + cb_off)
                                               : *reinterpret_cast<const uint32_t*>(buffer_.data() + cb_off);
                    if (cb_va == 0) break;
                    if (cb_va >= image_base_) {
                        tls_rvas_.insert(cb_va - image_base_);
                    }
                    cb_off += step;
                }
            }
        }
    }

    // 4. Exception Directory (.pdata)
    if (count > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        uint32_t pdata_rva = data_dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        uint32_t pdata_size = data_dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
        uint64_t file_off = rva_to_file_offset(pdata_rva);
        if (pdata_rva != 0 && pdata_size > 0 && file_off != 0 && file_off + pdata_size <= buffer_.size()) {
            size_t num_funcs = pdata_size / sizeof(PeRuntimeFunction);
            const auto* funcs = reinterpret_cast<const PeRuntimeFunction*>(buffer_.data() + file_off);
            for (size_t i = 0; i < num_funcs; ++i) {
                if (funcs[i].BeginAddress != 0 && funcs[i].EndAddress > funcs[i].BeginAddress) {
                    pdata_functions_.push_back(std::make_pair(funcs[i].BeginAddress, funcs[i].EndAddress));
                }
            }
            std::sort(pdata_functions_.begin(), pdata_functions_.end());
        }
    }
}

const SectionInfo* PeParser::find_section_by_rva(uint64_t rva) const {
    for (const auto& sec : all_sections_) {
        uint64_t sec_rva = sec.virtual_address - image_base_;
        uint64_t sec_len = std::max<uint64_t>(sec.raw_size, sec.virtual_size);
        if (rva >= sec_rva && rva < sec_rva + sec_len) {
            return &sec;
        }
    }
    return nullptr;
}

const SectionInfo* PeParser::find_section_by_offset(uint64_t offset) const {
    for (const auto& sec : all_sections_) {
        if (offset >= sec.raw_offset && offset < sec.raw_offset + sec.raw_size) {
            return &sec;
        }
    }
    return nullptr;
}

uint64_t PeParser::rva_to_file_offset(uint64_t rva) const {
    for (const auto& sec : all_sections_) {
        uint64_t sec_rva = sec.virtual_address - image_base_;
        uint64_t sec_len = std::max<uint64_t>(sec.raw_size, sec.virtual_size);
        if (rva >= sec_rva && rva < sec_rva + sec_len) {
            uint64_t diff = rva - sec_rva;
            if (diff < sec.raw_size) {
                return sec.raw_offset + diff;
            }
        }
    }
    return 0;
}

uint64_t PeParser::file_offset_to_rva(uint64_t offset) const {
    for (const auto& sec : all_sections_) {
        if (offset >= sec.raw_offset && offset < sec.raw_offset + sec.raw_size) {
            uint64_t diff = offset - sec.raw_offset;
            uint64_t sec_rva = sec.virtual_address - image_base_;
            return sec_rva + diff;
        }
    }
    return 0;
}

bool PeParser::is_reloc_rva(uint64_t rva) const {
    return reloc_rvas_.find(rva) != reloc_rvas_.end();
}

bool PeParser::is_iat_rva(uint64_t rva) const {
    return iat_rvas_.find(rva) != iat_rvas_.end();
}

bool PeParser::is_tls_rva(uint64_t rva) const {
    return tls_rvas_.find(rva) != tls_rvas_.end();
}

bool PeParser::is_pdata_code_rva(uint64_t rva) const {
    if (pdata_functions_.empty()) return false;
    uint32_t target_rva = static_cast<uint32_t>(rva);
    auto it = std::upper_bound(pdata_functions_.begin(), pdata_functions_.end(), target_rva,
        [](uint32_t val, const std::pair<uint32_t, uint32_t>& elem) {
            return val < elem.first;
        });
    if (it != pdata_functions_.begin()) {
        --it;
        if (target_rva >= it->first && target_rva < it->second) {
            return true;
        }
    }
    return false;
}