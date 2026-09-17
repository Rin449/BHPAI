#include "WWPack.hpp"
#include <iostream>
#include <cstring>
#include <memory>
#include <algorithm>

// Standard PE Structures
#define IMAGE_DOS_SIGNATURE          0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE           0x00004550  // PE\0\0
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b

// Bit reader for compression stream
class ClamBitReader {
public:
    ClamBitReader(const uint8_t* start, uint32_t size)
        : cur(start), end(start + size), bitBuffer(0), bitsLeft(0), hasError(false) 
    {
        refill(32); 
    }

    uint32_t readBit() {
        return readBits(1);
    }

    uint32_t readBits(int n) {
        if (n == 0 || hasError) return 0;

        if (bitsLeft < n) {
            refill(n);
            if (hasError) return 0;
        }

        uint32_t value = (bitBuffer >> (bitsLeft - n)) & ((1U << n) - 1);
        bitsLeft -= n;
        return value;
    }

    bool error() const { return hasError; }

private:
    void refill(int n) {
        while (bitsLeft < n) {
            if (cur + 4 <= end) {
                // Read Big-Endian DWORD for compatibility with ClamAV stream format
                uint32_t next4Bytes = (uint32_t(cur[0]) << 24) | 
                                      (uint32_t(cur[1]) << 16) | 
                                      (uint32_t(cur[2]) << 8)  | 
                                      uint32_t(cur[3]);
                bitBuffer = (bitBuffer << 32) | next4Bytes;
                bitsLeft += 32;
                cur += 4;
            } 
            else if (cur < end) {
                bitBuffer = (bitBuffer << 8) | *cur++;
                bitsLeft += 8;
            } 
            else {
                hasError = true;
                break;
            }
        }
    }

    const uint8_t* cur;
    const uint8_t* end;
    uint64_t bitBuffer; 
    int bitsLeft;       
    bool hasError;
};

// Standalone WWPack decompressor (ported from ClamAV)
static bool wwunpack_standalone(uint8_t *exe, uint32_t exesz, uint8_t *wwsect, const ExeSection *sects, uint16_t scount, uint32_t pe)
{
    const uint8_t* structs = wwsect + 0x2a1;
    uint8_t *compd = nullptr;
    uint8_t *unpd, *ucur;
    uint32_t src, srcend, szd;
    bool success = true;

    uint32_t wwsect_rsz = sects[scount].rsz;

    while (1) {
        if (!isContained(wwsect, wwsect_rsz, structs, 17)) {
            std::cerr << "WWPack: Array of structs out of section\n";
            break;
        }
        src = sects[scount].rva - readInt32LE(structs);
        structs += 8;
        szd = readInt32LE(structs) * 4;
        structs += 4;
        srcend = readInt32LE(structs);
        structs += 4;

        unpd = ucur = exe + src + srcend + 4 - szd;
        if (!szd || !isContained(exe, exesz, unpd, szd)) {
            std::cerr << "WWPack: Compressed data out of file\n";
            break;
        }

        compd = new (std::nothrow) uint8_t[szd];
        if (!compd) {
            std::cerr << "WWPack: Unable to allocate memory\n";
            break;
        }
        std::memcpy(compd, unpd, szd);
        std::memset(unpd, -1, szd); 

        ClamBitReader reader(compd, szd);

        while (success && !reader.error()) {
            uint32_t backbytes, backsize;
            uint8_t saved;

            if (!reader.readBit()) { 
                if (!isContained(exe, exesz, ucur, 1)) {
                    success = false;
                } else {
                    *ucur++ = (uint8_t)reader.readBits(8);
                }
                continue;
            }

            uint32_t bits_2 = reader.readBits(2);
            if (bits_2 == 3) { /* WORD backcopy */
                uint8_t shifted, subbed = 31;
                uint32_t bits_next = reader.readBits(2);
                shifted = bits_next + 5;
                if (bits_next >= 2) {
                    shifted++;
                    subbed += 0x80;
                }
                backbytes = (1 << shifted) - subbed; 
                
                uint32_t bits_sh = reader.readBits(shifted);
                if (reader.error() || bits_sh == 0x1ff) break;
                backbytes += bits_sh;
                
                if (!isContained(exe, exesz, ucur, 2) || !isContained(exe, exesz, ucur - backbytes, 2)) {
                    success = false;
                } else {
                    ucur[0] = *(ucur - backbytes);
                    ucur[1] = *(ucur - backbytes + 1);
                    ucur += 2;
                }
                continue;
            }

            /* BLOCK backcopy */
            saved = bits_2; 

            uint32_t bits_3 = reader.readBits(3);
            if (bits_3 < 6) {
                backbytes = bits_3;
                switch (bits_3) {
                    case 4: 
                        backbytes++;
                        // fall-through
                    case 3: 
                        backbytes += reader.readBit();
                        // fall-through
                    case 0:
                    case 1:
                    case 2: 
                        backbytes += 5;
                        break;
                    case 5: 
                        backbytes = 12;
                        break;
                }
                bits_3 = reader.readBits(backbytes);
                bits_3 += (1 << backbytes) - 31;
            } else if (bits_3 == 6) {
                bits_3 = reader.readBits(0x0e);
                bits_3 += 0x1fe1;
            } else {
                bits_3 = reader.readBits(0x0f);
                bits_3 += 0x5fe1;
            }

            backbytes = bits_3;

            if (!saved) {
                if (!reader.readBit()) {
                    if (!reader.readBit()) {
                        bits_3 = 5;
                    } else {
                        bits_3 = 0; // Safe fallback
                    }
                } else {
                    uint32_t b_tmp = reader.readBits(3);
                    if (b_tmp) {
                        bits_3 = b_tmp + 6;
                    } else {
                        b_tmp = reader.readBits(4);
                        if (b_tmp) {
                            bits_3 = b_tmp + 13;
                        } else {
                            uint8_t cnt = 4;
                            uint16_t shifted = 0x0d;

                            do {
                                if (cnt == 7) {
                                    cnt = 0x0e;
                                    shifted = 0;
                                    break;
                                }
                                shifted = ((shifted + 2) << 1) - 1;
                                b_tmp = reader.readBit();
                                cnt++;
                            } while (!b_tmp);
                            bits_3 = reader.readBits(cnt) + shifted;
                        }
                    }
                }
                backsize = bits_3;
            } else {
                backsize = saved + 2;
            }

            if (reader.error() || !isContained(exe, exesz, ucur, backsize) || !isContained(exe, exesz, ucur - backbytes, backsize)) {
                success = false;
            } else {
                while (backsize--) {
                    *ucur = *(ucur - backbytes);
                    ucur++;
                }
            }
        }
        
        delete[] compd;
        compd = nullptr;

        if (!success || reader.error()) {
            std::cerr << "WWPack: Decompression error\n";
            return false;
        }
        if (!*structs++) break;
    }

    // Reconstruct original PE structures
    if (success) {
        if (!isContained(exe, exesz, exe + pe + 0x50, 4) || !isContained(wwsect, wwsect_rsz, wwsect + 0x295, 4)) {
            std::cerr << "WWPack: Unpack address out of bounds.\n";
            return false;
        }

        exe[pe + 6] = (uint8_t)scount;
        exe[pe + 7] = (uint8_t)(scount >> 8);

        writeInt32LE(&exe[pe + 0x28], readInt32LE(wwsect + 0x295) + sects[scount].rva + 0x299);
        writeInt32LE(&exe[pe + 0x50], readInt32LE(&exe[pe + 0x50]) - sects[scount].vsz);

        // Read SizeOfOptionalHeader
        uint32_t optionalHeaderSize = 0xffff & readInt32LE(&exe[pe + 0x14]);
        uint8_t* out_structs = &exe[optionalHeaderSize + pe + 0x18];

        for (uint16_t i = 0; i < scount; i++) {
            if (!isContained(exe, exesz, out_structs, 0x28)) {
                std::cerr << "WWPack: Structs pointer out of bounds\n";
                return false;
            }
            writeInt32LE(out_structs + 8,  sects[i].vsz);
            writeInt32LE(out_structs + 12, sects[i].rva);
            writeInt32LE(out_structs + 16, sects[i].vsz);
            writeInt32LE(out_structs + 20, sects[i].rva);
            out_structs += 0x28;
        }
        if (!isContained(exe, exesz, out_structs, 0x28)) {
            std::cerr << "WWPack: Final structs pointer out of bounds\n";
            return false;
        }
        std::memset(out_structs, 0, 0x28);
    }
    return success;
}

bool WWPackUnpacker::isWWPack(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 0x40) return false;

    // Check MZ signature
    uint16_t e_magic = (buffer[0]) | (buffer[1] << 8);
    if (e_magic != IMAGE_DOS_SIGNATURE) return false;

    // Get PE signature offset
    uint32_t e_lfanew = buffer[0x3c] | (buffer[0x3d] << 8) | (buffer[0x3e] << 16) | (buffer[0x3f] << 24);
    if (e_lfanew >= buffer.size() - 0x100) return false;

    // Check PE signature
    uint32_t pe_sig = readInt32LE(&buffer[e_lfanew]);
    if (pe_sig != IMAGE_NT_SIGNATURE) return false;

    // Get number of sections
    uint16_t num_sections = buffer[e_lfanew + 6] | (buffer[e_lfanew + 7] << 8);
    if (num_sections < 2) return false;

    // Check optional header magic (must be 32-bit for WWPack)
    uint16_t opt_magic = buffer[e_lfanew + 0x18] | (buffer[e_lfanew + 0x19] << 8);
    if (opt_magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;

    // Get optional header size and entry point
    uint16_t size_of_opt_header = buffer[e_lfanew + 0x14] | (buffer[e_lfanew + 0x15] << 8);
    uint32_t ep = readInt32LE(&buffer[e_lfanew + 0x28]);

    // Section table offset
    uint32_t sect_offset = e_lfanew + 24 + size_of_opt_header;
    if (sect_offset + num_sections * 40 > buffer.size()) return false;

    // Retrieve last section (packer section)
    uint32_t last_sect_offset = sect_offset + (num_sections - 1) * 40;
    uint32_t last_vsize = readInt32LE(&buffer[last_sect_offset + 8]);
    uint32_t last_vaddr = readInt32LE(&buffer[last_sect_offset + 12]);
    uint32_t last_raw_offset = readInt32LE(&buffer[last_sect_offset + 20]);

    // Entry point must point within the last section
    if (ep >= last_vaddr && ep < last_vaddr + last_vsize) {
        // Check section name for typical ".wwp" or "WWP" substrings
        char name[9] = {0};
        std::memcpy(name, &buffer[last_sect_offset], 8);
        std::string sname(name);
        std::transform(sname.begin(), sname.end(), sname.begin(), ::tolower);
        if (sname.find("wwp") != std::string::npos) {
            return true;
        }

        // Or verify typical entry code signature of WWPack at the start of the packer section
        if (last_raw_offset != 0 && last_raw_offset + 8 <= buffer.size()) {
            if (std::memcmp(&buffer[last_raw_offset], "\x8B\x44\x24\x04\x8B\x4C\x24\x08", 8) == 0) {
                return true;
            }
        }
    }

    return false;
}

bool WWPackUnpacker::unpack(const std::vector<uint8_t>& packed, std::vector<uint8_t>& unpacked) {
    if (!isWWPack(packed)) return false;

    // Parse PE Header offset
    uint32_t pe = packed[0x3c] | (packed[0x3d] << 8) | (packed[0x3e] << 16) | (packed[0x3f] << 24);
    uint16_t num_sections = packed[pe + 6] | (packed[pe + 7] << 8);
    uint16_t size_of_opt_header = packed[pe + 0x14] | (packed[pe + 0x15] << 8);

    uint32_t size_of_image = readInt32LE(&packed[pe + 0x50]);
    uint32_t size_of_headers = readInt32LE(&packed[pe + 0x54]);

    // Create the mapped PE buffer
    std::vector<uint8_t> mapped(size_of_image, 0);
    
    // Copy PE headers
    uint32_t headers_to_copy = std::min(size_of_headers, static_cast<uint32_t>(packed.size()));
    std::memcpy(mapped.data(), packed.data(), headers_to_copy);

    // Retrieve section information
    uint32_t sect_offset = pe + 24 + size_of_opt_header;
    std::vector<ExeSection> sects(num_sections);

    for (uint16_t i = 0; i < num_sections; ++i) {
        uint32_t offset = sect_offset + i * 40;
        sects[i].vsz = readInt32LE(&packed[offset + 8]);
        sects[i].rva = readInt32LE(&packed[offset + 12]);
        sects[i].rsz = readInt32LE(&packed[offset + 16]);
        uint32_t raw_offset = readInt32LE(&packed[offset + 20]);

        if (raw_offset != 0 && sects[i].rsz != 0) {
            uint32_t size_to_copy = std::min(sects[i].rsz, static_cast<uint32_t>(packed.size() - raw_offset));
            if (sects[i].rva + size_to_copy <= mapped.size()) {
                std::memcpy(mapped.data() + sects[i].rva, packed.data() + raw_offset, size_to_copy);
            }
        }
    }

    // Call unpacker
    uint16_t scount = num_sections - 1; // Index of the packer section
    uint8_t* wwsect = mapped.data() + sects[scount].rva;

    if (!wwunpack_standalone(mapped.data(), mapped.size(), wwsect, sects.data(), scount, pe)) {
        return false;
    }

    // The unpacker modified mapped in-place. Let's read the updated size of image.
    uint32_t new_size_of_image = readInt32LE(&mapped[pe + 0x50]);
    if (new_size_of_image > mapped.size()) {
        new_size_of_image = mapped.size();
    }

    unpacked = std::move(mapped);
    if (unpacked.size() > new_size_of_image) {
        unpacked.resize(new_size_of_image);
    }

    return true;
}
