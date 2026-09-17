#include "UPX.hpp"
#include <iostream>
#include <cstring>
#include <memory>
#include <algorithm>
#include <climits>

// Standard PE Structures
#define IMAGE_DOS_SIGNATURE_UPX      0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE_UPX       0x00004550  // PE\0\0
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC_UPX 0x10b

#define PEALIGN(o, a) (((a)) ? (((o) / (a)) * (a)) : (o))
#define PESALIGN(o, a) (((a)) ? (((o) / (a) + ((o) % (a) != 0)) * (a)) : (o))

// --- PE Header Templates for reconstruction ---
static const char HEADERS[] =
"\x4D\x5A\x90\x00\x02\x00\x00\x00\x04\x00\x0F\x00\xFF\xFF\x00\x00"
"\xB0\x00\x00\x00\x00\x00\x00\x00\x40\x00\x1A\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD0\x00\x00\x00"
"\x0E\x1F\xB4\x09\xBA\x0D\x00\xCD\x21\xB4\x4C\xCD\x21\x54\x68\x69"
"\x73\x20\x66\x69\x6C\x65\x20\x77\x61\x73\x20\x63\x72\x65\x61\x74"
"\x65\x64\x20\x62\x79\x20\x43\x6C\x61\x6D\x41\x56\x20\x66\x6F\x72"
"\x20\x69\x6E\x74\x65\x72\x6E\x61\x6C\x20\x75\x73\x65\x20\x61\x6E"
"\x64\x20\x73\x68\x6F\x75\x6C\x64\x20\x6E\x6F\x74\x20\x62\x65\x20"
"\x72\x75\x6E\x2E\x0D\x0A\x43\x6C\x61\x6D\x41\x56\x20\x2D\x20\x41"
"\x20\x47\x50\x4C\x20\x76\x69\x72\x75\x73\x20\x73\x63\x61\x6E\x6E"
"\x65\x72\x20\x2D\x20\x68\x74\x74\x70\x3A\x2F\x2F\x77\x77\x77\x2E"
"\x63\x6C\x61\x6D\x61\x76\x2E\x6E\x65\x74\x0D\x0A\x24\x00\x00\x00";

static const char FAKEPE[] =
"\x50\x45\x00\x00\x4C\x01\x01\x00\x43\x4C\x41\x4D\x00\x00\x00\x00"
"\x00\x00\x00\x00\xE0\x00\x83\x8F\x0B\x01\x00\x00\x00\x10\x00\x00"
"\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00"
"\x00\x10\x00\x00\x00\x00\x40\x00\x00\x10\x00\x00\x00\x02\x00\x00"
"\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x0A\x00\x00\x00\x00\x00"
"\xFF\xFF\xFF\xFF\x00\x02\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00"
"\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00"
"\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x2e\x63\x6c\x61\x6d\x30\x31\x00"
"\xFF\xFF\xFF\xFF\x00\x10\x00\x00\xFF\xFF\xFF\xFF\x00\x02\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff";

// --- Integrity Hash ---
uint32_t calculate_simple_hash(const char* data, uint32_t size) {
    uint32_t hash = 5381;
    for (uint32_t i = 0; i < size; ++i) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

// --- Check PE header within decompressed buffer ---
static char* checkpe(char* dst, uint32_t dsize, char* pehdr, uint32_t* valign, unsigned int* sectcnt) {
    char* sections;
    if (!upx_is_contained(dst, dsize, pehdr, 0xf8)) return nullptr;
    if (upx_read_int32(pehdr) != 0x4550) return nullptr;
    if (!(*valign = upx_read_int32(pehdr + 0x38))) return nullptr;

    sections = pehdr + 0xf8;
    if (!(*sectcnt = (unsigned char)pehdr[6] + (unsigned char)pehdr[7] * 256)) return nullptr;
    if (!upx_is_contained(dst, dsize, sections, *sectcnt * 0x28)) return nullptr;

    return sections;
}

// --- Rebuild PE from UPX decompressed data ---
static int pefromupx(const char* src, uint32_t ssize, char* dst, uint32_t* dsize, uint32_t ep, uint32_t upx0, uint32_t upx1, uint32_t* magic, uint32_t dend) {
    char *imports, *sections = nullptr, *pehdr = nullptr;
    unsigned int sectcnt = 0, upd = 1;
    uint32_t realstuffsz = 0, valign = 0;
    uint32_t foffset = 0xd0 + 0xf8;

    if ((dst == nullptr) || (src == nullptr)) return 0;

    while ((valign = magic[sectcnt++])) {
        if (upx_is_contained(src, ssize - 5, src + ep - upx1 + valign - 2, 2) &&
            src[ep - upx1 + valign - 2] == '\x8d' &&
            src[ep - upx1 + valign - 1] == '\xbe')
            break;
    }

    if (!valign && upx_is_contained(src, ssize - 8, src + ep - upx1 + 0x80, 8)) {
        const char* pt = &src[ep - upx1 + 0x80];
        Logger::debug("UPX: bad magic - scanning for imports");

        while ((pt = mem_str(pt, ssize - (pt - src) - 8, "\x8d\xbe", 2))) {
            if (pt[6] == '\x8b' && pt[7] == '\x07') {
                valign = pt - src + 2 - ep + upx1;
                break;
            }
            pt++;
        }
    }

    if (valign && upx_is_contained(src, ssize, src + ep - upx1 + valign, 4)) {
        imports = dst + upx_read_int32(src + ep - upx1 + valign);
        realstuffsz = imports - dst;

        if (realstuffsz >= *dsize) {
            Logger::debug("UPX: wrong realstuff size");
        } else {
            pehdr = imports;
            while (upx_is_contained(dst, *dsize, pehdr, 8) && upx_read_int32(pehdr)) {
                pehdr += 8;
                while (upx_is_contained(dst, *dsize, pehdr, 2) && *pehdr) {
                    pehdr++;
                    while (upx_is_contained(dst, *dsize, pehdr, 2) && *pehdr) pehdr++;
                    pehdr++;
                }
                pehdr++;
            }

            pehdr += 4;
            if (!(sections = checkpe(dst, *dsize, pehdr, &valign, &sectcnt))) pehdr = nullptr;
        }
    }

    if (!pehdr && dend > 0xf8 + 0x28) {
        Logger::debug("UPX: no luck - scanning for PE");
        pehdr = &dst[dend - 0xf8 - 0x28];
        while (pehdr > dst) {
            if ((sections = checkpe(dst, *dsize, pehdr, &valign, &sectcnt))) break;
            pehdr--;
        }
        if (!(realstuffsz = pehdr - dst)) pehdr = nullptr;
    }

    if (!pehdr) {
        uint32_t rebsz = PESALIGN(dend, 0x1000);
        Logger::debug("UPX: no luck - brutally crafting a reasonable PE");

        std::vector<char> newbuf_vec(rebsz + 0x200, 0);
        char* newbuf = newbuf_vec.data();

        std::memcpy(newbuf, HEADERS, 0xd0);
        std::memcpy(newbuf + 0xd0, FAKEPE, 0x120);
        std::memcpy(newbuf + 0x200, dst, dend);
        std::memcpy(dst, newbuf, dend + 0x200);

        upx_write_int32(dst + 0xd0 + 0x50, rebsz + 0x1000);
        upx_write_int32(dst + 0xd0 + 0x100, rebsz);
        upx_write_int32(dst + 0xd0 + 0x108, rebsz);
        *dsize = rebsz + 0x200;

        Logger::success("UPX: PE structure added to uncompressed data. Hash: " + std::to_string(calculate_simple_hash(dst, *dsize)));
        return 1;
    }

    if (!sections) sectcnt = 0;
    foffset = PESALIGN(foffset + 0x28 * sectcnt, valign);

    for (upd = 0; upd < sectcnt; upd++) {
        uint32_t vsize = PESALIGN((uint32_t)upx_read_int32(sections + 8), valign);
        uint32_t urva  = PEALIGN((uint32_t)upx_read_int32(sections + 12), valign);

        if (!upx_is_contained(reinterpret_cast<const void*>(static_cast<uintptr_t>(upx0)), realstuffsz, reinterpret_cast<const void*>(static_cast<uintptr_t>(urva)), vsize)) {
            Logger::error("UPX: Sect out of bounds - giving up rebuild");
            return 0;
        }

        upx_write_int32(sections + 8, vsize);
        upx_write_int32(sections + 12, urva);
        upx_write_int32(sections + 16, vsize);
        upx_write_int32(sections + 20, foffset);
        if (foffset + vsize < foffset) return 0;
        foffset += vsize;
        sections += 0x28;
    }

    upx_write_int32(pehdr + 8, 0x4d414c43);
    upx_write_int32(pehdr + 0x3c, valign);

    std::vector<char> newbuf_vec(foffset, 0);
    char* newbuf = newbuf_vec.data();

    std::memcpy(newbuf, HEADERS, 0xd0);
    std::memcpy(newbuf + 0xd0, pehdr, 0xf8 + 0x28 * sectcnt);
    sections = pehdr + 0xf8;

    for (upd = 0; upd < sectcnt; upd++) {
        uint32_t offset1 = (uint32_t)upx_read_int32(sections + 20);
        uint32_t offset2 = (uint32_t)upx_read_int32(sections + 16);
        if (offset1 > foffset || offset2 > foffset || offset1 + offset2 > foffset) return 1;

        uint32_t offset3 = (uint32_t)upx_read_int32(sections + 12);
        if (offset3 - upx0 > *dsize) return 1;

        std::memcpy(newbuf + offset1, dst + offset3 - upx0, offset2);
        sections += 0x28;
    }

    if (foffset > *dsize + 8192) {
        Logger::error("UPX: wrong raw size - giving up rebuild");
        return 0;
    }

    std::memcpy(dst, newbuf, foffset);
    *dsize = foffset;

    Logger::success("UPX: PE structure successfully rebuilt. Integrity Hash: " + std::to_string(calculate_simple_hash(dst, *dsize)));
    return 1;
}

// --- Bit-stream reader for NRV decompression ---
static int doubleebx(const char* src, uint32_t* myebx, uint32_t* scur, uint32_t ssize) {
    uint32_t oldebx = *myebx;
    *myebx *= 2;
    if (!(oldebx & 0x7fffffff)) {
        if (!upx_is_contained(src, ssize, src + *scur, 4)) return -1;
        oldebx = upx_read_int32(src + *scur);
        *myebx = oldebx * 2 + 1;
        *scur += 4;
    }
    return (oldebx >> 31);
}

// NRV2B Decompressor
int upx_inflate2b(const char* src, uint32_t ssize, char* dst, uint32_t* dsize, uint32_t upx0, uint32_t upx1, uint32_t ep) {
    int32_t backbytes, unp_offset = -1;
    uint32_t backsize, myebx = 0, scur = 0, dcur = 0, i, magic[] = {0x108, 0x110, 0xd5, 0};
    int oob;

    while (1) {
        while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 1) {
            if (scur >= ssize || dcur >= *dsize) return -1;
            dst[dcur++] = src[scur++];
        }
        if (oob == -1) return -1;
        backbytes = 1;

        while (1) {
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
            if (((int64_t)backbytes + oob) > INT32_MAX / 2) return -1;
            backbytes = backbytes * 2 + oob;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
            if (oob) break;
        }

        backbytes -= 3;
        if (backbytes >= 0) {
            if (scur >= ssize) return -1;
            if (backbytes & 0xff000000) return -1;
            backbytes <<= 8;
            backbytes += (unsigned char)(src[scur++]);
            backbytes ^= 0xffffffff;
            if (!backbytes) break;
            unp_offset = backbytes;
        }

        if ((backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff) return -1;
        if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
        if (backsize + oob > UINT32_MAX / 2) return -1;
        backsize = backsize * 2 + oob;
        if (!backsize) {
            backsize++;
            do {
                if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
                if (backsize + oob > UINT32_MAX / 2) return -1;
                backsize = backsize * 2 + oob;
            } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
            if (oob == -1) return -1;
            if (backsize > UINT32_MAX - 2) return -1;
            backsize += 2;
        }

        if ((uint32_t)unp_offset < 0xfffff300) backsize++;
        backsize++;

        if (!upx_is_contained(dst, *dsize, dst + dcur + unp_offset, backsize) || !upx_is_contained(dst, *dsize, dst + dcur, backsize) || unp_offset >= 0) return -1;
        for (i = 0; i < backsize; i++) dst[dcur + i] = dst[dcur + unp_offset + i];
        dcur += backsize;
    }

    return pefromupx(src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur);
}

// NRV2D Decompressor
int upx_inflate2d(const char* src, uint32_t ssize, char* dst, uint32_t* dsize, uint32_t upx0, uint32_t upx1, uint32_t ep) {
    int32_t backbytes, unp_offset = -1;
    uint32_t backsize, myebx = 0, scur = 0, dcur = 0, i, magic[] = {0x11c, 0x124, 0};
    int oob;

    while (1) {
        while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 1) {
            if (scur >= ssize || dcur >= *dsize) return -1;
            dst[dcur++] = src[scur++];
        }
        if (oob == -1) return -1;
        backbytes = 1;

        while (1) {
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
            if (((int64_t)backbytes + oob) > INT32_MAX / 2) return -1;
            backbytes = backbytes * 2 + oob;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
            if (oob) break;
            backbytes--;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
            if (((int64_t)backbytes + oob) > INT32_MAX / 2) return -1;
            backbytes = backbytes * 2 + oob;
        }

        backsize = 0;
        backbytes -= 3;

        if (backbytes >= 0) {
            if (scur >= ssize) return -1;
            if (backbytes & 0xff000000) return -1;
            backbytes <<= 8;
            backbytes += (unsigned char)(src[scur++]);
            backbytes ^= 0xffffffff;
            if (!backbytes) break;
            backsize = backbytes & 1;
            sar_shift(backbytes, 1);
            unp_offset = backbytes;
        } else {
            if ((backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff) return -1;
        }

        if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
        if (backsize + oob > UINT32_MAX / 2) return -1;
        backsize = backsize * 2 + oob;
        if (!backsize) {
            backsize++;
            do {
                if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
                if (backsize + oob > UINT32_MAX / 2) return -1;
                backsize = backsize * 2 + oob;
            } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
            if (oob == -1) return -1;
            if (backsize > UINT32_MAX - 2) return -1;
            backsize += 2;
        }

        if ((uint32_t)unp_offset < 0xfffffb00) backsize++;
        backsize++;
        if (!upx_is_contained(dst, *dsize, dst + dcur + unp_offset, backsize) || !upx_is_contained(dst, *dsize, dst + dcur, backsize) || unp_offset >= 0) return -1;
        for (i = 0; i < backsize; i++) dst[dcur + i] = dst[dcur + unp_offset + i];
        dcur += backsize;
    }

    return pefromupx(src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur);
}

// NRV2E Decompressor
int upx_inflate2e(const char* src, uint32_t ssize, char* dst, uint32_t* dsize, uint32_t upx0, uint32_t upx1, uint32_t ep) {
    int32_t backbytes, unp_offset = -1;
    uint32_t backsize, myebx = 0, scur = 0, dcur = 0, i, magic[] = {0x128, 0x130, 0};
    int oob;

    for (;;) {
        while ((oob = doubleebx(src, &myebx, &scur, ssize))) {
            if (oob == -1) return -1;
            if (scur >= ssize || dcur >= *dsize) return -1;
            dst[dcur++] = src[scur++];
        }

        backbytes = 1;

        for (;;) {
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
            if (((int64_t)backbytes + oob) > INT32_MAX / 2) return -1;
            backbytes = backbytes * 2 + oob;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
            if (oob) break;
            backbytes--;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
            if (((int64_t)backbytes + oob) > INT32_MAX / 2) return -1;
            backbytes = backbytes * 2 + oob;
        }

        backbytes -= 3;

        if (backbytes >= 0) {
            if (scur >= ssize) return -1;
            if (backbytes & 0xff000000) return -1;
            backbytes <<= 8;
            backbytes += (unsigned char)(src[scur++]);
            backbytes ^= 0xffffffff;
            if (!backbytes) break;
            backsize = backbytes & 1;
            sar_shift(backbytes, 1);
            unp_offset = backbytes;
        } else {
            if ((backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff) return -1;
        }

        if (backsize) {
            if ((backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff) return -1;
        } else {
            backsize = 1;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
            if (oob) {
                if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
                if (backsize + oob > UINT32_MAX / 2) return -1;
                backsize = 2 + oob;
            } else {
                do {
                    if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1) return -1;
                    if (backsize + oob > UINT32_MAX / 2) return -1;
                    backsize = backsize * 2 + oob;
                } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
                if (oob == -1) return -1;
                if (backsize > UINT32_MAX - 2) return -1;
                backsize += 2;
            }
        }

        if ((uint32_t)unp_offset < 0xfffffb00) backsize++;
        if (backsize > UINT32_MAX - 2) return -1;
        backsize += 2;

        if (!upx_is_contained(dst, *dsize, dst + dcur + unp_offset, backsize) || !upx_is_contained(dst, *dsize, dst + dcur, backsize) || unp_offset >= 0) return -1;
        for (i = 0; i < backsize; i++) dst[dcur + i] = dst[dcur + unp_offset + i];
        dcur += backsize;
    }

    return pefromupx(src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur);
}

// UPX Detection
bool UPXUnpacker::isUPX(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 0x40) return false;

    // Check MZ signature
    uint16_t e_magic = buffer[0] | (buffer[1] << 8);
    if (e_magic != IMAGE_DOS_SIGNATURE_UPX) return false;

    // Get PE signature offset
    uint32_t e_lfanew = readInt32LE(&buffer[0x3c]);
    if (e_lfanew >= buffer.size() - 0x100) return false;

    // Check PE signature
    uint32_t pe_sig = readInt32LE(&buffer[e_lfanew]);
    if (pe_sig != IMAGE_NT_SIGNATURE_UPX) return false;

    // Search for UPX! magic anywhere in the file
    for (size_t i = 0; i + 4 <= buffer.size(); ++i) {
        if (std::memcmp(&buffer[i], "UPX!", 4) == 0) {
            return true;
        }
    }

    // Check section names for UPX0/UPX1/UPX2
    uint16_t num_sections = buffer[e_lfanew + 6] | (buffer[e_lfanew + 7] << 8);
    uint16_t size_of_opt_header = buffer[e_lfanew + 0x14] | (buffer[e_lfanew + 0x15] << 8);
    uint32_t sect_offset = e_lfanew + 24 + size_of_opt_header;

    for (uint16_t i = 0; i < num_sections && sect_offset + (i + 1) * 40 <= buffer.size(); ++i) {
        uint32_t off = sect_offset + i * 40;
        char name[9] = {0};
        std::memcpy(name, &buffer[off], 8);
        std::string sname(name);
        if (sname.find("UPX") != std::string::npos) {
            return true;
        }
    }

    return false;
}

// UPX Unpacker — tries NRV2B, NRV2D, NRV2E
bool UPXUnpacker::unpack(const std::vector<uint8_t>& packed, std::vector<uint8_t>& unpacked) {
    if (!isUPX(packed)) return false;

    // Parse PE header
    uint32_t pe = readInt32LE(&packed[0x3c]);
    uint16_t num_sections = packed[pe + 6] | (packed[pe + 7] << 8);
    uint16_t size_of_opt_header = packed[pe + 0x14] | (packed[pe + 0x15] << 8);
    uint32_t ep_rva = readInt32LE(&packed[pe + 0x28]);

    if (num_sections < 2) {
        Logger::error("UPX: Not enough sections for UPX format");
        return false;
    }

    // Parse sections
    uint32_t sect_offset = pe + 24 + size_of_opt_header;
    std::vector<ExeSection> sects(num_sections);

    for (uint16_t i = 0; i < num_sections; ++i) {
        uint32_t off = sect_offset + i * 40;
        if (off + 40 > packed.size()) return false;
        sects[i].vsz = readInt32LE(&packed[off + 8]);
        sects[i].rva = readInt32LE(&packed[off + 12]);
        sects[i].rsz = readInt32LE(&packed[off + 16]);
    }

    // UPX layout: section 0 = UPX0 (uninitialized, destination)
    //             section 1 = UPX1 (compressed data)
    uint32_t upx0_rva = sects[0].rva;
    uint32_t upx0_vsz = sects[0].vsz;
    uint32_t upx1_rva = sects[1].rva;
    uint32_t upx1_rsz = sects[1].rsz;

    // Find UPX1 raw offset
    uint32_t upx1_raw = readInt32LE(&packed[sect_offset + 40 + 20]);  // section 1 PointerToRawData

    if (upx1_raw + upx1_rsz > packed.size()) {
        Logger::error("UPX: Compressed section exceeds file bounds");
        return false;
    }

    // Allocate destination buffer: UPX0.vsz + UPX1.vsz + extra room
    uint32_t dest_size = upx0_vsz + sects[1].vsz;
    // Add some padding for PE reconstruction
    uint32_t alloc_size = dest_size + 0x2000;
    std::vector<char> dst_vec(alloc_size, 0);
    char* dst = dst_vec.data();
    uint32_t dsize = alloc_size;

    const char* src = reinterpret_cast<const char*>(packed.data() + upx1_raw);
    uint32_t ssize = upx1_rsz;

    Logger::debug("UPX: Trying NRV2B decompression...");
    int result = upx_inflate2b(src, ssize, dst, &dsize, upx0_rva, upx1_rva, ep_rva);

    if (result <= 0) {
        // Reset and try NRV2D
        std::memset(dst_vec.data(), 0, alloc_size);
        dsize = alloc_size;
        Logger::debug("UPX: NRV2B failed, trying NRV2D...");
        result = upx_inflate2d(src, ssize, dst, &dsize, upx0_rva, upx1_rva, ep_rva);
    }

    if (result <= 0) {
        // Reset and try NRV2E
        std::memset(dst_vec.data(), 0, alloc_size);
        dsize = alloc_size;
        Logger::debug("UPX: NRV2D failed, trying NRV2E...");
        result = upx_inflate2e(src, ssize, dst, &dsize, upx0_rva, upx1_rva, ep_rva);
    }

    if (result <= 0) {
        Logger::error("UPX: All decompression methods failed");
        return false;
    }

    // Success — copy result to output
    unpacked.assign(dst, dst + dsize);
    Logger::success("UPX: Successfully unpacked " + std::to_string(packed.size()) + " -> " + std::to_string(dsize) + " bytes");
    return true;
}
