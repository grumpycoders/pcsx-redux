/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include "psyqo/memory-card-filesystem.hh"

#include "common/util/sjis-encode.h"
#include "psyqo/sio0-bus.hh"

namespace {

// Little-endian byte accessors, used in place of struct overlays so that the
// code is free of any alignment or endianness assumptions.
inline void put16(uint8_t *p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}
inline void put32(uint8_t *p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}
inline uint16_t get16(const uint8_t *p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
inline uint32_t get32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

// The first data sector of a block. Pure shift: 64 sectors per block.
inline uint16_t blockToSector(unsigned block) { return static_cast<uint16_t>(block << 6); }

}  // namespace

using Error = psyqo::MemoryCard::Error;
using Port = psyqo::MemoryCard::Port;

uint8_t psyqo::MemoryCardFileSystem::frameChecksum(const uint8_t *frame) {
    uint8_t checksum = 0;
    for (uint32_t i = 0; i < 0x7f; i++) checksum ^= frame[i];
    return checksum;
}

void psyqo::MemoryCardFileSystem::finishDirEntry(uint8_t *entry) { entry[c_offChecksum] = frameChecksum(entry); }

bool psyqo::MemoryCardFileSystem::nameMatches(const uint8_t *entry, const char *name) {
    const char *cardName = reinterpret_cast<const char *>(entry + c_offName);
    for (uint32_t i = 0; i < c_maxNameLength; i++) {
        char a = cardName[i];
        char b = name[i];
        if (a != b) return false;
        if (a == '\0') return true;
    }
    // Both ran to the 20 character limit without a mismatch; equal iff the
    // caller's name also ends here.
    return name[c_maxNameLength] == '\0';
}

Error psyqo::MemoryCardFileSystem::getCardState(Port port) {
    SIO0Bus::Lock lock;
    Frame frame;
    Error error = m_card.readSectorBlocking(port, 0, frame.bytes);
    if (error != Error::OK) return error;
    if (frame.bytes[0] != 'M' || frame.bytes[1] != 'C') return Error::NotFormatted;
    return Error::OK;
}

Error psyqo::MemoryCardFileSystem::readDirectory(Port port, Frame *dir15) {
    for (unsigned i = 0; i < 15; i++) {
        Error error = m_card.readSectorBlocking(port, static_cast<uint16_t>(i + 1), dir15[i].bytes);
        if (error != Error::OK) return error;
    }
    return Error::OK;
}

Error psyqo::MemoryCardFileSystem::findFirstBlock(const Frame *dir15, const char *name, int *outBlock) {
    *outBlock = -1;
    for (unsigned i = 0; i < 15; i++) {
        const uint8_t *entry = dir15[i].bytes;
        if (entry[c_offAlloc] == c_stateFirst && nameMatches(entry, name)) {
            *outBlock = static_cast<int>(i + 1);
            return Error::OK;
        }
    }
    return Error::OK;
}

Error psyqo::MemoryCardFileSystem::format(Port port) {
    SIO0Bus::Lock lock;
    Frame frame;

    // Header frame (sector 0): "MC" + checksum.
    __builtin_memset(frame.bytes, 0, sizeof(frame.bytes));
    frame.bytes[0] = 'M';
    frame.bytes[1] = 'C';
    finishDirEntry(frame.bytes);
    Error error = m_card.writeSectorBlocking(port, 0, frame.bytes);
    if (error != Error::OK) return error;

    // Directory frames (sectors 1..15): all free.
    __builtin_memset(frame.bytes, 0, sizeof(frame.bytes));
    put32(frame.bytes + c_offAlloc, c_stateFree);
    put32(frame.bytes + c_offSize, 0);
    put16(frame.bytes + c_offNext, 0xffff);
    finishDirEntry(frame.bytes);
    for (uint16_t sector = 1; sector <= 15; sector++) {
        error = m_card.writeSectorBlocking(port, sector, frame.bytes);
        if (error != Error::OK) return error;
    }

    // Broken sector list (sectors 16..35): all unused.
    __builtin_memset(frame.bytes, 0, sizeof(frame.bytes));
    put32(frame.bytes + 0x00, 0xffffffff);
    put16(frame.bytes + 0x08, 0xffff);
    finishDirEntry(frame.bytes);
    for (uint16_t sector = 16; sector <= 35; sector++) {
        error = m_card.writeSectorBlocking(port, sector, frame.bytes);
        if (error != Error::OK) return error;
    }

    // Broken sector replacement data and reserved frames (sectors 36..62): zero.
    __builtin_memset(frame.bytes, 0, sizeof(frame.bytes));
    for (uint16_t sector = 36; sector <= 62; sector++) {
        error = m_card.writeSectorBlocking(port, sector, frame.bytes);
        if (error != Error::OK) return error;
    }

    // Write-test frame (sector 63): a copy of the header frame.
    __builtin_memset(frame.bytes, 0, sizeof(frame.bytes));
    frame.bytes[0] = 'M';
    frame.bytes[1] = 'C';
    finishDirEntry(frame.bytes);
    return m_card.writeSectorBlocking(port, 63, frame.bytes);
}

Error psyqo::MemoryCardFileSystem::getFreeBlockCount(Port port, uint32_t *outFreeBlocks) {
    SIO0Bus::Lock lock;
    if (outFreeBlocks) *outFreeBlocks = 0;
    Error error = getCardState(port);
    if (error != Error::OK) return error;

    Frame dir[15];
    error = readDirectory(port, dir);
    if (error != Error::OK) return error;

    uint32_t free = 0;
    for (unsigned i = 0; i < 15; i++) {
        if (isFreeState(dir[i].bytes[c_offAlloc])) free++;
    }
    if (outFreeBlocks) *outFreeBlocks = free;
    return Error::OK;
}

Error psyqo::MemoryCardFileSystem::listFiles(Port port, FileEntry *out, uint32_t maxEntries, uint32_t *outCount) {
    SIO0Bus::Lock lock;
    if (outCount) *outCount = 0;
    Error error = getCardState(port);
    if (error != Error::OK) return error;

    Frame dir[15];
    error = readDirectory(port, dir);
    if (error != Error::OK) return error;

    uint32_t count = 0;
    for (unsigned i = 0; i < 15; i++) {
        const uint8_t *entry = dir[i].bytes;
        if (entry[c_offAlloc] != c_stateFirst) continue;
        if (out && count < maxEntries) {
            FileEntry &dst = out[count];
            __builtin_memcpy(dst.name, entry + c_offName, 20);
            dst.name[20] = '\0';
            dst.sizeInBlocks = static_cast<uint16_t>(get32(entry + c_offSize) >> 13);
            dst.firstBlock = static_cast<uint8_t>(i + 1);
        }
        count++;
    }
    if (outCount) *outCount = count;
    return Error::OK;
}

Error psyqo::MemoryCardFileSystem::fileExists(Port port, const char *name, bool *outExists) {
    SIO0Bus::Lock lock;
    if (outExists) *outExists = false;
    Error error = getCardState(port);
    if (error != Error::OK) return error;

    Frame dir[15];
    error = readDirectory(port, dir);
    if (error != Error::OK) return error;

    int block = -1;
    findFirstBlock(dir, name, &block);
    if (outExists) *outExists = block != -1;
    return Error::OK;
}

Error psyqo::MemoryCardFileSystem::readFile(Port port, const char *name, void *buffer, uint32_t maxLen,
                                            uint32_t *outLen) {
    SIO0Bus::Lock lock;
    if (outLen) *outLen = 0;
    Error error = getCardState(port);
    if (error != Error::OK) return error;

    Frame dir[15];
    error = readDirectory(port, dir);
    if (error != Error::OK) return error;

    int first = -1;
    findFirstBlock(dir, name, &first);
    if (first == -1) return Error::FileNotFound;

    // Determine how many leading frames are title + icon by reading the title.
    Frame title;
    error = m_card.readSectorBlocking(port, blockToSector(first), title.bytes);
    if (error != Error::OK) return error;
    uint32_t headerFrames = 0;
    if (title.bytes[0] == 'S' && title.bytes[1] == 'C') {
        uint32_t iconFrames = title.bytes[2] & 0x0f;
        if (iconFrames < 1 || iconFrames > 3) iconFrames = 1;
        headerFrames = 1 + iconFrames;
    }

    // Walk the block chain, guarding against malformed loops.
    uint8_t chain[16];
    uint32_t chainLength = 0;
    uint16_t visited = 0;
    int block = first;
    while (block >= 1 && block <= 15 && chainLength < 16) {
        if (visited & (1 << block)) return Error::BadData;
        visited |= (1 << block);
        chain[chainLength++] = static_cast<uint8_t>(block);
        uint16_t next = get16(dir[block - 1].bytes + c_offNext);
        if (next == 0xffff) break;
        block = next + 1;
    }

    uint32_t totalSectors = chainLength * MemoryCard::c_sectorsPerBlock;
    uint32_t dataBytes = (totalSectors - headerFrames) * MemoryCard::c_sectorSize;

    uint8_t *dst = reinterpret_cast<uint8_t *>(buffer);
    uint32_t written = 0;
    for (uint32_t bi = 0; bi < chainLength && written < maxLen; bi++) {
        unsigned base = chain[bi] << 6;
        uint32_t startFrame = (bi == 0) ? headerFrames : 0;
        for (uint32_t frame = startFrame; frame < MemoryCard::c_sectorsPerBlock && written < maxLen; frame++) {
            Frame fr;
            error = m_card.readSectorBlocking(port, static_cast<uint16_t>(base + frame), fr.bytes);
            if (error != Error::OK) return error;
            uint32_t chunk = MemoryCard::c_sectorSize;
            if (chunk > maxLen - written) chunk = maxLen - written;
            __builtin_memcpy(dst + written, fr.bytes, chunk);
            written += chunk;
        }
    }

    if (outLen) *outLen = dataBytes < maxLen ? dataBytes : maxLen;
    return Error::OK;
}

Error psyqo::MemoryCardFileSystem::writeFile(Port port, const char *name, const char *title, const Icon &icon,
                                             const void *data, uint32_t dataLen) {
    SIO0Bus::Lock lock;  // own the SIO0 bus for the whole multi-sector transaction
    // Validate the name length.
    uint32_t nameLen = 0;
    while (name[nameLen] != '\0') {
        nameLen++;
        if (nameLen > c_maxNameLength) return Error::NameTooLong;
    }

    uint32_t iconFrames = icon.frameCount;
    if (iconFrames < 1) iconFrames = 1;
    if (iconFrames > 3) iconFrames = 3;
    uint32_t headerFrames = 1 + iconFrames;

    uint32_t totalBytes = headerFrames * MemoryCard::c_sectorSize + dataLen;
    uint32_t blocksNeeded = (totalBytes + (MemoryCard::c_blockSize - 1)) >> 13;  // ceil over 8192
    if (blocksNeeded < 1) blocksNeeded = 1;
    if (blocksNeeded > 15) return Error::FileTooLarge;

    Error error = getCardState(port);
    if (error != Error::OK) return error;

    Frame dir[15];
    error = readDirectory(port, dir);
    if (error != Error::OK) return error;

    bool dirty[15] = {};

    // Free any existing file with the same name (in memory) so its blocks can
    // be reused and the old entry is overwritten.
    int existing = -1;
    findFirstBlock(dir, name, &existing);
    if (existing != -1) {
        uint16_t visited = 0;
        int block = existing;
        while (block >= 1 && block <= 15) {
            if (visited & (1 << block)) break;
            visited |= (1 << block);
            uint8_t *entry = dir[block - 1].bytes;
            uint16_t next = get16(entry + c_offNext);
            __builtin_memset(entry, 0, sizeof(Frame));
            put32(entry + c_offAlloc, c_stateFree);
            put16(entry + c_offNext, 0xffff);
            finishDirEntry(entry);
            dirty[block - 1] = true;
            if (next == 0xffff) break;
            block = next + 1;
        }
    }

    // Collect free blocks.
    uint8_t chain[15];
    uint32_t freeCount = 0;
    for (unsigned i = 0; i < 15 && freeCount < blocksNeeded; i++) {
        if (isFreeState(dir[i].bytes[c_offAlloc])) chain[freeCount++] = static_cast<uint8_t>(i + 1);
    }
    if (freeCount < blocksNeeded) return Error::OutOfSpace;

    // --- Write the data first; commit the directory last. ---

    const uint8_t *dataBytes = reinterpret_cast<const uint8_t *>(data);
    uint32_t dataOffset = 0;
    Frame fr;

    // Title frame (frame 0 of the first block).
    unsigned firstBase = chain[0] << 6;
    __builtin_memset(fr.bytes, 0, sizeof(fr.bytes));
    fr.bytes[0] = 'S';
    fr.bytes[1] = 'C';
    fr.bytes[2] = static_cast<uint8_t>(0x10 + iconFrames);  // 0x11/0x12/0x13
    fr.bytes[3] = static_cast<uint8_t>(blocksNeeded);
    // Encode the human-readable title to the 64-byte Shift-JIS field the BIOS
    // manager displays (fr.bytes is already zeroed, so this zero-pads).
    Sjis::utf8ToSjisTitle(fr.bytes + 0x04, 64, title);
    for (uint32_t c = 0; c < 16; c++) put16(fr.bytes + 0x60 + c * 2, icon.clut[c]);
    error = m_card.writeSectorBlocking(port, static_cast<uint16_t>(firstBase), fr.bytes);
    if (error != Error::OK) return error;

    // Icon frames (frames 1..iconFrames of the first block).
    for (uint32_t k = 0; k < iconFrames; k++) {
        __builtin_memcpy(fr.bytes, icon.pixels[k], 128);
        error = m_card.writeSectorBlocking(port, static_cast<uint16_t>(firstBase + 1 + k), fr.bytes);
        if (error != Error::OK) return error;
    }

    // Payload frames.
    for (uint32_t bi = 0; bi < blocksNeeded; bi++) {
        unsigned base = chain[bi] << 6;
        uint32_t startFrame = (bi == 0) ? headerFrames : 0;
        for (uint32_t frame = startFrame; frame < MemoryCard::c_sectorsPerBlock; frame++) {
            __builtin_memset(fr.bytes, 0, sizeof(fr.bytes));
            if (dataOffset < dataLen) {
                uint32_t chunk = dataLen - dataOffset;
                if (chunk > MemoryCard::c_sectorSize) chunk = MemoryCard::c_sectorSize;
                __builtin_memcpy(fr.bytes, dataBytes + dataOffset, chunk);
                dataOffset += chunk;
            }
            error = m_card.writeSectorBlocking(port, static_cast<uint16_t>(base + frame), fr.bytes);
            if (error != Error::OK) return error;
        }
    }

    // Build and mark the directory chain dirty.
    for (uint32_t bi = 0; bi < blocksNeeded; bi++) {
        uint8_t *entry = dir[chain[bi] - 1].bytes;
        __builtin_memset(entry, 0, sizeof(Frame));
        uint8_t state;
        if (blocksNeeded == 1) {
            state = c_stateFirst;
        } else if (bi == 0) {
            state = c_stateFirst;
        } else if (bi == blocksNeeded - 1) {
            state = c_stateLast;
        } else {
            state = c_stateMiddle;
        }
        put32(entry + c_offAlloc, state);
        if (bi == 0) {
            put32(entry + c_offSize, blocksNeeded * MemoryCard::c_blockSize);
            __builtin_memcpy(entry + c_offName, name, nameLen);  // null bytes already zeroed
        } else {
            put32(entry + c_offSize, 0);
        }
        uint16_t next = (bi == blocksNeeded - 1) ? 0xffff : static_cast<uint16_t>(chain[bi + 1] - 1);
        put16(entry + c_offNext, next);
        finishDirEntry(entry);
        dirty[chain[bi] - 1] = true;
    }

    // Commit all dirty directory entries.
    for (unsigned i = 0; i < 15; i++) {
        if (!dirty[i]) continue;
        error = m_card.writeSectorBlocking(port, static_cast<uint16_t>(i + 1), dir[i].bytes);
        if (error != Error::OK) return error;
    }
    return Error::OK;
}

Error psyqo::MemoryCardFileSystem::deleteFile(Port port, const char *name) {
    SIO0Bus::Lock lock;
    Error error = getCardState(port);
    if (error != Error::OK) return error;

    Frame dir[15];
    error = readDirectory(port, dir);
    if (error != Error::OK) return error;

    int first = -1;
    findFirstBlock(dir, name, &first);
    if (first == -1) return Error::FileNotFound;

    bool dirty[15] = {};
    uint16_t visited = 0;
    int block = first;
    while (block >= 1 && block <= 15) {
        if (visited & (1 << block)) break;
        visited |= (1 << block);
        uint8_t *entry = dir[block - 1].bytes;
        uint16_t next = get16(entry + c_offNext);
        __builtin_memset(entry, 0, sizeof(Frame));
        put32(entry + c_offAlloc, c_stateFree);
        put16(entry + c_offNext, 0xffff);
        finishDirEntry(entry);
        dirty[block - 1] = true;
        if (next == 0xffff) break;
        block = next + 1;
    }

    for (unsigned i = 0; i < 15; i++) {
        if (!dirty[i]) continue;
        error = m_card.writeSectorBlocking(port, static_cast<uint16_t>(i + 1), dir[i].bytes);
        if (error != Error::OK) return error;
    }
    return Error::OK;
}
