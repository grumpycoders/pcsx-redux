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
#include "psyqo/gpu.hh"
#include "psyqo/kernel.hh"
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

// ── Pure directory helpers ─────────────────────────────────────────────────

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
    return name[c_maxNameLength] == '\0';
}

bool psyqo::MemoryCardFileSystem::findFirstBlock(const Frame *dir15, const char *name, int *outBlock) {
    *outBlock = -1;
    for (unsigned i = 0; i < 15; i++) {
        const uint8_t *entry = dir15[i].bytes;
        if (entry[c_offAlloc] == c_stateFirst && nameMatches(entry, name)) {
            *outBlock = static_cast<int>(i + 1);
            return true;
        }
    }
    return false;
}

// ── Asynchronous engine ────────────────────────────────────────────────────

void psyqo::MemoryCardFileSystem::begin(GPU &gpu, Op op, Port port, eastl::function<void(Error)> &&callback) {
    Kernel::assert(!m_busy, "MemoryCardFileSystem: an operation is already in flight");
    m_busy = true;
    m_gpu = &gpu;
    m_op = op;
    m_port = port;
    m_callback = eastl::move(callback);
    m_result = Error::OK;
    m_idx = 0;
    if (!m_lockHeld) {
        SIO0Bus::acquire();
        m_lockHeld = true;
    }

    // Per-operation preflight and the starting phase.
    switch (op) {
        case Op::Format:
            m_phase = Phase::Format;
            break;
        case Op::WriteFile: {
            uint32_t nameLen = 0;
            while (m_name[nameLen] != '\0') {
                if (++nameLen > c_maxNameLength) {
                    m_result = Error::NameTooLong;
                    m_phase = Phase::Fail;
                    return;
                }
            }
            m_iconFrames = m_icon.frameCount;
            if (m_iconFrames < 1) m_iconFrames = 1;
            if (m_iconFrames > 3) m_iconFrames = 3;
            m_headerFrames = 1 + m_iconFrames;
            uint32_t totalBytes = m_headerFrames * MemoryCard::c_sectorSize + m_dataLen;
            m_blocksNeeded = (totalBytes + (MemoryCard::c_blockSize - 1)) >> 13;  // ceil over 8192
            if (m_blocksNeeded < 1) m_blocksNeeded = 1;
            if (m_blocksNeeded > 15) {
                m_result = Error::FileTooLarge;
                m_phase = Phase::Fail;
                return;
            }
            m_phase = Phase::Header;
            break;
        }
        default:
            m_phase = Phase::Header;
            break;
    }
}

void psyqo::MemoryCardFileSystem::armTick() {
    m_timer = m_gpu->armPeriodicTimer(c_tickPeriod, [this](uint32_t) { onTick(); });
}

void psyqo::MemoryCardFileSystem::onTick() {
    if (!m_busy) return;
    if (pump() == StepResult::Done) finish(m_result);
}

Error psyqo::MemoryCardFileSystem::runBlocking(GPU &gpu) {
    // Drive the state machine directly, pumping the GPU between sectors so the
    // display and other callbacks stay alive during the blocking operation.
    while (m_busy) {
        if (pump() == StepResult::Done) finish(m_result);
        gpu.pumpCallbacks();
    }
    return m_result;
}

void psyqo::MemoryCardFileSystem::finish(Error error) {
    if (m_timer) {
        m_gpu->cancelTimer(m_timer);
        m_timer = 0;
    }
    if (m_lockHeld) {
        SIO0Bus::release();
        m_lockHeld = false;
    }
    m_busy = false;
    m_result = error;
    auto callback = eastl::move(m_callback);
    m_callback = nullptr;
    if (callback) callback(error);
}

// One sector transfer per call; advances the per-operation state machine.
psyqo::MemoryCardFileSystem::StepResult psyqo::MemoryCardFileSystem::pump() {
    switch (m_phase) {
        case Phase::Fail:
            return StepResult::Done;

        case Phase::Header: {
            m_result = m_card.readSectorBlocking(m_port, 0, m_scratch.bytes);
            if (m_result != Error::OK) return StepResult::Done;
            bool formatted = m_scratch.bytes[0] == 'M' && m_scratch.bytes[1] == 'C';
            if (m_op == Op::GetCardState) {
                if (!formatted) m_result = Error::NotFormatted;
                return StepResult::Done;
            }
            if (!formatted) {
                m_result = Error::NotFormatted;
                return StepResult::Done;
            }
            m_phase = Phase::ReadDir;
            m_idx = 0;
            return StepResult::Continue;
        }

        case Phase::ReadDir: {
            m_result = m_card.readSectorBlocking(m_port, static_cast<uint16_t>(m_idx + 1), m_dir[m_idx].bytes);
            if (m_result != Error::OK) return StepResult::Done;
            if (++m_idx < 15) return StepResult::Continue;
            return afterReadDir();
        }

        case Phase::ReadTitle: {
            // Read the file's first frame to learn how many leading frames are
            // title + icon (not part of the payload).
            m_result = m_card.readSectorBlocking(m_port, blockToSector(m_chain[0]), m_scratch.bytes);
            if (m_result != Error::OK) return StepResult::Done;
            m_headerFrames = 0;
            if (m_scratch.bytes[0] == 'S' && m_scratch.bytes[1] == 'C') {
                uint32_t iconFrames = m_scratch.bytes[2] & 0x0f;
                if (iconFrames < 1 || iconFrames > 3) iconFrames = 1;
                m_headerFrames = 1 + iconFrames;
            }
            m_blockIdx = 0;
            m_frameInBlock = m_headerFrames;
            m_written = 0;
            m_phase = Phase::ReadData;
            return StepResult::Continue;
        }

        case Phase::ReadData: {
            unsigned base = m_chain[m_blockIdx] << 6;
            m_result =
                m_card.readSectorBlocking(m_port, static_cast<uint16_t>(base + m_frameInBlock), m_scratch.bytes);
            if (m_result != Error::OK) return StepResult::Done;
            uint32_t chunk = MemoryCard::c_sectorSize;
            if (chunk > m_maxLen - m_written) chunk = m_maxLen - m_written;
            __builtin_memcpy(reinterpret_cast<uint8_t *>(m_readBuffer) + m_written, m_scratch.bytes, chunk);
            m_written += chunk;
            if (++m_frameInBlock >= MemoryCard::c_sectorsPerBlock) {
                m_frameInBlock = 0;
                m_blockIdx++;
            }
            if (m_blockIdx >= m_chainLen || m_written >= m_maxLen) {
                uint32_t totalSectors = m_chainLen * MemoryCard::c_sectorsPerBlock;
                uint32_t dataBytes = (totalSectors - m_headerFrames) * MemoryCard::c_sectorSize;
                if (m_outLen) *m_outLen = dataBytes < m_maxLen ? dataBytes : m_maxLen;
                return StepResult::Done;
            }
            return StepResult::Continue;
        }

        case Phase::WriteData: {
            unsigned base = m_chain[m_blockIdx] << 6;
            uint32_t frame = m_frameInBlock;
            __builtin_memset(m_scratch.bytes, 0, sizeof(m_scratch.bytes));
            if (m_blockIdx == 0 && frame == 0) {
                // Title frame.
                m_scratch.bytes[0] = 'S';
                m_scratch.bytes[1] = 'C';
                m_scratch.bytes[2] = static_cast<uint8_t>(0x10 + m_iconFrames);  // 0x11/0x12/0x13
                m_scratch.bytes[3] = static_cast<uint8_t>(m_blocksNeeded);
                Sjis::utf8ToSjisTitle(m_scratch.bytes + 0x04, 64, m_title);
                for (uint32_t c = 0; c < 16; c++) put16(m_scratch.bytes + 0x60 + c * 2, m_icon.clut[c]);
            } else if (m_blockIdx == 0 && frame >= 1 && frame <= m_iconFrames) {
                // Icon frame.
                __builtin_memcpy(m_scratch.bytes, m_icon.pixels[frame - 1], 128);
            } else {
                // Payload frame.
                if (m_dataOffset < m_dataLen) {
                    uint32_t chunk = m_dataLen - m_dataOffset;
                    if (chunk > MemoryCard::c_sectorSize) chunk = MemoryCard::c_sectorSize;
                    __builtin_memcpy(m_scratch.bytes,
                                     reinterpret_cast<const uint8_t *>(m_writeData) + m_dataOffset, chunk);
                    m_dataOffset += chunk;
                }
            }
            m_result = m_card.writeSectorBlocking(m_port, static_cast<uint16_t>(base + frame), m_scratch.bytes);
            if (m_result != Error::OK) return StepResult::Done;
            if (++m_frameInBlock >= MemoryCard::c_sectorsPerBlock) {
                m_frameInBlock = 0;
                m_blockIdx++;
            }
            if (m_blockIdx >= m_blocksNeeded) {
                // All data written. Build the directory chain in memory, then
                // commit it (the directory is written last so an interrupted
                // write never leaves a referenced but corrupt file).
                uint32_t nameLen = 0;
                while (m_name[nameLen] != '\0') nameLen++;
                for (uint32_t bi = 0; bi < m_blocksNeeded; bi++) {
                    uint8_t *entry = m_dir[m_chain[bi] - 1].bytes;
                    __builtin_memset(entry, 0, sizeof(Frame));
                    uint8_t state;
                    if (m_blocksNeeded == 1 || bi == 0) {
                        state = c_stateFirst;
                    } else if (bi == m_blocksNeeded - 1) {
                        state = c_stateLast;
                    } else {
                        state = c_stateMiddle;
                    }
                    put32(entry + c_offAlloc, state);
                    if (bi == 0) {
                        put32(entry + c_offSize, m_blocksNeeded * MemoryCard::c_blockSize);
                        __builtin_memcpy(entry + c_offName, m_name, nameLen);
                    } else {
                        put32(entry + c_offSize, 0);
                    }
                    uint16_t next =
                        (bi == m_blocksNeeded - 1) ? 0xffff : static_cast<uint16_t>(m_chain[bi + 1] - 1);
                    put16(entry + c_offNext, next);
                    finishDirEntry(entry);
                    m_dirty[m_chain[bi] - 1] = true;
                }
                m_phase = Phase::WriteDir;
                m_idx = 0;
            }
            return StepResult::Continue;
        }

        case Phase::WriteDir: {
            // Write the next dirty directory entry; finish when none remain.
            while (m_idx < 15 && !m_dirty[m_idx]) m_idx++;
            if (m_idx >= 15) return StepResult::Done;
            m_result = m_card.writeSectorBlocking(m_port, static_cast<uint16_t>(m_idx + 1), m_dir[m_idx].bytes);
            if (m_result != Error::OK) return StepResult::Done;
            m_idx++;
            return StepResult::Continue;
        }

        case Phase::Format: {
            uint16_t sector = static_cast<uint16_t>(m_idx);
            __builtin_memset(m_scratch.bytes, 0, sizeof(m_scratch.bytes));
            if (sector == 0 || sector == 63) {
                // Header frame and the write-test frame: "MC".
                m_scratch.bytes[0] = 'M';
                m_scratch.bytes[1] = 'C';
                finishDirEntry(m_scratch.bytes);
            } else if (sector >= 1 && sector <= 15) {
                // Directory frames: all free.
                put32(m_scratch.bytes + c_offAlloc, c_stateFree);
                put32(m_scratch.bytes + c_offSize, 0);
                put16(m_scratch.bytes + c_offNext, 0xffff);
                finishDirEntry(m_scratch.bytes);
            } else if (sector >= 16 && sector <= 35) {
                // Broken sector list: all unused.
                put32(m_scratch.bytes + 0x00, 0xffffffff);
                put16(m_scratch.bytes + 0x08, 0xffff);
                finishDirEntry(m_scratch.bytes);
            }
            // sectors 36..62: zero (already memset).
            m_result = m_card.writeSectorBlocking(m_port, sector, m_scratch.bytes);
            if (m_result != Error::OK) return StepResult::Done;
            if (++m_idx > 63) return StepResult::Done;
            return StepResult::Continue;
        }
    }
    return StepResult::Done;
}

// Pure per-operation transition once the 15 directory frames are in memory.
psyqo::MemoryCardFileSystem::StepResult psyqo::MemoryCardFileSystem::afterReadDir() {
    switch (m_op) {
        case Op::GetFreeBlockCount: {
            uint32_t free = 0;
            for (unsigned i = 0; i < 15; i++) {
                if (isFreeState(m_dir[i].bytes[c_offAlloc])) free++;
            }
            if (m_outFreeBlocks) *m_outFreeBlocks = free;
            return StepResult::Done;
        }

        case Op::ListFiles: {
            uint32_t count = 0;
            for (unsigned i = 0; i < 15; i++) {
                const uint8_t *entry = m_dir[i].bytes;
                if (entry[c_offAlloc] != c_stateFirst) continue;
                if (m_outEntries && count < m_maxEntries) {
                    FileEntry &dst = m_outEntries[count];
                    __builtin_memcpy(dst.name, entry + c_offName, 20);
                    dst.name[20] = '\0';
                    dst.sizeInBlocks = static_cast<uint16_t>(get32(entry + c_offSize) >> 13);
                    dst.firstBlock = static_cast<uint8_t>(i + 1);
                }
                count++;
            }
            if (m_outCount) *m_outCount = count;
            return StepResult::Done;
        }

        case Op::FileExists: {
            int block = -1;
            findFirstBlock(m_dir, m_name, &block);
            if (m_outExists) *m_outExists = block != -1;
            return StepResult::Done;
        }

        case Op::ReadFile: {
            int first = -1;
            findFirstBlock(m_dir, m_name, &first);
            if (first == -1) {
                m_result = Error::FileNotFound;
                return StepResult::Done;
            }
            // Walk the block chain, guarding against malformed loops.
            m_chainLen = 0;
            uint16_t visited = 0;
            int block = first;
            while (block >= 1 && block <= 15 && m_chainLen < 16) {
                if (visited & (1 << block)) {
                    m_result = Error::BadData;
                    return StepResult::Done;
                }
                visited |= (1 << block);
                m_chain[m_chainLen++] = static_cast<uint8_t>(block);
                uint16_t next = get16(m_dir[block - 1].bytes + c_offNext);
                if (next == 0xffff) break;
                block = next + 1;
            }
            m_phase = Phase::ReadTitle;
            return StepResult::Continue;
        }

        case Op::WriteFile: {
            for (unsigned i = 0; i < 15; i++) m_dirty[i] = false;
            // Free any existing file with the same name so its blocks can be
            // reused and its old entry overwritten.
            int existing = -1;
            findFirstBlock(m_dir, m_name, &existing);
            if (existing != -1) {
                uint16_t visited = 0;
                int block = existing;
                while (block >= 1 && block <= 15) {
                    if (visited & (1 << block)) break;
                    visited |= (1 << block);
                    uint8_t *entry = m_dir[block - 1].bytes;
                    uint16_t next = get16(entry + c_offNext);
                    __builtin_memset(entry, 0, sizeof(Frame));
                    put32(entry + c_offAlloc, c_stateFree);
                    put16(entry + c_offNext, 0xffff);
                    finishDirEntry(entry);
                    m_dirty[block - 1] = true;
                    if (next == 0xffff) break;
                    block = next + 1;
                }
            }
            // Collect the free blocks the new file will occupy.
            m_chainLen = 0;
            for (unsigned i = 0; i < 15 && m_chainLen < m_blocksNeeded; i++) {
                if (isFreeState(m_dir[i].bytes[c_offAlloc])) m_chain[m_chainLen++] = static_cast<uint8_t>(i + 1);
            }
            if (m_chainLen < m_blocksNeeded) {
                m_result = Error::OutOfSpace;
                return StepResult::Done;
            }
            m_blockIdx = 0;
            m_frameInBlock = 0;
            m_dataOffset = 0;
            m_phase = Phase::WriteData;
            return StepResult::Continue;
        }

        case Op::DeleteFile: {
            for (unsigned i = 0; i < 15; i++) m_dirty[i] = false;
            int first = -1;
            findFirstBlock(m_dir, m_name, &first);
            if (first == -1) {
                m_result = Error::FileNotFound;
                return StepResult::Done;
            }
            uint16_t visited = 0;
            int block = first;
            while (block >= 1 && block <= 15) {
                if (visited & (1 << block)) break;
                visited |= (1 << block);
                uint8_t *entry = m_dir[block - 1].bytes;
                uint16_t next = get16(entry + c_offNext);
                __builtin_memset(entry, 0, sizeof(Frame));
                put32(entry + c_offAlloc, c_stateFree);
                put16(entry + c_offNext, 0xffff);
                finishDirEntry(entry);
                m_dirty[block - 1] = true;
                if (next == 0xffff) break;
                block = next + 1;
            }
            m_phase = Phase::WriteDir;
            m_idx = 0;
            return StepResult::Continue;
        }

        default:
            return StepResult::Done;
    }
}

// ── Public asynchronous operations (the callback basis) ────────────────────

void psyqo::MemoryCardFileSystem::getCardState(GPU &gpu, Port port, eastl::function<void(Error)> &&callback) {
    begin(gpu, Op::GetCardState, port, eastl::move(callback));
    armTick();
}

void psyqo::MemoryCardFileSystem::format(GPU &gpu, Port port, eastl::function<void(Error)> &&callback) {
    begin(gpu, Op::Format, port, eastl::move(callback));
    armTick();
}

void psyqo::MemoryCardFileSystem::getFreeBlockCount(GPU &gpu, Port port, uint32_t *outFreeBlocks,
                                                    eastl::function<void(Error)> &&callback) {
    m_outFreeBlocks = outFreeBlocks;
    if (outFreeBlocks) *outFreeBlocks = 0;
    begin(gpu, Op::GetFreeBlockCount, port, eastl::move(callback));
    armTick();
}

void psyqo::MemoryCardFileSystem::listFiles(GPU &gpu, Port port, FileEntry *out, uint32_t maxEntries,
                                            uint32_t *outCount, eastl::function<void(Error)> &&callback) {
    m_outEntries = out;
    m_maxEntries = maxEntries;
    m_outCount = outCount;
    if (outCount) *outCount = 0;
    begin(gpu, Op::ListFiles, port, eastl::move(callback));
    armTick();
}

void psyqo::MemoryCardFileSystem::fileExists(GPU &gpu, Port port, const char *name, bool *outExists,
                                             eastl::function<void(Error)> &&callback) {
    m_name = name;
    m_outExists = outExists;
    if (outExists) *outExists = false;
    begin(gpu, Op::FileExists, port, eastl::move(callback));
    armTick();
}

void psyqo::MemoryCardFileSystem::readFile(GPU &gpu, Port port, const char *name, void *buffer, uint32_t maxLen,
                                           uint32_t *outLen, eastl::function<void(Error)> &&callback) {
    m_name = name;
    m_readBuffer = buffer;
    m_maxLen = maxLen;
    m_outLen = outLen;
    if (outLen) *outLen = 0;
    begin(gpu, Op::ReadFile, port, eastl::move(callback));
    armTick();
}

void psyqo::MemoryCardFileSystem::writeFile(GPU &gpu, Port port, const char *name, const char *title,
                                            const Icon &icon, const void *data, uint32_t dataLen,
                                            eastl::function<void(Error)> &&callback) {
    m_name = name;
    m_title = title;
    m_icon = icon;
    m_writeData = data;
    m_dataLen = dataLen;
    begin(gpu, Op::WriteFile, port, eastl::move(callback));
    armTick();
}

void psyqo::MemoryCardFileSystem::deleteFile(GPU &gpu, Port port, const char *name,
                                             eastl::function<void(Error)> &&callback) {
    m_name = name;
    begin(gpu, Op::DeleteFile, port, eastl::move(callback));
    armTick();
}

// ── Blocking variants ──────────────────────────────────────────────────────

Error psyqo::MemoryCardFileSystem::getCardStateBlocking(GPU &gpu, Port port) {
    begin(gpu, Op::GetCardState, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::formatBlocking(GPU &gpu, Port port) {
    begin(gpu, Op::Format, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::getFreeBlockCountBlocking(GPU &gpu, Port port, uint32_t *outFreeBlocks) {
    m_outFreeBlocks = outFreeBlocks;
    if (outFreeBlocks) *outFreeBlocks = 0;
    begin(gpu, Op::GetFreeBlockCount, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::listFilesBlocking(GPU &gpu, Port port, FileEntry *out, uint32_t maxEntries,
                                                     uint32_t *outCount) {
    m_outEntries = out;
    m_maxEntries = maxEntries;
    m_outCount = outCount;
    if (outCount) *outCount = 0;
    begin(gpu, Op::ListFiles, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::fileExistsBlocking(GPU &gpu, Port port, const char *name, bool *outExists) {
    m_name = name;
    m_outExists = outExists;
    if (outExists) *outExists = false;
    begin(gpu, Op::FileExists, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::readFileBlocking(GPU &gpu, Port port, const char *name, void *buffer,
                                                    uint32_t maxLen, uint32_t *outLen) {
    m_name = name;
    m_readBuffer = buffer;
    m_maxLen = maxLen;
    m_outLen = outLen;
    if (outLen) *outLen = 0;
    begin(gpu, Op::ReadFile, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::writeFileBlocking(GPU &gpu, Port port, const char *name, const char *title,
                                                     const Icon &icon, const void *data, uint32_t dataLen) {
    m_name = name;
    m_title = title;
    m_icon = icon;
    m_writeData = data;
    m_dataLen = dataLen;
    begin(gpu, Op::WriteFile, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::deleteFileBlocking(GPU &gpu, Port port, const char *name) {
    m_name = name;
    begin(gpu, Op::DeleteFile, port, {});
    return runBlocking(gpu);
}
