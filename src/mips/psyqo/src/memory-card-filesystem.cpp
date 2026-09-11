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

#include "common/util/sjis-title-encoder.hh"
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

// -- Pure directory helpers -------------------------------------------------

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

uint16_t psyqo::MemoryCardFileSystem::reachableBlocks(const Frame *dir15) {
    uint16_t inUse = 0;
    for (unsigned i = 0; i < 15; i++) {
        if (dir15[i].bytes[c_offAlloc] != c_stateFirst) continue;
        // Walk this file's chain, marking each block in use; stop on a malformed
        // loop so a corrupt card cannot hang the scan. A middle/last block that
        // no head reaches is left unmarked, hence treated as free.
        uint16_t visited = 0;
        int block = static_cast<int>(i + 1);
        while (block >= 1 && block <= 15) {
            if (visited & (1 << block)) break;
            visited |= 1 << block;
            inUse |= 1 << block;
            uint16_t next = get16(dir15[block - 1].bytes + c_offNext);
            if (next == 0xffff) break;
            block = next + 1;
        }
    }
    return inUse;
}

// -- Asynchronous engine ----------------------------------------------------

void psyqo::MemoryCardFileSystem::begin(Op op, Port port, eastl::function<void(Error)> &&callback) {
    Kernel::assert(!m_busy, "MemoryCardFileSystem: an operation is already in flight");
    m_busy = true;
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

Error psyqo::MemoryCardFileSystem::runBlocking(GPU &gpu) {
    // Drive the same asynchronous chain, pumping the kernel callback queue (where
    // the card's interrupt-completion callbacks are delivered) until the
    // transaction finishes, so the display and other callbacks stay alive.
    issueOrFinish();
    while (m_busy) gpu.pumpCallbacks();
    return m_result;
}

void psyqo::MemoryCardFileSystem::finish(Error error) {
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

// Issues the asynchronous device transfer for the current phase/indices (the
// pre-I/O half of a step: it also builds the outgoing frame for write phases),
// then returns; `onSectorDone` runs the post-I/O half when the card interrupts
// completion. A phase with no transfer left to do finishes the transaction.
void psyqo::MemoryCardFileSystem::issueOrFinish() {
    switch (m_phase) {
        case Phase::Fail:
            finish(m_result);
            return;

        case Phase::Header:
            m_card.readSector(m_port, 0, m_scratch.bytes, [this](Error e) { onSectorDone(e); });
            return;

        case Phase::ReadDir:
            m_card.readSector(m_port, static_cast<uint16_t>(m_idx + 1), m_dir[m_idx].bytes,
                              [this](Error e) { onSectorDone(e); });
            return;

        case Phase::ReadTitle:
            // Read the file's first frame to learn how many leading frames are
            // title + icon (not part of the payload).
            m_card.readSector(m_port, blockToSector(m_chain[0]), m_scratch.bytes,
                              [this](Error e) { onSectorDone(e); });
            return;

        case Phase::ReadData: {
            unsigned base = m_chain[m_blockIdx] << 6;
            m_card.readSector(m_port, static_cast<uint16_t>(base + m_frameInBlock), m_scratch.bytes,
                              [this](Error e) { onSectorDone(e); });
            return;
        }

        case Phase::ReadInfo:
            // Read the file's first block: frame 0 is the title + palette,
            // frames 1..N are the icon bitmaps.
            m_card.readSector(m_port, static_cast<uint16_t>(blockToSector(m_chain[0]) + m_frameInBlock),
                              m_scratch.bytes, [this](Error e) { onSectorDone(e); });
            return;

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
                Sjis::g_titleEncoder(m_scratch.bytes + 0x04, 64, m_title);
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
            m_card.writeSector(m_port, static_cast<uint16_t>(base + frame), m_scratch.bytes,
                               [this](Error e) { onSectorDone(e); });
            return;
        }

        case Phase::WriteDir: {
            // Commit the directory entries in m_writeOrder (head last for a
            // create, head first for a delete); finish when all are written.
            if (m_idx >= m_writeOrderLen) {
                finish(m_result);
                return;
            }
            uint8_t slot = m_writeOrder[m_idx];
            m_card.writeSector(m_port, static_cast<uint16_t>(slot + 1), m_dir[slot].bytes,
                               [this](Error e) { onSectorDone(e); });
            return;
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
            m_card.writeSector(m_port, sector, m_scratch.bytes, [this](Error e) { onSectorDone(e); });
            return;
        }
    }
}

// The post-I/O half of a step: the just-issued transfer has completed with
// `error`. Consume its result, advance the per-operation state machine, then
// chain the next transfer (or finish).
void psyqo::MemoryCardFileSystem::onSectorDone(Error error) {
    m_result = error;
    if (error != Error::OK) {
        finish(error);
        return;
    }
    switch (m_phase) {
        case Phase::Fail:
            finish(m_result);
            return;

        case Phase::Header: {
            bool formatted = m_scratch.bytes[0] == 'M' && m_scratch.bytes[1] == 'C';
            if (m_op == Op::GetCardState) {
                if (!formatted) m_result = Error::NotFormatted;
                finish(m_result);
                return;
            }
            if (!formatted) {
                m_result = Error::NotFormatted;
                finish(m_result);
                return;
            }
            m_phase = Phase::ReadDir;
            m_idx = 0;
            break;
        }

        case Phase::ReadDir: {
            if (++m_idx < 15) break;  // read the next directory frame
            if (afterReadDir() == StepResult::Done) {
                finish(m_result);
                return;
            }
            break;  // afterReadDir set up the next phase
        }

        case Phase::ReadTitle: {
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
            break;
        }

        case Phase::ReadData: {
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
                finish(m_result);
                return;
            }
            break;
        }

        case Phase::ReadInfo: {
            if (m_frameInBlock == 0) {
                // Title frame: magic "SC", the icon frame count, the raw
                // Shift-JIS title and the 16-colour palette.
                uint32_t iconFrames = 1;
                if (m_scratch.bytes[0] == 'S' && m_scratch.bytes[1] == 'C') {
                    iconFrames = m_scratch.bytes[2] & 0x0f;
                    if (iconFrames < 1 || iconFrames > 3) iconFrames = 1;
                }
                m_iconFrames = iconFrames;
                if (m_outInfo) {
                    __builtin_memcpy(m_outInfo->title, m_scratch.bytes + 0x04, 64);
                    m_outInfo->title[64] = '\0';
                    m_outInfo->icon.frameCount = static_cast<uint8_t>(iconFrames);
                    for (uint32_t c = 0; c < 16; c++) {
                        m_outInfo->icon.clut[c] = get16(m_scratch.bytes + 0x60 + c * 2);
                    }
                    __builtin_memset(m_outInfo->icon.pixels, 0, sizeof(m_outInfo->icon.pixels));
                }
            } else if (m_outInfo && m_frameInBlock <= m_iconFrames) {
                // Icon frame.
                __builtin_memcpy(m_outInfo->icon.pixels[m_frameInBlock - 1], m_scratch.bytes, 128);
            }
            if (++m_frameInBlock > m_iconFrames) {
                finish(m_result);
                return;
            }
            break;
        }

        case Phase::WriteData: {
            if (++m_frameInBlock >= MemoryCard::c_sectorsPerBlock) {
                m_frameInBlock = 0;
                m_blockIdx++;
            }
            if (m_blockIdx >= m_blocksNeeded) {
                // All data written. Build the new file's directory entries in
                // memory, then commit them with the head (the 0x51 first block)
                // written LAST, so a power loss can only orphan tail blocks and
                // never publishes a half-formed file.
                uint32_t nameLen = 0;
                while (m_name[nameLen] != '\0') nameLen++;
                uint16_t inNewChain = 0;
                for (uint32_t bi = 0; bi < m_blocksNeeded; bi++) inNewChain |= 1 << m_chain[bi];
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
                }
                // Commit order: any blocks of a replaced file that are not reused
                // (now marked deleted) first, then the new chain from its tail up
                // to its head, so the 0x51 head lands last.
                m_writeOrderLen = 0;
                for (unsigned s = 0; s < 15; s++) {
                    if (m_dirty[s] && !(inNewChain & (1 << (s + 1)))) {
                        m_writeOrder[m_writeOrderLen++] = static_cast<uint8_t>(s);
                    }
                }
                for (uint32_t bi = m_blocksNeeded; bi-- > 0;) {
                    m_writeOrder[m_writeOrderLen++] = static_cast<uint8_t>(m_chain[bi] - 1);
                }
                m_phase = Phase::WriteDir;
                m_idx = 0;
            }
            break;
        }

        case Phase::WriteDir:
            m_idx++;  // advance to the next entry in the write order
            break;

        case Phase::Format:
            if (++m_idx > 63) {
                finish(m_result);
                return;
            }
            break;
    }
    issueOrFinish();
}

// Pure per-operation transition once the 15 directory frames are in memory.
psyqo::MemoryCardFileSystem::StepResult psyqo::MemoryCardFileSystem::afterReadDir() {
    switch (m_op) {
        case Op::GetFreeBlockCount: {
            uint16_t inUse = reachableBlocks(m_dir);
            uint32_t free = 0;
            for (unsigned i = 0; i < 15; i++) {
                if (!(inUse & (1 << (i + 1)))) free++;
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
            for (;;) {
                // The only clean way out of a chain is the 0xffff terminator. A
                // block index outside [1, 15], a link we have already visited
                // (a loop), or an impossibly long chain all mean the on-card
                // link table is corrupt: bail with BadData rather than silently
                // returning the truncated prefix as a successful read. (The
                // original BIOS truncates and reports success here; we don't.)
                if (block < 1 || block > 15 || m_chainLen >= 16 || (visited & (1 << block))) {
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

        case Op::ReadInfo: {
            // The title and icon live in the file's first block; no need to walk
            // the rest of the chain.
            int first = -1;
            findFirstBlock(m_dir, m_name, &first);
            if (first == -1) {
                m_result = Error::FileNotFound;
                return StepResult::Done;
            }
            m_chain[0] = static_cast<uint8_t>(first);
            m_frameInBlock = 0;
            m_iconFrames = 1;
            m_phase = Phase::ReadInfo;
            return StepResult::Continue;
        }

        case Op::WriteFile: {
            for (unsigned i = 0; i < 15; i++) m_dirty[i] = false;
            // Delete any existing file with the same name so its blocks can be
            // reused. Mark the chain deleted in place (keep links and name), the
            // same as deleteFile, rather than wiping it.
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
                    entry[c_offAlloc] = deletedState(entry[c_offAlloc]);
                    finishDirEntry(entry);
                    m_dirty[block - 1] = true;
                    if (next == 0xffff) break;
                    block = next + 1;
                }
            }
            // Collect the blocks the new file will occupy, preferring
            // never-allocated blocks over deleted ones (so deletions stay
            // recoverable) and ignoring blocks any valid file still references.
            uint16_t inUse = reachableBlocks(m_dir);
            m_chainLen = 0;
            for (unsigned i = 0; i < 15 && m_chainLen < m_blocksNeeded; i++) {
                if (!(inUse & (1 << (i + 1))) && m_dir[i].bytes[c_offAlloc] == c_stateFree) {
                    m_chain[m_chainLen++] = static_cast<uint8_t>(i + 1);
                }
            }
            for (unsigned i = 0; i < 15 && m_chainLen < m_blocksNeeded; i++) {
                if (!(inUse & (1 << (i + 1))) && m_dir[i].bytes[c_offAlloc] != c_stateFree) {
                    m_chain[m_chainLen++] = static_cast<uint8_t>(i + 1);
                }
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
            int first = -1;
            findFirstBlock(m_dir, m_name, &first);
            if (first == -1) {
                m_result = Error::FileNotFound;
                return StepResult::Done;
            }
            // Mark the chain deleted in place (keep links and name so it stays
            // recoverable), recording the write order head-first: cutting the
            // 0x51 head to 0xa1 is the first commit, so a power loss leaves only
            // orphaned tail blocks, which read as free.
            m_writeOrderLen = 0;
            uint16_t visited = 0;
            int block = first;
            while (block >= 1 && block <= 15) {
                if (visited & (1 << block)) break;
                visited |= (1 << block);
                uint8_t *entry = m_dir[block - 1].bytes;
                uint16_t next = get16(entry + c_offNext);
                entry[c_offAlloc] = deletedState(entry[c_offAlloc]);
                finishDirEntry(entry);
                m_writeOrder[m_writeOrderLen++] = static_cast<uint8_t>(block - 1);
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

// -- Public asynchronous operations (the callback basis) --------------------

void psyqo::MemoryCardFileSystem::getCardState(Port port, eastl::function<void(Error)> &&callback) {
    begin(Op::GetCardState, port, eastl::move(callback));
    issueOrFinish();
}

void psyqo::MemoryCardFileSystem::format(Port port, eastl::function<void(Error)> &&callback) {
    begin(Op::Format, port, eastl::move(callback));
    issueOrFinish();
}

void psyqo::MemoryCardFileSystem::getFreeBlockCount(Port port, uint32_t *outFreeBlocks,
                                                    eastl::function<void(Error)> &&callback) {
    m_outFreeBlocks = outFreeBlocks;
    if (outFreeBlocks) *outFreeBlocks = 0;
    begin(Op::GetFreeBlockCount, port, eastl::move(callback));
    issueOrFinish();
}

void psyqo::MemoryCardFileSystem::listFiles(Port port, FileEntry *out, uint32_t maxEntries,
                                            uint32_t *outCount, eastl::function<void(Error)> &&callback) {
    m_outEntries = out;
    m_maxEntries = maxEntries;
    m_outCount = outCount;
    if (outCount) *outCount = 0;
    begin(Op::ListFiles, port, eastl::move(callback));
    issueOrFinish();
}

void psyqo::MemoryCardFileSystem::fileExists(Port port, const char *name, bool *outExists,
                                             eastl::function<void(Error)> &&callback) {
    m_name = name;
    m_outExists = outExists;
    if (outExists) *outExists = false;
    begin(Op::FileExists, port, eastl::move(callback));
    issueOrFinish();
}

void psyqo::MemoryCardFileSystem::readFile(Port port, const char *name, void *buffer, uint32_t maxLen,
                                           uint32_t *outLen, eastl::function<void(Error)> &&callback) {
    m_name = name;
    m_readBuffer = buffer;
    m_maxLen = maxLen;
    m_outLen = outLen;
    if (outLen) *outLen = 0;
    begin(Op::ReadFile, port, eastl::move(callback));
    issueOrFinish();
}

void psyqo::MemoryCardFileSystem::readFileInfo(Port port, const char *name, FileInfo *out,
                                               eastl::function<void(Error)> &&callback) {
    m_name = name;
    m_outInfo = out;
    begin(Op::ReadInfo, port, eastl::move(callback));
    issueOrFinish();
}

void psyqo::MemoryCardFileSystem::writeFile(Port port, const char *name, const char *title,
                                            const Icon &icon, const void *data, uint32_t dataLen,
                                            eastl::function<void(Error)> &&callback) {
    m_name = name;
    m_title = title;
    m_icon = icon;
    m_writeData = data;
    m_dataLen = dataLen;
    begin(Op::WriteFile, port, eastl::move(callback));
    issueOrFinish();
}

void psyqo::MemoryCardFileSystem::deleteFile(Port port, const char *name,
                                             eastl::function<void(Error)> &&callback) {
    m_name = name;
    begin(Op::DeleteFile, port, eastl::move(callback));
    issueOrFinish();
}

// -- Blocking variants ------------------------------------------------------

Error psyqo::MemoryCardFileSystem::getCardStateBlocking(GPU &gpu, Port port) {
    begin(Op::GetCardState, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::formatBlocking(GPU &gpu, Port port) {
    begin(Op::Format, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::getFreeBlockCountBlocking(GPU &gpu, Port port, uint32_t *outFreeBlocks) {
    m_outFreeBlocks = outFreeBlocks;
    if (outFreeBlocks) *outFreeBlocks = 0;
    begin(Op::GetFreeBlockCount, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::listFilesBlocking(GPU &gpu, Port port, FileEntry *out, uint32_t maxEntries,
                                                     uint32_t *outCount) {
    m_outEntries = out;
    m_maxEntries = maxEntries;
    m_outCount = outCount;
    if (outCount) *outCount = 0;
    begin(Op::ListFiles, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::fileExistsBlocking(GPU &gpu, Port port, const char *name, bool *outExists) {
    m_name = name;
    m_outExists = outExists;
    if (outExists) *outExists = false;
    begin(Op::FileExists, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::readFileBlocking(GPU &gpu, Port port, const char *name, void *buffer,
                                                    uint32_t maxLen, uint32_t *outLen) {
    m_name = name;
    m_readBuffer = buffer;
    m_maxLen = maxLen;
    m_outLen = outLen;
    if (outLen) *outLen = 0;
    begin(Op::ReadFile, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::readFileInfoBlocking(GPU &gpu, Port port, const char *name, FileInfo *out) {
    m_name = name;
    m_outInfo = out;
    begin(Op::ReadInfo, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::writeFileBlocking(GPU &gpu, Port port, const char *name, const char *title,
                                                     const Icon &icon, const void *data, uint32_t dataLen) {
    m_name = name;
    m_title = title;
    m_icon = icon;
    m_writeData = data;
    m_dataLen = dataLen;
    begin(Op::WriteFile, port, {});
    return runBlocking(gpu);
}

Error psyqo::MemoryCardFileSystem::deleteFileBlocking(GPU &gpu, Port port, const char *name) {
    m_name = name;
    begin(Op::DeleteFile, port, {});
    return runBlocking(gpu);
}
