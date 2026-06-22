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

#pragma once

#include <stdint.h>

#include "psyqo/memory-card.hh"

namespace psyqo {

/**
 * @brief A Sony-compatible memory card filesystem.
 *
 * @details This class implements the on-card filesystem used by the retail
 * PlayStation BIOS, on top of the raw sector access provided by `MemoryCard`.
 * Files written through it are 100% compatible with the BIOS memory card
 * manager: they show up with their title and icon, and can be copied or
 * deleted from the BIOS like any other save.
 *
 * The card is laid out as a 16-block device (block 0 is the directory, blocks
 * 1..15 hold files). A file occupies one or more whole 8KiB blocks, chained
 * through the directory as a linked list. The first block of a file starts
 * with a "title frame" (magic "SC", a Shift-JIS title and a 16-colour palette)
 * followed by 1..3 icon frames (16x16, 4bpp); the rest of the blocks hold the
 * caller's payload.
 *
 * All operations are blocking and return a `MemoryCard::Error` describing
 * exactly what went wrong; there are no silent failures. A single filesystem
 * instance can serve both ports (the port is passed per call). For non-trivial
 * payloads an operation can take a noticeable fraction of a second, so it is
 * best performed at a deliberate save point.
 */
class MemoryCardFileSystem {
  public:
    /**
     * @brief A save icon, in the native PlayStation format.
     *
     * @details The palette is 16 entries of 15-bit BGR555 (bit 15 is the
     * semi-transparency flag). Each frame is a 16x16, 4bpp bitmap (128 bytes,
     * two pixels per byte, low nibble first). `frameCount` selects how many
     * frames animate (1 = static).
     */
    struct Icon {
        uint8_t frameCount;      // 1..3
        uint16_t clut[16];       // 16-colour palette, BGR555
        uint8_t pixels[3][128];  // up to 3 frames of 16x16 4bpp
    };

    /**
     * @brief A directory listing entry.
     */
    struct FileEntry {
        char name[21];         // null-terminated Sony filename
        uint16_t sizeInBlocks;  // 1..15
        uint8_t firstBlock;    // 1..15
    };

    explicit MemoryCardFileSystem(MemoryCard &card) : m_card(card) {}

    /**
     * @brief Determines whether a usable, formatted card is present.
     *
     * @return Error::OK if formatted, Error::NoCard if absent,
     * Error::NotFormatted if present but not a Sony card.
     */
    MemoryCard::Error getCardState(MemoryCard::Port port);

    /**
     * @brief Writes a fresh, empty Sony filesystem to the card.
     *
     * @details This erases the directory; any existing files become
     * unreachable. The 15 file blocks themselves are not touched (they are
     * simply marked free), matching what the BIOS does.
     */
    MemoryCard::Error format(MemoryCard::Port port);

    /**
     * @brief Returns the number of free 8KiB blocks (0..15).
     */
    MemoryCard::Error getFreeBlockCount(MemoryCard::Port port, uint32_t *outFreeBlocks);

    /**
     * @brief Lists the files on the card.
     *
     * @param out An array to receive up to `maxEntries` entries.
     * @param outCount Receives the number of files found (may exceed
     * `maxEntries`, in which case only `maxEntries` were written).
     */
    MemoryCard::Error listFiles(MemoryCard::Port port, FileEntry *out, uint32_t maxEntries, uint32_t *outCount);

    /**
     * @brief Reports whether a named file exists.
     */
    MemoryCard::Error fileExists(MemoryCard::Port port, const char *name, bool *outExists);

    /**
     * @brief Reads the payload of a file.
     *
     * @details Returns the bytes that follow the title and icon frames, i.e.
     * exactly the `data` region passed to `writeFile`, rounded up to whole
     * frames. The caller is responsible for knowing the logical length of its
     * own payload (typically via a small header it embeds in `data`).
     *
     * @param buffer Receives up to `maxLen` payload bytes.
     * @param outLen Receives the number of payload bytes available (capped at
     * `maxLen`).
     */
    MemoryCard::Error readFile(MemoryCard::Port port, const char *name, void *buffer, uint32_t maxLen,
                               uint32_t *outLen);

    /**
     * @brief Creates or overwrites a file.
     *
     * @details The file is sized to hold the title frame, the icon frames and
     * `dataLen` payload bytes, rounded up to whole 8KiB blocks. If a file with
     * the same name already exists it is replaced. The data is written first
     * and the directory committed last, so an interrupted write never leaves a
     * referenced but corrupt file.
     *
     * @param name The Sony filename (up to 20 characters).
     * @param title The save title, as a UTF-8 string. It is encoded to the
     * 64-byte Shift-JIS field the BIOS manager displays, with printable ASCII
     * promoted to its fullwidth form (the BIOS title convention) and any other
     * codepoint (e.g. Japanese) encoded directly.
     * @param icon The save icon.
     * @param data The payload bytes.
     * @param dataLen The number of payload bytes.
     */
    MemoryCard::Error writeFile(MemoryCard::Port port, const char *name, const char *title, const Icon &icon,
                                const void *data, uint32_t dataLen);

    /**
     * @brief Deletes a file, freeing all of its blocks.
     */
    MemoryCard::Error deleteFile(MemoryCard::Port port, const char *name);

  private:
    // A 4-byte aligned 128-byte frame buffer.
    struct Frame {
        alignas(4) uint8_t bytes[128];
    };

    // Directory allocation states (low byte of the 32-bit state word).
    static constexpr uint8_t c_stateFirst = 0x51;   // first or only block
    static constexpr uint8_t c_stateMiddle = 0x52;  // middle block
    static constexpr uint8_t c_stateLast = 0x53;    // last block
    static constexpr uint8_t c_stateFree = 0xa0;    // free (freshly formatted)

    // Directory entry field offsets.
    static constexpr uint32_t c_offAlloc = 0x00;
    static constexpr uint32_t c_offSize = 0x04;
    static constexpr uint32_t c_offNext = 0x08;
    static constexpr uint32_t c_offName = 0x0a;
    static constexpr uint32_t c_offChecksum = 0x7f;
    static constexpr uint32_t c_maxNameLength = 20;

    static uint8_t frameChecksum(const uint8_t *frame);
    static void finishDirEntry(uint8_t *entry);
    static bool isFreeState(uint8_t state) { return (state & 0xf0) == 0xa0; }
    static bool nameMatches(const uint8_t *entry, const char *name);

    MemoryCard::Error readDirectory(MemoryCard::Port port, Frame *dir15);
    MemoryCard::Error findFirstBlock(const Frame *dir15, const char *name, int *outBlock);

    MemoryCard &m_card;
};

}  // namespace psyqo
