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

#include <EASTL/functional.h>
#include <stdint.h>

#include "psyqo/memory-card.hh"

namespace psyqo {

class GPU;

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
 * @details A whole filesystem operation is a transaction that spans many
 * individual sector transfers and therefore several frames. To avoid stalling
 * the main loop for that whole time, operations are asynchronous, following the
 * same contract as `CDRomDevice`: only ONE operation may be in flight at a
 * time, and progress is driven by chaining the `MemoryCard` device's own
 * interrupt-driven sector transfers - each transfer's completion callback
 * issues the next - so the game keeps running between sectors, with no timer.
 * Every operation comes in two forms:
 *   - a callback variant, the basis: an `eastl::function` callback that is
 *     invoked, from the main loop during callback pumping, with the resulting
 *     `MemoryCard::Error`; and
 *   - a `*Blocking(GPU&)` variant that pumps the GPU until the operation
 *     completes and returns the error directly.
 *
 * The `SIO0Bus` is owned for the entire transaction, so `AdvancedPad` stands
 * down for its full duration (see the `MemoryCard` warning: this filesystem is
 * usable with `AdvancedPad` only, never `SimplePad`).
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
        char name[21];          // null-terminated Sony filename
        uint16_t sizeInBlocks;  // 1..15
        uint8_t firstBlock;     // 1..15
    };

    explicit MemoryCardFileSystem(MemoryCard &card) : m_card(card) {}

    /**
     * @brief Whether the filesystem is ready to accept a new operation.
     */
    [[nodiscard]] bool isIdle() const { return !m_busy; }

    using Error = MemoryCard::Error;
    using Port = MemoryCard::Port;

    // -- Asynchronous operations (the callback basis) -----------------------
    // Each starts a transaction and returns immediately; `callback` fires from
    // the main loop, during GPU pumping, once the transaction completes. Only
    // one may be in flight at a time (asserts idle).

    /**
     * @brief Determines whether a usable, formatted card is present.
     * @return Via the callback: Error::OK if formatted, Error::NoCard if
     * absent, Error::NotFormatted if present but not a Sony card.
     */
    void getCardState(Port port, eastl::function<void(Error)> &&callback);

    /**
     * @brief Writes a fresh, empty Sony filesystem to the card.
     *
     * @details This erases the directory; any existing files become
     * unreachable. The 15 file blocks themselves are not touched (they are
     * simply marked free), matching what the BIOS does.
     */
    void format(Port port, eastl::function<void(Error)> &&callback);

    /**
     * @brief Counts the free 8KiB blocks (0..15) into *outFreeBlocks.
     */
    void getFreeBlockCount(Port port, uint32_t *outFreeBlocks, eastl::function<void(Error)> &&callback);

    /**
     * @brief Lists the files on the card.
     *
     * @param out An array to receive up to `maxEntries` entries.
     * @param outCount Receives the number of files found (may exceed
     * `maxEntries`, in which case only `maxEntries` were written).
     */
    void listFiles(Port port, FileEntry *out, uint32_t maxEntries, uint32_t *outCount,
                   eastl::function<void(Error)> &&callback);

    /**
     * @brief Reports whether a named file exists, into *outExists.
     */
    void fileExists(Port port, const char *name, bool *outExists, eastl::function<void(Error)> &&callback);

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
    void readFile(Port port, const char *name, void *buffer, uint32_t maxLen, uint32_t *outLen,
                  eastl::function<void(Error)> &&callback);

    /**
     * @brief Creates or overwrites a file.
     *
     * @details The file is sized to hold the title frame, the icon frames and
     * `dataLen` payload bytes, rounded up to whole 8KiB blocks. If a file with
     * the same name already exists it is replaced. The data is written first
     * and the directory committed last, so an interrupted write never leaves a
     * referenced but corrupt file.
     *
     * @param name The Sony filename (up to 20 characters). The pointer must
     * stay valid until the callback fires.
     * @param title The save title, as a UTF-8 string, encoded to the 64-byte
     * Shift-JIS field the BIOS manager displays, with printable ASCII promoted
     * to its fullwidth form. Must stay valid until the callback fires.
     * @param icon The save icon. Copied, so it need not outlive the call.
     * @param data The payload bytes. Must stay valid until the callback fires.
     * @param dataLen The number of payload bytes.
     */
    void writeFile(Port port, const char *name, const char *title, const Icon &icon, const void *data,
                   uint32_t dataLen, eastl::function<void(Error)> &&callback);

    /**
     * @brief Deletes a file, freeing all of its blocks.
     */
    void deleteFile(Port port, const char *name, eastl::function<void(Error)> &&callback);

    // -- Blocking variants --------------------------------------------------
    // These run the same transaction but pump the GPU until it finishes and
    // return the error directly. They still take a few hundred milliseconds for
    // a non-trivial payload, so they are best used at a deliberate save point.

    Error getCardStateBlocking(GPU &gpu, Port port);
    Error formatBlocking(GPU &gpu, Port port);
    Error getFreeBlockCountBlocking(GPU &gpu, Port port, uint32_t *outFreeBlocks);
    Error listFilesBlocking(GPU &gpu, Port port, FileEntry *out, uint32_t maxEntries, uint32_t *outCount);
    Error fileExistsBlocking(GPU &gpu, Port port, const char *name, bool *outExists);
    Error readFileBlocking(GPU &gpu, Port port, const char *name, void *buffer, uint32_t maxLen, uint32_t *outLen);
    Error writeFileBlocking(GPU &gpu, Port port, const char *name, const char *title, const Icon &icon,
                            const void *data, uint32_t dataLen);
    Error deleteFileBlocking(GPU &gpu, Port port, const char *name);

  private:
    // A 4-byte aligned 128-byte frame buffer.
    struct Frame {
        alignas(4) uint8_t bytes[128];
    };

    // Directory allocation states (low byte of the 32-bit state word). The high
    // nibble separates in-use (0x5x) from available (0xax); the low nibble is
    // the block's position in its chain, preserved across deletion so a deleted
    // chain stays recoverable.
    static constexpr uint8_t c_stateFirst = 0x51;          // in use: first or only block
    static constexpr uint8_t c_stateMiddle = 0x52;         // in use: middle block
    static constexpr uint8_t c_stateLast = 0x53;           // in use: last block
    static constexpr uint8_t c_stateFree = 0xa0;           // available: never allocated
    static constexpr uint8_t c_stateDeletedFirst = 0xa1;   // available: a deleted first block
    static constexpr uint8_t c_stateDeletedMiddle = 0xa2;  // available: a deleted middle block
    static constexpr uint8_t c_stateDeletedLast = 0xa3;    // available: a deleted last block

    // Directory entry field offsets.
    static constexpr uint32_t c_offAlloc = 0x00;
    static constexpr uint32_t c_offSize = 0x04;
    static constexpr uint32_t c_offNext = 0x08;
    static constexpr uint32_t c_offName = 0x0a;
    static constexpr uint32_t c_offChecksum = 0x7f;
    static constexpr uint32_t c_maxNameLength = 20;

    static uint8_t frameChecksum(const uint8_t *frame);
    static void finishDirEntry(uint8_t *entry);
    // Marks an in-use block (0x5x) deleted, keeping its chain position (0x5x ->
    // 0xax) and so its links, so the deleted chain stays recoverable.
    static uint8_t deletedState(uint8_t inUse) { return static_cast<uint8_t>((inUse & 0x0f) | 0xa0); }
    static bool nameMatches(const uint8_t *entry, const char *name);
    static bool findFirstBlock(const Frame *dir15, const char *name, int *outBlock);
    // The set of blocks (bit (slot + 1)) reachable from a valid first-block
    // head. Anything else - free, deleted, or an orphaned middle/last block with
    // no head - is available for allocation.
    static uint16_t reachableBlocks(const Frame *dir15);

    // -- Asynchronous transaction engine -----------------------------------
    // The operation in flight, and where in it we are. Each device sector
    // completion advances the machine by exactly one sector transfer.
    enum class Op : uint8_t {
        None,
        GetCardState,
        Format,
        GetFreeBlockCount,
        ListFiles,
        FileExists,
        ReadFile,
        WriteFile,
        DeleteFile,
    };
    enum class Phase : uint8_t {
        Fail,       // m_result is set; finish on the next tick
        Header,     // read sector 0, validate "MC"
        ReadDir,    // read the 15 directory frames (m_idx = 0..14)
        ReadTitle,  // read a file's first frame to size its header (readFile)
        ReadData,   // read a file's payload frames (readFile)
        WriteData,  // write title/icon/payload frames (writeFile)
        WriteDir,   // commit the dirty directory frames (write/delete)
        Format,     // write the format frames (m_idx = 0..63)
    };
    enum class StepResult : uint8_t { Continue, Done };

    void begin(Op op, Port port, eastl::function<void(Error)> &&callback);
    Error runBlocking(GPU &gpu);
    // Issues exactly one asynchronous device sector transfer for the current
    // phase, or finishes the transaction if the current phase has no transfer
    // left to do.
    void issueOrFinish();
    // The device's per-sector completion callback: consumes the transfer's
    // result, advances the per-operation state machine, then chains the next
    // transfer (or finishes).
    void onSectorDone(Error error);
    StepResult afterReadDir();
    void finish(Error error);

    MemoryCard &m_card;

    // engine state
    bool m_busy = false;
    bool m_lockHeld = false;
    eastl::function<void(Error)> m_callback;
    Error m_result = Error::OK;
    Op m_op = Op::None;
    Phase m_phase = Phase::Fail;
    Port m_port = Port::Port0;
    uint32_t m_idx = 0;  // step within the current phase

    // working buffers / per-operation state
    Frame m_dir[15];
    Frame m_scratch;
    uint8_t m_chain[16];
    uint32_t m_chainLen = 0;
    uint32_t m_headerFrames = 0;
    uint32_t m_blocksNeeded = 0;
    uint32_t m_iconFrames = 0;
    bool m_dirty[15] = {};
    // The directory slots to commit, in the order they must be written: for a
    // create the file's head (the 0x51 first block) is written last; for a
    // delete its head (cut to 0xa1) is written first. So a power loss mid-commit
    // can only orphan tail blocks, never leave a referenced file pointing at a
    // half-written chain.
    uint8_t m_writeOrder[15] = {};
    uint32_t m_writeOrderLen = 0;
    uint32_t m_dataOffset = 0;
    uint32_t m_written = 0;
    uint32_t m_blockIdx = 0;     // current block within the chain
    uint32_t m_frameInBlock = 0;  // current frame within the current block

    // saved operation arguments
    const char *m_name = nullptr;
    const char *m_title = nullptr;
    void *m_readBuffer = nullptr;
    const void *m_writeData = nullptr;
    uint32_t m_dataLen = 0;
    uint32_t m_maxLen = 0;
    uint32_t *m_outLen = nullptr;
    uint32_t *m_outFreeBlocks = nullptr;
    uint32_t *m_outCount = nullptr;
    bool *m_outExists = nullptr;
    FileEntry *m_outEntries = nullptr;
    uint32_t m_maxEntries = 0;
    Icon m_icon = {};
};

}  // namespace psyqo
