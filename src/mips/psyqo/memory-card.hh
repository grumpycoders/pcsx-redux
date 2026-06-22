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

namespace psyqo {

/**
 * @brief A low level driver for the PlayStation memory cards.
 *
 * @details This class drives the raw memory card protocol over the SIO0
 * serial bus, the same bus used by the controllers. It exposes the lowest
 * useful unit of the card: the 128-byte sector (also called a "frame").
 * The card is 128KiB total, organized as 1024 sectors of 128 bytes,
 * themselves grouped into 16 blocks of 64 sectors (8KiB each). Block 0
 * holds the directory; blocks 1..15 hold files.
 *
 * This class is intentionally agnostic of the Sony on-card filesystem;
 * see `MemoryCardFileSystem` for a Sony-compatible filesystem built on top
 * of it. It supports both memory card ports.
 *
 * @warning The memory card and the controllers share a single SIO0 bus, so
 * this driver can ONLY be used alongside `AdvancedPad`, which drives SIO0
 * directly and honors the `SIO0Bus` ownership lock this driver takes for the
 * duration of a transaction (standing down its polling while a card op is in
 * flight). Using `SimplePad` (the BIOS-driven pad) at the same time is
 * unsupported and is undefined behavior: the BIOS pad handler accesses SIO0
 * outside this lock and will collide with card transfers. Use `AdvancedPad`,
 * or no pad at all, with this driver.
 *
 * A single sector transfer is a self-contained, busy-polled SIO0 exchange run
 * with all interrupts disabled: the bytes of one transfer are timing sensitive
 * and must flow without interruption or the card aborts. A sector takes a few
 * milliseconds, so these per-sector transfers are synchronous and blocking.
 * The asynchronicity lives one level up: a whole card transaction spans many
 * sectors across several frames, so `MemoryCardFileSystem` chains these
 * per-sector transfers from a main-loop timer (never an interrupt), which is
 * why this transport does not rely on an SIO0 acknowledge interrupt at all -
 * it polls the latched acknowledge bit. As with the rest of psyqo, the class
 * is meant to be used as a singleton, typically held by the `Application`.
 */
class MemoryCard {
  public:
    /**
     * @brief The error codes returned by every memory card operation.
     *
     * @details There are never any silent failures: every operation returns
     * one of these, and `errorMessage` turns it into a human readable string.
     */
    enum class Error : uint8_t {
        OK = 0,             // No error.
        NoCard,             // No card present / no acknowledge on the bus.
        NotFormatted,       // Card is present but is not a valid Sony card.
        BadChecksum,        // A frame checksum did not match.
        BadSector,          // The card reported a bad / out of range sector.
        Timeout,            // The card stopped acknowledging mid-transfer.
        Unconnected,        // The port could not be selected.
        ProtocolError,      // Unexpected response byte from the card.
        DirectoryFull,      // No free directory entry for a new file.
        OutOfSpace,         // Not enough free blocks for a file.
        FileNotFound,       // The requested file does not exist.
        FileExists,         // A file with that name already exists.
        NameTooLong,        // The filename exceeds 20 characters.
        FileTooLarge,       // The payload would not fit in 15 blocks.
        SerializeOverflow,  // The serialized payload exceeded the buffer.
        BadData,            // The payload header / structure is corrupt.
        BadPort,            // The port argument is invalid.
    };

    /**
     * @brief The memory card port to talk to.
     */
    enum class Port : unsigned { Port0 = 0, Port1 = 1 };

    // Geometry constants.
    static constexpr uint32_t c_sectorSize = 128;       // bytes per sector / frame
    static constexpr uint32_t c_sectorCount = 1024;     // sectors per card
    static constexpr uint32_t c_blockSize = 8192;       // bytes per block
    static constexpr uint32_t c_blockCount = 16;        // blocks per card
    static constexpr uint32_t c_sectorsPerBlock = 64;   // sectors per block

    static constexpr uint32_t sectorSize() { return c_sectorSize; }
    static constexpr uint32_t sectorCount() { return c_sectorCount; }
    static constexpr uint32_t blockSize() { return c_blockSize; }
    static constexpr uint32_t blockCount() { return c_blockCount; }

    /**
     * @brief Returns a human readable string for an error code.
     */
    static const char *errorMessage(Error error);

    /**
     * @brief Prepares the SIO0 bus for memory card access.
     *
     * @details Should be called once from `Application::prepare`. `AdvancedPad`
     * may be used alongside this driver (they share the SIO0 bus and serialize
     * through the `SIO0Bus` ownership lock); `SimplePad` may not (see the class
     * warning above).
     */
    void prepare();

    /**
     * @brief Reads a single 128-byte sector synchronously.
     *
     * @param port The port to read from.
     * @param sector The sector index (0..1023).
     * @param buffer A buffer of at least 128 bytes.
     * @return Error::OK on success.
     */
    Error readSectorBlocking(Port port, uint16_t sector, void *buffer);

    /**
     * @brief Writes a single 128-byte sector synchronously.
     *
     * @param port The port to write to.
     * @param sector The sector index (0..1023).
     * @param buffer A buffer of at least 128 bytes.
     * @return Error::OK on success.
     */
    Error writeSectorBlocking(Port port, uint16_t sector, const void *buffer);

    /**
     * @brief Probes the card for presence.
     *
     * @return Error::OK if a card acknowledges on the given port,
     * Error::NoCard otherwise.
     */
    Error probeBlocking(Port port);

  private:
    // ── Retry / dispatch layer ────────────────────────────────────────────
    Error singleSectorRead(Port port, uint16_t sector, uint8_t *out);
    Error singleSectorWrite(Port port, uint16_t sector, const uint8_t *in);
    Error readSectorRetried(Port port, uint16_t sector, uint8_t *out);
    Error writeSectorRetried(Port port, uint16_t sector, const uint8_t *in);
    static bool isTransient(Error error);

    // ── Sector transport ──────────────────────────────────────────────────
    // A single sector is a self-contained, busy-polled SIO0 exchange run with
    // interrupts disabled (the bytes must flow without interruption). It is the
    // atomic unit the asynchronous, timer-driven filesystem layer chains.
    Error doReadSector(Port port, uint16_t sector, uint8_t *out);
    Error doWriteSector(Port port, uint16_t sector, const uint8_t *in);
    void selectPort(Port port);
    void deselect();
    void flushRxBuffer();
    // Waits for the card's acknowledge interrupt latch and clears it. Returns
    // false if it does not arrive within `timeout` iterations (a missing card).
    bool waitCardIRQ(uint32_t timeout);
    // Clocks one byte out and waits for the card to acknowledge that its state
    // machine advanced. Returns false on acknowledge timeout (e.g. no card).
    bool advance(uint8_t outByte, uint32_t timeout);
    // Polls the card's output until its state machine reaches `want`. Reading
    // the data register is a no-op until the chip advances, so this synchronizes
    // to the card's per-state timing; bounded so a broken card cannot hang.
    bool expect(uint8_t want);

    static void busyLoop(int delay) {
        for (; delay >= 0; delay--) asm("");
    }

    // The first (addressing) byte uses this timeout to detect a missing card.
    // It is the one value that is deliberately generous: a present-but-slow
    // real card can take a while to acknowledge the very first byte after the
    // port is selected, and too short a value here is what makes a good card
    // spuriously report "no card". It does not affect mid-transfer timing
    // (a present card acknowledges the first byte well before the limit).
    static constexpr uint32_t c_ackTimeoutShort = 0x4000;
    // Sony cards introduce a ~31000 cycle gap before the acknowledge that
    // follows the seventh byte of a read; the long timeout covers it with a
    // comfortable margin and is also used as the general mid-transfer timeout.
    static constexpr uint32_t c_ackTimeoutLong = 0x40000;
    // Settle time after asserting the port select, before the first clock.
    static constexpr unsigned c_selectDelay = 100;
    // How many times a whole-sector transient failure is retried.
    static constexpr unsigned c_maxAttempts = 3;
};

}  // namespace psyqo
