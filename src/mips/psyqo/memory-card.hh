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

#include <coroutine>

#include "psyqo/task.hh"

namespace psyqo {

class GPU;

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
 * Each sector transfer is a self-contained synchronous SIO0 exchange, the
 * same proven approach `AdvancedPad` uses to talk to the bus. The Controller
 * interrupt is masked for the duration of a transfer so that nothing else on
 * the bus (a BIOS pad handler, for instance) steals the bytes, and its prior
 * mask state is restored afterwards. As with the rest of psyqo, the class is
 * meant to be used as a singleton, typically held by the `Application`.
 *
 * Following the conventions of `CDRomDevice`, every operation comes in four
 * forms: a callback variant, a `*Blocking` variant, a coroutine-friendly
 * awaiter, and a `TaskQueue::Task` scheduler. A single sector transfer is
 * short (a few milliseconds), so the blocking variants do not need a `GPU`
 * to pump events.
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

    // --- Callback variants -------------------------------------------------
    void readSector(Port port, uint16_t sector, void *buffer, eastl::function<void(Error)> &&callback);
    void writeSector(Port port, uint16_t sector, const void *buffer, eastl::function<void(Error)> &&callback);

    // --- TaskQueue schedulers ---------------------------------------------
    TaskQueue::Task scheduleReadSector(Port port, uint16_t sector, void *buffer, Error *resultOut);
    TaskQueue::Task scheduleWriteSector(Port port, uint16_t sector, const void *buffer, Error *resultOut);

    // --- Coroutine-friendly awaiters --------------------------------------
    struct ReadSectorAwaiter {
        ReadSectorAwaiter(MemoryCard &device, Port port, uint16_t sector, void *buffer)
            : m_device(device), m_port(port), m_sector(sector), m_buffer(buffer) {}
        bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_device.readSector(m_port, m_sector, m_buffer, [handle, this](Error result) {
                m_result = result;
                handle.resume();
            });
        }
        Error await_resume() { return m_result; }

      private:
        MemoryCard &m_device;
        Port m_port;
        uint16_t m_sector;
        void *m_buffer;
        Error m_result = Error::OK;
    };

    struct WriteSectorAwaiter {
        WriteSectorAwaiter(MemoryCard &device, Port port, uint16_t sector, const void *buffer)
            : m_device(device), m_port(port), m_sector(sector), m_buffer(buffer) {}
        bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_device.writeSector(m_port, m_sector, m_buffer, [handle, this](Error result) {
                m_result = result;
                handle.resume();
            });
        }
        Error await_resume() { return m_result; }

      private:
        MemoryCard &m_device;
        Port m_port;
        uint16_t m_sector;
        const void *m_buffer;
        Error m_result = Error::OK;
    };

    ReadSectorAwaiter readSector(Port port, uint16_t sector, void *buffer) { return {*this, port, sector, buffer}; }
    WriteSectorAwaiter writeSector(Port port, uint16_t sector, const void *buffer) {
        return {*this, port, sector, buffer};
    }

  private:
    // ── Transport selection ───────────────────────────────────────────────
    // The driver has two interchangeable transports for a single sector:
    //   * an interrupt-driven state machine (the default, modelled on the
    //     retail BIOS / openbios sio0 driver), and
    //   * a synchronous busy-polled transport (kept as a proven fallback).
    // If the IRQ transport ever misbehaves on a particular setup, flip this to
    // false to fall back to polling without touching anything else.
    static constexpr bool c_useIrq = true;

    // ── Retry / dispatch layer ────────────────────────────────────────────
    Error singleSectorRead(Port port, uint16_t sector, uint8_t *out);
    Error singleSectorWrite(Port port, uint16_t sector, const uint8_t *in);
    Error readSectorRetried(Port port, uint16_t sector, uint8_t *out);
    Error writeSectorRetried(Port port, uint16_t sector, const uint8_t *in);
    static bool isTransient(Error error);

    // ── Interrupt-driven transport ────────────────────────────────────────
    enum class Action : uint8_t { None, Read, Write };
    enum class StepResult { Continue, Done };

    void installIrqHandler();
    void irq();  // entered on each SIO0 (controller) acknowledge interrupt
    void startTransfer(Action action, Port port, uint16_t sector, void *readBuf, const void *writeBuf);
    void finishTransfer(Error result);
    StepResult readStep();
    StepResult writeStep();
    uint8_t exchangeByte(uint8_t out);  // openbios-style: read previous, send next, ack
    Error irqTransferBlocking(Action action, Port port, uint16_t sector, void *readBuf, const void *writeBuf);
    static uint16_t portMask(Port port);

    // ── Polled transport (fallback) ───────────────────────────────────────
    Error doReadSector(Port port, uint16_t sector, uint8_t *out);
    Error doWriteSector(Port port, uint16_t sector, const uint8_t *in);
    void selectPort(Port port);
    void deselect();
    void flushRxBuffer();
    uint8_t transceive(uint8_t dataOut);
    bool waitAck(uint32_t timeout);

    static void busyLoop(unsigned delay) {
        unsigned cycles = 0;
        while (++cycles < delay) asm("");
    }

    // ── Interrupt-driven state ────────────────────────────────────────────
    volatile Action m_action = Action::None;
    int m_step = 0;
    Port m_port = Port::Port0;
    uint16_t m_sector = 0;
    uint8_t *m_readBuffer = nullptr;
    const uint8_t *m_writeBuffer = nullptr;
    uint8_t m_runningChecksum = 0;
    uint8_t m_cardChecksum = 0;
    volatile bool m_done = false;
    volatile Error m_result = Error::OK;
    bool m_blocking = false;
    eastl::function<void(Error)> m_callback;
    uint32_t m_event = 0;

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
    static constexpr uint32_t c_ackHighTimeout = 0x4000;
    // Settle time after asserting the port select, before the first clock.
    static constexpr unsigned c_selectDelay = 100;
    // How many times a whole-sector transient failure is retried.
    static constexpr unsigned c_maxAttempts = 3;
    // Spin-loop bound for the blocking IRQ path: large enough never to trip
    // during a normal ~8ms transfer, small enough to bail on a dead bus.
    static constexpr uint32_t c_irqWatchdog = 0x800000;
};

}  // namespace psyqo
