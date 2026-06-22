/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#include "psyqo/memory-card.hh"

#include "psyqo/hardware/cpu.hh"
#include "psyqo/hardware/sio.hh"
#include "psyqo/kernel.hh"
#include "psyqo/sio0-bus.hh"

using namespace psyqo::Hardware;

namespace {

// RAII guard that disables all interrupts for the duration of a single sector
// transfer. The SIO0 card protocol is timing sensitive: the bytes of one
// transfer must keep flowing without interruption or the card aborts, so the
// inner transfer busy-polls the latched I_STAT acknowledge bit with interrupts
// off. The outer, multi-transfer state machine runs with interrupts enabled,
// advanced from the main loop by a timer.
struct CriticalSection {
    CriticalSection() { psyqo::Kernel::fastEnterCriticalSection(); }
    ~CriticalSection() { psyqo::Kernel::fastLeaveCriticalSection(); }
};

// SIO0 memory card protocol bytes. The host sends a command and the card
// answers with a fixed sequence of identifier and acknowledge bytes; naming
// them keeps the transfer readable (no hanging hex literals).
enum Command : uint8_t {
    kAccess = 0x81,  // memory card bus address
    kRead = 0x52,    // 'R'
    kWrite = 0x57,   // 'W'
};
enum Reply : uint8_t {
    kId1 = 0x5a,             // first card identifier byte
    kId2 = 0x5d,             // second card identifier byte
    kCommandAck1 = 0x5c,     // command acknowledge, byte 1
    kCommandAck2 = 0x5d,     // command acknowledge, byte 2
    kEndGood = 0x47,         // 'G': transfer succeeded
    kEndBadChecksum = 0x4e,  // 'N': checksum mismatch
    kEndBadSector = 0xff,    // addressed sector was out of range
};

// Pacing for one byte exchange, in busyLoop iterations, from the reference
// inner loop. These are timing sensitive; do not tune without a real card.
static constexpr int kPaceLead = 200;    // before re-asserting select for the byte
static constexpr int kPaceSettle = 2000;  // after re-asserting select, before clocking
static constexpr int kPaceClock = 20;     // around the data-register write

}  // namespace

const char *psyqo::MemoryCard::errorMessage(Error error) {
    switch (error) {
        case Error::OK:
            return "OK";
        case Error::NoCard:
            return "no memory card present";
        case Error::NotFormatted:
            return "memory card is not formatted";
        case Error::BadChecksum:
            return "bad checksum";
        case Error::BadSector:
            return "bad sector";
        case Error::Timeout:
            return "memory card timed out";
        case Error::Unconnected:
            return "port not connected";
        case Error::ProtocolError:
            return "memory card protocol error";
        case Error::DirectoryFull:
            return "memory card directory is full";
        case Error::OutOfSpace:
            return "not enough free blocks on the card";
        case Error::FileNotFound:
            return "file not found";
        case Error::FileExists:
            return "file already exists";
        case Error::NameTooLong:
            return "filename too long";
        case Error::FileTooLarge:
            return "file too large for a memory card";
        case Error::SerializeOverflow:
            return "serialized data too large";
        case Error::BadData:
            return "corrupt save data";
        case Error::BadPort:
            return "invalid port";
    }
    return "unknown error";
}

void psyqo::MemoryCard::prepare() {
    // Bring SIO0 to a known good state, matching AdvancedPad's initialization.
    SIO::Ctrl = SIO::Control::CTRL_IR;
    SIO::Baud = 0x88;  // 250kHz
    SIO::Mode = 0xd;   // MUL1, 8bit, no parity, normal polarity
    SIO::Ctrl = 0;
}

psyqo::MemoryCard::Error psyqo::MemoryCard::singleSectorRead(Port port, uint16_t sector, uint8_t *out) {
    if (sector >= c_sectorCount) return Error::BadSector;
    return doReadSector(port, sector, out);
}

psyqo::MemoryCard::Error psyqo::MemoryCard::singleSectorWrite(Port port, uint16_t sector, const uint8_t *in) {
    if (sector >= c_sectorCount) return Error::BadSector;
    return doWriteSector(port, sector, in);
}

void psyqo::MemoryCard::selectPort(Port port) {
    SIO::Ctrl = (static_cast<unsigned>(port) * SIO::Control::CTRL_PORTSEL) | SIO::Control::CTRL_DTR;
    SIO::Baud = 0x88;  // 250kHz
    flushRxBuffer();
    SIO::Ctrl |= (SIO::Control::CTRL_TXEN | SIO::Control::CTRL_ACKIRQEN);
    busyLoop(c_selectDelay);  // bus stabilization delay before the first clock pulse
}

void psyqo::MemoryCard::deselect() { SIO::Ctrl = 0; }

void psyqo::MemoryCard::flushRxBuffer() {
    while (SIO::Stat & SIO::Status::STAT_RXRDY) {
        SIO::Data.throwAway();
    }
}

bool psyqo::MemoryCard::waitCardIRQ(uint32_t timeout) {
    // Wait for the card's acknowledge interrupt latch, then clear it. Bounded so
    // a missing card (which never acknowledges) reports a timeout instead of
    // hanging; the reference inner loop omits the bound because it assumes a
    // present card, but a driver has to detect absence.
    uint32_t cycles = 0;
    while (!CPU::IReg.isSet(CPU::IRQ::Controller)) {
        if (++cycles >= timeout) return false;
    }
    CPU::IReg.clear(CPU::IRQ::Controller);
    return true;
}

bool psyqo::MemoryCard::advance(uint8_t outByte, uint32_t timeout) {
    busyLoop(kPaceLead);
    SIO::Ctrl |= (SIO::Control::CTRL_DTR | SIO::Control::CTRL_ERRRES);
    busyLoop(kPaceSettle);
    busyLoop(kPaceClock);
    SIO::Data = outByte;
    busyLoop(kPaceClock);
    SIO::Ctrl |= SIO::Control::CTRL_ERRRES;
    CPU::IReg.clear(CPU::IRQ::Controller);
    return waitCardIRQ(timeout);
}

bool psyqo::MemoryCard::expect(uint8_t want) {
    for (uint32_t i = 0; i < c_ackTimeoutLong; i++) {
        if (SIO::Data == want) return true;
    }
    return false;
}

psyqo::MemoryCard::Error psyqo::MemoryCard::doReadSector(Port port, uint16_t sector, uint8_t *out) {
    if (sector >= c_sectorCount) return Error::BadSector;

    CriticalSection guard;
    selectPort(port);

    const uint8_t msb = sector >> 8;
    const uint8_t lsb = sector & 0xff;

    // Address the card. A missing card never acknowledges this first byte.
    if (!advance(kAccess, c_ackTimeoutShort)) return deselect(), Error::NoCard;
    // Read command; the card answers with its two identifier bytes.
    if (!advance(kRead, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!expect(kId1)) return deselect(), Error::ProtocolError;
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!expect(kId2)) return deselect(), Error::ProtocolError;
    // Acknowledge slot, then the sector address. After the address the card
    // reads the sector internally: a slow state, covered by the long timeout and
    // the poll on the command-acknowledge bytes below.
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!advance(msb, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!advance(lsb, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!expect(kCommandAck1)) return deselect(), Error::ProtocolError;
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!expect(kCommandAck2)) return deselect(), Error::ProtocolError;
    // Confirmed address: 0xffff means the card rejected the sector.
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    uint8_t confMSB = SIO::Data;
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    uint8_t confLSB = SIO::Data;
    if (confMSB == 0xff && confLSB == 0xff) return deselect(), Error::BadSector;

    // 128 data bytes (regular, acknowledge-paced), then the checksum and the end
    // byte. The checksum covers the address and the data.
    uint8_t checksum = msb ^ lsb;
    for (uint32_t i = 0; i < c_sectorSize; i++) {
        if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
        out[i] = SIO::Data;
        checksum ^= out[i];
    }
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    uint8_t cardChecksum = SIO::Data;
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    uint8_t endByte = SIO::Data;
    deselect();

    if (cardChecksum != checksum) return Error::BadChecksum;
    if (endByte != kEndGood) return Error::ProtocolError;
    return Error::OK;
}

psyqo::MemoryCard::Error psyqo::MemoryCard::doWriteSector(Port port, uint16_t sector, const uint8_t *in) {
    if (sector >= c_sectorCount) return Error::BadSector;

    CriticalSection guard;
    selectPort(port);

    const uint8_t msb = sector >> 8;
    const uint8_t lsb = sector & 0xff;

    uint8_t checksum = msb ^ lsb;
    for (uint32_t i = 0; i < c_sectorSize; i++) checksum ^= in[i];

    // NOTE: the write path mirrors doReadSector's structure (the proven read
    // loop's model); the reference only covered reads, so the write sequence is
    // the standard protocol and needs validation on a real card.

    // Address the card. A missing card never acknowledges this first byte.
    if (!advance(kAccess, c_ackTimeoutShort)) return deselect(), Error::NoCard;
    // Write command; the card answers with its two identifier bytes.
    if (!advance(kWrite, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!expect(kId1)) return deselect(), Error::ProtocolError;
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!expect(kId2)) return deselect(), Error::ProtocolError;
    // Sector address, then the 128 data bytes and the checksum.
    if (!advance(msb, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!advance(lsb, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    for (uint32_t i = 0; i < c_sectorSize; i++) {
        if (!advance(in[i], c_ackTimeoutLong)) return deselect(), Error::Timeout;
    }
    if (!advance(checksum, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    // The card commits the write (a slow state) then acknowledges and reports
    // the outcome in its end byte.
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!expect(kCommandAck1)) return deselect(), Error::ProtocolError;
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    if (!expect(kCommandAck2)) return deselect(), Error::ProtocolError;
    if (!advance(0, c_ackTimeoutLong)) return deselect(), Error::Timeout;
    uint8_t endByte = SIO::Data;
    deselect();

    switch (endByte) {
        case kEndGood:
            return Error::OK;
        case kEndBadChecksum:
            return Error::BadChecksum;
        case kEndBadSector:
            return Error::BadSector;
        default:
            return Error::ProtocolError;
    }
}

bool psyqo::MemoryCard::isTransient(Error error) {
    switch (error) {
        case Error::NoCard:     // a slow real card can momentarily miss the first ack
        case Error::Timeout:
        case Error::BadChecksum:
        case Error::ProtocolError:
            return true;
        default:
            return false;
    }
}

psyqo::MemoryCard::Error psyqo::MemoryCard::readSectorRetried(Port port, uint16_t sector, uint8_t *out) {
    Error error = Error::NoCard;
    for (unsigned attempt = 0; attempt < c_maxAttempts; attempt++) {
        error = singleSectorRead(port, sector, out);
        if (error == Error::OK || !isTransient(error)) return error;
        busyLoop(2000);  // brief recovery before retrying
    }
    return error;
}

psyqo::MemoryCard::Error psyqo::MemoryCard::writeSectorRetried(Port port, uint16_t sector, const uint8_t *in) {
    Error error = Error::NoCard;
    for (unsigned attempt = 0; attempt < c_maxAttempts; attempt++) {
        error = singleSectorWrite(port, sector, in);
        // The card only returns 'G' once the write has committed, so a success
        // is trusted as-is. Transient errors are retried; real ones (BadSector)
        // are not.
        if (error == Error::OK || !isTransient(error)) return error;
        busyLoop(2000);  // brief recovery before retrying
    }
    return error;
}

psyqo::MemoryCard::Error psyqo::MemoryCard::readSectorBlocking(Port port, uint16_t sector, void *buffer) {
    SIO0Bus::Lock lock;
    return readSectorRetried(port, sector, reinterpret_cast<uint8_t *>(buffer));
}

psyqo::MemoryCard::Error psyqo::MemoryCard::writeSectorBlocking(Port port, uint16_t sector, const void *buffer) {
    SIO0Bus::Lock lock;
    return writeSectorRetried(port, sector, reinterpret_cast<const uint8_t *>(buffer));
}

psyqo::MemoryCard::Error psyqo::MemoryCard::probeBlocking(Port port) {
    SIO0Bus::Lock lock;
    uint8_t scratch[c_sectorSize];
    Error error = readSectorRetried(port, 0, scratch);
    // A formatting problem still means a card is present and responding.
    if (error == Error::BadChecksum || error == Error::ProtocolError || error == Error::NotFormatted) {
        return Error::OK;
    }
    return error;
}

