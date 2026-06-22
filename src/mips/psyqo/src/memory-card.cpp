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

uint8_t psyqo::MemoryCard::transceive(uint8_t dataOut) {
    SIO::Ctrl |= SIO::Control::CTRL_ERRRES;  // clear error
    CPU::IReg.clear(CPU::IRQ::Controller);   // clear the latched acknowledge

    SIO::Data = dataOut;

    // Wait for the byte to be clocked in and out of the FIFO.
    while (!(SIO::Stat & SIO::Status::STAT_RXRDY));

    return SIO::Data;
}

bool psyqo::MemoryCard::waitAck(uint32_t timeout) {
    uint32_t cycles = 0;
    while (!CPU::IReg.isSet(CPU::IRQ::Controller) && ++cycles < timeout);
    if (cycles >= timeout) return false;

    // Wait for the acknowledge line to return high before clocking the next
    // byte; bounded so a stuck line cannot hang the transfer forever. No extra
    // delay is inserted here: a card expects the bytes of a transaction to keep
    // flowing, and adding gaps can make it abort mid-transfer.
    uint32_t high = 0;
    while ((SIO::Stat & SIO::Status::STAT_ACK) && ++high < c_ackHighTimeout);
    return true;
}

psyqo::MemoryCard::Error psyqo::MemoryCard::doReadSector(Port port, uint16_t sector, uint8_t *out) {
    if (sector >= c_sectorCount) return Error::BadSector;

    CriticalSection guard;
    selectPort(port);

    const uint8_t msb = sector >> 8;
    const uint8_t lsb = sector & 0xff;

    // Byte 1: card address. A missing card never acknowledges this byte.
    transceive(0x81);
    if (!waitAck(c_ackTimeoutShort)) {
        deselect();
        return Error::NoCard;
    }
    // Byte 2: 'R' read command -> FLAG byte (ignored here).
    transceive(0x52);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    // Bytes 3-4: memory card ID (0x5A, 0x5D).
    transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    // Bytes 5-6: sector address (MSB then LSB).
    transceive(msb);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    transceive(lsb);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    // Bytes 7-8: command acknowledge (0x5C, 0x5D). The acknowledge that follows
    // byte 7 is the late one, hence the long timeout above and below.
    transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    // Bytes 9-10: confirmed address. 0xFFFF means the sector was rejected.
    uint8_t confMSB = transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    uint8_t confLSB = transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    if (confMSB == 0xff && confLSB == 0xff) {
        deselect();
        return Error::BadSector;
    }

    // Bytes 11..138: 128 data bytes.
    uint8_t checksum = msb ^ lsb;
    for (uint32_t i = 0; i < c_sectorSize; i++) {
        uint8_t value = transceive(0x00);
        out[i] = value;
        checksum ^= value;
        if (!waitAck(c_ackTimeoutLong)) {
            deselect();
            return Error::Timeout;
        }
    }
    // Byte 139: checksum.
    uint8_t cardChecksum = transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    // Byte 140: end byte (0x47 = 'G' = good). No acknowledge follows.
    uint8_t endByte = transceive(0x00);
    deselect();

    if (cardChecksum != checksum) return Error::BadChecksum;
    if (endByte != 0x47) return Error::ProtocolError;
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

    // Byte 1: card address.
    transceive(0x81);
    if (!waitAck(c_ackTimeoutShort)) {
        deselect();
        return Error::NoCard;
    }
    // Byte 2: 'W' write command -> FLAG.
    transceive(0x57);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    // Bytes 3-4: memory card ID.
    transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    // Bytes 5-6: sector address.
    transceive(msb);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    transceive(lsb);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    // Bytes 7..134: 128 data bytes.
    for (uint32_t i = 0; i < c_sectorSize; i++) {
        transceive(in[i]);
        if (!waitAck(c_ackTimeoutLong)) {
            deselect();
            return Error::Timeout;
        }
    }
    // Byte 135: checksum.
    transceive(checksum);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    // Bytes 136-137: command acknowledge (0x5C, 0x5D).
    transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    transceive(0x00);
    if (!waitAck(c_ackTimeoutLong)) {
        deselect();
        return Error::Timeout;
    }
    // Byte 138: end byte. No acknowledge follows.
    uint8_t endByte = transceive(0x00);
    deselect();

    switch (endByte) {
        case 0x47:  // 'G' good
            return Error::OK;
        case 0x4e:  // 'N' bad checksum
            return Error::BadChecksum;
        case 0xff:
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

