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

#include "psyqo/memory-card.hh"

#include <EASTL/atomic.h>

#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/hardware/cpu.hh"
#include "psyqo/hardware/sio.hh"
#include "psyqo/kernel.hh"

using namespace psyqo::Hardware;

namespace {

// RAII guard that masks the Controller (SIO0) interrupt for the duration of a
// transfer and restores its previous mask state on destruction. We still poll
// the latched I_STAT bit during the transfer; masking only prevents another
// handler from being dispatched and consuming the acknowledge for us.
struct MaskedControllerIRQ {
    MaskedControllerIRQ() {
        m_wasSet = CPU::IMask.isSet(CPU::IRQ::Controller);
        CPU::IMask.clear(CPU::IRQ::Controller);
        CPU::flushWriteQueue();
    }
    ~MaskedControllerIRQ() {
        if (m_wasSet) CPU::IMask.set(CPU::IRQ::Controller);
        CPU::flushWriteQueue();
    }

  private:
    bool m_wasSet;
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
    if (c_useIrq) installIrqHandler();
}

uint16_t psyqo::MemoryCard::portMask(Port port) {
    return port == Port::Port1 ? SIO::Control::CTRL_PORTSEL : 0;
}

// Hold the bus deselected (/CS high) for the inter-transaction recovery window
// before a fresh select. The retail BIOS gets this for free by kicking each
// sector from the vblank handler (~16ms apart); we chain transactions back to
// back, and a slow third-party card reselected too soon serves stale (valid-
// checksum but wrong) sector data. Spending the time here, with the bus
// deselected, gives the card the recovery it expects between transactions.
void psyqo::MemoryCard::recoverBeforeSelect() {
    SIO::Ctrl = 0;  // ensure deselected
    busyLoop(c_interTransactionDelay);
}

void psyqo::MemoryCard::installIrqHandler() {
    // Start with the controller interrupt masked: it is only unmasked while a
    // card operation is actually running, so it never fires during AdvancedPad's
    // polled reads (which share SIO0 / IRQ7). This mirrors the BIOS, which
    // toggles the controller mask around each card operation.
    CPU::IMask.clear(CPU::IRQ::Controller);
    CPU::flushWriteQueue();

    eastl::function<void()> callback = [this]() {
        CPU::IReg.clear(CPU::IRQ::Controller);
        irq();
    };
    if (Kernel::isKernelTakenOver()) {
        Kernel::queueIRQHandler(Kernel::IRQ::Controller, eastl::move(callback));
    } else {
        m_event = Kernel::openEvent(EVENT_CONTROLLER, 0x1000, EVENT_MODE_CALLBACK, eastl::move(callback));
        syscall_enableEvent(m_event);
    }
}

// openbios-style byte exchange: the value clocked in during the *previous*
// transfer is already waiting in the FIFO, so read it, push the next byte, then
// clear the error latch and acknowledge the controller interrupt.
uint8_t psyqo::MemoryCard::exchangeByte(uint8_t out) {
    uint8_t ret = SIO::Data;
    SIO::Data = out;
    SIO::Ctrl |= SIO::Control::CTRL_ERRRES;
    CPU::IReg.clear(CPU::IRQ::Controller);
    return ret;
}

void psyqo::MemoryCard::startTransfer(Action action, Port port, uint16_t sector, void *readBuf, const void *writeBuf) {
    m_action = action;
    m_port = port;
    m_sector = sector;
    m_readBuffer = reinterpret_cast<uint8_t *>(readBuf);
    m_writeBuffer = reinterpret_cast<const uint8_t *>(writeBuf);
    m_runningChecksum = 0;
    m_cardChecksum = 0;
    m_result = Error::OK;
    m_done = false;
    m_step = 1;

    // Give the card its inter-transaction recovery window (bus deselected)
    // before reselecting, so a slow third-party card is never reselected
    // mid-recovery and made to serve stale data.
    recoverBeforeSelect();

    // Select the port exactly the way the proven AdvancedPad / polling path do:
    // assert the port select, enable the transmitter and the acknowledge IRQ,
    // and only THEN let the bus settle before the first clock. The settle delay
    // must come *after* TXEN/ACKIRQEN are enabled - it is the ~23us of card
    // ready-time before the first clock pulse. Settling before enabling the
    // transmitter (as an earlier version did) gives the card no ready-time, so
    // it misses the first acknowledge on real hardware and looks absent.
    SIO::Ctrl = portMask(port) | SIO::Control::CTRL_DTR;
    SIO::Baud = 0x88;
    flushRxBuffer();
    SIO::Ctrl |= (SIO::Control::CTRL_TXEN | SIO::Control::CTRL_ACKIRQEN);
    busyLoop(c_selectDelay);

    // Fire the first byte (step 1) synchronously, then wait for its acknowledge
    // with a bounded poll. A missing card never acknowledges, so this is where
    // "no card" is detected quickly, before handing the rest off to interrupts.
    CPU::IReg.clear(CPU::IRQ::Controller);
    if (action == Action::Read) {
        readStep();
    } else {
        writeStep();
    }

    uint32_t spins = 0;
    while (!CPU::IReg.isSet(CPU::IRQ::Controller) && ++spins < c_ackTimeoutShort);
    if (spins >= c_ackTimeoutShort) {
        finishTransfer(Error::NoCard);
        return;
    }

    // The first acknowledge is latched; unmasking now makes it (and every
    // subsequent one) drive the state machine through `irq()`.
    CPU::IMask.set(CPU::IRQ::Controller);
    CPU::flushWriteQueue();
}

void psyqo::MemoryCard::finishTransfer(Error result) {
    SIO::Ctrl = 0;  // deselect
    CPU::IMask.clear(CPU::IRQ::Controller);
    CPU::flushWriteQueue();
    m_action = Action::None;
    m_result = result;
    if (!m_blocking && m_callback) {
        auto cb = eastl::move(m_callback);
        m_callback = nullptr;
        Kernel::queueCallbackFromISR([cb = eastl::move(cb), result]() mutable { cb(result); });
    }
    eastl::atomic_signal_fence(eastl::memory_order_release);
    m_done = true;
}

void psyqo::MemoryCard::irq() {
    if (m_action == Action::None) return;  // not our interrupt
    // Re-assert the select and clear the error latch, like the BIOS handler.
    SIO::Ctrl |= portMask(m_port) | SIO::Control::CTRL_ERRRES | SIO::Control::CTRL_DTR;
    m_step++;
    StepResult result = (m_action == Action::Read) ? readStep() : writeStep();
    if (result == StepResult::Done) finishTransfer(m_result);
}

psyqo::MemoryCard::StepResult psyqo::MemoryCard::readStep() {
    const uint8_t msb = m_sector >> 8;
    const uint8_t lsb = m_sector & 0xff;
    switch (m_step) {
        case 1:
            // The bus was selected, enabled and settled in startTransfer; just
            // clock the addressing byte onto it.
            exchangeByte(0x81);
            return StepResult::Continue;
        case 2:
            exchangeByte(0x52);  // 'R'
            return StepResult::Continue;
        case 3:
            exchangeByte(0x00);  // FLAG byte (ignored)
            return StepResult::Continue;
        case 4:
            if (exchangeByte(0x00) != 0x5a) {
                m_result = Error::ProtocolError;
                return StepResult::Done;
            }
            return StepResult::Continue;
        case 5:
            if (exchangeByte(msb) != 0x5d) {
                m_result = Error::ProtocolError;
                return StepResult::Done;
            }
            return StepResult::Continue;
        case 6:
            exchangeByte(lsb);
            return StepResult::Continue;
        case 7:
            exchangeByte(0x00);
            return StepResult::Continue;
        case 8:
            if (exchangeByte(0x00) != 0x5c) {
                m_result = Error::ProtocolError;
                return StepResult::Done;
            }
            return StepResult::Continue;
        case 9:
            if (exchangeByte(0x00) != 0x5d) {
                m_result = Error::ProtocolError;
                return StepResult::Done;
            }
            return StepResult::Continue;
        case 10:
            if (exchangeByte(0x00) != msb) {
                m_result = Error::BadSector;
                return StepResult::Done;
            }
            m_runningChecksum = msb ^ lsb;
            return StepResult::Continue;
        case 11:
            if (exchangeByte(0x00) != lsb) {
                m_result = Error::BadSector;
                return StepResult::Done;
            }
            return StepResult::Continue;
        default: {
            // Steps 12..139 read the 128 data bytes.
            if (m_step >= 12 && m_step <= 139) {
                uint8_t b = exchangeByte(0x00);
                m_readBuffer[m_step - 12] = b;
                m_runningChecksum ^= b;
                return StepResult::Continue;
            }
            // Step 140: read the checksum, then the (un-acknowledged) end byte.
            if (m_step == 140) {
                m_cardChecksum = exchangeByte(0x00);
                uint32_t spins = 0;
                while (!(SIO::Stat & SIO::Status::STAT_RXRDY) && ++spins < c_ackTimeoutLong);
                uint8_t endByte = SIO::Data;
                if (m_cardChecksum != m_runningChecksum) {
                    m_result = Error::BadChecksum;
                } else if (endByte != 0x47) {
                    m_result = Error::ProtocolError;
                } else {
                    m_result = Error::OK;
                }
                return StepResult::Done;
            }
            m_result = Error::ProtocolError;
            return StepResult::Done;
        }
    }
}

psyqo::MemoryCard::StepResult psyqo::MemoryCard::writeStep() {
    const uint8_t msb = m_sector >> 8;
    const uint8_t lsb = m_sector & 0xff;
    switch (m_step) {
        case 1:
            // The bus was selected, enabled and settled in startTransfer; just
            // clock the addressing byte onto it.
            exchangeByte(0x81);
            return StepResult::Continue;
        case 2:
            exchangeByte(0x57);  // 'W'
            return StepResult::Continue;
        case 3:
            exchangeByte(0x00);  // FLAG byte (ignored)
            return StepResult::Continue;
        case 4:
            if (exchangeByte(0x00) != 0x5a) {
                m_result = Error::ProtocolError;
                return StepResult::Done;
            }
            return StepResult::Continue;
        case 5:
            if (exchangeByte(msb) != 0x5d) {
                m_result = Error::ProtocolError;
                return StepResult::Done;
            }
            m_runningChecksum = msb;
            return StepResult::Continue;
        case 6:
            exchangeByte(lsb);
            m_runningChecksum ^= lsb;
            return StepResult::Continue;
        default: {
            // Steps 7..134 send the 128 data bytes.
            if (m_step >= 7 && m_step <= 134) {
                uint8_t d = m_writeBuffer[m_step - 7];
                exchangeByte(d);
                m_runningChecksum ^= d;
                return StepResult::Continue;
            }
            if (m_step == 135) {
                exchangeByte(m_runningChecksum);  // checksum
                return StepResult::Continue;
            }
            if (m_step == 136) {
                exchangeByte(0x00);
                return StepResult::Continue;
            }
            if (m_step == 137) {
                if (exchangeByte(0x00) != 0x5c) {
                    m_result = Error::ProtocolError;
                    return StepResult::Done;
                }
                return StepResult::Continue;
            }
            // Step 138: read the second ack, then the (un-acknowledged) end byte.
            if (m_step == 138) {
                if (exchangeByte(0x00) != 0x5d) {
                    m_result = Error::ProtocolError;
                    return StepResult::Done;
                }
                uint32_t spins = 0;
                while (!(SIO::Stat & SIO::Status::STAT_RXRDY) && ++spins < c_ackTimeoutLong);
                uint8_t endByte = SIO::Data;
                switch (endByte) {
                    case 0x47:
                        m_result = Error::OK;
                        break;
                    case 0x4e:
                        m_result = Error::BadChecksum;
                        break;
                    case 0xff:
                        m_result = Error::BadSector;
                        break;
                    default:
                        m_result = Error::ProtocolError;
                        break;
                }
                return StepResult::Done;
            }
            m_result = Error::ProtocolError;
            return StepResult::Done;
        }
    }
}

psyqo::MemoryCard::Error psyqo::MemoryCard::irqTransferBlocking(Action action, Port port, uint16_t sector,
                                                                void *readBuf, const void *writeBuf) {
    m_blocking = true;
    m_callback = nullptr;
    startTransfer(action, port, sector, readBuf, writeBuf);

    uint32_t watchdog = 0;
    while (!m_done) {
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
        if (++watchdog >= c_irqWatchdog) {
            // The interrupt stopped advancing us; abort rather than hang.
            finishTransfer(m_step <= 1 ? Error::NoCard : Error::Timeout);
            break;
        }
    }
    m_blocking = false;
    return m_result;
}

psyqo::MemoryCard::Error psyqo::MemoryCard::singleSectorRead(Port port, uint16_t sector, uint8_t *out) {
    if (sector >= c_sectorCount) return Error::BadSector;
    if (c_useIrq) return irqTransferBlocking(Action::Read, port, sector, out, nullptr);
    return doReadSector(port, sector, out);
}

psyqo::MemoryCard::Error psyqo::MemoryCard::singleSectorWrite(Port port, uint16_t sector, const uint8_t *in) {
    if (sector >= c_sectorCount) return Error::BadSector;
    if (c_useIrq) return irqTransferBlocking(Action::Write, port, sector, nullptr, in);
    return doWriteSector(port, sector, in);
}

void psyqo::MemoryCard::selectPort(Port port) {
    recoverBeforeSelect();  // deselected recovery window before reselecting
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

    MaskedControllerIRQ guard;
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

    MaskedControllerIRQ guard;
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
    return readSectorRetried(port, sector, reinterpret_cast<uint8_t *>(buffer));
}

psyqo::MemoryCard::Error psyqo::MemoryCard::writeSectorBlocking(Port port, uint16_t sector, const void *buffer) {
    return writeSectorRetried(port, sector, reinterpret_cast<const uint8_t *>(buffer));
}

psyqo::MemoryCard::Error psyqo::MemoryCard::probeBlocking(Port port) {
    uint8_t scratch[c_sectorSize];
    Error error = readSectorRetried(port, 0, scratch);
    // A formatting problem still means a card is present and responding.
    if (error == Error::BadChecksum || error == Error::ProtocolError || error == Error::NotFormatted) {
        return Error::OK;
    }
    return error;
}

void psyqo::MemoryCard::readSector(Port port, uint16_t sector, void *buffer, eastl::function<void(Error)> &&callback) {
    if (!c_useIrq) {
        Kernel::queueCallback([this, port, sector, buffer, callback = eastl::move(callback)]() mutable {
            callback(readSectorRetried(port, sector, reinterpret_cast<uint8_t *>(buffer)));
        });
        return;
    }
    if (sector >= c_sectorCount) {
        Kernel::queueCallback([callback = eastl::move(callback)]() mutable { callback(Error::BadSector); });
        return;
    }
    // True interrupt-driven, non-blocking transfer: returns immediately, the
    // callback fires (from a queued main-thread callback) once the interrupt
    // state machine completes. The caller is responsible for not letting an
    // AdvancedPad poll run while this single-sector op is in flight (it shares
    // SIO0); a sector completes well within a frame. A transient failure is
    // retried internally (a safeguard behind the corrected timing) before the
    // callback fires.
    m_blocking = false;
    m_attempt = 0;
    m_userCallback = eastl::move(callback);
    startAsyncAttempt(Action::Read, port, sector, buffer, nullptr);
}

void psyqo::MemoryCard::writeSector(Port port, uint16_t sector, const void *buffer,
                                    eastl::function<void(Error)> &&callback) {
    if (!c_useIrq) {
        Kernel::queueCallback([this, port, sector, buffer, callback = eastl::move(callback)]() mutable {
            callback(writeSectorRetried(port, sector, reinterpret_cast<const uint8_t *>(buffer)));
        });
        return;
    }
    if (sector >= c_sectorCount) {
        Kernel::queueCallback([callback = eastl::move(callback)]() mutable { callback(Error::BadSector); });
        return;
    }
    m_blocking = false;
    m_attempt = 0;
    m_userCallback = eastl::move(callback);
    startAsyncAttempt(Action::Write, port, sector, nullptr, buffer);
}

// Issues one attempt of an asynchronous transfer. `m_callback` is the internal
// per-attempt handler; the real user callback waits in `m_userCallback` and is
// invoked only once the transfer succeeds or the retries are exhausted.
void psyqo::MemoryCard::startAsyncAttempt(Action action, Port port, uint16_t sector, void *readBuf,
                                          const void *writeBuf) {
    m_retryAction = action;
    m_callback = [this](Error result) { onAsyncAttemptDone(result); };
    startTransfer(action, port, sector, readBuf, writeBuf);
}

void psyqo::MemoryCard::onAsyncAttemptDone(Error result) {
    // Runs from a queued main-thread callback, so re-issuing here is safe.
    if (result != Error::OK && isTransient(result) && ++m_attempt < c_maxAttempts) {
        busyLoop(2000);  // brief recovery before retrying, matching the blocking path
        startAsyncAttempt(m_retryAction, m_port, m_sector, m_readBuffer, m_writeBuffer);
        return;
    }
    auto cb = eastl::move(m_userCallback);
    m_userCallback = nullptr;
    if (cb) cb(result);
}

psyqo::TaskQueue::Task psyqo::MemoryCard::scheduleReadSector(Port port, uint16_t sector, void *buffer,
                                                             Error *resultOut) {
    return TaskQueue::Task([this, port, sector, buffer, resultOut](auto task) {
        readSector(port, sector, buffer, [task, resultOut](Error error) {
            if (resultOut) *resultOut = error;
            task->complete(error == Error::OK);
        });
    });
}

psyqo::TaskQueue::Task psyqo::MemoryCard::scheduleWriteSector(Port port, uint16_t sector, const void *buffer,
                                                              Error *resultOut) {
    return TaskQueue::Task([this, port, sector, buffer, resultOut](auto task) {
        writeSector(port, sector, buffer, [task, resultOut](Error error) {
            if (resultOut) *resultOut = error;
            task->complete(error == Error::OK);
        });
    });
}
