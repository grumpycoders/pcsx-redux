/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

/*
 * Handles all CD-ROM registers and functions.
 */

#include "core/cdrom.h"

#include <string_view>

#include "cdrom/iec-60908b.h"
#include "cdrom/iso9660-reader.h"
#include "core/debug.h"
#include "core/psxdma.h"
#include "core/psxemulator.h"
#include "magic_enum/include/magic_enum.hpp"
#include "spu/interface.h"
#include "support/strings-helpers.h"

namespace {

using namespace std::literals;

class CDRomImpl final : public PCSX::CDRom {
    enum Commands {
        CdlSync = 0,
        CdlNop = 1,
        CdlSetLoc = 2,
        CdlPlay = 3,
        CdlForward = 4,
        CdlBackward = 5,
        CdlReadN = 6,
        CdlStandby = 7,
        CdlStop = 8,
        CdlPause = 9,
        CdlInit = 10,
        CdlMute = 11,
        CdlDemute = 12,
        CdlSetFilter = 13,
        CdlSetMode = 14,
        CdlGetParam = 15,
        CdlGetLocL = 16,
        CdlGetLocP = 17,
        CdlReadT = 18,
        CdlGetTN = 19,
        CdlGetTD = 20,
        CdlSeekL = 21,
        CdlSeekP = 22,
        CdlSetClock = 23,
        CdlGetClock = 24,
        CdlTest = 25,
        CdlID = 26,
        CdlReadS = 27,
        CdlReset = 28,
        CdlGetQ = 29,
        CdlReadToc = 30,
    };

    static constexpr size_t c_cdCmdEnumCount = magic_enum::enum_count<Commands>();
    static constexpr bool isValidBCD(uint8_t value) { return (value & 0x0f) <= 9 && (value & 0xf0) <= 0x90; }
    static std::optional<PCSX::IEC60908b::MSF> getMSF(const uint8_t *msf) {
        bool validBCD = isValidBCD(msf[0]) && isValidBCD(msf[1]) && isValidBCD(msf[2]);
        if (!validBCD) return {};
        uint8_t m = PCSX::IEC60908b::btoi(msf[0]);
        uint8_t s = PCSX::IEC60908b::btoi(msf[1]);
        uint8_t f = PCSX::IEC60908b::btoi(msf[2]);

        if (s >= 60) return {};
        if (f >= 75) return {};
        return PCSX::IEC60908b::MSF(m, s, f);
    }

    void reset() override {
        m_dataFIFOIndex = 0;
        m_dataFIFOSize = 0;
        m_registerIndex = 0;
        m_currentPosition.reset();
        m_seekPosition.reset();
        m_speed = Speed::Simple;
        m_speedChanged = false;
        m_status = Status::Idle;
        m_dataRequested = false;
        m_causeMask = 0x1f;
        m_subheaderFilter = false;
        m_realtime = false;
        m_commandFifo.clear();
        m_commandExecuting.clear();
        m_responseFifo[0].clear();
        m_responseFifo[1].clear();
    }

    void fifoScheduledCallback() override { maybeStartCommand(); }

    void commandsScheduledCallback() override {
        auto command = m_commandExecuting.value;
        auto handler = c_commandsHandlers[command];
        (this->*handler)(m_commandExecuting, false);
    }

    void readScheduledCallback() override {
        static const std::chrono::nanoseconds c_retryDelay = 50us;
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingCDROM>();
        if (m_startReading) {
            m_startReading = false;
            m_status = Status::ReadingData;
        }
        if ((m_status == Status::Idle) || (m_status == Status::Seeking)) {
            m_readingType = ReadingType::None;
            if (debug) {
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CDRom: readInterrupt: cancelling read.\n");
            }
            return;
        }

        switch (m_status) {
            case Status::ReadingData: {
                unsigned track = m_iso->getTrack(m_currentPosition);
                if (m_iso->getTrackType(track) == PCSX::CDRIso::TrackType::CDDA) {
                    m_status = Status::Idle;
                    maybeEnqueueError(4, 4);
                } else if (track == 0) {
                    m_status = Status::Idle;
                    maybeEnqueueError(4, 0x10);
                } else {
                    m_invalidLocL = false;
                    m_iso->readTrack(m_currentPosition);
                    auto buffer = m_iso->getBuffer();
                    memcpy(m_lastLocL, buffer, sizeof(m_lastLocL));
                    uint32_t size = 0;
                    switch (m_readSpan) {
                        case ReadSpan::S2048:
                            size = 2048;
                            if (buffer[3] == 1) {
                                memcpy(m_dataFIFO, buffer + 4, 2048);
                            } else {
                                memcpy(m_dataFIFO, buffer + 12, 2048);
                            }
                            break;
                        case ReadSpan::S2328:
                            size = 2328;
                            memcpy(m_dataFIFO, buffer + 12, 2328);
                            break;
                        case ReadSpan::S2340:
                            size = 2340;
                            memcpy(m_dataFIFO, buffer, 2340);
                            break;
                    }
                    auto readDelay = computeReadDelay();
                    m_dataFIFOIndex = 0;
                    m_dataFIFOPending = size;
                    if (m_dataRequested) m_dataFIFOSize = size;
                    m_currentPosition++;
                    if (debug) {
                        std::string msfFormat = fmt::format("{}", m_currentPosition);
                        PCSX::g_system->log(PCSX::LogClass::CDROM, "CDRom: readInterrupt: advancing to %s.\n",
                                            msfFormat);
                    }
                    QueueElement ready;
                    ready.pushPayloadData(getStatus());
                    maybeTriggerIRQ(Cause::DataReady, ready);
                    scheduleRead(readDelay);
                }
            } break;
            default:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "unsupported yet\n");
                PCSX::g_system->pause();
                break;
        }
    }

    void scheduleDmaCallback() override {
        if (HW_DMA3_CHCR & SWAP_LE32(0x01000000)) {
            HW_DMA3_CHCR &= SWAP_LE32(~0x01000000);
            DMA_INTERRUPT<3>();
        }
    }

    void scheduleFifo(uint32_t cycles) { PCSX::g_emulator->m_cpu->schedule(PCSX::Schedule::CDRFIFO, cycles); }
    void scheduleFifo(std::chrono::nanoseconds delay) { scheduleFifo(PCSX::psxRegisters::durationToCycles(delay)); }

    void schedule(uint32_t cycles) { PCSX::g_emulator->m_cpu->schedule(PCSX::Schedule::CDRCOMMANDS, cycles); }
    void schedule(std::chrono::nanoseconds delay) { schedule(PCSX::psxRegisters::durationToCycles(delay)); }

    void scheduleRead(uint32_t cycles) { PCSX::g_emulator->m_cpu->schedule(PCSX::Schedule::CDREAD, cycles); }
    void scheduleRead(std::chrono::nanoseconds delay) { scheduleRead(PCSX::psxRegisters::durationToCycles(delay)); }

    void scheduleDMA(uint32_t cycles) { PCSX::g_emulator->m_cpu->schedule(PCSX::Schedule::CDRDMA, cycles); }
    void scheduleDMA(std::chrono::nanoseconds delay) { scheduleDMA(PCSX::psxRegisters::durationToCycles(delay)); }

    void maybeTriggerIRQ(Cause cause, QueueElement &element) {
        uint8_t causeValue = static_cast<uint8_t>(cause);
        uint8_t bit = 1 << (causeValue - 1);
        if (m_causeMask & bit) {
            element.setValue(cause);
            maybeEnqueueResponse(element);
            psxHu32ref(0x1070) |= SWAP_LE32(uint32_t(4));
            const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                                   .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
            if (debug) {
                auto &regs = PCSX::g_emulator->m_cpu->m_regs;
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] triggering IRQ with cause %d\n", regs.pc,
                                    regs.cycle, causeValue);
            }
        } else {
            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                    .get<PCSX::Emulator::DebugSettings::LoggingCDROM>()) {
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: wanted to trigger IRQ but cause %d is masked...\n",
                                    causeValue);
            }
        }
    }

    uint8_t getStatus(bool resetLid = false) {
        bool lidOpen = isLidOpen();
        if (resetLid && !lidOpen) m_wasLidOpened = false;
        uint8_t v1 = m_motorOn && !lidOpen ? 0x02 : 0;
        uint8_t v4 = m_wasLidOpened ? 0x10 : 0;
        uint8_t v567 = 0;
        switch (m_status) {
            case Status::ReadingData:
                v567 = 0x20;
                break;
            case Status::Seeking:
                v567 = 0x40;
                break;
            case Status::PlayingCDDA:
                v567 = 0x80;
                break;
        }
        return v1 | v4 | v567;
    }

    uint8_t read0() override {
        uint8_t v01 = m_registerIndex & 3;
        uint8_t adpcmPlaying = 0;
        uint8_t v3 = m_commandFifo.isPayloadEmpty() ? 0x08 : 0;
        uint8_t v4 = !m_commandFifo.isPayloadFull() ? 0x10 : 0;
        uint8_t v5 = !m_responseFifo[0].empty() ? 0x20 : 0;
        uint8_t v6 = m_dataFIFOSize != m_dataFIFOIndex ? 0x40 : 0;
        uint8_t v7 = m_commandFifo.hasValue ? 0x80 : 0;

        uint8_t ret = v01 | adpcmPlaying | v3 | v4 | v5 | v6 | v7;
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] r0: %02x\n", regs.pc, regs.cycle, ret);
        }

        return ret;
    }

    uint8_t read1() override {
        uint8_t ret = m_responseFifo[0].readPayloadByte();
        // TODO: if empty, move response FIFO and maybe trigger IRQ.

        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] r1: %02x\n", regs.pc, regs.cycle, ret);
        }
        return ret;
    }

    uint8_t read2() override {
        uint8_t ret = 0;
        if (!dataFIFOHasData()) {
            ret = 0;
        } else {
            ret = m_dataFIFO[m_dataFIFOIndex++];
        }

        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] r2: %02x\n", regs.pc, regs.cycle, ret);
        }
        return ret;
    }

    uint8_t read3() override {
        uint8_t ret = 0;
        switch (m_registerIndex & 1) {
            case 0: {
                ret = m_causeMask | 0xe0;
            } break;
            case 1: {
                // cause
                // TODO: add bit 4
                ret = m_responseFifo[0].getValue() | 0xe0;
            } break;
        }
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] r3.%i: %02x\n", regs.pc, regs.cycle,
                                m_registerIndex & 1, ret);
        }
        return ret;
    }

    void write0(uint8_t value) override {
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] w0: %02x\n", regs.pc, regs.cycle, value);
        }
        m_registerIndex = value & 3;
    }

    void write1(uint8_t value) override {
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] w1.%i: %02x\n", regs.pc, regs.cycle,
                                m_registerIndex, value);
        }
        switch (m_registerIndex) {
            case 0:
                m_commandFifo.value = value;
                if (!m_commandFifo.hasValue) {
                    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                            .get<PCSX::Emulator::DebugSettings::LoggingCDROM>()) {
                        logCDROM(m_commandFifo);
                    }
                    scheduleFifo(1ms);
                }
                m_commandFifo.hasValue = true;
                break;
            case 1: {
                // ??
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w1:1 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 2: {
                // ??
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w1:2 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 3: {
                // Volume setting RR
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w1:3 not available yet\n");
            } break;
        }
    }

    void write2(uint8_t value) override {
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] w2.%i: %02x\n", regs.pc, regs.cycle,
                                m_registerIndex, value);
        }
        switch (m_registerIndex) {
            case 0: {
                m_commandFifo.pushPayloadData(value);
            } break;
            case 1: {
                m_causeMask = value;
            } break;
            case 2: {
                // Volume setting LL
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w2:2 not available yet\n");
            } break;
            case 3: {
                // Volume setting RL
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w2:3 not available yet\n");
            } break;
        }
    }

    void write3(uint8_t value) override {
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] w3.%i: %02x\n", regs.pc, regs.cycle,
                                m_registerIndex, value);
        }
        switch (m_registerIndex) {
            case 0: {
                // ??
                if (value == 0) {
                    m_dataRequested = false;
                    m_dataFIFOSize = 0;
                    m_dataFIFOIndex = 0;
                    return;
                }
                if (value == 0x80) {
                    m_dataRequested = true;
                    m_dataFIFOSize = m_dataFIFOPending;
                    return;
                }
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w3:0(%02x) not available yet\n", value);
                PCSX::g_system->pause();
            } break;
            case 1: {
                bool ack = false;
                // cause ack
                if (value == 0x07) {
                    // partial ack?
                    ack = true;
                }
                if (value == 0x1f) {
                    // all ack?
                    ack = true;
                }
                if (ack) {
                    m_responseFifo[0].valueRead = true;
                    // TODO: if empty, move response FIFO and maybe trigger IRQ.
                    return;
                }
                if (value & 0x10) {
                    // request ack?
                    // TODO: act on this?
                }
                if (value & 0x08) {
                    // ??
                    // TODO: act on this?
                }
                if (value & 0x40) {
                    m_commandFifo.payloadSize = 0;
                    return;
                }
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w3:1(%02x) not available yet\n", value);
                PCSX::g_system->pause();
            } break;
            case 2: {
                // Volume setting LR
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w3:2 not available yet\n");
            } break;
            case 3: {
                // SPU settings latch
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w3:3 not available yet\n");
            } break;
        }
    }

    void dma(uint32_t madr, uint32_t bcr, uint32_t chcr) override {
        uint32_t size = bcr >> 16;
        size *= bcr & 0xffff;
        size *= 4;
        if (size == 0) size = 0xffffffff;
        size = std::min(m_dataFIFOSize - m_dataFIFOIndex, size);
        auto ptr = (uint8_t *)PSXM(madr);
        for (auto i = 0; i < size; i++) {
            *ptr++ = m_dataFIFO[m_dataFIFOIndex++];
        }
        PCSX::g_emulator->m_cpu->Clear(madr, size / 4);
        if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                .get<PCSX::Emulator::DebugSettings::Debug>()) {
            PCSX::g_emulator->m_debug->checkDMAwrite(3, madr, size);
        }
        if (chcr == 0x11400100) {
            scheduleDMA(size / 16);
        } else {
            scheduleDMA(size / 4);
        }
    }

    void maybeEnqueueError(uint8_t mask1, uint8_t mask2) {
        QueueElement error;
        error.pushPayloadData(getStatus() | mask1);
        error.pushPayloadData(mask2);
        maybeTriggerIRQ(Cause::Error, error);
    }

    void maybeStartCommand() {
        auto command = m_commandFifo.value;
        static constexpr unsigned c_commandMax = sizeof(c_commandsArgumentsCount) / sizeof(c_commandsArgumentsCount[0]);
        if (command >= c_commandMax) {
            maybeEnqueueError(1, 0x40);
            endCommand();
            return;
        }
        auto expectedCount = c_commandsArgumentsCount[command];
        if ((expectedCount >= 0) && (expectedCount != m_commandFifo.payloadSize)) {
            maybeEnqueueError(1, 0x20);
            endCommand();
            return;
        }
        auto handler = c_commandsHandlers[command];
        if (handler) {
            if ((this->*handler)(m_commandFifo, true)) {
                m_commandExecuting = m_commandFifo;
            }
            m_commandFifo.clear();
        } else {
            maybeEnqueueError(1, 0x40);
            endCommand();
            return;
        }
    }

    void endCommand() {
        if (!responseFifoFull() && !m_commandFifo.empty()) scheduleFifo(1ms);
    }

    enum class SeekType { DATA, CDDA };

    std::chrono::nanoseconds computeSeekDelay(MSF from, MSF to, SeekType seekType) {
        unsigned destTrack = m_iso->getTrack(to);
        if (destTrack == 0) return 650ms;
        if ((seekType == SeekType::DATA) && (m_iso->getTrackType(destTrack) == PCSX::CDRIso::TrackType::CDDA)) {
            return 4s;
        }
        uint32_t distance = 0;
        if (from > to) {
            distance = (from - to).toLBA();
        } else {
            distance = (to - from).toLBA();
        }
        // TODO: ought to be a decent approximation for now,
        // but may require some tuning later on.
        return std::chrono::microseconds(distance * 3) + 150ms;
    }

    std::chrono::nanoseconds computeReadDelay() { return m_speed == Speed::Simple ? 13333us : 6666us; }

    // Command 1.
    bool cdlNop(const QueueElement &command, bool start) {
        QueueElement response;
        response.pushPayloadData(getStatus(true));
        maybeTriggerIRQ(Cause::Acknowledge, response);
        endCommand();
        return false;
    }

    // Command 2.
    bool cdlSetLoc(const QueueElement &command, bool start) {
        // TODO: probably should error out if no disc or
        // lid open?
        // What happens when issued during Read / Play?
        auto maybeMSF = getMSF(command.payload);
        QueueElement response;
        Cause cause;
        if (maybeMSF.has_value()) {
            response.pushPayloadData(getStatus());
            cause = Cause::Acknowledge;
            maybeTriggerIRQ(cause, response);
            m_seekPosition = maybeMSF.value();
        } else {
            maybeEnqueueError(1, 0x10);
        }
        endCommand();
        return false;
    }

    // Command 6.
    bool cdlReadN(const QueueElement &command, bool start) {
        auto seekDelay = computeSeekDelay(m_currentPosition, m_seekPosition, SeekType::DATA);
        if (m_speedChanged) {
            m_speedChanged = false;
            seekDelay += 650ms;
        }
        scheduleRead(seekDelay + computeReadDelay());
        QueueElement response;
        response.pushPayloadData(getStatus());
        m_currentPosition = m_seekPosition;
        m_startReading = true;
        m_readingType = ReadingType::Normal;
        maybeTriggerIRQ(Cause::Acknowledge, response);
        endCommand();
        return false;
    }

    // Command 9.
    bool cdlPause(const QueueElement &command, bool start) {
        if (start) {
            if (m_status == Status::Idle) {
                schedule(200us);
            } else {
                schedule(m_speed == Speed::Simple ? 70ms : 35ms);
            }
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Acknowledge, response);
            return true;
        } else {
            m_status = Status::Idle;
            m_invalidLocL = true;
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Complete, response);
            endCommand();
            return false;
        }
    }

    // Command 10.
    bool cdlInit(const QueueElement &command, bool start) {
        if (start) {
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Acknowledge, response);
            schedule(120ms);
            return true;
        } else {
            // TODO: figure out exactly the various states of the CD-Rom controller
            // that are being reset, and their value.
            m_motorOn = true;
            m_speedChanged = false;
            m_currentPosition.reset();
            m_currentPosition.s = 2;
            m_seekPosition.reset();
            m_seekPosition.s = 2;
            m_invalidLocL = false;
            m_speed = Speed::Simple;
            m_status = Status::Idle;
            m_causeMask = 0x1f;
            memset(m_lastLocP, 0, sizeof(m_lastLocP));
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Complete, response);
            endCommand();
            return false;
        }
    }

    // Command 11
    bool cdlMute(const QueueElement &command, bool start) {
        // TODO: probably should error out if no disc or
        // lid open?
        PCSX::g_system->log(PCSX::LogClass::CDROM, "CDRom: Mute - not yet implemented.\n");
        QueueElement response;
        response.pushPayloadData(getStatus());
        maybeTriggerIRQ(Cause::Acknowledge, response);
        endCommand();
        return false;
    }

    // Command 12
    bool cdlDemute(const QueueElement &command, bool start) {
        // TODO: probably should error out if no disc or
        // lid open?
        PCSX::g_system->log(PCSX::LogClass::CDROM, "CDRom: Demute - not yet implemented.\n");
        QueueElement response;
        response.pushPayloadData(getStatus());
        maybeTriggerIRQ(Cause::Acknowledge, response);
        endCommand();
        return false;
    }

    // Command 14
    bool cdlSetMode(const QueueElement &command, bool start) {
        uint8_t mode = command.payload[0];
        // TODO: add the rest of the mode bits.
        if (mode & 0x80) {
            if (m_speed == Speed::Simple) {
                m_speed = Speed::Double;
                m_speedChanged = true;
            }
        } else {
            if (m_speed == Speed::Double) {
                m_speed = Speed::Simple;
                m_speedChanged = true;
            }
        }
        switch ((mode & 0x30) >> 4) {
            case 0:
                m_readSpan = ReadSpan::S2048;
                break;
            case 1:
                m_readSpan = ReadSpan::S2328;
                break;
            case 2:
                m_readSpan = ReadSpan::S2340;
                break;
            case 3:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: unsupported mode:\n", mode);
                PCSX::g_system->pause();
                break;
        }
        m_subheaderFilter = (mode & 0x08) != 0;
        m_realtime = (mode & 0x40) != 0;
        if (mode & 0x07) {
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: unsupported mode:\n", mode);
            PCSX::g_system->pause();
        }
        QueueElement response;
        response.pushPayloadData(getStatus());
        maybeTriggerIRQ(Cause::Acknowledge, response);
        endCommand();
        return false;
    }

    // Command 16.
    bool cdlGetLocL(const QueueElement &command, bool start) {
        // TODO: probably should error out if no disc or
        // lid open?
        if (m_invalidLocL) {
            maybeEnqueueError(1, 0x80);
        } else {
            QueueElement response;
            response.pushPayloadData(std::string_view((char *)m_lastLocL, sizeof(m_lastLocL)));
            maybeTriggerIRQ(Cause::Acknowledge, response);
        }
        endCommand();
        return false;
    }

    // Command 17.
    bool cdlGetLocP(const QueueElement &command, bool start) {
        // TODO: probably should error out if no disc or
        // lid open?
        m_iso->getLocP(m_currentPosition, m_lastLocP);
        QueueElement response;
        response.pushPayloadData(std::string_view((char *)m_lastLocP, sizeof(m_lastLocP)));
        maybeTriggerIRQ(Cause::Acknowledge, response);
        endCommand();
        return false;
    }

    // Command 19.
    bool cdlGetTN(const QueueElement &command, bool start) {
        // TODO: probably should error out if no disc or
        // lid open?
        QueueElement response;
        response.pushPayloadData(getStatus());
        response.pushPayloadData(1);
        response.pushPayloadData(PCSX::IEC60908b::itob(m_iso->getTN()));
        maybeTriggerIRQ(Cause::Acknowledge, response);
        endCommand();
        return false;
    }

    // Command 20.
    bool cdlGetTD(const QueueElement &command, bool start) {
        // TODO: probably should error out if no disc or
        // lid open?
        auto track = PCSX::IEC60908b::btoi(command.payload[0]);
        if (!isValidBCD(command.payload[0]) || (track > m_iso->getTN())) {
            maybeEnqueueError(1, 0x10);
        } else {
            auto td = m_iso->getTD(track);
            QueueElement response;
            response.pushPayloadData(getStatus());
            response.pushPayloadData(PCSX::IEC60908b::itob(td.m));
            response.pushPayloadData(PCSX::IEC60908b::itob(td.s));
            maybeTriggerIRQ(Cause::Acknowledge, response);
        }
        endCommand();
        return false;
    }

    // Command 21.
    bool cdlSeekL(const QueueElement &command, bool start) {
        if (start) {
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Acknowledge, response);
            auto seekDelay = computeSeekDelay(m_currentPosition, m_seekPosition, SeekType::DATA);
            if (m_speedChanged) {
                m_speedChanged = false;
                seekDelay += 650ms;
            }
            m_status = Status::Seeking;
            schedule(seekDelay);
            return true;
        } else {
            m_status = Status::Idle;
            m_currentPosition = m_seekPosition;
            unsigned track = m_iso->getTrack(m_seekPosition);
            if (m_iso->getTrackType(track) == PCSX::CDRIso::TrackType::CDDA) {
                maybeEnqueueError(4, 4);
            } else if (track == 0) {
                maybeEnqueueError(4, 0x10);
            } else {
                QueueElement response;
                response.pushPayloadData(getStatus());
                maybeTriggerIRQ(Cause::Complete, response);
            }
            m_invalidLocL = true;
            endCommand();
            return false;
        }
    }

    // Command 22.
    bool cdlSeekP(const QueueElement &command, bool start) {
        if (start) {
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Acknowledge, response);
            auto seekDelay = computeSeekDelay(m_currentPosition, m_seekPosition, SeekType::CDDA);
            if (m_speedChanged) {
                m_speedChanged = false;
                seekDelay += 650ms;
            }
            m_status = Status::Seeking;
            schedule(seekDelay);
            return true;
        } else {
            m_status = Status::Idle;
            MSF fudge = m_seekPosition - MSF{m_seekPosition.toLBA() / 32768};
            m_currentPosition = fudge;
            if (m_iso->getTrack(m_seekPosition) == 0) {
                maybeEnqueueError(4, 0x10);
            } else {
                QueueElement response;
                response.pushPayloadData(getStatus());
                maybeTriggerIRQ(Cause::Complete, response);
            }
            m_invalidLocL = true;
            endCommand();
            return false;
        }
    }

    // Command 25.
    bool cdlTest(const QueueElement &command, bool start) {
        static constexpr uint8_t c_test20[] = {0x94, 0x09, 0x19, 0xc0};
        if (command.isPayloadEmpty()) {
            maybeEnqueueError(1, 0x20);
            endCommand();
            return false;
        }

        switch (command.payload[0]) {
            case 0x20:
                if (command.payloadSize == 1) {
                    QueueElement response;
                    response.pushPayloadData(std::string_view((const char *)c_test20, sizeof(c_test20)));
                    maybeTriggerIRQ(Cause::Acknowledge, response);
                } else {
                    maybeEnqueueError(1, 0x20);
                }
                break;
            default:
                maybeEnqueueError(1, 0x10);
                break;
        }
        endCommand();
        return false;
    }

    // Command 26.
    bool cdlID(const QueueElement &command, bool start) {
        if (start) {
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Acknowledge, response);
            schedule(5ms);
            return true;
        } else {
            // Adjust this response for various types of discs and situations.
            QueueElement response;
            response.pushPayloadData(getStatus());
            response.pushPayloadData(0x00);
            response.pushPayloadData(0x20);
            response.pushPayloadData(0x00);
            response.pushPayloadData("PCSX"sv);
            maybeTriggerIRQ(Cause::Complete, response);
            endCommand();
            return false;
        }
    }

    // Command 27.
    bool cdlReadS(const QueueElement &command, bool start) {
        bool ret = cdlReadN(command, start);
        m_readingType = ReadingType::Streaming;
        return ret;
    }

    typedef bool (CDRomImpl::*CommandType)(const QueueElement &, bool);

    const CommandType c_commandsHandlers[31] {
#if 0
        &CDRomImpl::cdlSync, &CDRomImpl::cdlNop, &CDRomImpl::cdlSetLoc, &CDRomImpl::cdlPlay, // 0
        &CDRomImpl::cdlForward, &CDRomImpl::cdlBackward, &CDRomImpl::cdlReadN, &CDRomImpl::cdlStandby, // 4
        &CDRomImpl::cdlStop, &CDRomImpl::cdlPause, &CDRomImpl::cdlInit, &CDRomImpl::cdlMute, // 8
        &CDRomImpl::cdlDemute, &CDRomImpl::cdlSetFilter, &CDRomImpl::cdlSetMode, &CDRomImpl::cdlGetParam, // 12
        &CDRomImpl::cdlGetLocL, &CDRomImpl::cdlGetLocP, &CDRomImpl::cdlReadT, &CDRomImpl::cdlGetTN, // 16
        &CDRomImpl::cdlGetTD, &CDRomImpl::cdlSeekL, &CDRomImpl::cdlSeekP, &CDRomImpl::cdlSetClock,  // 20
        &CDRomImpl::cdlGetClock, &CDRomImpl::cdlTest, &CDRomImpl::cdlID, &CDRomImpl::cdlReadS, // 24
        &CDRomImpl::cdlReset, &CDRomImpl::cdlGetQ, &CDRomImpl::cdlReadTOC,                    // 28
#else
        nullptr, &CDRomImpl::cdlNop, &CDRomImpl::cdlSetLoc, nullptr,                        // 0
            nullptr, nullptr, &CDRomImpl::cdlReadN, nullptr,                                // 4
            nullptr, &CDRomImpl::cdlPause, &CDRomImpl::cdlInit, &CDRomImpl::cdlMute,        // 8
            &CDRomImpl::cdlDemute, nullptr, &CDRomImpl::cdlSetMode, nullptr,                // 12
            &CDRomImpl::cdlGetLocL, &CDRomImpl::cdlGetLocP, nullptr, &CDRomImpl::cdlGetTN,  // 16
            &CDRomImpl::cdlGetTD, &CDRomImpl::cdlSeekL, &CDRomImpl::cdlSeekP, nullptr,      // 20
            nullptr, &CDRomImpl::cdlTest, &CDRomImpl::cdlID, &CDRomImpl::cdlReadS,          // 24
            nullptr, nullptr, nullptr,                                                      // 28
#endif
    };

    static constexpr int c_commandsArgumentsCount[31] = {
        0, 0,  3, -1,  // 0
        0, 0,  0, 0,   // 4
        0, 0,  0, 0,   // 8
        0, 2,  1, 0,   // 12
        0, 0,  1, 0,   // 16
        1, 0,  0, 0,   // 20
        0, -1, 0, 0,   // 24
        0, 0,  0,      // 28
    };

    void logCDROM(const QueueElement &command) {
        auto &regs = PCSX::g_emulator->m_cpu->m_regs;

        switch (command.value) {
            case CdlTest:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] Command: CdlTest %02x\n", regs.pc,
                                    regs.cycle, command.payload[0]);
                break;
            case CdlSetLoc:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] Command: CdlSetloc %02x:%02x:%02x\n",
                                    regs.pc, regs.cycle, command.payload[0], command.payload[1], command.payload[2]);
                break;
            case CdlPlay:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] Command: CdlPlay %i\n", regs.pc,
                                    regs.cycle, command.payload[0]);
                break;
            case CdlSetFilter:
                PCSX::g_system->log(PCSX::LogClass::CDROM,
                                    "CD-Rom: %08x.%08x] Command: CdlSetfilter file: %i, channel: %i\n", regs.pc,
                                    regs.cycle, command.payload[0], command.payload[1]);
                break;
            case CdlSetMode: {
                auto mode = command.payload[0];
                std::string modeDecode = mode & 1 ? "CDDA" : "DATA";
                if (mode & 2) modeDecode += " Autopause";
                if (mode & 4) modeDecode += " Report";
                if (mode & 8) modeDecode += " SubheaderFilter";
                switch ((mode & 0x30) >> 4) {
                    case 0:
                        modeDecode += " 2048bytes";
                        break;
                    case 1:
                        modeDecode += " 2328bytes";
                        break;
                    case 2:
                        modeDecode += " 2340bytes";
                        break;
                    case 3:
                        modeDecode += " *wrong read mode*";
                        break;
                }
                if (mode & 0x40) modeDecode += " RealTimePlay";
                modeDecode += mode & 0x80 ? " @2x" : " @1x";
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] Command: CdlSetmode %02x (%s)\n",
                                    regs.pc, regs.cycle, command.payload[0], modeDecode);
            } break;
            case CdlGetTN:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] Command: CdlGetTN (returns %i)\n",
                                    regs.pc, regs.cycle, m_iso->getTN());
                break;
            case CdlGetTD: {
                auto ret = m_iso->getTD(command.payload[0]);
                PCSX::g_system->log(PCSX::LogClass::CDROM,
                                    "CD-Rom: %08x.%08x] Command: CdlGetTD %i (returns %02i:%02i:%02i)\n", regs.pc,
                                    regs.cycle, command.payload[0], ret.m, ret.s, ret.f);
            } break;
            default:
                if (command.value > c_cdCmdEnumCount) {
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] Command: CdlUnknown(0x%02X)\n",
                                        regs.pc, regs.cycle, command.value);
                } else {
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] Command: %s\n", regs.pc, regs.cycle,
                                        magic_enum::enum_names<Commands>()[command.value]);
                }
                break;
        }
    }
};

}  // namespace

PCSX::CDRom *PCSX::CDRom::factory() { return new CDRomImpl; }

void PCSX::CDRom::parseIso() {
    m_cdromId.clear();
    m_cdromLabel.clear();
    ISO9660Reader reader(m_iso);
    if (reader.failed()) return;
    IO<File> systemcnf(reader.open("SYSTEM.CNF;1"));
    std::string exename;
    m_cdromLabel = StringsHelpers::trim(reader.getLabel());

    if (!systemcnf->failed()) {
        while (!systemcnf->eof()) {
            std::string lineStorage = systemcnf->gets();
            auto line = StringsHelpers::trim(lineStorage);
            if (!StringsHelpers::startsWith(line, "BOOT")) continue;
            auto pathLoc = line.find("cdrom:");
            if (pathLoc == std::string::npos) break;
            auto paths = StringsHelpers::split(line.substr(pathLoc + 6), "/\\");
            if (paths.empty()) break;

            for (auto &path : paths) {
                exename += path;
                exename += '/';
            }
            exename.resize(exename.size() - 1);

            auto filename = paths[paths.size() - 1];
            // pattern is XXXX_YYY.ZZ;1
            if ((filename.size() == 13) && (filename[4] == '_') && (filename[8] == '.') && (filename[11] == ';') &&
                (filename[12] == '1')) {
                m_cdromId = filename.substr(0, 4);
                m_cdromId += filename.substr(5, 3);
                m_cdromId += filename.substr(9, 2);
            }

            break;
        }
    } else {
        IO<File> psxexe(reader.open("PSX.EXE;1"));
        if (!psxexe->failed()) {
            m_cdromId = "SLUS99999";
            exename = "PSX.EXE;1";
        }
    }

    g_system->printf(_("CD-ROM Label: %.32s\n"), m_cdromLabel);
    g_system->printf(_("CD-ROM ID: %.9s\n"), m_cdromId);
    g_system->printf(_("CD-ROM EXE Name: %.255s\n"), exename);
}

bool PCSX::CDRom::isLidOpen() {
    if (m_lidCloseScheduled) {
        const uint32_t cycle = g_emulator->m_cpu->m_regs.cycle;
        if (((int32_t)(m_lidCloseAtCycles - cycle)) <= 0) {
            m_lidCloseScheduled = false;
            m_lidOpen = false;
        }
    }
    return m_lidOpen;
}
