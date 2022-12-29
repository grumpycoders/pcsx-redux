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
    static std::optional<PCSX::IEC60908b::MSF> getMSF(uint8_t *msf) {
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
        m_paramFIFOSize = 0;
        m_responseFIFOIndex = 0;
        m_responseFIFOSize = 0;
        m_registerIndex = 0;
        m_busy = false;
        m_state = 0;
        m_command = 0;
        m_cause = Cause::None;
        m_currentPosition.reset();
        m_seekPosition.reset();
        m_gotAck = false;
        m_waitingAck = false;
        m_speed = Speed::Simple;
        m_speedChanged = false;
        m_status = Status::IDLE;
        m_readDelayed = 0;
        m_dataRequested = false;
        m_causeMask = 0x1f;
        m_subheaderFilter = false;
        m_realtime = false;
    }

    void interrupt() override {
        if (m_errorArgumentsCount) {
            m_errorArgumentsCount = false;
            m_cause = Cause::Error;
            m_paramFIFOSize = 0;
            m_command = 0;
            setResponse(getStatus() | 1);
            appendResponse(0x20);
            triggerIRQ();
            return;
        }
        auto handler = c_commandsHandlers[m_command];
        if (handler) {
            (this->*handler)();
        } else {
            setResponse(getStatus() | 1);
            appendResponse(0x40);
            m_cause = Cause::Error;
            m_paramFIFOSize = 0;
            m_state = 0;
            m_command = 0;
            triggerIRQ();
        }
    }

    void readInterrupt() override {
        static const std::chrono::nanoseconds c_retryDelay = 50us;
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingCDROM>();
        if ((m_status == Status::IDLE) || (m_status == Status::SEEKING)) {
            m_readDelayed = 0;
            if (debug) {
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CDRom: readInterrupt: cancelling read.\n");
            }
            return;
        }
        if (m_command != 0) {
            m_readDelayed++;
            scheduleRead(c_retryDelay);
            return;
        }
        switch (m_status) {
            case Status::READING_DATA: {
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
                readDelay -= m_readDelayed * c_retryDelay;
                m_readDelayed = 0;
                m_cause = Cause::DataReady;
                m_dataFIFOIndex = 0;
                m_dataFIFOPending = size;
                if (m_dataRequested) m_dataFIFOSize = size;
                m_currentPosition++;
                if (debug) {
                    std::string msfFormat = fmt::format("{}", m_currentPosition);
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "CDRom: readInterrupt: advancing to %s.\n", msfFormat);
                }
                setResponse(getStatus());
                triggerIRQ();
                scheduleRead(readDelay);
            } break;
            default:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "unsupported yet\n");
                PCSX::g_system->pause();
                break;
        }
    }

    void dmaInterrupt() override {
        if (HW_DMA3_CHCR & SWAP_LE32(0x01000000)) {
            HW_DMA3_CHCR &= SWAP_LE32(~0x01000000);
            DMA_INTERRUPT<3>();
        }
    }

    void schedule(uint32_t cycles) { PCSX::g_emulator->m_cpu->scheduleInterrupt(PCSX::PSXINT_CDR, cycles); }
    void schedule(std::chrono::nanoseconds delay) { schedule(PCSX::psxRegisters::durationToCycles(delay)); }

    void scheduleRead(uint32_t cycles) { PCSX::g_emulator->m_cpu->scheduleInterrupt(PCSX::PSXINT_CDREAD, cycles); }
    void scheduleRead(std::chrono::nanoseconds delay) { scheduleRead(PCSX::psxRegisters::durationToCycles(delay)); }

    void scheduleDMA(uint32_t cycles) { PCSX::g_emulator->m_cpu->scheduleInterrupt(PCSX::PSXINT_CDRDMA, cycles); }
    void scheduleDMA(std::chrono::nanoseconds delay) { scheduleDMA(PCSX::psxRegisters::durationToCycles(delay)); }

    void triggerIRQ() {
        assert(m_cause != Cause::None);
        assert(!m_waitingAck);
        uint8_t bit = 1 << (static_cast<uint8_t>(m_cause) - 1);
        if (m_causeMask & bit) {
            m_gotAck = false;
            psxHu32ref(0x1070) |= SWAP_LE32(uint32_t(4));
        } else {
            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                    .get<PCSX::Emulator::DebugSettings::LoggingCDROM>()) {
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: wanted to trigger IRQ but cause %d is masked...\n",
                                    static_cast<uint8_t>(m_cause));
            }
        }
    }

    void clearIRQ() { psxHu32ref(0x1070) &= SWAP_LE32(~uint32_t(4)); }

    void setResponse(std::string_view response) {
        std::copy(response.begin(), response.end(), m_responseFIFO);
        m_responseFIFOSize = response.size();
        m_responseFIFOIndex = 0;
    }

    void setResponse(uint8_t response) {
        m_responseFIFO[0] = response;
        m_responseFIFOSize = 1;
        m_responseFIFOIndex = 0;
    }

    void appendResponse(std::string_view response) {
        std::copy(response.begin(), response.end(), m_responseFIFO + m_responseFIFOSize);
        m_responseFIFOSize += response.size();
    }

    void appendResponse(uint8_t response) { m_responseFIFO[m_responseFIFOSize++] = response; }

    uint8_t getStatus(bool resetLid = false) {
        bool lidOpen = isLidOpen();
        if (resetLid && !lidOpen) m_wasLidOpened = false;
        uint8_t v1 = m_motorOn && !lidOpen ? 0x02 : 0;
        uint8_t v4 = m_wasLidOpened ? 0x10 : 0;
        uint8_t v567 = 0;
        switch (m_status) {
            case Status::READING_DATA:
                v567 = 0x20;
                break;
            case Status::SEEKING:
                v567 = 0x40;
                break;
            case Status::PLAYING_CDDA:
                v567 = 0x80;
                break;
        }
        return v1 | v4 | v567;
    }

    uint8_t read0() override {
        uint8_t v01 = m_registerIndex & 3;
        uint8_t adpcmPlaying = 0;
        uint8_t v3 = m_paramFIFOSize == 0 ? 0x08 : 0;
        uint8_t v4 = paramFIFOAvailable() ? 0x10 : 0;
        uint8_t v5 = responseFIFOHasData() ? 0x20 : 0;
        uint8_t v6 = m_dataFIFOSize != m_dataFIFOIndex ? 0x40 : 0;
        uint8_t v7 = m_busy ? 0x80 : 0;

        uint8_t ret = v01 | adpcmPlaying | v3 | v4 | v5 | v6 | v7;

        return ret;
    }

    uint8_t read1() override {
        uint8_t ret = 0;
        if (!responseFIFOHasData()) {
            ret = 0;
        } else {
            ret = m_responseFIFO[m_responseFIFOIndex++];
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

        return ret;
    }

    uint8_t read3() override {
        switch (m_registerIndex & 1) {
            case 0: {
                return m_causeMask | 0xe0;
            } break;
            case 1: {
                // cause
                // TODO: add bit 4
                uint8_t ret = magic_enum::enum_integer(m_cause) | 0xe0;
                return ret;
            } break;
        }
        // should not be reachable
        return 0;
    }

    void write0(uint8_t value) override { m_registerIndex = value & 3; }

    void write1(uint8_t value) override {
        switch (m_registerIndex) {
            case 0: {
                if (m_busy) {
                    // The CD-Rom controller is already executing a command.
                    // This basically results in undefined behavior. We'll still
                    // have to address this, as some games will do it anyway.
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: command while controller is busy\n");
                    PCSX::g_system->pause();
                }
                startCommand(value);
            } break;
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
        switch (m_registerIndex) {
            case 0: {
                if (paramFIFOAvailable()) m_paramFIFO[m_paramFIFOSize++] = value;
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
                    m_cause = Cause::None;
                    if (m_waitingAck) {
                        m_waitingAck = false;
                        schedule(350us);
                    }
                    m_gotAck = true;
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
                    m_paramFIFOSize = 0;
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

    void startCommand(uint8_t command) {
        m_state = 0;
        m_command = command;
        if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                .get<PCSX::Emulator::DebugSettings::LoggingCDROM>()) {
            logCDROM(command);
        }

        if (command > 30) {
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: Unknown CD-Rom command\n");
            PCSX::g_system->pause();
            return;
        }

        auto count = c_commandsArgumentsCount[command];
        if (count >= 0) {
            if (m_paramFIFOSize != count) {
                m_errorArgumentsCount = true;
                schedule(750us);
                return;
            }
        }

        auto handler = c_commandsHandlers[command];

        std::chrono::nanoseconds initialDelay = c_commandsInitialDelay[command];

        if (handler == nullptr) {
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: Unknown CD-Rom command %i\n", m_command);
            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                    .get<PCSX::Emulator::DebugSettings::LoggingCDROM>()) {
                PCSX::g_system->pause();
            }
            initialDelay = 750us;
        }

        m_state = 1;
        schedule(initialDelay);
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
    void cdlNop() {
        setResponse(getStatus(true));
        m_cause = Cause::Acknowledge;
        m_command = 0;
        triggerIRQ();
    }

    // Command 2.
    void cdlSetLoc() {
        // TODO: probably should error out if no disc or
        // lid open?
        // What happens when issued during Read / Play?
        auto maybeMSF = getMSF(m_paramFIFO);
        if (maybeMSF.has_value()) {
            setResponse(getStatus());
            m_cause = Cause::Acknowledge;
            m_seekPosition = maybeMSF.value();
        } else {
            setResponse(getStatus() | 1);
            appendResponse(0x10);
            m_cause = Cause::Error;
        }
        m_paramFIFOSize = 0;
        m_command = 0;
        triggerIRQ();
    }

    // Command 6.
    void cdlReadN() {
        switch (m_state) {
            case 1: {
                auto seekDelay = computeSeekDelay(m_currentPosition, m_seekPosition, SeekType::DATA);
                if (m_speedChanged) {
                    m_speedChanged = false;
                    seekDelay += 650ms;
                }
                schedule(seekDelay);
                m_cause = Cause::Acknowledge;
                m_state = 2;
                setResponse(getStatus());
                m_status = Status::SEEKING;
                triggerIRQ();
            } break;
            case 2:
                m_status = Status::IDLE;
                if (!m_gotAck) {
                    m_waitingAck = true;
                    m_state = 3;
                    break;
                }
                [[fallthrough]];
            case 3: {
                m_currentPosition = m_seekPosition;
                unsigned track = m_iso->getTrack(m_seekPosition);
                if (m_iso->getTrackType(track) == PCSX::CDRIso::TrackType::CDDA) {
                    m_cause = Cause::Error;
                    setResponse(getStatus() | 4);
                    appendResponse(4);
                    triggerIRQ();
                } else if (track == 0) {
                    m_cause = Cause::Error;
                    setResponse(getStatus() | 4);
                    appendResponse(0x10);
                    triggerIRQ();
                } else {
                    m_status = Status::READING_DATA;
                    scheduleRead(computeReadDelay());
                }
                m_command = 0;
            } break;
        }
    }

    // Command 9.
    void cdlPause() {
        switch (m_state) {
            case 1: {
                if (m_status == Status::IDLE) {
                    schedule(200us);
                } else {
                    schedule(m_speed == Speed::Simple ? 70ms : 35ms);
                }
                m_cause = Cause::Acknowledge;
                m_state = 2;
                setResponse(getStatus());
                triggerIRQ();
            } break;
            case 2:
                m_status = Status::IDLE;
                m_invalidLocL = true;
                if (!m_gotAck) {
                    m_waitingAck = true;
                    m_state = 3;
                    break;
                }
                [[fallthrough]];
            case 3:
                m_cause = Cause::Complete;
                m_command = 0;
                setResponse(getStatus());
                triggerIRQ();
                break;
        }
    }

    // Command 10.
    void cdlInit() {
        switch (m_state) {
            case 1:
                m_cause = Cause::Acknowledge;
                m_state = 2;
                setResponse(getStatus());
                triggerIRQ();
                schedule(120ms);
                break;
            case 2:
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
                m_status = Status::IDLE;
                m_causeMask = 0x1f;
                memset(m_lastLocP, 0, sizeof(m_lastLocP));
                if (!m_gotAck) {
                    m_waitingAck = true;
                    m_state = 3;
                    break;
                }
                [[fallthrough]];
            case 3:
                m_cause = Cause::Complete;
                m_command = 0;
                setResponse(getStatus());
                triggerIRQ();
                break;
        }
    }

    // Command 11
    void cdlMute() {
        // TODO: probably should error out if no disc or
        // lid open?
        setResponse(getStatus());
        m_cause = Cause::Acknowledge;
        m_command = 0;
        PCSX::g_system->log(PCSX::LogClass::CDROM, "CDRom: Mute - not yet implemented.\n");
        triggerIRQ();
    }

    // Command 12
    void cdlDemute() {
        // TODO: probably should error out if no disc or
        // lid open?
        setResponse(getStatus());
        m_cause = Cause::Acknowledge;
        m_command = 0;
        PCSX::g_system->log(PCSX::LogClass::CDROM, "CDRom: Demute - not yet implemented.\n");
        triggerIRQ();
    }

    // Command 14
    void cdlSetMode() {
        uint8_t mode = m_paramFIFO[0];
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
        setResponse(getStatus());
        m_cause = Cause::Acknowledge;
        m_paramFIFOSize = 0;
        m_command = 0;
        triggerIRQ();
    }

    // Command 16.
    void cdlGetLocL() {
        // TODO: probably should error out if no disc or
        // lid open?
        if (m_invalidLocL) {
            setResponse(getStatus() | 1);
            appendResponse(0x80);
            m_cause = Cause::Error;
        } else {
            setResponse(std::string_view((char *)m_lastLocL, sizeof(m_lastLocL)));
            m_cause = Cause::Acknowledge;
        }
        m_command = 0;
        triggerIRQ();
    }

    // Command 17.
    void cdlGetLocP() {
        // TODO: probably should error out if no disc or
        // lid open?
        m_iso->getLocP(m_currentPosition, m_lastLocP);
        setResponse(std::string_view((char *)m_lastLocP, sizeof(m_lastLocP)));
        m_cause = Cause::Acknowledge;
        m_command = 0;
        triggerIRQ();
    }

    // Command 19.
    void cdlGetTN() {
        // TODO: probably should error out if no disc or
        // lid open?
        setResponse(getStatus());
        appendResponse(1);
        appendResponse(PCSX::IEC60908b::itob(m_iso->getTN()));
        m_cause = Cause::Acknowledge;
        m_command = 0;
        triggerIRQ();
    }

    // Command 20.
    void cdlGetTD() {
        // TODO: probably should error out if no disc or
        // lid open?
        auto track = PCSX::IEC60908b::btoi(m_paramFIFO[0]);
        if (!isValidBCD(m_paramFIFO[0]) || (track > m_iso->getTN())) {
            setResponse(getStatus() | 1);
            appendResponse(0x10);
            m_cause = Cause::Error;
        } else {
            setResponse(getStatus());
            auto td = m_iso->getTD(track);
            appendResponse(PCSX::IEC60908b::itob(td.m));
            appendResponse(PCSX::IEC60908b::itob(td.s));
            m_cause = Cause::Acknowledge;
        }
        m_paramFIFOSize = 0;
        m_command = 0;
        triggerIRQ();
    }

    // Command 21.
    void cdlSeekL() {
        switch (m_state) {
            case 1:
                m_cause = Cause::Acknowledge;
                m_state = 2;
                setResponse(getStatus());
                triggerIRQ();
                auto seekDelay = computeSeekDelay(m_currentPosition, m_seekPosition, SeekType::DATA);
                if (m_speedChanged) {
                    m_speedChanged = false;
                    seekDelay += 650ms;
                }
                m_status = Status::SEEKING;
                schedule(seekDelay);
                break;
            case 2:
                m_status = Status::IDLE;
                if (!m_gotAck) {
                    m_waitingAck = true;
                    m_state = 3;
                    break;
                }
                [[fallthrough]];
            case 3: {
                m_currentPosition = m_seekPosition;
                unsigned track = m_iso->getTrack(m_seekPosition);
                if (m_iso->getTrackType(track) == PCSX::CDRIso::TrackType::CDDA) {
                    m_cause = Cause::Error;
                    setResponse(getStatus() | 4);
                    appendResponse(4);
                } else if (track == 0) {
                    m_cause = Cause::Error;
                    setResponse(getStatus() | 4);
                    appendResponse(0x10);
                } else {
                    m_cause = Cause::Complete;
                    setResponse(getStatus());
                }
                m_invalidLocL = true;
                m_command = 0;
                triggerIRQ();
            } break;
        }
    }

    // Command 22.
    void cdlSeekP() {
        switch (m_state) {
            case 1:
                m_cause = Cause::Acknowledge;
                m_state = 2;
                setResponse(getStatus());
                triggerIRQ();
                auto seekDelay = computeSeekDelay(m_currentPosition, m_seekPosition, SeekType::CDDA);
                if (m_speedChanged) {
                    m_speedChanged = false;
                    seekDelay += 650ms;
                }
                m_status = Status::SEEKING;
                schedule(seekDelay);
                break;
            case 2:
                m_status = Status::IDLE;
                if (!m_gotAck) {
                    m_waitingAck = true;
                    m_state = 3;
                    break;
                }
                [[fallthrough]];
            case 3: {
                MSF fudge = m_seekPosition - MSF{m_seekPosition.toLBA() / 32768};
                m_currentPosition = fudge;
                if (m_iso->getTrack(m_seekPosition) == 0) {
                    m_cause = Cause::Error;
                    setResponse(getStatus() | 4);
                    appendResponse(0x10);
                } else {
                    m_cause = Cause::Complete;
                    setResponse(getStatus());
                }
                m_invalidLocL = true;
                m_command = 0;
                triggerIRQ();
            } break;
        }
    }

    // Command 25.
    void cdlTest() {
        static constexpr uint8_t c_test20[] = {0x94, 0x09, 0x19, 0xc0};
        if (m_paramFIFOSize == 0) {
            m_cause = Cause::Error;
            m_paramFIFOSize = 0;
            m_command = 0;
            setResponse(getStatus() | 1);
            appendResponse(0x20);
            triggerIRQ();
            return;
        }

        switch (m_paramFIFO[0]) {
            case 0x20:
                if (m_paramFIFOSize == 1) {
                    setResponse(std::string_view((const char *)c_test20, sizeof(c_test20)));
                    m_cause = Cause::Acknowledge;
                } else {
                    setResponse(getStatus() | 1);
                    appendResponse(0x20);
                    m_cause = Cause::Error;
                }
                break;
            default:
                setResponse(getStatus() | 1);
                appendResponse(0x10);
                m_cause = Cause::Error;
                break;
        }
        m_paramFIFOSize = 0;
        m_command = 0;
        triggerIRQ();
    }

    // Command 26.
    void cdlID() {
        switch (m_state) {
            case 1:
                m_cause = Cause::Acknowledge;
                m_state = 2;
                setResponse(getStatus());
                triggerIRQ();
                schedule(5ms);
                break;
            case 2:
                if (!m_gotAck) {
                    m_waitingAck = true;
                    m_state = 3;
                    break;
                }
                [[fallthrough]];
            case 3: {
                // Adjust this response for various types of discs and situations.
                m_cause = Cause::Complete;
                setResponse(getStatus());
                appendResponse("\x00\x20\x00PCSX");
                m_command = 0;
                triggerIRQ();
            } break;
        }
    }

    // Command 27.
    void cdlReadS() {
        switch (m_state) {
            case 1: {
                auto seekDelay = computeSeekDelay(m_currentPosition, m_seekPosition, SeekType::DATA);
                if (m_speedChanged) {
                    m_speedChanged = false;
                    seekDelay += 650ms;
                }
                schedule(seekDelay);
                m_cause = Cause::Acknowledge;
                m_state = 2;
                setResponse(getStatus());
                m_status = Status::SEEKING;
                triggerIRQ();
            } break;
            case 2:
                m_status = Status::IDLE;
                if (!m_gotAck) {
                    m_waitingAck = true;
                    m_state = 3;
                    break;
                }
                [[fallthrough]];
            case 3: {
                m_currentPosition = m_seekPosition;
                unsigned track = m_iso->getTrack(m_seekPosition);
                if (m_iso->getTrackType(track) == PCSX::CDRIso::TrackType::CDDA) {
                    m_cause = Cause::Error;
                    setResponse(getStatus() | 4);
                    appendResponse(4);
                    triggerIRQ();
                } else if (track == 0) {
                    m_cause = Cause::Error;
                    setResponse(getStatus() | 4);
                    appendResponse(0x10);
                    triggerIRQ();
                } else {
                    m_status = Status::READING_DATA;
                    scheduleRead(computeReadDelay());
                }
                m_command = 0;
            } break;
        }
    }

    typedef void (CDRomImpl::*CommandType)();

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

    static constexpr std::chrono::nanoseconds c_commandsInitialDelay[31] = {
        0ns,   750us, 1ms,   0ns,    // 0
        0ns,   0ns,   1ms,   0ns,    // 4
        0ns,   1ms,   2ms,   750us,  // 8
        750us, 0ns,   750us, 0ns,    // 12
        750us, 750us, 0ns,   2ms,    // 16
        750us, 1ms,   1ms,   0ns,    // 20
        0ns,   750us, 5ms,   1ms,    // 24
        0ns,   0ns,   0ns,           // 28
    };

    void logCDROM(uint8_t command) {
        uint32_t pc = PCSX::g_emulator->m_cpu->m_regs.pc;

        switch (command & 0xff) {
            case CdlTest:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x] Command: CdlTest %02x\n", pc, m_paramFIFO[0]);
                break;
            case CdlSetLoc:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x] Command: CdlSetloc %02x:%02x:%02x\n", pc,
                                    m_paramFIFO[0], m_paramFIFO[1], m_paramFIFO[2]);
                break;
            case CdlPlay:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x] Command: CdlPlay %i\n", pc, m_paramFIFO[0]);
                break;
            case CdlSetFilter:
                PCSX::g_system->log(PCSX::LogClass::CDROM,
                                    "CD-Rom: %08x] Command: CdlSetfilter file: %i, channel: %i\n", pc, m_paramFIFO[0],
                                    m_paramFIFO[1]);
                break;
            case CdlSetMode: {
                auto mode = m_paramFIFO[0];
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
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x] Command: CdlSetmode %02x (%s)\n", pc,
                                    m_paramFIFO[0], modeDecode);
            } break;
            case CdlGetTN:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x] Command: CdlGetTN (returns %i)\n", pc,
                                    m_iso->getTN());
                break;
            case CdlGetTD: {
                auto ret = m_iso->getTD(m_paramFIFO[0]);
                PCSX::g_system->log(PCSX::LogClass::CDROM,
                                    "CD-Rom: %08x] Command: CdlGetTD %i (returns %02i:%02i:%02i)\n", pc, m_paramFIFO[0],
                                    ret.m, ret.s, ret.f);
            } break;
            default:
                if ((command & 0xff) > c_cdCmdEnumCount) {
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x] Command: CdlUnknown(0x%02X)\n", pc,
                                        command & 0xff);
                } else {
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x] Command: %s\n", pc,
                                        magic_enum::enum_names<Commands>()[command & 0xff]);
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
