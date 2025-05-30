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

#include <magic_enum_all.hpp>
#include <string_view>

#include "cdrom/iso9660-reader.h"
#include "core/debug.h"
#include "core/psxdma.h"
#include "core/psxemulator.h"
#include "spu/interface.h"
#include "support/strings-helpers.h"
#include "supportpsx/iec-60908b.h"

namespace {

using namespace std::literals;

// The buffer/decoder chip the PSX CPU will talk to is the CXD1199, which
// datasheet can be found at https://archive.org/details/cxd-1199

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

    std::string_view commandName(uint8_t command) {
        if (command > c_cdCmdEnumCount) {
            return "Unknown";
        } else {
            return magic_enum::enum_names<Commands>()[command];
        }
    }

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

    uint32_t rand() {
        m_seed *= 14726776315600504853ull;
        return m_seed >> 9;
    }

    void reset() override {
        m_seed = 9223521712174600777ull;
        m_dataFIFOIndex = 0;
        m_dataFIFOSize = 0;
        m_registerAddress = 0;
        m_currentPosition.reset();
        m_seekPosition.reset();
        m_speed = Speed::Simple;
        m_speedChanged = false;
        m_status = Status::Idle;
        m_dataRequested = false;
        m_interruptCauseMask = 0x1f;
        m_subheaderFilter = false;
        m_realtime = false;
        m_commandFifo.clear();
        m_commandExecuting.clear();
        m_responseFifo[0].clear();
        m_responseFifo[1].clear();
        m_readingState = ReadingState::None;
    }

    void fifoScheduledCallback() override {
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingCDROM>();
        if (m_responseFifo[0].valueEmpty() && !m_responseFifo[1].empty()) {
            m_responseFifo[0] = m_responseFifo[1];
            m_responseFifo[1].clear();
            PCSX::g_emulator->m_mem->setIRQ(4);
            if (debug) {
                PCSX::g_system->log(PCSX::LogClass::CDROM,
                                    "CD-Rom: response fifo sliding one response, triggering IRQ.\n");
            }
        }
        maybeStartCommand();
    }

    void commandsScheduledCallback() override {
        auto command = m_commandExecuting.value;
        auto handler = c_commandsHandlers[command];
        (this->*handler)(m_commandExecuting, false);
    }

    void readScheduledCallback() override {
        static const std::chrono::nanoseconds c_retryDelay = 50us;
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingCDROM>();
        if (m_readingState == ReadingState::Seeking) {
            auto seekDelay = computeSeekDelay(m_currentPosition, m_seekPosition, SeekType::DATA, true);
            m_status = Status::Seeking;
            if (m_speedChanged) {
                m_speedChanged = false;
                seekDelay += 650ms;
            }
            m_currentPosition = m_seekPosition;
            scheduleRead(seekDelay + computeReadDelay());
            m_readingState = ReadingState::Reading;
            return;
        } else if (m_readingState == ReadingState::Reading) {
            m_readingState = ReadingState::None;
            m_status = Status::ReadingData;
        } else if ((m_status == Status::Idle) || (m_status == Status::Seeking)) {
            m_readingType = ReadingType::None;
            if (debug) {
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: readInterrupt: cancelling read.\n");
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
                    bool passToData = true;
                    if ((buffer[3] == 2) && m_realtime) {
                        PCSX::IEC60908b::SubHeaders subHeaders;
                        subHeaders.fromBuffer(buffer + 4);
                        if (subHeaders.isRealTime() && subHeaders.isAudio()) {
                            passToData = false;
                            if (m_subheaderFilter) {
                                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: filtering not supported yet.\n");
                                PCSX::g_system->pause();
                            }
                            // TODO: play XA sector.
                        }
                    }
                    if (passToData) {
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
                    }
                    auto readDelay = computeReadDelay();
                    m_dataFIFOIndex = 0;
                    m_dataFIFOPending = size;
                    if (m_dataRequested) m_dataFIFOSize = size;
                    m_currentPosition++;
                    if (debug) {
                        std::string msfFormat = fmt::format("{}", m_currentPosition);
                        PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: readInterrupt: advancing to %s.\n",
                                            msfFormat);
                    }
                    if (passToData) {
                        QueueElement ready;
                        ready.pushPayloadData(getStatus());
                        maybeTriggerIRQ(Cause::DataReady, ready);
                    }
                    scheduleRead(readDelay);
                }
            } break;
            default:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "unsupported yet\n");
                PCSX::g_system->pause();
                break;
        }
    }

    void scheduledDmaCallback() override {
        auto &mem = PCSX::g_emulator->m_mem;
        if (mem->isDMABusy<3>()) {
            mem->clearDMABusy<3>();
            mem->dmaInterrupt<3>();
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

    bool maybeEnqueueResponse(QueueElement &response) {
        if (m_responseFifo[0].valueEmpty() && !m_responseFifo[1].empty()) {
            m_responseFifo[0] = m_responseFifo[1];
            m_responseFifo[1] = response;
            return true;
        }
        if (m_responseFifo[0].empty()) {
            m_responseFifo[0] = response;
            return true;
        } else if (m_responseFifo[1].empty()) {
            m_responseFifo[1] = response;
        }
        return false;
    }

    void maybeTriggerIRQ(Cause cause, QueueElement &element) {
        uint8_t causeValue = static_cast<uint8_t>(cause);
        uint8_t bit = 1 << (causeValue - 1);
        if (m_interruptCauseMask & bit) {
            element.setValue(cause);
            bool actuallyTriggering = false;
            if (maybeEnqueueResponse(element)) {
                PCSX::g_emulator->m_mem->setIRQ(4);
                actuallyTriggering = true;
            }
            const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                                   .get<PCSX::Emulator::DebugSettings::LoggingCDROM>();
            if (debug) {
                auto &regs = PCSX::g_emulator->m_cpu->m_regs;
                if (actuallyTriggering) {
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] triggering IRQ with cause %d\n",
                                        regs.pc, regs.cycle, causeValue);
                } else {
                    PCSX::g_system->log(PCSX::LogClass::CDROM,
                                        "CD-Rom: %08x.%08x] wanted to trigger IRQ with cause %d, but queue is full\n",
                                        regs.pc, regs.cycle, causeValue);
                }
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
        // HSTS (host status) register
        /*
          bit 7: BUSYSTS (busy status)
                 This is high when the host writes a command into the command register and low when the sub
                 CPU sets the CLRBUSY bit (bit 6) of the CLRCTL register.
         */
        uint8_t v7 = m_commandFifo.hasValue ? 0x80 : 0;
        /*
          bit 6: DRQSTS (data request status)
                 Indicates to the host that the buffer memory data transfer request status is established. When
                 transferring data in the I/O mode, the host should confirm that this bit is high before accessing the
                 WRDATA or RDDATA register.
         */
        uint8_t v6 = m_dataFIFOSize != m_dataFIFOIndex ? 0x40 : 0;
        /*
          bit 5: RSLRRDY (result read ready)
                 The result register is not empty when this bit is high. At this time, the host can read the result
                 register.
         */
        uint8_t v5 = !m_responseFifo[0].isPayloadAtEnd() ? 0x20 : 0;
        /*
          bit 4: PRMWRDY (parameter write ready)
                 The PARAMETER register is not full when this bit is high. At this time, the host writes data into the
                 PARAMETER register.
         */
        uint8_t v4 = !m_commandFifo.isPayloadFull() ? 0x10 : 0;
        /*
          bit 3: PRMEMPT (parameter empty)
                 The PARAMETER register is empty when this bit is high.
         */
        uint8_t v3 = m_commandFifo.isPayloadEmpty() ? 0x08 : 0;
        /*
          bit 2: ADPBUSY (ADPCM busy)
                 This bit is set high for ADPCM decoding.
         */
        uint8_t v2 = 0; /* adpcmPlaying */
        /*
          bits 1, 0: RA1, 0
                 The values of the RA1 and 0 bits for the ADDRESS register can be read from these bits.
         */
        uint8_t v01 = m_registerAddress & 3;

        uint8_t ret = v01 | v2 | v3 | v4 | v5 | v6 | v7;
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] r0: %02x\n", regs.pc, regs.cycle, ret);
        }

        return ret;
    }

    uint8_t read1() override {
        // RESULT
        uint8_t ret = m_responseFifo[0].readPayloadByte();
        maybeScheduleNextCommand();

        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] r1: %02x\n", regs.pc, regs.cycle, ret);
        }
        return ret;
    }

    uint8_t read2() override {
        // RD DATA
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
        /*
         * bit 4: BFWRDY (buffer write ready)
         *        The BFWRDY status is established if there is area where writing is possible in the buffer of 1 sector
         *        or more for sound map playback. It is established in any of the following cases:
         *        (1) When the host has set the SMEN bit (bit 5) of the HCHPCTL register high
         *        (2) When there is sound map data area of 1 sector or more in the buffer memory (when the buffer
         *            is not full) after the sound map data equivalent to 1 sector from the host has been written into
         *            the buffer memory
         *        (3) When an area for writing the sound map data has been created in the buffer memory by the
         *            completion of the sound map ADPCM decoding of one sector
         * bit 3: BFEMPT (buffer empty)
         *        The BFEMPT status is established when there is no more sector data in the buffer memory upon
         *        completion of the sound map ADPCM decoding of one sector for sound map playback.
         * bits 2 to 0: INTSTS#2 to 0
         *        The values of these bits are those of the corresponding bits for the sub CPU HIFCTL register.
         */

        uint8_t ret = 0;
        switch (m_registerAddress & 1) {
            case 0: {
                // HINT MSK (host interrupt mask)
                ret = m_interruptCauseMask;
            } break;
            case 1: {
                // HINT STS (host interrupt status)
                ret = m_responseFifo[0].getValue();
            } break;
        }
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] r3.%i: %02x\n", regs.pc, regs.cycle,
                                m_registerAddress & 1, ret);
        }
        return ret | 0xe0;
    }

    void write0(uint8_t value) override {
        // ADDRESS
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] w0: %02x\n", regs.pc, regs.cycle, value);
        }
        m_registerAddress = value & 3;
    }

    void write1(uint8_t value) override {
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] w1.%i: %02x\n", regs.pc, regs.cycle,
                                m_registerAddress, value);
        }
        switch (m_registerAddress) {
            case 0:
                // COMMAND
                m_commandFifo.value = value;
                if (!m_commandFifo.hasValue) {
                    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                            .get<PCSX::Emulator::DebugSettings::LoggingCDROM>()) {
                        logCDROM(m_commandFifo);
                    }
                    scheduleFifo(797us);
                }
                m_commandFifo.hasValue = true;
                break;
            case 1: {
                // WR DATA
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w1:1 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 2: {
                /*
                CI (coding information)
                This sets the coding information for sound map playback. The bit allocation is the same as that for the
                coding information bytes of the sub header.
                  bits 7, 5, 3, 1: Reserved
                  bit 6: EMPHASIS
                      High: Emphasis ON
                      Low : Emphasis OFF
                  bit 4: BITLNGTH
                      High: 8 bits
                      Low : 4 bits
                  bit 2: FS
                      High: 18.9 kHz
                      Low : 37.8 kHz
                  bit 0: S/M (stereo/mono)
                      High: Stereo
                      Low : Mono
                */
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w1:2 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 3: {
                // ATV2 Right-to-Right
                m_atv[2] = value;
            } break;
        }
    }

    void write2(uint8_t value) override {
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] w2.%i: %02x\n", regs.pc, regs.cycle,
                                m_registerAddress, value);
        }
        switch (m_registerAddress) {
            case 0: {
                // PARAMETER
                m_commandFifo.pushPayloadData(value);
            } break;
            case 1: {
                // HINT MSK (host interrupt mask)
                m_interruptCauseMask = value;
            } break;
            case 2: {
                // ATV0 Left-to-Left
                m_atv[0] = value;
            } break;
            case 3: {
                // ATV3 Right-to-Left
                m_atv[3] = value;
            } break;
        }
    }

    void write3(uint8_t value) override {
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingHWCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] w3.%i: %02x\n", regs.pc, regs.cycle,
                                m_registerAddress, value);
        }
        switch (m_registerAddress) {
            case 0: {
                // clang-format off
                /*
                HCHPCTL (host chip control) register
                  bit 7: BFRD (buffer read)
                         The transfer of (drive) data from the buffer memory to the host is started by setting this bit high.
                         The bit is automatically set low upon completion of the transfer.
                  bit 6: BFWR (buffer write)
                         The transfer of data from the host to the buffer memory is started by setting this bit high. The bit is
                         automatically set low upon completion of the transfer.
                  bit 5: SMEN (sound map En)
                         This is set high to perform sound map ADPCM playback.
                */
                // clang-format on
                bool bfrd = value & 0x80;
                bool bfwr = value & 0x40;
                bool smen = value & 0x20;
                if (bfrd) {
                    m_dataRequested = true;
                    m_dataFIFOSize = m_dataFIFOPending;
                } else {
                    m_dataRequested = false;
                    m_dataFIFOSize = 0;
                    m_dataFIFOIndex = 0;
                }
                m_soundMapEnabled = smen;
            } break;
            case 1: {
                // clang-format off
                /*
                HCLRCTL (host clear control)
                When each bit of this register is set high, the chip, status, register, interrupt status and interrupt request to
                the host generated by the status are cleared.
                  bit 7: CHPRST (chip reset)
                         The inside of the IC is initialized by setting this bit high. The bit is automatically set low upon
                         completion of the initialization of the IC. There is therefore no need for the host to reset low. When
                         the inside of the IC is initialized by setting bit high, the XHRS pin is set low.
                  bit 6: CLRPRM (clear parameter)
                         The parameter register is cleared by setting this bit high. The bit is automatically set low upon
                         completion of the clearing for the parameter register. There is therefore no need for the host to
                         reset low.
                  bit 5: SMADPCLR (sound map ADPCM clear)
                         This bit is set high to terminate sound map ADPCM decoding forcibly.
                         (1) When this bit has been set high for sound map ADPCM playback (when both SMEN and
                             ADPBSY (HSTS register bit 2) are high):
                             • ADPCM decoding during playback is suspended. (Noise may be generated).
                             • The sound map and buffer management circuits in the IC are cleared, making the buffer
                               empty. The BFEMPT interrupt status is established.
                             (Note) Set the SMEN bit low at the same time as this bit is set high.
                         (2) Setting this bit high when the sound map ADPCM playback is not being performed has no
                             effect whatsoever
                  bit 4: CLRBFWRDY (clear buffer write ready interrupt)
                  bit 3: CLRBFEMPT (clear buffer write empty interrupt)
                  bits 2 to 0: CLRINT#2 to 0 (clear interrupt #2 to 0)
                      bit 4 clears the corresponding interrupt status.
                */
                // clang-format on
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
                    if (debug) {
                        PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: acked %02x (was %i)\n", value,
                                            m_responseFifo[0].value);
                    }
                    m_responseFifo[0].valueRead = true;
                    maybeScheduleNextCommand();
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
                // ATV1 Left-to-Right
                m_atv[1] = value;
            } break;
            case 3: {
                // clang-format off
                /*
                ADPCTL (ADPCM control) register
                  bit 5: CHNGATV (change ATV register)
                         The host sets this bit high after the changes of the ATV 3 to 0 registers have been completed. The
                         attenuator value in the IC is switched for the first time. There is no need for the host to set this bit
                         low. The bit used to set the ATV3 to 0 registers of the host and to synchronize the IC audio
                         playback.
                  bit 0: ADPMUTE (ADPCM mute)
                         Set high to mute the ADPCM sound for ADPCM decoding.
                  bits 7, 6, 4 to 1: Reserved
                */
                // clang-format on
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: w3:3 not available yet\n");
            } break;
        }
    }

    void dma(uint32_t madr, uint32_t bcr, uint32_t chcr) override {
        uint32_t size = bcr & 0xffff;
        size *= 4;
        if (size == 0) size = 0xffffffff;
        size = std::min(m_dataFIFOSize - m_dataFIFOIndex, size);
        PCSX::IO<PCSX::File> memFile = PCSX::g_emulator->m_mem->getMemoryAsFile();
        memFile->wSeek(madr);
        memFile->write(m_dataFIFO + m_dataFIFOIndex, size);
        m_dataFIFOIndex += size;
        PCSX::g_emulator->m_cpu->Clear(madr, size / 4);
        PCSX::g_emulator->m_mem->msanDmaWrite(madr, size);
        if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                .get<PCSX::Emulator::DebugSettings::Debug>()) {
            PCSX::g_emulator->m_debug->checkDMAwrite(3, madr, size);
        }
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingCDROM>();
        if (debug) {
            auto &regs = PCSX::g_emulator->m_cpu->m_regs;
            PCSX::g_system->log(PCSX::LogClass::CDROM,
                                "CD-Rom: %08x.%08x] DMA transfer requested to address %08x, size %08x\n", regs.pc,
                                regs.cycle, madr, size);
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
        if (m_commandFifo.empty()) return;
        auto command = m_commandFifo.value;
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingCDROM>();
        if (!m_responseFifo[0].valueRead || !m_responseFifo[1].empty()) {
            if (debug) {
                PCSX::g_system->log(PCSX::LogClass::CDROM,
                                    "CD-Rom: command %s (%i) pending, but response fifo full; won't start.\n",
                                    commandName(command), command);
            }
            return;
        }
        if (debug) {
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: Starting command %s (%i)\n", commandName(command),
                                command);
        }
        static constexpr unsigned c_commandMax = sizeof(c_commandsArgumentsCount) / sizeof(c_commandsArgumentsCount[0]);
        if (command >= c_commandMax) {
            maybeEnqueueError(1, 0x40);
            maybeScheduleNextCommand();
            m_commandFifo.clear();
            return;
        }
        auto expectedCount = c_commandsArgumentsCount[command];
        if ((expectedCount >= 0) && (expectedCount != m_commandFifo.payloadSize)) {
            maybeEnqueueError(1, 0x20);
            maybeScheduleNextCommand();
            m_commandFifo.clear();
            return;
        }
        auto handler = c_commandsHandlers[command];
        if (handler) {
            if ((this->*handler)(m_commandFifo, true)) m_commandExecuting = m_commandFifo;
        } else {
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: Unsupported command %i (%s).\n", command,
                                commandName(command));
            PCSX::g_system->pause();
            maybeEnqueueError(1, 0x40);
            maybeScheduleNextCommand();
        }
        m_commandFifo.clear();
    }

    void maybeScheduleNextCommand() {
        const bool debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                               .get<PCSX::Emulator::DebugSettings::LoggingCDROM>();
        if (!responseFifoFull()) {
            if (debug) {
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: Scheduling queued next command to run.\n");
            }
            scheduleFifo(797us);
        } else if (debug) {
            PCSX::g_system->log(PCSX::LogClass::CDROM,
                                "CD-Rom: Won't schedule next command to run as response fifo is full.\n");
        }
    }

    enum class SeekType { DATA, CDDA };

    std::chrono::nanoseconds computeSeekDelay(MSF from, MSF to, SeekType seekType, bool forReading = false) {
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
        return std::chrono::microseconds(distance * 3) + (forReading ? 1ms : 167ms);
    }

    std::chrono::nanoseconds computeReadDelay() { return m_speed == Speed::Simple ? 13333us : 6666us; }

    // "Command" 0, which doesn't actually exist.
    bool cdlSync(const QueueElement &command, bool start) {
        maybeEnqueueError(1, 0x40);
        maybeScheduleNextCommand();
        return false;
    }

    // Command 1.
    bool cdlNop(const QueueElement &command, bool start) {
        QueueElement response;
        response.pushPayloadData(getStatus(true));
        maybeTriggerIRQ(Cause::Acknowledge, response);
        maybeScheduleNextCommand();
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
        maybeScheduleNextCommand();
        return false;
    }

    // Command 6.
    bool cdlReadN(const QueueElement &command, bool start) {
        m_status = Status::Idle;
        scheduleRead(20ms);
        m_readingType = ReadingType::Normal;
        QueueElement response;
        response.pushPayloadData(getStatus());
        maybeTriggerIRQ(Cause::Acknowledge, response);
        maybeScheduleNextCommand();
        m_readingState = ReadingState::Seeking;
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
            m_status = Status::Idle;
            m_invalidLocL = true;
            return true;
        } else {
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Complete, response);
            maybeScheduleNextCommand();
            return false;
        }
    }

    // Command 10.
    bool cdlInit(const QueueElement &command, bool start) {
        if (start) {
            QueueElement response;
            m_motorOn = true;
            m_speedChanged = false;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Acknowledge, response);
            schedule(120ms);
            // TODO: figure out exactly the various states of the CD-Rom controller
            // that are being reset, and their value.
            m_currentPosition.reset();
            m_currentPosition.s = 2;
            m_seekPosition.reset();
            m_seekPosition.s = 2;
            m_invalidLocL = false;
            m_speed = Speed::Simple;
            m_status = Status::Idle;
            m_interruptCauseMask = 0x1f;
            m_readingState = ReadingState::None;
            memset(m_lastLocP, 0, sizeof(m_lastLocP));
            // Probably need to cancel other scheduled tasks here.
            return true;
        } else {
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Complete, response);
            maybeScheduleNextCommand();
            return false;
        }
    }

    // Command 11
    bool cdlMute(const QueueElement &command, bool start) {
        // TODO: probably should error out if no disc or
        // lid open?
        PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: Mute - not yet implemented.\n");
        QueueElement response;
        response.pushPayloadData(getStatus());
        maybeTriggerIRQ(Cause::Acknowledge, response);
        maybeScheduleNextCommand();
        return false;
    }

    // Command 12
    bool cdlDemute(const QueueElement &command, bool start) {
        // TODO: probably should error out if no disc or
        // lid open?
        PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: Demute - not yet implemented.\n");
        QueueElement response;
        response.pushPayloadData(getStatus());
        maybeTriggerIRQ(Cause::Acknowledge, response);
        maybeScheduleNextCommand();
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
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: unsupported mode: %02x\n", mode);
                PCSX::g_system->pause();
                break;
        }
        m_subheaderFilter = (mode & 0x08) != 0;
        m_realtime = (mode & 0x40) != 0;
        if (mode & 0x07) {
            PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: unsupported mode: %02x\n", mode);
            PCSX::g_system->pause();
        }
        QueueElement response;
        response.pushPayloadData(getStatus());
        maybeTriggerIRQ(Cause::Acknowledge, response);
        maybeScheduleNextCommand();
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
        maybeScheduleNextCommand();
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
        maybeScheduleNextCommand();
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
        maybeScheduleNextCommand();
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
        maybeScheduleNextCommand();
        return false;
    }

    // Command 21.
    bool cdlSeekL(const QueueElement &command, bool start) {
        m_readingState = ReadingState::None;
        if (start) {
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Acknowledge, response);
            schedule(15ms);
            return true;
        } else if (m_status != Status::Seeking) {
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
            maybeScheduleNextCommand();
            return false;
        }
    }

    // Command 22.
    bool cdlSeekP(const QueueElement &command, bool start) {
        m_readingState = ReadingState::None;
        if (start) {
            QueueElement response;
            response.pushPayloadData(getStatus());
            maybeTriggerIRQ(Cause::Acknowledge, response);
            schedule(15ms);
            return true;
        } else if (m_status != Status::Seeking) {
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
            maybeScheduleNextCommand();
            return false;
        }
    }

    // Command 25.
    bool cdlTest(const QueueElement &command, bool start) {
        static constexpr uint8_t c_test20[] = {0x94, 0x09, 0x19, 0xc0};
        if (command.isPayloadEmpty()) {
            maybeEnqueueError(1, 0x20);
            maybeScheduleNextCommand();
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
        maybeScheduleNextCommand();
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
            maybeScheduleNextCommand();
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

    const CommandType c_commandsHandlers[31]{
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
        &CDRomImpl::cdlSync,
        &CDRomImpl::cdlNop,
        &CDRomImpl::cdlSetLoc,
        nullptr,  // 0
        nullptr,
        nullptr,
        &CDRomImpl::cdlReadN,
        nullptr,  // 4
        nullptr,
        &CDRomImpl::cdlPause,
        &CDRomImpl::cdlInit,
        &CDRomImpl::cdlMute,  // 8
        &CDRomImpl::cdlDemute,
        nullptr,
        &CDRomImpl::cdlSetMode,
        nullptr,  // 12
        &CDRomImpl::cdlGetLocL,
        &CDRomImpl::cdlGetLocP,
        nullptr,
        &CDRomImpl::cdlGetTN,  // 16
        &CDRomImpl::cdlGetTD,
        &CDRomImpl::cdlSeekL,
        &CDRomImpl::cdlSeekP,
        nullptr,  // 20
        nullptr,
        &CDRomImpl::cdlTest,
        &CDRomImpl::cdlID,
        &CDRomImpl::cdlReadS,  // 24
        nullptr,
        nullptr,
        nullptr,  // 28
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
                if (command.payloadSize == 0) {
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] Command: CdlPlay\n", regs.pc,
                                        regs.cycle);
                } else {
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom: %08x.%08x] Command: CdlPlay %i\n", regs.pc,
                                        regs.cycle, command.payload[0]);
                }
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
                                        commandName(command.value));
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
