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

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include "cdrom/cdriso.h"
#include "cdrom/iec-60908b.h"
#include "core/decode_xa.h"
#include "core/psxemulator.h"
#include "core/psxhw.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sstate.h"
#include "core/system.h"

namespace PCSX {

namespace Widgets {
class IsoBrowser;
}

class CDRom {
  public:
    using MSF = IEC60908b::MSF;
    CDRom() : m_iso(new CDRIso()) {}
    virtual ~CDRom() {}
    static CDRom* factory();
    bool isLidOpen();
    void closeLid() {
        m_lidOpen = false;
        m_lidCloseScheduled = false;
    }
    void openLid() {
        m_lidOpen = true;
        m_wasLidOpened = true;
        m_lidCloseScheduled = false;
    }
    void scheduleCloseLid() {
        m_lidOpen = true;
        m_wasLidOpened = true;
        m_lidCloseScheduled = true;
        using namespace std::chrono_literals;
        m_lidCloseAtCycles = g_emulator->m_cpu->m_regs.getFutureCycle(1s);
    }
    void parseIso();

    std::shared_ptr<CDRIso> getIso() { return m_iso; }
    void clearIso() {
        m_iso.reset();
        g_system->m_eventBus->signal(Events::IsoMounted{});
    }
    void setIso(CDRIso* iso) {
        m_iso.reset(iso);
        g_system->m_eventBus->signal(Events::IsoMounted{});
    }

    const std::string& getCDRomID() { return m_cdromId; }
    const std::string& getCDRomLabel() { return m_cdromLabel; }

    virtual void reset() = 0;

    virtual void fifoScheduledCallback() = 0;
    virtual void commandsScheduledCallback() = 0;
    virtual void readScheduledCallback() = 0;
    virtual void scheduleDmaCallback() = 0;
    virtual uint8_t read0() = 0;
    virtual uint8_t read1() = 0;
    virtual uint8_t read2() = 0;
    virtual uint8_t read3() = 0;
    virtual void write0(uint8_t rt) = 0;
    virtual void write1(uint8_t rt) = 0;
    virtual void write2(uint8_t rt) = 0;
    virtual void write3(uint8_t rt) = 0;

    virtual void dma(uint32_t madr, uint32_t bcr, uint32_t chcr) = 0;

  protected:
    std::shared_ptr<CDRIso> m_iso;
    friend SaveStates::SaveState SaveStates::constructSaveState();

    bool dataFIFOHasData() { return m_dataFIFOIndex != m_dataFIFOSize; }

    bool m_lidOpen = false;
    bool m_wasLidOpened = false;
    bool m_lidCloseScheduled = false;
    uint32_t m_lidCloseAtCycles = 0;

    // to save/init
    uint8_t m_dataFIFO[2352] = {0};
    uint32_t m_dataFIFOIndex = 0;
    uint32_t m_dataFIFOSize = 0;
    uint32_t m_dataFIFOPending = 0;
    uint8_t m_registerIndex = 0;
    bool m_motorOn = false;
    bool m_speedChanged = false;
    bool m_invalidLocL = false;
    bool m_dataRequested = false;
    bool m_subheaderFilter = false;
    bool m_realtime = false;
    bool m_startReading = false;
    bool m_startPlaying = false;
    enum class ReadingType : uint8_t {
        None,
        Normal,
        Streaming,
    } m_readingType = ReadingType::None;
    enum class Status : uint8_t {
        Idle,
        ReadingData,
        Seeking,
        PlayingCDDA,
    } m_status = Status::Idle;
    enum class Speed : uint8_t { Simple, Double } m_speed;
    enum class ReadSpan : uint8_t { S2048, S2328, S2340 } m_readSpan;
    uint8_t m_causeMask = 0x1f;

    enum class Cause : uint8_t {
        None = 0,
        DataReady = 1,
        Complete = 2,
        Acknowledge = 3,
        End = 4,
        Error = 5,
    };

    MSF m_currentPosition;
    MSF m_seekPosition;
    uint8_t m_lastLocP[8] = {0};
    uint8_t m_lastLocL[8] = {0};

    struct QueueElement {
        uint8_t value;
        uint8_t payload[16];
        bool valueRead = false;
        bool hasValue = false;
        uint8_t payloadSize = 0;
        uint8_t payloadIndex = 0;
        bool isPayloadEmpty() const { return payloadSize == payloadIndex; }
        bool isPayloadFull() const { return payloadSize == sizeof(payload); }
        bool empty() const { return (!hasValue || valueRead) && isPayloadEmpty(); }
        void clear() {
            hasValue = false;
            valueRead = false;
            payloadSize = 0;
            payloadIndex = 0;
        }
        void setValue(uint8_t newValue) {
            value = newValue;
            hasValue = true;
        }
        void setValue(Cause cause) { setValue(static_cast<uint8_t>(cause)); }
        void pushPayloadData(uint8_t value) {
            if (payloadSize < sizeof(payload)) payload[payloadSize++] = value;
        }
        void pushPayloadData(std::string_view values) {
            for (auto value : values) {
                pushPayloadData(value);
            }
        }
        uint8_t getValue() const { return valueRead ? 0 : value; }
        uint8_t readPayloadByte() {
            if (payloadIndex < payloadSize) {
                return payload[payloadIndex++];
            }
            return 0;
        }
    };

    QueueElement m_commandFifo;
    QueueElement m_commandExecuting;
    QueueElement m_responseFifo[2];
    bool responseFifoFull() { return !m_responseFifo[0].empty() && !m_responseFifo[1].empty(); }
    bool maybeEnqueueResponse(QueueElement& response) {
        if (m_responseFifo[0].empty()) {
            m_responseFifo[0] = response;
            return true;
        } else if (m_responseFifo[1].empty()) {
            m_responseFifo[1] = response;
        }
        return false;
    }

  private:
    friend class Widgets::IsoBrowser;
    std::string m_cdromId;
    std::string m_cdromLabel;
};

}  // namespace PCSX
