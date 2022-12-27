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

struct CdrStat {
    uint32_t Type;
    uint32_t Status;
    IEC60908b::MSF Time;
};

class CDRom {
  public:
    using MSF = PCSX::IEC60908b::MSF;
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

    virtual void interrupt() = 0;
    virtual void readInterrupt() = 0;
    virtual void dmaInterrupt() = 0;
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
    bool paramFIFOAvailable() { return m_paramFIFOSize != 16; }
    bool responseFIFOHasData() { return m_responseFIFOIndex != m_responseFIFOSize; }

    bool m_lidOpen = false;
    bool m_wasLidOpened = false;
    bool m_lidCloseScheduled = false;
    uint32_t m_lidCloseAtCycles = 0;

    // to save/init
    uint8_t m_dataFIFO[2352] = {0};
    uint8_t m_paramFIFO[16] = {0};
    uint8_t m_responseFIFO[16] = {0};
    uint32_t m_dataFIFOIndex = 0;
    uint32_t m_dataFIFOSize = 0;
    uint8_t m_paramFIFOSize = 0;
    uint8_t m_responseFIFOIndex = 0;
    uint8_t m_responseFIFOSize = 0;
    uint8_t m_registerIndex = 0;
    bool m_errorArgumentsCount = false;
    bool m_busy = false;
    bool m_gotAck = false;
    bool m_waitingAck = false;
    bool m_motorOn = false;
    bool m_invalidLocL = false;
    enum class Status {
        STOPPED,
        READING_DATA,
        SEEKING,
        PLAYING_CDDA,
    };
    Status m_status = Status::STOPPED;
    uint8_t m_state = 0;
    uint8_t m_command = 0;

    enum class Cause : uint8_t {
        None = 0,
        DataReady = 1,
        Complete = 2,
        Acknowledge = 3,
        End = 4,
        Error = 5,
    };
    Cause m_cause = Cause::None;

    MSF m_currentPosition;
    MSF m_seekPosition;
    uint8_t m_lastLocP[8] = {0};
    uint8_t m_lastLocL[8] = {0};

  private:
    friend class Widgets::IsoBrowser;
    std::string m_cdromId;
    std::string m_cdromLabel;
};

}  // namespace PCSX
