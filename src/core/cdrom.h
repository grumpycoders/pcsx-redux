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
#include "core/decode_xa.h"
#include "core/psxemulator.h"
#include "core/psxhw.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sstate.h"
#include "core/system.h"
#include "supportpsx/iec-60908b.h"

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
    CDRom() : m_iso(new CDRIso(new FailedFile)) {}
    virtual ~CDRom() {}
    static CDRom* factory();
    bool isLidOpened() { return m_lidOpenTime < 0 || m_lidOpenTime > (int64_t)time(nullptr); }
    void setLidOpenTime(int64_t time) { m_lidOpenTime = time; }
    void check();

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
    virtual void attenuate(int16_t* buf, int samples, int stereo) = 0;

    virtual void interrupt() = 0;
    virtual void readInterrupt() = 0;
    virtual void decodedBufferInterrupt() = 0;
    virtual void lidSeekInterrupt() = 0;
    virtual void playInterrupt() = 0;
    virtual void dmaInterrupt() = 0;
    virtual void lidInterrupt() = 0;
    virtual uint8_t read0(void) = 0;
    virtual uint8_t read1(void) = 0;
    virtual uint8_t read2(void) = 0;
    virtual uint8_t read3(void) = 0;
    virtual void write0(uint8_t rt) = 0;
    virtual void write1(uint8_t rt) = 0;
    virtual void write2(uint8_t rt) = 0;
    virtual void write3(uint8_t rt) = 0;
    virtual void load() = 0;

    virtual void dma(uint32_t madr, uint32_t bcr, uint32_t chcr) = 0;

    std::shared_ptr<CDRIso> getIso() const { return m_iso; }

  protected:
    std::shared_ptr<CDRIso> m_iso;
    // savestate stuff starts here
    uint8_t m_reg1Mode;
    uint8_t m_reg2;
    uint8_t m_cmdProcess;
    uint8_t m_ctrl;
    uint8_t m_stat;

    uint8_t m_statP;

    uint8_t m_transfer[PCSX::IEC60908b::FRAMESIZE_RAW];
    unsigned int m_transferIndex;

    MSF m_prev;
    uint8_t m_param[8];
    uint8_t m_result[16];

    uint8_t m_paramC;
    uint8_t m_resultC;
    uint8_t m_resultP;
    uint8_t m_resultReady;
    uint8_t m_cmd;
    uint8_t m_read;
    uint8_t m_setlocPending;
    bool m_locationChanged;
    uint32_t m_reading;

    MSF m_setSectorPlay;
    MSF m_setSectorEnd;
    MSF m_setSector;
    uint8_t m_track;
    bool m_play, m_muted;
    int m_curTrack;
    int m_mode, m_file, m_channel;
    bool m_suceeded;
    int m_firstSector;

  public:
    // this belongs in the SPU, not here.
    xa_decode_t m_xa;

  protected:
    int64_t m_lidOpenTime = 0;
    uint16_t m_irq;
    uint8_t m_irqRepeated;
    uint32_t m_eCycle;

    uint8_t m_seeked;
    uint8_t m_readRescheduled;

    uint8_t m_driveState;
    uint8_t m_fastForward;
    uint8_t m_fastBackward;

    uint8_t m_attenuatorLeftToLeft, m_attenuatorLeftToRight;
    uint8_t m_attenuatorRightToRight, m_attenuatorRightToLeft;
    uint8_t m_attenuatorLeftToLeftT, m_attenuatorLeftToRightT;
    uint8_t m_attenuatorRightToRightT, m_attenuatorRightToLeftT;

    struct {
        uint8_t track;
        uint8_t index;
        uint8_t relative[3];
        uint8_t absolute[3];
    } m_subq;
    bool m_trackChanged;
    // end savestate
    friend SaveStates::SaveState SaveStates::constructSaveState();

  private:
    friend class Widgets::IsoBrowser;
    std::string m_cdromId;
    std::string m_cdromLabel;
};

}  // namespace PCSX
