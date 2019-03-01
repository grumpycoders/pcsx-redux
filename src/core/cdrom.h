/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

#include "core/cdriso.h"
#include "core/decode_xa.h"
#include "core/plugins.h"
#include "core/ppf.h"
#include "core/psxemulator.h"
#include "core/psxhw.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

namespace PCSX {

class CDRom {
  public:
    virtual ~CDRom() {}
    static CDRom* factory();
    static inline constexpr uint8_t btoi(uint8_t b) { return ((b / 16) * 10) + (b % 16); }
    static inline constexpr uint8_t itob(uint8_t i) { return ((i / 10) * 16) + (i % 10); }

    static inline constexpr uint32_t MSF2SECT(uint8_t m, uint8_t s, uint8_t f) { return (m * 60 + s - 2) * 75 + f; }
    static const ssize_t CD_FRAMESIZE_RAW = 2352;
    static const ssize_t DATA_SIZE = CD_FRAMESIZE_RAW - 12;
    static const ssize_t SUB_FRAMESIZE = 96;

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
    virtual int freeze(gzFile f, int Mode) = 0;

    virtual void dma(uint32_t madr, uint32_t bcr, uint32_t chcr) = 0;

    void setCdOpenCaseTime(int64_t time) { m_iso.setCdOpenCaseTime(time); }
    bool isLidOpen() { return m_iso.isLidOpened(); }

    CDRiso m_iso;
    PPF m_ppf;
};

}  // namespace PCSX
