/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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
#include <stdexcept>
#include <utility>

#include "core/display.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/sstate.h"
#include "support/slice.h"

namespace PCSX {
class GUI;

class GPU {
  public:
    uint32_t gpuReadStatus();
    void dma(uint32_t madr, uint32_t bcr, uint32_t chcr);
    static void gpuInterrupt();

    // These functions do not touch GPUSTAT. GPU backends should mirror the IRQ status into GPUSTAT
    // when readStatus is called
    void requestIRQ1() { psxHu32ref(0x1070) |= SWAP_LEu32(0x2); }
    void acknowledgeIRQ1() { psxHu32ref(0x1070) &= ~SWAP_LEu32(0x2); }

    bool m_showCfg = false;
    bool m_showDebug = false;
    Display m_display;

    virtual bool configure() = 0;
    virtual void debug() = 0;
    virtual ~GPU() {}

  private:
    // Taken from PEOPS SOFTGPU
    uint32_t s_lUsedAddr[3];

    bool CheckForEndlessLoop(uint32_t laddr);
    uint32_t gpuDmaChainSize(uint32_t addr);

  public:
    virtual int init(GUI *) = 0;
    virtual int shutdown() = 0;
    virtual uint32_t readData() = 0;
    virtual void startDump() { throw std::runtime_error("Not yet implemented"); }
    virtual void stopDump() { throw std::runtime_error("Not yet implemented"); }
    virtual void readDataMem(uint32_t *pMem, int iSize) = 0;
    virtual uint32_t readStatus() = 0;
    virtual void writeData(uint32_t gdata) = 0;
    virtual void writeDataMem(uint32_t *pMem, int iSize) = 0;
    virtual void writeStatus(uint32_t gdata) = 0;
    virtual int32_t dmaChain(uint32_t *baseAddrL, uint32_t addr) = 0;
    virtual void setOpenGLContext() {}
    virtual void save(SaveStates::GPU &gpu) { throw std::runtime_error("Not yet implemented"); }
    virtual void load(const SaveStates::GPU &gpu) { throw std::runtime_error("Not yet implemented"); }

    virtual void vblank() = 0;
    virtual void addVertex(short sx, short sy, int64_t fx, int64_t fy, int64_t fz) {
        throw std::runtime_error("Not yet implemented");
    }
    virtual void pgxpMemory(unsigned int addr, unsigned char *pVRAM) {}
    virtual void pgxpCacheVertex(short sx, short sy, const unsigned char *_pVertex) {
        throw std::runtime_error("Not yet implemented");
    }

    virtual void setDither(int setting) = 0;
    virtual void reset() = 0;
    virtual void clearVRAM() = 0;
    virtual GLuint getVRAMTexture() = 0;
    virtual void setLinearFiltering() = 0;

    static std::unique_ptr<GPU> getSoft();
    static std::unique_ptr<GPU> getOpenGL();

    virtual Slice getVRAM() { throw std::runtime_error("Not yet implemented"); }
    virtual void partialUpdateVRAM(int x, int y, int w, int h, const uint16_t *pixels) {
        throw std::runtime_error("Not yet implemented");
    }

    struct ScreenShot {
        Slice data;
        uint16_t width, height;
        enum { BPP_16, BPP_24 } bpp;
    };
    virtual ScreenShot takeScreenShot() { throw std::runtime_error("Not yet implemented"); }
};

}  // namespace PCSX
