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

#include "core/psxemulator.h"
#include "core/sstate.h"
#include "support/opengl.h"

namespace PCSX {
class GUI;

class GPU {
  public:
    int gpuReadStatus();
    void dma(uint32_t madr, uint32_t bcr, uint32_t chcr);
    static void gpuInterrupt();

    bool m_showCfg = false;
    bool m_showDebug = false;
    virtual bool configure() = 0;
    virtual void debug() = 0;
    virtual ~GPU() {}

  private:
    // Taken from PEOPS SOFTGPU
    uint32_t s_lUsedAddr[3];

    bool CheckForEndlessLoop(uint32_t laddr);
    uint32_t gpuDmaChainSize(uint32_t addr);

  public:
    virtual int init() = 0;
    virtual int shutdown() = 0;
    virtual int open(GUI *) = 0;
    virtual int close() = 0;
    virtual uint32_t readData() = 0;
    virtual void startDump() = 0;
    virtual void stopDump() = 0;
    virtual void readDataMem(uint32_t *pMem, int iSize) = 0;
    virtual uint32_t readStatus() = 0;
    virtual void writeData(uint32_t gdata) = 0;
    virtual void writeDataMem(uint32_t *pMem, int iSize) = 0;
    virtual void writeStatus(uint32_t gdata) = 0;
    virtual int32_t dmaChain(uint32_t *baseAddrL, uint32_t addr) = 0;
    virtual void startFrame() {}
    virtual void save(SaveStates::GPU &gpu) = 0;
    virtual void load(const SaveStates::GPU &gpu) = 0;

    virtual void displayText(char *pText) { PCSX::g_system->printf("%s\n", pText); }
    virtual void makeSnapshot(void) {}
    virtual void toggleDebug(void) {}
    virtual int32_t getScreenPic(unsigned char *pMem) { return -1; }
    virtual int32_t showScreenPic(unsigned char *pMem) { return -1; }
    virtual void clearDynarec(void (*callback)(void)) {}
    virtual void vblank() {}
    virtual void visualVibration(uint32_t iSmall, uint32_t iBig) {}
    virtual void cursor(int player, int x, int y) {}
    virtual void addVertex(short sx, short sy, int64_t fx, int64_t fy, int64_t fz) {}
    virtual void setSpeed(float newSpeed) {}
    virtual void pgxpMemory(unsigned int addr, unsigned char *pVRAM) {}
    virtual void pgxpCacheVertex(short sx, short sy, const unsigned char *_pVertex) {}
    virtual int32_t test(void) { return 0; }
    virtual void about(void) {}

    virtual void setDither(int setting) {}
    virtual void reset() {}
    virtual void clearVRAM() {}
    virtual GLuint getVRAMTexture() { return 0; }

    static std::unique_ptr<GPU> getSoft();
    static std::unique_ptr<GPU> getOpenGL();

    virtual void partialUpdateVRAM(int x, int y, int w, int h, const uint16_t *pixels) {}
};

}  // namespace PCSX
