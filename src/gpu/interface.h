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

#include "core/gpu.h"
#include "gpu/externals.h"
#include "gpu/prim.h"

namespace PCSX {

class GUI;

namespace SoftGPU {

class impl : public GPU {
    virtual int32_t init() final;
    virtual int32_t shutdown() final;
    virtual int32_t open(GUI *) final;
    virtual int32_t close() final;
    virtual uint32_t readData() final {
        uint32_t l;
        readDataMem(&l, 1);
        return lGPUdataRet;
    }
    virtual void readDataMem(uint32_t *pMem, int iSize) final;
    virtual uint32_t readStatus() final;
    virtual void writeData(uint32_t gdata) final { writeDataMem(&gdata, 1); }
    virtual void writeDataMem(uint32_t *pMem, int iSize) final;
    virtual void writeStatus(uint32_t gdata) final;
    virtual int32_t dmaChain(uint32_t *baseAddrL, uint32_t addr) final;
    virtual void updateLace() final;
    virtual int32_t freeze(uint32_t ulGetFreezeData, GPUFreeze_t *pF) final;
    virtual bool configure() final {
        if (m_showCfg) {
            return m_softPrim.configure(&m_showCfg);
        } else {
            return false;
        }
    }

    SoftPrim m_softPrim;

    ////////////////////////////////////////////////////////////////////////
    // memory image of the PSX vram
    ////////////////////////////////////////////////////////////////////////

    //    unsigned char *psxVSecure;
    //    unsigned char *psxVub;
    //    signed char *psxVsb;
    //    uint16_t *psxVuw;
    //    uint16_t *psxVuw_eom;
    //    int16_t *psxVsw;
    //    uint32_t *psxVul;
    //    int32_t *psxVsl;

    ////////////////////////////////////////////////////////////////////////
    // GPU globals
    ////////////////////////////////////////////////////////////////////////

    int32_t lGPUdataRet;
    //    int32_t lGPUstatusRet;
    //    char szDispBuf[64];
    //    char szMenuBuf[36];
    //    char szDebugText[512];
    //    uint32_t ulStatusControl[256];

    //    uint32_t gpuDataM[256];
    //    unsigned char gpuCommand = 0;
    //    int32_t gpuDataC = 0;
    //    int32_t gpuDataP = 0;

    //    VRAMLoad_t VRAMWrite;
    //    VRAMLoad_t VRAMRead;
    //    DATAREGISTERMODES DataWriteMode;
    //    DATAREGISTERMODES DataReadMode;

    //    bool bSkipNextFrame = false;
    //    DWORD dwLaceCnt = 0;
    //    int iColDepth;
    //    int iWindowMode;
    //    int16_t sDispWidths[8] = {256, 320, 512, 640, 368, 384, 512, 640};
    //    PSXDisplay_t PSXDisplay;
    //    PSXDisplay_t PreviousPSXDisplay;
    //    int32_t lSelectedSlot = 0;
    //    bool bChangeWinMode = false;
    //    bool bDoLazyUpdate = false;
    //    uint32_t lGPUInfoVals[16];
    //    int iFakePrimBusy = 0;
    //    int iRumbleVal = 0;
    //    int iRumbleTime = 0;
};

}  // namespace SoftGPU

}  // namespace PCSX
