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

#include <stdint.h>

#include "gpu/soft/externals.h"
#include "gpu/soft/soft.h"

namespace PCSX {

namespace SoftGPU {

class SoftPrim : public SoftRenderer {
  public:
    inline void callFunc(uint8_t cmd, unsigned char *baseAddr) {
        if (!bSkipNextFrame) {
            (*this.*(funcs[cmd]))(baseAddr);
        } else {
            (*this.*(skip[cmd]))(baseAddr);
        }
    }

    bool configure(bool *);

    inline void reset() {
        GlobalTextAddrX = 0;
        GlobalTextAddrY = 0;
        GlobalTextTP = 0;
        GlobalTextABR = 0;
        bUsingTWin = false;
        usMirror = 0;
        drawX = drawY = 0;
        drawW = drawH = 0;
        bCheckMask = false;
        sSetMask = 0;
        lSetMask = 0;
    }

  private:
    int iUseDither = 0;
    long GlobalTextREST;

    typedef void (SoftPrim::*func_t)(unsigned char *);
    typedef const func_t cfunc_t;
    void cmdSTP(unsigned char *baseAddr);
    void cmdTexturePage(unsigned char *baseAddr);
    void cmdTextureWindow(unsigned char *baseAddr);
    void cmdDrawAreaStart(unsigned char *baseAddr);
    void cmdDrawAreaEnd(unsigned char *baseAddr);
    void cmdDrawOffset(unsigned char *baseAddr);
    void primLoadImage(unsigned char *baseAddr);
    void primStoreImage(unsigned char *baseAddr);
    void primBlkFill(unsigned char *baseAddr);
    void primMoveImage(unsigned char *baseAddr);
    void primTileS(unsigned char *baseAddr);
    void primTile1(unsigned char *baseAddr);
    void primTile8(unsigned char *baseAddr);
    void primTile16(unsigned char *baseAddr);
    void primSprt8(unsigned char *baseAddr);
    void primSprt16(unsigned char *baseAddr);
    void primSprtSRest(unsigned char *baseAddr, unsigned short type);
    void primSprtS(unsigned char *baseAddr);
    void primPolyF4(unsigned char *baseAddr);
    void primPolyG4(unsigned char *baseAddr);
    void primPolyFT3(unsigned char *baseAddr);
    void primPolyFT4(unsigned char *baseAddr);
    void primPolyGT3(unsigned char *baseAddr);
    void primPolyG3(unsigned char *baseAddr);
    void primPolyGT4(unsigned char *baseAddr);
    void primPolyF3(unsigned char *baseAddr);
    void primLineGSkip(unsigned char *baseAddr);
    void primLineGEx(unsigned char *baseAddr);
    void primLineG2(unsigned char *baseAddr);
    void primLineFSkip(unsigned char *baseAddr);
    void primLineFEx(unsigned char *baseAddr);
    void primLineF2(unsigned char *baseAddr);
    void primNI(unsigned char *baseAddr);

    static const func_t funcs[256];
    static const func_t skip[256];

    void UpdateGlobalTP(unsigned short gdata);
    void SetRenderMode(uint32_t DrawAttributes);
    void AdjustCoord4();
    void AdjustCoord3();
    void AdjustCoord2();
    void AdjustCoord1();

    bool CheckCoord4();
    bool CheckCoord3();
    bool CheckCoord2();

    long lLowerpart;
};

}  // namespace SoftGPU

}  // namespace PCSX
