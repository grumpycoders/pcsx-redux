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

#include "gpu/debug.h"
#include "gpu/externals.h"
#include "gpu/renderer.h"

namespace PCSX {

namespace GPU {

class Prim : public Renderer {
  public:
    inline void callFunc(uint8_t cmd, uint8_t *baseAddr) {
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
    int32_t GlobalTextREST;

    typedef void (Prim::*func_t)(uint8_t *);
    typedef const func_t cfunc_t;
    typedef Debug::Command *(Prim::*dbgFunc_t)(uint8_t, uint8_t *);
    typedef const func_t cdbgFunc_t;
    void cmdSTP(uint8_t *baseAddr);
    void cmdTexturePage(uint8_t *baseAddr);
    void cmdTextureWindow(uint8_t *baseAddr);
    void cmdDrawAreaStart(uint8_t *baseAddr);
    void cmdDrawAreaEnd(uint8_t *baseAddr);
    void cmdDrawOffset(uint8_t *baseAddr);
    void primLoadImage(uint8_t *baseAddr);
    void primStoreImage(uint8_t *baseAddr);
    void primBlkFill(uint8_t *baseAddr);
    void primMoveImage(uint8_t *baseAddr);
    void primTileS(uint8_t *baseAddr);
    void primTile1(uint8_t *baseAddr);
    void primTile8(uint8_t *baseAddr);
    void primTile16(uint8_t *baseAddr);
    void primSprt8(uint8_t *baseAddr);
    void primSprt16(uint8_t *baseAddr);
    void primSprtSRest(uint8_t *baseAddr, uint16_t type);
    void primSprtS(uint8_t *baseAddr);
    void primPolyF4(uint8_t *baseAddr);
    void primPolyG4(uint8_t *baseAddr);
    void primPolyFT3(uint8_t *baseAddr);
    void primPolyFT4(uint8_t *baseAddr);
    void primPolyGT3(uint8_t *baseAddr);
    void primPolyG3(uint8_t *baseAddr);
    void primPolyGT4(uint8_t *baseAddr);
    void primPolyF3(uint8_t *baseAddr);
    void primLineGSkip(uint8_t *baseAddr);
    void primLineGEx(uint8_t *baseAddr);
    void primLineG2(uint8_t *baseAddr);
    void primLineFSkip(uint8_t *baseAddr);
    void primLineFEx(uint8_t *baseAddr);
    void primLineF2(uint8_t *baseAddr);
    void primNI(uint8_t *baseAddr);
    
    static const func_t funcs[256];
    static const func_t skip[256];

    void UpdateGlobalTP(uint16_t gdata);
    void SetRenderMode(uint32_t DrawAttributes);
    void AdjustCoord4();
    void AdjustCoord3();
    void AdjustCoord2();
    void AdjustCoord1();

    bool CheckCoord4();
    bool CheckCoord3();
    bool CheckCoord2();

    int32_t lLowerpart;
};

}  // namespace GPU

}  // namespace PCSX
