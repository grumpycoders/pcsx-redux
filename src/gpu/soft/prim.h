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

namespace PCSX {

namespace SoftGPU {

class Prim {
  public:
    inline void callFunc(uint8_t cmd, unsigned char *baseAddr) {
        if (!bSkipNextFrame) {
            (*this.*(funcs[cmd]))(baseAddr);
        } else {
            (*this.*(skip[cmd]))(baseAddr);
        }
    }

    inline void reset() {
        GlobalTextAddrX = 0;
        GlobalTextAddrY = 0;
        GlobalTextTP = 0;
        GlobalTextABR = 0;
        bUsingTWin = false;
    }

  protected:
    virtual void offsetPSXLine() = 0;
    virtual void offsetPSX2() = 0;
    virtual void offsetPSX3() = 0;
    virtual void offsetPSX4() = 0;

    virtual void FillSoftwareAreaTrans(short x0, short y0, short x1, short y1, unsigned short col) = 0;
    virtual void FillSoftwareArea(short x0, short y0, short x1, short y1, unsigned short col) = 0;
    virtual void drawPoly3G(long rgb1, long rgb2, long rgb3) = 0;
    virtual void drawPoly4G(long rgb1, long rgb2, long rgb3, long rgb4) = 0;
    virtual void drawPoly3F(long rgb) = 0;
    virtual void drawPoly4F(long rgb) = 0;
    virtual void drawPoly4FT(unsigned char *baseAddr) = 0;
    virtual void drawPoly4GT(unsigned char *baseAddr) = 0;
    virtual void drawPoly3FT(unsigned char *baseAddr) = 0;
    virtual void drawPoly3GT(unsigned char *baseAddr) = 0;
    virtual void DrawSoftwareSprite(unsigned char *baseAddr, short w, short h, long tx, long ty) = 0;
    virtual void DrawSoftwareSpriteTWin(unsigned char *baseAddr, long w, long h) = 0;
    virtual void DrawSoftwareSpriteMirror(unsigned char *baseAddr, long w, long h) = 0;
    virtual void DrawSoftwareLineShade(long rgb0, long rgb1) = 0;
    virtual void DrawSoftwareLineFlat(long rgb) = 0;

    bool bUsingTWin = false;
    bool DrawSemiTrans = false;
    short g_m1 = 255, g_m2 = 255, g_m3 = 255;
    short ly0, lx0, ly1, lx1, ly2, lx2, ly3, lx3;  // global psx vertex coords

    long GlobalTextAddrX, GlobalTextAddrY, GlobalTextTP;
    long GlobalTextREST, GlobalTextABR;

  private:
    typedef void (Prim::*func_t)(unsigned char *);
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
    void SetRenderMode(unsigned long DrawAttributes);
    void AdjustCoord4();
    void AdjustCoord3();
    void AdjustCoord2();
    void AdjustCoord1();

    bool CheckCoord4();
    bool CheckCoord3();
    bool CheckCoord2();
};

}  // namespace SoftGPU

}  // namespace PCSX
