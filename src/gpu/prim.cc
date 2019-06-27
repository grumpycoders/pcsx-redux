/***************************************************************************
                          prim.c  -  description
                             -------------------
    begin                : Sun Oct 28 2001
    copyright            : (C) 2001 by Pete Bernert
    email                : BlackDove@addcom.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version. See also the license.txt file for *
 *   additional informations.                                              *
 *                                                                         *
 ***************************************************************************/

//*************************************************************************//
// History of changes:
//
// 2004/01/31 - Pete
// - added zn bits and two zn cheats (TileS & move image - 2004/03/13)
//
// 2003/07/22 - Pete
// - added sprite x coord wrap (skullmonkey) - new: sprite y coord wrap as well
//
// 2002/12/14 - Pete
// - added dithering flag
//
// 2002/10/03 - Farfetch'd & Pete
// - changed: polylines, 11 bit coords, polygon discarding, BlkFill align, mask bits
//
// 2002/09/19 - Farfetch'd
// - STP: read control register is now masked correctly with 0x3
//
// 2002/08/16 - Pete
// - additional mask bit handling for sprites (Alone in the Dark 4 & FF6)
//
// 2002/08/10 - Lewpy & E}I{
// - correct TW coord adjustment (RRT4)
//
// 2002/07/22 - Pete
// - problem with the "2002/05/19 fixed mdec mask bit problem in FF9" fixed (hopefully)
//
// 2002/06/04 - Lewpy
// - new line drawing funcs
//
// 2002/05/19 - Pete
// - mdec mask bit problem in FF9 fixed
//
// 2002/05/14 - Pete
// - new coord check
//
// 2002/03/29 - Pete
// - tex window coord adjustment - thanx to E}I{
// - faster generic coord check - thanx to E}I{
// - StoreImage wrap (Devilsummoner Soul Hackers)
//
// 2002/03/27 - Pete
// - improved sprite texture wrapping func on _very_ big sprites
//
// 2002/02/23 - Pete
// - added Lunar "ignore blending color" fix
//
// 2002/02/12 - Pete
// - removed "no sprite transparency" and "black poly" fixes
//
// 2002/02/10 - Pete
// - additional Load/MoveImage checks for a few FF9/BOF4 effects
//
// 2001/12/10 - Pete
// - additional coord checks for Nascar and SF2 (and more...?)
//
// 2001/11/08 - Linuzappz
// - BGR24to16 converted to nasm, C version still works: define __i386_
//   to use the asm version
//
// 2001/10/28 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include "gpu/prim.h"
#include "gpu/draw.h"
#include "gpu/externals.h"
#include "gpu/gpu.h"
#include "gpu/renderer.h"
#include "imgui.h"

////////////////////////////////////////////////////////////////////////
// globals
////////////////////////////////////////////////////////////////////////

// configuration items
uint32_t dwCfgFixes;
uint32_t dwActFixes = 0;
uint32_t dwEmuFixes = 0;
int iUseFixes;
// ??
bool bDoVSyncUpdate = false;

bool PCSX::GPU::Prim::configure(bool *show) {
    bool changed = false;
    ImGui::SetNextWindowPos(ImVec2(60, 60), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(300, 200), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Soft GPU configuration", show)) {
        ImGui::End();
    }
    static const char *ditherValues[] = {"No dithering (fastest)", "Game dependend dithering (slow)",
                                         "Always dither g-shaded polygons (slowest)"};
    changed |= ImGui::Combo("Dithering", &iUseDither, ditherValues, 3);
    changed |= ImGui::Checkbox("UseFrameLimit", &UseFrameLimit);
    changed |= ImGui::Checkbox("UseFrameSkip", &UseFrameSkip);
    changed |= ImGui::Checkbox("SSSPSXLimit", &bSSSPSXLimit);
    ImGui::End();
    return changed;
}

static constexpr inline uint16_t BGR24to16(uint32_t BGR) {
    return (uint16_t)(((BGR >> 3) & 0x1f) | ((BGR & 0xf80000) >> 9) | ((BGR & 0xf800) >> 6));
}

////////////////////////////////////////////////////////////////////////
// Update global TP infos
////////////////////////////////////////////////////////////////////////

inline void PCSX::GPU::Prim::UpdateGlobalTP(uint16_t gdata) {
    GlobalTextAddrX = (gdata << 6) & 0x3c0;  // texture addr

    if (iGPUHeight == 1024) {
        if (dwGPUVersion == 2) {
            GlobalTextAddrY = ((gdata & 0x60) << 3);
            GlobalTextIL = (gdata & 0x2000) >> 13;
            GlobalTextABR = (uint16_t)((gdata >> 7) & 0x3);
            GlobalTextTP = (gdata >> 9) & 0x3;
            if (GlobalTextTP == 3) GlobalTextTP = 2;
            usMirror = 0;
            lGPUstatusRet = (lGPUstatusRet & 0xffffe000) | (gdata & 0x1fff);

            // tekken dithering? right now only if dithering is forced by user
            if (iUseDither == 2)
                iDither = 2;
            else
                iDither = 0;

            return;
        } else {
            GlobalTextAddrY = (uint16_t)(((gdata << 4) & 0x100) | ((gdata >> 2) & 0x200));
        }
    } else
        GlobalTextAddrY = (gdata << 4) & 0x100;

    usMirror = gdata & 0x3000;

    if (iUseDither == 2) {
        iDither = 2;
    } else {
        if (gdata & 200)
            iDither = iUseDither;
        else
            iDither = 0;
    }

    GlobalTextTP = (gdata >> 7) & 0x3;  // tex mode (4,8,15)

    if (GlobalTextTP == 3) GlobalTextTP = 2;  // seen in Wild9 :(

    GlobalTextABR = (gdata >> 5) & 0x3;  // blend mode

    lGPUstatusRet &= ~0x07ff;           // Clear the necessary bits
    lGPUstatusRet |= (gdata & 0x07ff);  // set the necessary bits
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::GPU::Prim::SetRenderMode(uint32_t DrawAttributes) {
    DrawSemiTrans = (SEMITRANSBIT(DrawAttributes));

    if (SHADETEXBIT(DrawAttributes)) {
        g_m1 = g_m2 = g_m3 = 128;
    } else {
        if ((dwActFixes & 4) && ((DrawAttributes & 0x00ffffff) == 0)) DrawAttributes |= 0x007f7f7f;

        g_m1 = (int16_t)(DrawAttributes & 0xff);
        g_m2 = (int16_t)((DrawAttributes >> 8) & 0xff);
        g_m3 = (int16_t)((DrawAttributes >> 16) & 0xff);
    }
}

////////////////////////////////////////////////////////////////////////

// oki, here are the psx gpu coord rules: poly coords are
// 11 bit signed values (-1024...1023). If the x or y distance
// exceeds 1024, the polygon will not be drawn.
// Since quads are treated as two triangles by the real gpu,
// this 'discard rule' applies to each of the quad's triangle
// (so one triangle can be drawn, the other one discarded).
// Also, y drawing is wrapped at 512 one time,
// then it will get negative (and therefore not drawn). The
// 'CheckCoord' funcs are a simple (not comlete!) approach to
// do things right, I will add a better detection soon... the
// current approach will be easier to do in hw/accel plugins, imho

// 11 bit signed
#define SIGNSHIFT 21
static const int CHKMAX_X = 1024;
static const int CHKMAX_Y = 512;

inline void PCSX::GPU::Prim::AdjustCoord4() {
    lx0 = (int16_t)(((int)lx0 << SIGNSHIFT) >> SIGNSHIFT);
    lx1 = (int16_t)(((int)lx1 << SIGNSHIFT) >> SIGNSHIFT);
    lx2 = (int16_t)(((int)lx2 << SIGNSHIFT) >> SIGNSHIFT);
    lx3 = (int16_t)(((int)lx3 << SIGNSHIFT) >> SIGNSHIFT);
    ly0 = (int16_t)(((int)ly0 << SIGNSHIFT) >> SIGNSHIFT);
    ly1 = (int16_t)(((int)ly1 << SIGNSHIFT) >> SIGNSHIFT);
    ly2 = (int16_t)(((int)ly2 << SIGNSHIFT) >> SIGNSHIFT);
    ly3 = (int16_t)(((int)ly3 << SIGNSHIFT) >> SIGNSHIFT);
}

inline void PCSX::GPU::Prim::AdjustCoord3() {
    lx0 = (int16_t)(((int)lx0 << SIGNSHIFT) >> SIGNSHIFT);
    lx1 = (int16_t)(((int)lx1 << SIGNSHIFT) >> SIGNSHIFT);
    lx2 = (int16_t)(((int)lx2 << SIGNSHIFT) >> SIGNSHIFT);
    ly0 = (int16_t)(((int)ly0 << SIGNSHIFT) >> SIGNSHIFT);
    ly1 = (int16_t)(((int)ly1 << SIGNSHIFT) >> SIGNSHIFT);
    ly2 = (int16_t)(((int)ly2 << SIGNSHIFT) >> SIGNSHIFT);
}

inline void PCSX::GPU::Prim::AdjustCoord2() {
    lx0 = (int16_t)(((int)lx0 << SIGNSHIFT) >> SIGNSHIFT);
    lx1 = (int16_t)(((int)lx1 << SIGNSHIFT) >> SIGNSHIFT);
    ly0 = (int16_t)(((int)ly0 << SIGNSHIFT) >> SIGNSHIFT);
    ly1 = (int16_t)(((int)ly1 << SIGNSHIFT) >> SIGNSHIFT);
}

inline void PCSX::GPU::Prim::AdjustCoord1() {
    lx0 = (int16_t)(((int)lx0 << SIGNSHIFT) >> SIGNSHIFT);
    ly0 = (int16_t)(((int)ly0 << SIGNSHIFT) >> SIGNSHIFT);

    if (lx0 < -512 && PSXDisplay.DrawOffset.x <= -512) lx0 += 2048;

    if (ly0 < -512 && PSXDisplay.DrawOffset.y <= -512) ly0 += 2048;
}

////////////////////////////////////////////////////////////////////////
// special checks... nascar, syphon filter 2, mgs
////////////////////////////////////////////////////////////////////////

// xenogears FT4: not removed correctly right now... the tri 0,1,2
// should get removed, the tri 1,2,3 should stay... pfff

// x -466 1023 180 1023
// y   20 -228 222 -100

// 0 __1
//  . . .
//   2___3

inline bool PCSX::GPU::Prim::CheckCoord4() {
    if (lx0 < 0) {
        if (((lx1 - lx0) > CHKMAX_X) || ((lx2 - lx0) > CHKMAX_X)) {
            if (lx3 < 0) {
                if ((lx1 - lx3) > CHKMAX_X) return true;
                if ((lx2 - lx3) > CHKMAX_X) return true;
            }
        }
    }
    if (lx1 < 0) {
        if ((lx0 - lx1) > CHKMAX_X) return true;
        if ((lx2 - lx1) > CHKMAX_X) return true;
        if ((lx3 - lx1) > CHKMAX_X) return true;
    }
    if (lx2 < 0) {
        if ((lx0 - lx2) > CHKMAX_X) return true;
        if ((lx1 - lx2) > CHKMAX_X) return true;
        if ((lx3 - lx2) > CHKMAX_X) return true;
    }
    if (lx3 < 0) {
        if (((lx1 - lx3) > CHKMAX_X) || ((lx2 - lx3) > CHKMAX_X)) {
            if (lx0 < 0) {
                if ((lx1 - lx0) > CHKMAX_X) return true;
                if ((lx2 - lx0) > CHKMAX_X) return true;
            }
        }
    }

    if (ly0 < 0) {
        if ((ly1 - ly0) > CHKMAX_Y) return true;
        if ((ly2 - ly0) > CHKMAX_Y) return true;
    }
    if (ly1 < 0) {
        if ((ly0 - ly1) > CHKMAX_Y) return true;
        if ((ly2 - ly1) > CHKMAX_Y) return true;
        if ((ly3 - ly1) > CHKMAX_Y) return true;
    }
    if (ly2 < 0) {
        if ((ly0 - ly2) > CHKMAX_Y) return true;
        if ((ly1 - ly2) > CHKMAX_Y) return true;
        if ((ly3 - ly2) > CHKMAX_Y) return true;
    }
    if (ly3 < 0) {
        if ((ly1 - ly3) > CHKMAX_Y) return true;
        if ((ly2 - ly3) > CHKMAX_Y) return true;
    }

    return false;
}

inline bool PCSX::GPU::Prim::CheckCoord3() {
    if (lx0 < 0) {
        if ((lx1 - lx0) > CHKMAX_X) return true;
        if ((lx2 - lx0) > CHKMAX_X) return true;
    }
    if (lx1 < 0) {
        if ((lx0 - lx1) > CHKMAX_X) return true;
        if ((lx2 - lx1) > CHKMAX_X) return true;
    }
    if (lx2 < 0) {
        if ((lx0 - lx2) > CHKMAX_X) return true;
        if ((lx1 - lx2) > CHKMAX_X) return true;
    }
    if (ly0 < 0) {
        if ((ly1 - ly0) > CHKMAX_Y) return true;
        if ((ly2 - ly0) > CHKMAX_Y) return true;
    }
    if (ly1 < 0) {
        if ((ly0 - ly1) > CHKMAX_Y) return true;
        if ((ly2 - ly1) > CHKMAX_Y) return true;
    }
    if (ly2 < 0) {
        if ((ly0 - ly2) > CHKMAX_Y) return true;
        if ((ly1 - ly2) > CHKMAX_Y) return true;
    }

    return false;
}

inline bool PCSX::GPU::Prim::CheckCoord2() {
    if (lx0 < 0) {
        if ((lx1 - lx0) > CHKMAX_X) return true;
    }
    if (lx1 < 0) {
        if ((lx0 - lx1) > CHKMAX_X) return true;
    }
    if (ly0 < 0) {
        if ((ly1 - ly0) > CHKMAX_Y) return true;
    }
    if (ly1 < 0) {
        if ((ly0 - ly1) > CHKMAX_Y) return true;
    }

    return false;
}

static constexpr inline bool CheckCoordL(int16_t slx0, int16_t sly0, int16_t slx1, int16_t sly1) {
    if (slx0 < 0) {
        if ((slx1 - slx0) > CHKMAX_X) return true;
    }
    if (slx1 < 0) {
        if ((slx0 - slx1) > CHKMAX_X) return true;
    }
    if (sly0 < 0) {
        if ((sly1 - sly0) > CHKMAX_Y) return true;
    }
    if (sly1 < 0) {
        if ((sly0 - sly1) > CHKMAX_Y) return true;
    }

    return false;
}

////////////////////////////////////////////////////////////////////////
// mask stuff... used in silent hill
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::cmdSTP(uint8_t *baseAddr) {
    uint32_t gdata = ((uint32_t *)baseAddr)[0];

    lGPUstatusRet &= ~0x1800;                 // Clear the necessary bits
    lGPUstatusRet |= ((gdata & 0x03) << 11);  // Set the necessary bits

    if (gdata & 1) {
        sSetMask = 0x8000;
        lSetMask = 0x80008000;
    } else {
        sSetMask = 0;
        lSetMask = 0;
    }

    bCheckMask = gdata & 2;
}

////////////////////////////////////////////////////////////////////////
// cmd: Set texture page infos
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::cmdTexturePage(uint8_t *baseAddr) {
    uint32_t gdata = ((uint32_t *)baseAddr)[0];

    UpdateGlobalTP((uint16_t)gdata);
    GlobalTextREST = (gdata & 0x00ffffff) >> 9;
}

////////////////////////////////////////////////////////////////////////
// cmd: turn on/off texture window
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::cmdTextureWindow(uint8_t *baseAddr) {
    uint32_t gdata = ((uint32_t *)baseAddr)[0];

    uint32_t YAlign, XAlign;

    lGPUInfoVals[INFO_TW] = gdata & 0xFFFFF;

    if (gdata & 0x020)
        TWin.Position.y1 = 8;  // xxxx1
    else if (gdata & 0x040)
        TWin.Position.y1 = 16;  // xxx10
    else if (gdata & 0x080)
        TWin.Position.y1 = 32;  // xx100
    else if (gdata & 0x100)
        TWin.Position.y1 = 64;  // x1000
    else if (gdata & 0x200)
        TWin.Position.y1 = 128;  // 10000
    else
        TWin.Position.y1 = 256;  // 00000

    // Texture window size is determined by the least bit set of the relevant 5 bits

    if (gdata & 0x001)
        TWin.Position.x1 = 8;  // xxxx1
    else if (gdata & 0x002)
        TWin.Position.x1 = 16;  // xxx10
    else if (gdata & 0x004)
        TWin.Position.x1 = 32;  // xx100
    else if (gdata & 0x008)
        TWin.Position.x1 = 64;  // x1000
    else if (gdata & 0x010)
        TWin.Position.x1 = 128;  // 10000
    else
        TWin.Position.x1 = 256;  // 00000

    // Re-calculate the bit field, because we can't trust what is passed in the data

    YAlign = (uint32_t)(32 - (TWin.Position.y1 >> 3));
    XAlign = (uint32_t)(32 - (TWin.Position.x1 >> 3));

    // Absolute position of the start of the texture window

    TWin.Position.y0 = (int16_t)(((gdata >> 15) & YAlign) << 3);
    TWin.Position.x0 = (int16_t)(((gdata >> 10) & XAlign) << 3);

    if ((TWin.Position.x0 == 0 &&  // tw turned off
         TWin.Position.y0 == 0 && TWin.Position.x1 == 0 && TWin.Position.y1 == 0) ||
        (TWin.Position.x1 == 256 && TWin.Position.y1 == 256)) {
        bUsingTWin = false;  // -> just do it
    } else                   // otherwise
    {
        bUsingTWin = true;  // -> tw turned on
    }
}

////////////////////////////////////////////////////////////////////////
// cmd: start of drawing area... primitives will be clipped inside
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::cmdDrawAreaStart(uint8_t *baseAddr) {
    uint32_t gdata = ((uint32_t *)baseAddr)[0];

    drawX = gdata & 0x3ff;  // for soft drawing

    if (dwGPUVersion == 2) {
        lGPUInfoVals[INFO_DRAWSTART] = gdata & 0x3FFFFF;
        drawY = (gdata >> 12) & 0x3ff;
        if (drawY >= 1024) drawY = 1023;  // some security
    } else {
        lGPUInfoVals[INFO_DRAWSTART] = gdata & 0xFFFFF;
        drawY = (gdata >> 10) & 0x3ff;
        if (drawY >= 512) drawY = 511;  // some security
    }
}

////////////////////////////////////////////////////////////////////////
// cmd: end of drawing area... primitives will be clipped inside
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::cmdDrawAreaEnd(uint8_t *baseAddr) {
    uint32_t gdata = ((uint32_t *)baseAddr)[0];

    drawW = gdata & 0x3ff;  // for soft drawing

    if (dwGPUVersion == 2) {
        lGPUInfoVals[INFO_DRAWEND] = gdata & 0x3FFFFF;
        drawH = (gdata >> 12) & 0x3ff;
        if (drawH >= 1024) drawH = 1023;  // some security
    } else {
        lGPUInfoVals[INFO_DRAWEND] = gdata & 0xFFFFF;
        drawH = (gdata >> 10) & 0x3ff;
        if (drawH >= 512) drawH = 511;  // some security
    }
}

////////////////////////////////////////////////////////////////////////
// cmd: draw offset... will be added to prim coords
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::cmdDrawOffset(uint8_t *baseAddr) {
    uint32_t gdata = ((uint32_t *)baseAddr)[0];

    PSXDisplay.DrawOffset.x = (int16_t)(gdata & 0x7ff);

    if (dwGPUVersion == 2) {
        lGPUInfoVals[INFO_DRAWOFF] = gdata & 0x7FFFFF;
        PSXDisplay.DrawOffset.y = (int16_t)((gdata >> 12) & 0x7ff);
    } else {
        lGPUInfoVals[INFO_DRAWOFF] = gdata & 0x3FFFFF;
        PSXDisplay.DrawOffset.y = (int16_t)((gdata >> 11) & 0x7ff);
    }

    PSXDisplay.DrawOffset.y = (int16_t)(((int)PSXDisplay.DrawOffset.y << 21) >> 21);
    PSXDisplay.DrawOffset.x = (int16_t)(((int)PSXDisplay.DrawOffset.x << 21) >> 21);
}

////////////////////////////////////////////////////////////////////////
// cmd: load image to vram
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primLoadImage(uint8_t *baseAddr) {
    uint16_t *sgpuData = ((uint16_t *)baseAddr);

    VRAMWrite.x = sgpuData[2] & 0x3ff;
    VRAMWrite.y = sgpuData[3] & iGPUHeightMask;
    VRAMWrite.Width = sgpuData[4];
    VRAMWrite.Height = sgpuData[5];

    DataWriteMode = DR_VRAMTRANSFER;

    VRAMWrite.ImagePtr = psxVuw + (VRAMWrite.y << 10) + VRAMWrite.x;
    VRAMWrite.RowsRemaining = VRAMWrite.Width;
    VRAMWrite.ColsRemaining = VRAMWrite.Height;
}

////////////////////////////////////////////////////////////////////////
// cmd: vram -> psx mem
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primStoreImage(uint8_t *baseAddr) {
    uint16_t *sgpuData = ((uint16_t *)baseAddr);

    VRAMRead.x = sgpuData[2] & 0x03ff;
    VRAMRead.y = sgpuData[3] & iGPUHeightMask;
    VRAMRead.Width = sgpuData[4];
    VRAMRead.Height = sgpuData[5];

    VRAMRead.ImagePtr = psxVuw + (VRAMRead.y << 10) + VRAMRead.x;
    VRAMRead.RowsRemaining = VRAMRead.Width;
    VRAMRead.ColsRemaining = VRAMRead.Height;

    DataReadMode = DR_VRAMTRANSFER;

    lGPUstatusRet |= GPUSTATUS_READYFORVRAM;
}

////////////////////////////////////////////////////////////////////////
// cmd: blkfill - NO primitive! Doesn't care about draw areas...
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primBlkFill(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    int16_t sX = sgpuData[2];
    int16_t sY = sgpuData[3];
    int16_t sW = sgpuData[4] & 0x3ff;
    int16_t sH = sgpuData[5] & 0x3ff;

    sW = (sW + 15) & ~15;

    // Increase H & W if they are one int16_t of full values, because they never can be full values
    if (sH >= 1023) sH = 1024;
    if (sW >= 1023) sW = 1024;

    // x and y of end pos
    sW += sX;
    sH += sY;

    FillSoftwareArea(sX, sY, sW, sH, BGR24to16(gpuData[0]));

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: move image vram -> vram
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primMoveImage(uint8_t *baseAddr) {
    int16_t *sgpuData = ((int16_t *)baseAddr);

    int16_t imageY0, imageX0, imageY1, imageX1, imageSX, imageSY, i, j;

    imageX0 = sgpuData[2] & 0x03ff;
    imageY0 = sgpuData[3] & iGPUHeightMask;
    imageX1 = sgpuData[4] & 0x03ff;
    imageY1 = sgpuData[5] & iGPUHeightMask;
    imageSX = sgpuData[6];
    imageSY = sgpuData[7];

    if ((imageX0 == imageX1) && (imageY0 == imageY1)) return;
    if (imageSX <= 0) return;
    if (imageSY <= 0) return;

    // ZN SF2: screwed moves
    //
    // move sgpuData[2],sgpuData[3],sgpuData[4],sgpuData[5],sgpuData[6],sgpuData[7]
    //
    // move 365 182 32723 -21846 17219  15427
    // move 127 160 147   -1     20817  13409
    // move 141 165 16275 -21862 -32126 13442
    // move 161 136 24620 -1     16962  13388
    // move 168 138 32556 -13090 -29556 15500
    //
    // and here's the hack for it:

    if (iGPUHeight == 1024 && sgpuData[7] > 1024) return;

    if ((imageY0 + imageSY) > iGPUHeight || (imageX0 + imageSX) > 1024 || (imageY1 + imageSY) > iGPUHeight ||
        (imageX1 + imageSX) > 1024) {
        int i, j;
        for (j = 0; j < imageSY; j++)
            for (i = 0; i < imageSX; i++)
                psxVuw[(1024 * ((imageY1 + j) & iGPUHeightMask)) + ((imageX1 + i) & 0x3ff)] =
                    psxVuw[(1024 * ((imageY0 + j) & iGPUHeightMask)) + ((imageX0 + i) & 0x3ff)];

        bDoVSyncUpdate = true;

        return;
    }

    if (imageSX & 1)  // not dword aligned? slower func
    {
        uint16_t *SRCPtr, *DSTPtr;
        uint16_t LineOffset;

        SRCPtr = psxVuw + (1024 * imageY0) + imageX0;
        DSTPtr = psxVuw + (1024 * imageY1) + imageX1;

        LineOffset = 1024 - imageSX;

        for (j = 0; j < imageSY; j++) {
            for (i = 0; i < imageSX; i++) *DSTPtr++ = *SRCPtr++;
            SRCPtr += LineOffset;
            DSTPtr += LineOffset;
        }
    } else  // dword aligned
    {
        uint32_t *SRCPtr, *DSTPtr;
        uint16_t LineOffset;
        int dx = imageSX >> 1;

        SRCPtr = (uint32_t *)(psxVuw + (1024 * imageY0) + imageX0);
        DSTPtr = (uint32_t *)(psxVuw + (1024 * imageY1) + imageX1);

        LineOffset = 512 - dx;

        for (j = 0; j < imageSY; j++) {
            for (i = 0; i < dx; i++) *DSTPtr++ = *SRCPtr++;
            SRCPtr += LineOffset;
            DSTPtr += LineOffset;
        }
    }

    imageSX += imageX1;
    imageSY += imageY1;

    /*
     if(!PSXDisplay.Interlaced)                            // stupid frame skip stuff
      {
       if(UseFrameSkip &&
          imageX1<PSXDisplay.DisplayEnd.x &&
          imageSX>=PSXDisplay.DisplayPosition.x &&
          imageY1<PSXDisplay.DisplayEnd.y &&
          imageSY>=PSXDisplay.DisplayPosition.y)
        updateDisplay();
      }
    */

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: draw free-size Tile
////////////////////////////////////////////////////////////////////////

//#define SMALLDEBUG
//#include <dbgout.h>

void PCSX::GPU::Prim::primTileS(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);
    int16_t sW = sgpuData[4] & 0x3ff;
    int16_t sH = sgpuData[5] & iGPUHeightMask;  // mmm... limit tiles to 0x1ff or height?

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];

    if (!(dwActFixes & 8)) AdjustCoord1();

    // x and y of start
    ly2 = ly3 = ly0 + sH + PSXDisplay.DrawOffset.y;
    ly0 = ly1 = ly0 + PSXDisplay.DrawOffset.y;
    lx1 = lx2 = lx0 + sW + PSXDisplay.DrawOffset.x;
    lx0 = lx3 = lx0 + PSXDisplay.DrawOffset.x;

    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));

    if (!(iTileCheat && sH == 32 && gpuData[0] == 0x60ffffff))  // special cheat for certain ZiNc games
        FillSoftwareAreaTrans(lx0, ly0, lx2, ly2, BGR24to16(gpuData[0]));

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: draw 1 dot Tile (point)
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primTile1(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);
    int16_t sH = 1;
    int16_t sW = 1;

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];

    if (!(dwActFixes & 8)) AdjustCoord1();

    // x and y of start
    ly2 = ly3 = ly0 + sH + PSXDisplay.DrawOffset.y;
    ly0 = ly1 = ly0 + PSXDisplay.DrawOffset.y;
    lx1 = lx2 = lx0 + sW + PSXDisplay.DrawOffset.x;
    lx0 = lx3 = lx0 + PSXDisplay.DrawOffset.x;

    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));

    FillSoftwareAreaTrans(lx0, ly0, lx2, ly2,
                          BGR24to16(gpuData[0]));  // Takes Start and Offset

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: draw 8 dot Tile (small rect)
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primTile8(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);
    int16_t sH = 8;
    int16_t sW = 8;

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];

    if (!(dwActFixes & 8)) AdjustCoord1();

    // x and y of start
    ly2 = ly3 = ly0 + sH + PSXDisplay.DrawOffset.y;
    ly0 = ly1 = ly0 + PSXDisplay.DrawOffset.y;
    lx1 = lx2 = lx0 + sW + PSXDisplay.DrawOffset.x;
    lx0 = lx3 = lx0 + PSXDisplay.DrawOffset.x;

    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));

    FillSoftwareAreaTrans(lx0, ly0, lx2, ly2,
                          BGR24to16(gpuData[0]));  // Takes Start and Offset

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: draw 16 dot Tile (medium rect)
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primTile16(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);
    int16_t sH = 16;
    int16_t sW = 16;

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];

    if (!(dwActFixes & 8)) AdjustCoord1();

    // x and y of start
    ly2 = ly3 = ly0 + sH + PSXDisplay.DrawOffset.y;
    ly0 = ly1 = ly0 + PSXDisplay.DrawOffset.y;
    lx1 = lx2 = lx0 + sW + PSXDisplay.DrawOffset.x;
    lx0 = lx3 = lx0 + PSXDisplay.DrawOffset.x;

    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));

    FillSoftwareAreaTrans(lx0, ly0, lx2, ly2,
                          BGR24to16(gpuData[0]));  // Takes Start and Offset

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: small sprite (textured rect)
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primSprt8(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];

    if (!(dwActFixes & 8)) AdjustCoord1();

    SetRenderMode(gpuData[0]);

    if (bUsingTWin)
        DrawSoftwareSpriteTWin(baseAddr, 8, 8);
    else if (usMirror)
        DrawSoftwareSpriteMirror(baseAddr, 8, 8);
    else
        DrawSoftwareSprite(baseAddr, 8, 8, baseAddr[8], baseAddr[9]);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: medium sprite (textured rect)
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primSprt16(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];

    if (!(dwActFixes & 8)) AdjustCoord1();

    SetRenderMode(gpuData[0]);

    if (bUsingTWin)
        DrawSoftwareSpriteTWin(baseAddr, 16, 16);
    else if (usMirror)
        DrawSoftwareSpriteMirror(baseAddr, 16, 16);
    else
        DrawSoftwareSprite(baseAddr, 16, 16, baseAddr[8], baseAddr[9]);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: free-size sprite (textured rect)
////////////////////////////////////////////////////////////////////////

// func used on texture coord wrap
void PCSX::GPU::Prim::primSprtSRest(uint8_t *baseAddr, uint16_t type) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);
    uint16_t sTypeRest = 0;

    int16_t s;
    int16_t sX = sgpuData[2];
    int16_t sY = sgpuData[3];
    int16_t sW = sgpuData[6] & 0x3ff;
    int16_t sH = sgpuData[7] & 0x1ff;
    int16_t tX = baseAddr[8];
    int16_t tY = baseAddr[9];

    switch (type) {
        case 1:
            s = 256 - baseAddr[8];
            sW -= s;
            sX += s;
            tX = 0;
            break;
        case 2:
            s = 256 - baseAddr[9];
            sH -= s;
            sY += s;
            tY = 0;
            break;
        case 3:
            s = 256 - baseAddr[8];
            sW -= s;
            sX += s;
            tX = 0;
            s = 256 - baseAddr[9];
            sH -= s;
            sY += s;
            tY = 0;
            break;
        case 4:
            s = 512 - baseAddr[8];
            sW -= s;
            sX += s;
            tX = 0;
            break;
        case 5:
            s = 512 - baseAddr[9];
            sH -= s;
            sY += s;
            tY = 0;
            break;
        case 6:
            s = 512 - baseAddr[8];
            sW -= s;
            sX += s;
            tX = 0;
            s = 512 - baseAddr[9];
            sH -= s;
            sY += s;
            tY = 0;
            break;
    }

    SetRenderMode(gpuData[0]);

    if (tX + sW > 256) {
        sW = 256 - tX;
        sTypeRest += 1;
    }
    if (tY + sH > 256) {
        sH = 256 - tY;
        sTypeRest += 2;
    }

    lx0 = sX;
    ly0 = sY;

    if (!(dwActFixes & 8)) AdjustCoord1();

    DrawSoftwareSprite(baseAddr, sW, sH, tX, tY);

    if (sTypeRest && type < 4) {
        if (sTypeRest & 1 && type == 1) primSprtSRest(baseAddr, 4);
        if (sTypeRest & 2 && type == 2) primSprtSRest(baseAddr, 5);
        if (sTypeRest == 3 && type == 3) primSprtSRest(baseAddr, 6);
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primSprtS(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);
    int16_t sW, sH;

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];

    if (!(dwActFixes & 8)) AdjustCoord1();

    sW = sgpuData[6] & 0x3ff;
    sH = sgpuData[7] & 0x1ff;

    SetRenderMode(gpuData[0]);

    if (bUsingTWin)
        DrawSoftwareSpriteTWin(baseAddr, sW, sH);
    else if (usMirror)
        DrawSoftwareSpriteMirror(baseAddr, sW, sH);
    else {
        uint16_t sTypeRest = 0;
        int16_t tX = baseAddr[8];
        int16_t tY = baseAddr[9];

        if (tX + sW > 256) {
            sW = 256 - tX;
            sTypeRest += 1;
        }
        if (tY + sH > 256) {
            sH = 256 - tY;
            sTypeRest += 2;
        }

        DrawSoftwareSprite(baseAddr, sW, sH, tX, tY);

        if (sTypeRest) {
            if (sTypeRest & 1) primSprtSRest(baseAddr, 1);
            if (sTypeRest & 2) primSprtSRest(baseAddr, 2);
            if (sTypeRest == 3) primSprtSRest(baseAddr, 3);
        }
    }

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: flat shaded Poly4
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primPolyF4(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];
    lx1 = sgpuData[4];
    ly1 = sgpuData[5];
    lx2 = sgpuData[6];
    ly2 = sgpuData[7];
    lx3 = sgpuData[8];
    ly3 = sgpuData[9];

    if (!(dwActFixes & 8)) {
        AdjustCoord4();
        if (CheckCoord4()) return;
    }

    offsetPSX4();
    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));

    drawPoly4F(gpuData[0]);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: smooth shaded Poly4
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primPolyG4(uint8_t *baseAddr) {
    uint32_t *gpuData = (uint32_t *)baseAddr;
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];
    lx1 = sgpuData[6];
    ly1 = sgpuData[7];
    lx2 = sgpuData[10];
    ly2 = sgpuData[11];
    lx3 = sgpuData[14];
    ly3 = sgpuData[15];

    if (!(dwActFixes & 8)) {
        AdjustCoord4();
        if (CheckCoord4()) return;
    }

    offsetPSX4();
    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));

    drawPoly4G(gpuData[0], gpuData[2], gpuData[4], gpuData[6]);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: flat shaded Texture3
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primPolyFT3(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];
    lx1 = sgpuData[6];
    ly1 = sgpuData[7];
    lx2 = sgpuData[10];
    ly2 = sgpuData[11];

    lLowerpart = gpuData[4] >> 16;
    UpdateGlobalTP((uint16_t)lLowerpart);

    if (!(dwActFixes & 8)) {
        AdjustCoord3();
        if (CheckCoord3()) return;
    }

    offsetPSX3();
    SetRenderMode(gpuData[0]);

    drawPoly3FT(baseAddr);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: flat shaded Texture4
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primPolyFT4(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];
    lx1 = sgpuData[6];
    ly1 = sgpuData[7];
    lx2 = sgpuData[10];
    ly2 = sgpuData[11];
    lx3 = sgpuData[14];
    ly3 = sgpuData[15];

    lLowerpart = gpuData[4] >> 16;
    UpdateGlobalTP((uint16_t)lLowerpart);

    if (!(dwActFixes & 8)) {
        AdjustCoord4();
        if (CheckCoord4()) return;
    }

    offsetPSX4();

    SetRenderMode(gpuData[0]);

    drawPoly4FT(baseAddr);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: smooth shaded Texture3
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primPolyGT3(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];
    lx1 = sgpuData[8];
    ly1 = sgpuData[9];
    lx2 = sgpuData[14];
    ly2 = sgpuData[15];

    lLowerpart = gpuData[5] >> 16;
    UpdateGlobalTP((uint16_t)lLowerpart);

    if (!(dwActFixes & 8)) {
        AdjustCoord3();
        if (CheckCoord3()) return;
    }

    offsetPSX3();
    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));

    if (SHADETEXBIT(gpuData[0])) {
        gpuData[0] = (gpuData[0] & 0xff000000) | 0x00808080;
        gpuData[3] = (gpuData[3] & 0xff000000) | 0x00808080;
        gpuData[6] = (gpuData[6] & 0xff000000) | 0x00808080;
    }

    drawPoly3GT(baseAddr);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: smooth shaded Poly3
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primPolyG3(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];
    lx1 = sgpuData[6];
    ly1 = sgpuData[7];
    lx2 = sgpuData[10];
    ly2 = sgpuData[11];

    if (!(dwActFixes & 8)) {
        AdjustCoord3();
        if (CheckCoord3()) return;
    }

    offsetPSX3();
    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));

    drawPoly3G(gpuData[0], gpuData[2], gpuData[4]);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: smooth shaded Texture4
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primPolyGT4(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];
    lx1 = sgpuData[8];
    ly1 = sgpuData[9];
    lx2 = sgpuData[14];
    ly2 = sgpuData[15];
    lx3 = sgpuData[20];
    ly3 = sgpuData[21];

    lLowerpart = gpuData[5] >> 16;
    UpdateGlobalTP((uint16_t)lLowerpart);

    if (!(dwActFixes & 8)) {
        AdjustCoord4();
        if (CheckCoord4()) return;
    }

    offsetPSX4();
    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));

    if (SHADETEXBIT(gpuData[0])) {
        gpuData[0] = (gpuData[0] & 0xff000000) | 0x00808080;
        gpuData[3] = (gpuData[3] & 0xff000000) | 0x00808080;
        gpuData[6] = (gpuData[6] & 0xff000000) | 0x00808080;
        gpuData[9] = (gpuData[9] & 0xff000000) | 0x00808080;
    }

    drawPoly4GT(baseAddr);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: smooth shaded Poly3
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primPolyF3(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];
    lx1 = sgpuData[4];
    ly1 = sgpuData[5];
    lx2 = sgpuData[6];
    ly2 = sgpuData[7];

    if (!(dwActFixes & 8)) {
        AdjustCoord3();
        if (CheckCoord3()) return;
    }

    offsetPSX3();
    SetRenderMode(gpuData[0]);

    drawPoly3F(gpuData[0]);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: skipping shaded polylines
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primLineGSkip(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int iMax = 255;
    int i = 2;

    ly1 = (int16_t)((gpuData[1] >> 16) & 0xffff);
    lx1 = (int16_t)(gpuData[1] & 0xffff);

    while (!(((gpuData[i] & 0xF000F000) == 0x50005000) && i >= 4)) {
        i++;
        ly1 = (int16_t)((gpuData[i] >> 16) & 0xffff);
        lx1 = (int16_t)(gpuData[i] & 0xffff);
        i++;
        if (i > iMax) break;
    }
}

////////////////////////////////////////////////////////////////////////
// cmd: shaded polylines
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primLineGEx(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int iMax = 255;
    uint32_t lc0, lc1;
    int16_t slx0, slx1, sly0, sly1;
    int i = 2;
    bool bDraw = true;

    sly1 = (int16_t)((gpuData[1] >> 16) & 0xffff);
    slx1 = (int16_t)(gpuData[1] & 0xffff);

    if (!(dwActFixes & 8)) {
        slx1 = (int16_t)(((int)slx1 << SIGNSHIFT) >> SIGNSHIFT);
        sly1 = (int16_t)(((int)sly1 << SIGNSHIFT) >> SIGNSHIFT);
    }

    lc1 = gpuData[0] & 0xffffff;

    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));

    while (!(((gpuData[i] & 0xF000F000) == 0x50005000) && i >= 4)) {
        sly0 = sly1;
        slx0 = slx1;
        lc0 = lc1;
        lc1 = gpuData[i] & 0xffffff;

        i++;

        // no check needed on gshaded polyline positions
        // if((gpuData[i] & 0xF000F000) == 0x50005000) break;

        sly1 = (int16_t)((gpuData[i] >> 16) & 0xffff);
        slx1 = (int16_t)(gpuData[i] & 0xffff);

        if (!(dwActFixes & 8)) {
            slx1 = (int16_t)(((int)slx1 << SIGNSHIFT) >> SIGNSHIFT);
            sly1 = (int16_t)(((int)sly1 << SIGNSHIFT) >> SIGNSHIFT);
            bDraw = CheckCoordL(slx0, sly0, slx1, sly1);
        }

        if ((lx0 != lx1) || (ly0 != ly1)) {
            ly0 = sly0;
            lx0 = slx0;
            ly1 = sly1;
            lx1 = slx1;

            offsetPSX2();
            if (bDraw) DrawSoftwareLineShade(lc0, lc1);
        }
        i++;
        if (i > iMax) break;
    }

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: shaded polyline2
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primLineG2(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];
    lx1 = sgpuData[6];
    ly1 = sgpuData[7];

    if (!(dwActFixes & 8)) {
        AdjustCoord2();
        if (CheckCoord2()) return;
    }

    if ((lx0 == lx1) && (ly0 == ly1)) {
        lx1++;
        ly1++;
    }

    DrawSemiTrans = (SEMITRANSBIT(gpuData[0]));
    offsetPSX2();
    DrawSoftwareLineShade(gpuData[0], gpuData[2]);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: skipping flat polylines
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primLineFSkip(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int i = 2, iMax = 255;

    ly1 = (int16_t)((gpuData[1] >> 16) & 0xffff);
    lx1 = (int16_t)(gpuData[1] & 0xffff);

    while (!(((gpuData[i] & 0xF000F000) == 0x50005000) && i >= 3)) {
        ly1 = (int16_t)((gpuData[i] >> 16) & 0xffff);
        lx1 = (int16_t)(gpuData[i] & 0xffff);
        i++;
        if (i > iMax) break;
    }
}

////////////////////////////////////////////////////////////////////////
// cmd: drawing flat polylines
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primLineFEx(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int iMax;
    int16_t slx0, slx1, sly0, sly1;
    int i = 2;
    bool bDraw = true;

    iMax = 255;

    sly1 = (int16_t)((gpuData[1] >> 16) & 0xffff);
    slx1 = (int16_t)(gpuData[1] & 0xffff);
    if (!(dwActFixes & 8)) {
        slx1 = (int16_t)(((int)slx1 << SIGNSHIFT) >> SIGNSHIFT);
        sly1 = (int16_t)(((int)sly1 << SIGNSHIFT) >> SIGNSHIFT);
    }

    SetRenderMode(gpuData[0]);

    while (!(((gpuData[i] & 0xF000F000) == 0x50005000) && i >= 3)) {
        sly0 = sly1;
        slx0 = slx1;
        sly1 = (int16_t)((gpuData[i] >> 16) & 0xffff);
        slx1 = (int16_t)(gpuData[i] & 0xffff);
        if (!(dwActFixes & 8)) {
            slx1 = (int16_t)(((int)slx1 << SIGNSHIFT) >> SIGNSHIFT);
            sly1 = (int16_t)(((int)sly1 << SIGNSHIFT) >> SIGNSHIFT);

            bDraw = CheckCoordL(slx0, sly0, slx1, sly1);
        }

        ly0 = sly0;
        lx0 = slx0;
        ly1 = sly1;
        lx1 = slx1;

        offsetPSX2();
        if (bDraw) DrawSoftwareLineFlat(gpuData[0]);

        i++;
        if (i > iMax) break;
    }

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: drawing flat polyline2
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primLineF2(uint8_t *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);
    int16_t *sgpuData = ((int16_t *)baseAddr);

    lx0 = sgpuData[2];
    ly0 = sgpuData[3];
    lx1 = sgpuData[4];
    ly1 = sgpuData[5];

    if (!(dwActFixes & 8)) {
        AdjustCoord2();
        if (CheckCoord2()) return;
    }

    if ((lx0 == lx1) && (ly0 == ly1)) {
        lx1++;
        ly1++;
    }

    offsetPSX2();
    SetRenderMode(gpuData[0]);

    DrawSoftwareLineFlat(gpuData[0]);

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// cmd: well, easiest command... not implemented
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::Prim::primNI(uint8_t *baseAddr) {}

////////////////////////////////////////////////////////////////////////
// cmd func ptr table
////////////////////////////////////////////////////////////////////////

const PCSX::GPU::Prim::func_t PCSX::GPU::Prim::funcs[256] = {
    &Prim::primNI,         &Prim::primNI,         &Prim::primBlkFill,      &Prim::primNI,            // 00
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 04
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 08
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 0c
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 10
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 14
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 18
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 1c
    &Prim::primPolyF3,     &Prim::primPolyF3,     &Prim::primPolyF3,       &Prim::primPolyF3,        // 20
    &Prim::primPolyFT3,    &Prim::primPolyFT3,    &Prim::primPolyFT3,      &Prim::primPolyFT3,       // 24
    &Prim::primPolyF4,     &Prim::primPolyF4,     &Prim::primPolyF4,       &Prim::primPolyF4,        // 28
    &Prim::primPolyFT4,    &Prim::primPolyFT4,    &Prim::primPolyFT4,      &Prim::primPolyFT4,       // 2c
    &Prim::primPolyG3,     &Prim::primPolyG3,     &Prim::primPolyG3,       &Prim::primPolyG3,        // 30
    &Prim::primPolyGT3,    &Prim::primPolyGT3,    &Prim::primPolyGT3,      &Prim::primPolyGT3,       // 34
    &Prim::primPolyG4,     &Prim::primPolyG4,     &Prim::primPolyG4,       &Prim::primPolyG4,        // 38
    &Prim::primPolyGT4,    &Prim::primPolyGT4,    &Prim::primPolyGT4,      &Prim::primPolyGT4,       // 3c
    &Prim::primLineF2,     &Prim::primLineF2,     &Prim::primLineF2,       &Prim::primLineF2,        // 40
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 44
    &Prim::primLineFEx,    &Prim::primLineFEx,    &Prim::primLineFEx,      &Prim::primLineFEx,       // 48
    &Prim::primLineFEx,    &Prim::primLineFEx,    &Prim::primLineFEx,      &Prim::primLineFEx,       // 4c
    &Prim::primLineG2,     &Prim::primLineG2,     &Prim::primLineG2,       &Prim::primLineG2,        // 50
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 54
    &Prim::primLineGEx,    &Prim::primLineGEx,    &Prim::primLineGEx,      &Prim::primLineGEx,       // 58
    &Prim::primLineGEx,    &Prim::primLineGEx,    &Prim::primLineGEx,      &Prim::primLineGEx,       // 5c
    &Prim::primTileS,      &Prim::primTileS,      &Prim::primTileS,        &Prim::primTileS,         // 60
    &Prim::primSprtS,      &Prim::primSprtS,      &Prim::primSprtS,        &Prim::primSprtS,         // 64
    &Prim::primTile1,      &Prim::primTile1,      &Prim::primTile1,        &Prim::primTile1,         // 68
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 6c
    &Prim::primTile8,      &Prim::primTile8,      &Prim::primTile8,        &Prim::primTile8,         // 70
    &Prim::primSprt8,      &Prim::primSprt8,      &Prim::primSprt8,        &Prim::primSprt8,         // 74
    &Prim::primTile16,     &Prim::primTile16,     &Prim::primTile16,       &Prim::primTile16,        // 78
    &Prim::primSprt16,     &Prim::primSprt16,     &Prim::primSprt16,       &Prim::primSprt16,        // 7c
    &Prim::primMoveImage,  &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 80
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 84
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 88
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 8c
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 90
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 94
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 98
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 9c
    &Prim::primLoadImage,  &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // a0
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // a4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // a8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // ac
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // b0
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // b4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // b8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // bc
    &Prim::primStoreImage, &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // c0
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // c4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // c8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // cc
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // d0
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // d4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // d8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // dc
    &Prim::primNI,         &Prim::cmdTexturePage, &Prim::cmdTextureWindow, &Prim::cmdDrawAreaStart,  // e0
    &Prim::cmdDrawAreaEnd, &Prim::cmdDrawOffset,  &Prim::cmdSTP,           &Prim::primNI,            // e4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // e8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // ec
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // f0
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // f4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // f8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // fc
};

////////////////////////////////////////////////////////////////////////
// cmd func ptr table for skipping
////////////////////////////////////////////////////////////////////////

const PCSX::GPU::Prim::func_t PCSX::GPU::Prim::skip[256] = {
    &Prim::primNI,         &Prim::primNI,         &Prim::primBlkFill,      &Prim::primNI,            // 00
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 04
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 08
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 0c
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 10
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 14
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 18
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 1c
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 20
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 24
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 28
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 2c
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 30
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 34
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 38
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 3c
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 40
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 44
    &Prim::primLineFSkip,  &Prim::primLineFSkip,  &Prim::primLineFSkip,    &Prim::primLineFSkip,     // 48
    &Prim::primLineFSkip,  &Prim::primLineFSkip,  &Prim::primLineFSkip,    &Prim::primLineFSkip,     // 4c
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 50
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 54
    &Prim::primLineGSkip,  &Prim::primLineGSkip,  &Prim::primLineGSkip,    &Prim::primLineGSkip,     // 58
    &Prim::primLineGSkip,  &Prim::primLineGSkip,  &Prim::primLineGSkip,    &Prim::primLineGSkip,     // 5c
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 60
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 64
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 68
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 6c
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 70
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 74
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 78
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 7c
    &Prim::primMoveImage,  &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 80
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 84
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 88
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 8c
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 90
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 94
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 98
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // 9c
    &Prim::primLoadImage,  &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // a0
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // a4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // a8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // ac
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // b0
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // b4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // b8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // bc
    &Prim::primStoreImage, &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // c0
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // c4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // c8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // cc
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // d0
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // d4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // d8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // dc
    &Prim::primNI,         &Prim::cmdTexturePage, &Prim::cmdTextureWindow, &Prim::cmdDrawAreaStart,  // e0
    &Prim::cmdDrawAreaEnd, &Prim::cmdDrawOffset,  &Prim::cmdSTP,           &Prim::primNI,            // e4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // e8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // ec
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // f0
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // f4
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // f8
    &Prim::primNI,         &Prim::primNI,         &Prim::primNI,           &Prim::primNI,            // fc
};
