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

#include <algorithm>
#include <cstdint>

#ifdef _WIN32
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#endif

#include "core/debug.h"
#include "core/psxemulator.h"
#include "gpu/soft/externals.h"
#include "gpu/soft/gpu.h"
#include "gpu/soft/interface.h"
#include "gpu/soft/soft.h"
#include "imgui.h"
#include "tracy/Tracy.hpp"

////////////////////////////////////////////////////////////////////////
// memory image of the PSX vram
////////////////////////////////////////////////////////////////////////

unsigned char *psxVSecure;
unsigned char *psxVub;
signed char *psxVsb;
uint16_t *psxVuw;
uint16_t *psxVuw_eom;
int16_t *psxVsw;
uint32_t *psxVul;
int32_t *psxVsl;

// GPU globals
int32_t lGPUstatusRet;

int16_t sDispWidths[8] = {256, 320, 512, 640, 368, 384, 512, 640};
PSXDisplay_t PSXDisplay;
PSXDisplay_t PreviousPSXDisplay;
bool bDoLazyUpdate = false;
uint32_t lGPUInfoVals[16];

int32_t PCSX::SoftGPU::impl::initBackend(GUI *gui) {
    m_gui = gui;
    bDoVSyncUpdate = true;
    initDisplay();

    // always alloc one extra MB for soft drawing funcs security
    psxVSecure = new uint8_t[(iGPUHeight * 2) * 1024 + (1024 * 1024)]();
    if (!psxVSecure) return -1;

    //!!! ATTENTION !!!
    psxVub = psxVSecure + 512 * 1024;  // security offset into double sized psx vram!

    psxVsb = (signed char *)psxVub;  // different ways of accessing PSX VRAM
    psxVsw = (int16_t *)psxVub;
    psxVsl = (int32_t *)psxVub;
    psxVuw = (uint16_t *)psxVub;
    psxVul = (uint32_t *)psxVub;

    psxVuw_eom = psxVuw + 1024 * iGPUHeight;  // pre-calc of end of vram

    memset(lGPUInfoVals, 0x00, 16 * sizeof(uint32_t));

    PSXDisplay.RGB24 = false;  // init some stuff
    PSXDisplay.Interlaced = false;
    PSXDisplay.DrawOffset.x = 0;
    PSXDisplay.DrawOffset.y = 0;
    PSXDisplay.DisplayMode.x = 320;
    PSXDisplay.DisplayMode.y = 240;
    PreviousPSXDisplay.DisplayMode.x = 320;
    PreviousPSXDisplay.DisplayMode.y = 240;
    PSXDisplay.Disabled = false;
    PreviousPSXDisplay.Range.x0 = 0;
    PreviousPSXDisplay.Range.y0 = 0;
    PSXDisplay.Range.x0 = 0;
    PSXDisplay.Range.x1 = 0;
    PreviousPSXDisplay.DisplayModeNew.y = 0;
    PSXDisplay.Double = 1;
    lGPUdataRet = 0x400;

    // device initialised already !
    lGPUstatusRet = 0x14802000;
    GPUIsIdle;
    GPUIsReadyForCommands;

    return 0;
}

int32_t PCSX::SoftGPU::impl::shutdown() {
    delete[] psxVSecure;
    return 0;
}

std::unique_ptr<PCSX::GPU> PCSX::GPU::getSoft() { return std::unique_ptr<PCSX::GPU>(new PCSX::SoftGPU::impl()); }

void PCSX::SoftGPU::impl::updateDisplay() {
    if (PSXDisplay.Disabled) {
        glClearColor(1, 0, 0, 0);
        glClear(GL_COLOR_BUFFER_BIT);
        return;
    }

    doBufferSwap();
}

////////////////////////////////////////////////////////////////////////
// roughly emulated screen centering bits... not complete !!!
////////////////////////////////////////////////////////////////////////

void ChangeDispOffsetsX() {
    if (!PSXDisplay.Range.x1) return;

    int32_t l = PreviousPSXDisplay.DisplayMode.x;

    l *= (int32_t)PSXDisplay.Range.x1;
    l /= 2560;
    int32_t lx = l;
    l &= 0xfffffff8;

    if (l == PreviousPSXDisplay.Range.y1) return;  // abusing range.y1 for
    PreviousPSXDisplay.Range.y1 = (int16_t)l;      // storing last x range and test

    if (lx >= PreviousPSXDisplay.DisplayMode.x) {
        PreviousPSXDisplay.Range.x1 = (int16_t)PreviousPSXDisplay.DisplayMode.x;
        PreviousPSXDisplay.Range.x0 = 0;
    } else {
        PreviousPSXDisplay.Range.x1 = (int16_t)l;

        PreviousPSXDisplay.Range.x0 = (PSXDisplay.Range.x0 - 500) / 8;

        if (PreviousPSXDisplay.Range.x0 < 0) PreviousPSXDisplay.Range.x0 = 0;

        if ((PreviousPSXDisplay.Range.x0 + lx) > PreviousPSXDisplay.DisplayMode.x) {
            PreviousPSXDisplay.Range.x0 = (int16_t)(PreviousPSXDisplay.DisplayMode.x - lx);
            PreviousPSXDisplay.Range.x0 += 2;  //???

            PreviousPSXDisplay.Range.x1 += (int16_t)(lx - l);
        }
        glClearColor(1, 0, 0, 0);
        glClear(GL_COLOR_BUFFER_BIT);
    }

    bDoVSyncUpdate = true;
}

void ChangeDispOffsetsY() {
    int iT, iO = PreviousPSXDisplay.Range.y0;
    int iOldYOffset = PreviousPSXDisplay.DisplayModeNew.y;

    if ((PreviousPSXDisplay.DisplayModeNew.x + PSXDisplay.DisplayModeNew.y) > iGPUHeight) {
        int dy1 = iGPUHeight - PreviousPSXDisplay.DisplayModeNew.x;
        int dy2 = (PreviousPSXDisplay.DisplayModeNew.x + PSXDisplay.DisplayModeNew.y) - iGPUHeight;

        if (dy1 >= dy2) {
            PreviousPSXDisplay.DisplayModeNew.y = -dy2;
        } else {
            PSXDisplay.DisplayPosition.y = 0;
            PreviousPSXDisplay.DisplayModeNew.y = -dy1;
        }
    } else
        PreviousPSXDisplay.DisplayModeNew.y = 0;

    if (PreviousPSXDisplay.DisplayModeNew.y != iOldYOffset)  // if old offset!=new offset: recalc height
    {
        PSXDisplay.Height = PSXDisplay.Range.y1 - PSXDisplay.Range.y0 + PreviousPSXDisplay.DisplayModeNew.y;
        PSXDisplay.DisplayModeNew.y = PSXDisplay.Height * PSXDisplay.Double;
    }

    if (PSXDisplay.PAL)
        iT = 48;
    else
        iT = 28;

    if (PSXDisplay.Range.y0 >= iT) {
        PreviousPSXDisplay.Range.y0 = (int16_t)((PSXDisplay.Range.y0 - iT - 4) * PSXDisplay.Double);
        if (PreviousPSXDisplay.Range.y0 < 0) PreviousPSXDisplay.Range.y0 = 0;
        PSXDisplay.DisplayModeNew.y += PreviousPSXDisplay.Range.y0;
    } else
        PreviousPSXDisplay.Range.y0 = 0;

    if (iO != PreviousPSXDisplay.Range.y0) {
        glClearColor(1, 0, 0, 0);
        glClear(GL_COLOR_BUFFER_BIT);
    }
}

////////////////////////////////////////////////////////////////////////
// check if update needed
////////////////////////////////////////////////////////////////////////

void updateDisplayIfChanged() {
    if ((PSXDisplay.DisplayMode.y == PSXDisplay.DisplayModeNew.y) &&
        (PSXDisplay.DisplayMode.x == PSXDisplay.DisplayModeNew.x)) {
        if ((PSXDisplay.RGB24 == PSXDisplay.RGB24New) && (PSXDisplay.Interlaced == PSXDisplay.InterlacedNew)) return;
    }

    PSXDisplay.RGB24 = PSXDisplay.RGB24New;  // get new infos

    PSXDisplay.DisplayMode.y = PSXDisplay.DisplayModeNew.y;
    PSXDisplay.DisplayMode.x = PSXDisplay.DisplayModeNew.x;
    PreviousPSXDisplay.DisplayMode.x =            // previous will hold
        std::min(640, PSXDisplay.DisplayMode.x);  // max 640x512... that's
    PreviousPSXDisplay.DisplayMode.y =            // the size of my
        std::min(512, PSXDisplay.DisplayMode.y);  // back buffer surface
    PSXDisplay.Interlaced = PSXDisplay.InterlacedNew;

    PSXDisplay.DisplayEnd.x =  // calc end of display
        PSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
    PSXDisplay.DisplayEnd.y =
        PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;
    PreviousPSXDisplay.DisplayEnd.x = PreviousPSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
    PreviousPSXDisplay.DisplayEnd.y =
        PreviousPSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;

    ChangeDispOffsetsX();
}

void PCSX::SoftGPU::impl::vblank() {
    if (m_dumpFile) {
        uint32_t data = 0x02000000;
        fwrite(&data, sizeof(data), 1, (FILE *)m_dumpFile);
    }
    lGPUstatusRet ^= 0x80000000;  // odd/even bit

    if (PSXDisplay.Interlaced)  // interlaced mode?
    {
        if (bDoVSyncUpdate && PSXDisplay.DisplayMode.x > 0 && PSXDisplay.DisplayMode.y > 0) {
            updateDisplay();
        }
    } else  // non-interlaced?
    {
        // some primitives drawn?
        if (bDoVSyncUpdate) updateDisplay();  // -> update display
    }

    bDoVSyncUpdate = false;  // vsync done
}

////////////////////////////////////////////////////////////////////////
// process read request from GPU status register
////////////////////////////////////////////////////////////////////////

uint32_t PCSX::SoftGPU::impl::readStatusInternal() { return lGPUstatusRet; }

void PCSX::SoftGPU::impl::restoreStatus(uint32_t status) { lGPUstatusRet = status; }

// processes data send to GPU status register
// these are always single packet commands.
void PCSX::SoftGPU::impl::writeStatusInternal(uint32_t gdata) {
    ZoneScoped;
    if (m_dumpFile) {
        uint32_t data = 0x01000001;
        fwrite(&data, sizeof(data), 1, (FILE *)m_dumpFile);
        fwrite(&gdata, sizeof(gdata), 1, (FILE *)m_dumpFile);
    }

    uint32_t lCommand = (gdata >> 24) & 0xff;

    switch (lCommand) {
        // Reset gpu
        case 0x00:
            memset(lGPUInfoVals, 0x00, 16 * sizeof(uint32_t));
            lGPUstatusRet = 0x14802000;
            PSXDisplay.Disabled = 1;
            PSXDisplay.DrawOffset.x = PSXDisplay.DrawOffset.y = 0;
            m_softRenderer.reset();
            acknowledgeIRQ1();
            PSXDisplay.RGB24 = false;
            PSXDisplay.Interlaced = false;
            return;

        // Acknowledge IRQ1
        case 0x02:
            acknowledgeIRQ1();
            return;

        // dis/enable display
        case 0x03:

            PreviousPSXDisplay.Disabled = PSXDisplay.Disabled;
            PSXDisplay.Disabled = (gdata & 1);

            if (PSXDisplay.Disabled)
                lGPUstatusRet |= GPUSTATUS_DISPLAYDISABLED;
            else
                lGPUstatusRet &= ~GPUSTATUS_DISPLAYDISABLED;
            return;

        // setting transfer mode
        case 0x04:
            gdata &= 0x03;  // Only want the lower two bits

            lGPUstatusRet &= ~GPUSTATUS_DMABITS;  // Clear the current settings of the DMA bits
            lGPUstatusRet |= (gdata << 29);       // Set the DMA bits according to the received data

            return;

        // setting display position
        case 0x05: {
            PreviousPSXDisplay.DisplayPosition.x = PSXDisplay.DisplayPosition.x;
            PreviousPSXDisplay.DisplayPosition.y = PSXDisplay.DisplayPosition.y;

            // new
            PSXDisplay.DisplayPosition.y = (int16_t)((gdata >> 10) & 0x1ff);

            // store the same val in some helper var, we need it on later compares
            PreviousPSXDisplay.DisplayModeNew.x = PSXDisplay.DisplayPosition.y;

            if ((PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y) > iGPUHeight) {
                int dy1 = iGPUHeight - PSXDisplay.DisplayPosition.y;
                int dy2 = (PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y) - iGPUHeight;

                if (dy1 >= dy2) {
                    PreviousPSXDisplay.DisplayModeNew.y = -dy2;
                } else {
                    PSXDisplay.DisplayPosition.y = 0;
                    PreviousPSXDisplay.DisplayModeNew.y = -dy1;
                }
            } else
                PreviousPSXDisplay.DisplayModeNew.y = 0;
            // eon

            PSXDisplay.DisplayPosition.x = (int16_t)(gdata & 0x3ff);
            PSXDisplay.DisplayEnd.x = PSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
            PSXDisplay.DisplayEnd.y =
                PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;
            PreviousPSXDisplay.DisplayEnd.x = PreviousPSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
            PreviousPSXDisplay.DisplayEnd.y =
                PreviousPSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;

            bDoVSyncUpdate = true;
        }
            return;

        // setting width
        case 0x06:

            PSXDisplay.Range.x0 = (int16_t)(gdata & 0x7ff);
            PSXDisplay.Range.x1 = (int16_t)((gdata >> 12) & 0xfff);
            PSXDisplay.Range.x1 -= PSXDisplay.Range.x0;
            ChangeDispOffsetsX();
            return;

        // setting height
        case 0x07: {
            PSXDisplay.Range.y0 = (int16_t)(gdata & 0x3ff);
            PSXDisplay.Range.y1 = (int16_t)((gdata >> 10) & 0x3ff);

            PreviousPSXDisplay.Height = PSXDisplay.Height;

            PSXDisplay.Height = PSXDisplay.Range.y1 - PSXDisplay.Range.y0 + PreviousPSXDisplay.DisplayModeNew.y;

            if (PreviousPSXDisplay.Height != PSXDisplay.Height) {
                PSXDisplay.DisplayModeNew.y = PSXDisplay.Height * PSXDisplay.Double;

                ChangeDispOffsetsY();

                updateDisplayIfChanged();
            }
            return;
        }

        // setting display infos
        case 0x08:

            PSXDisplay.DisplayModeNew.x = sDispWidths[(gdata & 0x03) | ((gdata & 0x40) >> 4)];

            if (gdata & 0x04)
                PSXDisplay.Double = 2;
            else
                PSXDisplay.Double = 1;

            PSXDisplay.DisplayModeNew.y = PSXDisplay.Height * PSXDisplay.Double;

            ChangeDispOffsetsY();

            PSXDisplay.PAL = (gdata & 0x08) ? true : false;            // if 1 - PAL mode, else NTSC
            PSXDisplay.RGB24New = (gdata & 0x10) ? true : false;       // if 1 - TrueColor
            PSXDisplay.InterlacedNew = (gdata & 0x20) ? true : false;  // if 1 - Interlace

            if (g_emulator->settings.get<PCSX::Emulator::SettingAutoVideo>()) {
                if (PSXDisplay.PAL) {
                    g_emulator->settings.get<Emulator::SettingVideo>() = Emulator::PSX_TYPE_PAL;
                } else {
                    g_emulator->settings.get<Emulator::SettingVideo>() = Emulator::PSX_TYPE_NTSC;
                }
            }

            lGPUstatusRet &= ~GPUSTATUS_WIDTHBITS;                               // Clear the width bits
            lGPUstatusRet |= (((gdata & 0x03) << 17) | ((gdata & 0x40) << 10));  // Set the width bits

            if (PSXDisplay.InterlacedNew) {
                if (!PSXDisplay.Interlaced) {
                    PreviousPSXDisplay.DisplayPosition.x = PSXDisplay.DisplayPosition.x;
                    PreviousPSXDisplay.DisplayPosition.y = PSXDisplay.DisplayPosition.y;
                }
                lGPUstatusRet |= GPUSTATUS_INTERLACED;
            } else
                lGPUstatusRet &= ~GPUSTATUS_INTERLACED;

            if (PSXDisplay.PAL)
                lGPUstatusRet |= GPUSTATUS_PAL;
            else
                lGPUstatusRet &= ~GPUSTATUS_PAL;

            if (PSXDisplay.Double == 2)
                lGPUstatusRet |= GPUSTATUS_DOUBLEHEIGHT;
            else
                lGPUstatusRet &= ~GPUSTATUS_DOUBLEHEIGHT;

            if (PSXDisplay.RGB24New)
                lGPUstatusRet |= GPUSTATUS_RGB24;
            else
                lGPUstatusRet &= ~GPUSTATUS_RGB24;

            updateDisplayIfChanged();

            return;

        // Ask about GPU version and other stuff
        // We currently only emulate the old GPU version of this command
        case 0x10:
            switch (gdata & 0x7) {
                case 0x02:
                    lGPUdataRet = lGPUInfoVals[INFO_TW];  // tw infos
                    return;
                case 0x03:
                    lGPUdataRet = lGPUInfoVals[INFO_DRAWSTART];  // draw start
                    return;
                case 0x04:
                    lGPUdataRet = lGPUInfoVals[INFO_DRAWEND];  // draw end
                    return;
                case 0x05:
                    lGPUdataRet = lGPUInfoVals[INFO_DRAWOFF];  // draw offset
                    return;
            }
            return;
    }
}

// process gpu commands
uint32_t lUsedAddr[3];

__inline bool CheckForEndlessLoop(uint32_t laddr) {
    if (laddr == lUsedAddr[1]) return true;
    if (laddr == lUsedAddr[2]) return true;

    if (laddr < lUsedAddr[0])
        lUsedAddr[1] = laddr;
    else
        lUsedAddr[2] = laddr;
    lUsedAddr[0] = laddr;
    return false;
}

bool PCSX::SoftGPU::impl::configure() {
    bool changed = false;
    ImGui::SetNextWindowPos(ImVec2(60, 60), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(300, 200), ImGuiCond_FirstUseEver);
    static const char *ditherValues[] = {"No dithering (fastest)", "Game-dependent dithering (slow)",
                                         "Always dither g-shaded polygons (slowest)"};

    if (ImGui::Begin(_("Soft GPU configuration"), &m_showCfg)) {
        if (ImGui::Combo("Dithering", &m_softRenderer.m_useDither, ditherValues, 3)) {
            changed = true;
            g_emulator->settings.get<Emulator::SettingDither>() = m_softRenderer.m_useDither;
        }

        if (ImGui::Checkbox(_("Use linear filtering"),
                            &g_emulator->settings.get<Emulator::SettingLinearFiltering>().value)) {
            changed = true;
            setLinearFiltering();
        }
        ImGui::End();
    }

    return changed;
}

void PCSX::SoftGPU::impl::debug() {
    if (ImGui::Begin(_("Soft GPU debugger"), &m_showDebug)) {
        ImGui::Text(
            _("Debugging featurs are not supported when using the software renderer yet\nConsider enabling the OpenGL "
              "GPU option instead"));
        ImGui::End();
    }
}

static constexpr inline uint16_t BGR24to16(uint32_t BGR) {
    return (uint16_t)(((BGR >> 3) & 0x1f) | ((BGR & 0xf80000) >> 9) | ((BGR & 0xf800) >> 6));
}

void PCSX::SoftGPU::impl::write0(FastFill *prim) {
    int16_t sX = prim->x;
    int16_t sY = prim->y;
    int16_t sW = prim->w;
    int16_t sH = prim->h;

    sW = (sW + 15) & ~15;

    // Increase H & W if they are one int16_t of full values, because they never can be full values
    if (sH >= 1023) sH = 1024;
    if (sW >= 1023) sW = 1024;

    // x and y of end pos
    sW += sX;
    sH += sY;

    m_softRenderer.FillSoftwareArea(sX, sY, sW, sH, BGR24to16(prim->color));

    bDoVSyncUpdate = true;
}

template <PCSX::GPU::Shading shading, PCSX::GPU::Shape shape, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend,
          PCSX::GPU::Modulation modulation>
void PCSX::SoftGPU::impl::polyExec(Poly<shading, shape, textured, blend, modulation> *prim) {
    m_softRenderer.lx0 = prim->x[0];
    m_softRenderer.ly0 = prim->y[0];
    m_softRenderer.lx1 = prim->x[1];
    m_softRenderer.ly1 = prim->y[1];
    m_softRenderer.lx2 = prim->x[2];
    m_softRenderer.ly2 = prim->y[2];
    if constexpr (shape == Shape::Quad) {
        m_softRenderer.lx3 = prim->x[3];
        m_softRenderer.ly3 = prim->y[3];
        if (m_softRenderer.CheckCoord4()) return;
        m_softRenderer.offsetPSX4();
    } else {
        if (m_softRenderer.CheckCoord3()) return;
        m_softRenderer.offsetPSX3();
    }

    m_softRenderer.DrawSemiTrans = blend == Blend::Semi;

    if constexpr (modulation == Modulation::On) {
        m_softRenderer.g_m1 = (prim->colors[0] >> 0) & 0xff;
        m_softRenderer.g_m2 = (prim->colors[0] >> 8) & 0xff;
        m_softRenderer.g_m3 = (prim->colors[0] >> 16) & 0xff;
    } else {
        m_softRenderer.g_m1 = m_softRenderer.g_m2 = m_softRenderer.g_m3 = 128;
    }

    if constexpr (shading == Shading::Flat) {
        if constexpr (textured == Textured::Yes) {
            if (m_softRenderer.iDither) {
                prim->tpage.dither = true;
                prim->tpage.raw |= 0x200;
            }
            m_softRenderer.texturePage(&prim->tpage);
            if constexpr (shape == Shape::Quad) {
                switch (m_softRenderer.GlobalTextTP) {
                    case GPU::TexDepth::Tex4Bits:
                        m_softRenderer.drawPoly4TEx4(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                                     m_softRenderer.ly1, m_softRenderer.lx3, m_softRenderer.ly3,
                                                     m_softRenderer.lx2, m_softRenderer.ly2, prim->u[0], prim->v[0],
                                                     prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2],
                                                     prim->v[2], prim->clutX * 16, prim->clutY);
                        break;
                    case GPU::TexDepth::Tex8Bits:
                        m_softRenderer.drawPoly4TEx8(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                                     m_softRenderer.ly1, m_softRenderer.lx3, m_softRenderer.ly3,
                                                     m_softRenderer.lx2, m_softRenderer.ly2, prim->u[0], prim->v[0],
                                                     prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2],
                                                     prim->v[2], prim->clutX * 16, prim->clutY);
                        break;
                    case GPU::TexDepth::Tex16Bits:
                        m_softRenderer.drawPoly4TD(
                            m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1, m_softRenderer.ly1,
                            m_softRenderer.lx3, m_softRenderer.ly3, m_softRenderer.lx2, m_softRenderer.ly2, prim->u[0],
                            prim->v[0], prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2], prim->v[2]);
                        break;
                }
            } else {
                switch (m_softRenderer.GlobalTextTP) {
                    case GPU::TexDepth::Tex4Bits:
                        m_softRenderer.drawPoly3TEx4(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                                     m_softRenderer.ly1, m_softRenderer.lx2, m_softRenderer.ly2,
                                                     prim->u[0], prim->v[0], prim->u[1], prim->v[1], prim->u[2],
                                                     prim->v[2], prim->clutX * 16, prim->clutY);
                        break;
                    case GPU::TexDepth::Tex8Bits:
                        m_softRenderer.drawPoly3TEx8(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                                     m_softRenderer.ly1, m_softRenderer.lx2, m_softRenderer.ly2,
                                                     prim->u[0], prim->v[0], prim->u[1], prim->v[1], prim->u[2],
                                                     prim->v[2], prim->clutX * 16, prim->clutY);
                        break;
                    case GPU::TexDepth::Tex16Bits:
                        m_softRenderer.drawPoly3TD(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                                   m_softRenderer.ly1, m_softRenderer.lx2, m_softRenderer.ly2,
                                                   prim->u[0], prim->v[0], prim->u[1], prim->v[1], prim->u[2],
                                                   prim->v[2]);
                        break;
                }
            }
        } else {
            if constexpr (shape == Shape::Quad) {
                m_softRenderer.drawPoly4F(prim->colors[0]);
            } else {
                m_softRenderer.drawPoly3F(prim->colors[0]);
            }
        }
    } else {
        if constexpr (textured == Textured::Yes) {
            if (m_softRenderer.iDither) {
                prim->tpage.dither = true;
                prim->tpage.raw |= 0x200;
            }
            m_softRenderer.texturePage(&prim->tpage);
            if constexpr (shape == Shape::Quad) {
                switch (m_softRenderer.GlobalTextTP) {
                    case GPU::TexDepth::Tex4Bits:
                        m_softRenderer.drawPoly4TGEx4(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                                      m_softRenderer.ly1, m_softRenderer.lx3, m_softRenderer.ly3,
                                                      m_softRenderer.lx2, m_softRenderer.ly2, prim->u[0], prim->v[0],
                                                      prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2],
                                                      prim->v[2], prim->clutX * 16, prim->clutY, prim->colors[0],
                                                      prim->colors[1], prim->colors[2], prim->colors[3]);
                        break;
                    case GPU::TexDepth::Tex8Bits:
                        m_softRenderer.drawPoly4TGEx8(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                                      m_softRenderer.ly1, m_softRenderer.lx3, m_softRenderer.ly3,
                                                      m_softRenderer.lx2, m_softRenderer.ly2, prim->u[0], prim->v[0],
                                                      prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2],
                                                      prim->v[2], prim->clutX * 16, prim->clutY, prim->colors[0],
                                                      prim->colors[1], prim->colors[2], prim->colors[3]);
                        break;
                    case GPU::TexDepth::Tex16Bits:
                        m_softRenderer.drawPoly4TGD(
                            m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1, m_softRenderer.ly1,
                            m_softRenderer.lx3, m_softRenderer.ly3, m_softRenderer.lx2, m_softRenderer.ly2, prim->u[0],
                            prim->v[0], prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2], prim->v[2],
                            prim->colors[0], prim->colors[1], prim->colors[2], prim->colors[3]);
                        break;
                }
            } else {
                switch (m_softRenderer.GlobalTextTP) {
                    case GPU::TexDepth::Tex4Bits:
                        m_softRenderer.drawPoly3TGEx4(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                                      m_softRenderer.ly1, m_softRenderer.lx2, m_softRenderer.ly2,
                                                      prim->u[0], prim->v[0], prim->u[1], prim->v[1], prim->u[2],
                                                      prim->v[2], prim->clutX * 16, prim->clutY, prim->colors[0],
                                                      prim->colors[1], prim->colors[2]);
                        break;
                    case GPU::TexDepth::Tex8Bits:
                        m_softRenderer.drawPoly3TGEx8(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                                      m_softRenderer.ly1, m_softRenderer.lx2, m_softRenderer.ly2,
                                                      prim->u[0], prim->v[0], prim->u[1], prim->v[1], prim->u[2],
                                                      prim->v[2], prim->clutX * 16, prim->clutY, prim->colors[0],
                                                      prim->colors[1], prim->colors[2]);
                        break;
                    case GPU::TexDepth::Tex16Bits:
                        m_softRenderer.drawPoly3TGD(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                                    m_softRenderer.ly1, m_softRenderer.lx2, m_softRenderer.ly2,
                                                    prim->u[0], prim->v[0], prim->u[1], prim->v[1], prim->u[2],
                                                    prim->v[2], prim->colors[0], prim->colors[1], prim->colors[2]);
                        break;
                }
            }
        } else {
            if constexpr (shape == Shape::Quad) {
                m_softRenderer.drawPoly4G(prim->colors[0], prim->colors[1], prim->colors[2], prim->colors[3]);
            } else {
                m_softRenderer.drawPoly3G(prim->colors[0], prim->colors[1], prim->colors[2]);
            }
        }
    }
    bDoVSyncUpdate = true;
}

static const int CHKMAX_X = 1024;
static const int CHKMAX_Y = 512;

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

template <PCSX::GPU::Shading shading, PCSX::GPU::LineType lineType, PCSX::GPU::Blend blend>
void PCSX::SoftGPU::impl::lineExec(Line<shading, lineType, blend> *prim) {
    auto count = prim->colors.size();
    if (count < 2) return;

    m_softRenderer.DrawSemiTrans = prim->blend == Blend::Semi;

    for (unsigned i = 1; i < count; i++) {
        auto x0 = prim->x[i - 1];
        auto x1 = prim->x[i];
        auto y0 = prim->y[i - 1];
        auto y1 = prim->y[i];
        auto c0 = prim->colors[i - 1];
        auto c1 = prim->colors[i];

        if (CheckCoordL(x0, y0, x1, y1)) continue;
        m_softRenderer.ly0 = y0;
        m_softRenderer.lx0 = x0;
        m_softRenderer.ly1 = y1;
        m_softRenderer.lx1 = x1;

        m_softRenderer.offsetPSX2();
        if constexpr (shading == Shading::Gouraud) {
            m_softRenderer.DrawSoftwareLineShade(c0, c1);
        } else {
            m_softRenderer.DrawSoftwareLineFlat(c0);
        }
    }
    bDoVSyncUpdate = true;
}

template <PCSX::GPU::Size size, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend, PCSX::GPU::Modulation modulation>
void PCSX::SoftGPU::impl::rectExec(Rect<size, textured, blend, modulation> *prim) {
    int16_t w, h;

    m_softRenderer.lx0 = prim->x;
    m_softRenderer.ly0 = prim->y;

    if constexpr (size == Size::Variable) {
        w = prim->w;
        h = prim->h;
    } else if constexpr (size == Size::S1) {
        w = h = 1;
    } else if constexpr (size == Size::S8) {
        w = h = 8;
    } else if constexpr (size == Size::S16) {
        w = h = 16;
    }

    m_softRenderer.DrawSemiTrans = prim->blend == Blend::Semi;

    if constexpr (prim->modulation == Modulation::On) {
        m_softRenderer.g_m1 = (prim->color >> 0) & 0xff;
        m_softRenderer.g_m2 = (prim->color >> 8) & 0xff;
        m_softRenderer.g_m3 = (prim->color >> 16) & 0xff;
    } else {
        m_softRenderer.g_m1 = m_softRenderer.g_m2 = m_softRenderer.g_m3 = 128;
    }

    m_softRenderer.lx1 = m_softRenderer.lx2 = m_softRenderer.lx0 + w + PSXDisplay.DrawOffset.x;
    m_softRenderer.lx0 = m_softRenderer.lx3 = m_softRenderer.lx0 + PSXDisplay.DrawOffset.x;
    m_softRenderer.ly2 = m_softRenderer.ly3 = m_softRenderer.ly0 + h + PSXDisplay.DrawOffset.y;
    m_softRenderer.ly0 = m_softRenderer.ly1 = m_softRenderer.ly0 + PSXDisplay.DrawOffset.y;

    if constexpr (textured == Textured::Yes) {
        int16_t tx0, ty0, tx1, ty1, tx2, ty2, tx3, ty3;
        tx0 = tx3 = prim->u;
        tx1 = tx2 = tx0 + w;
        ty0 = ty1 = prim->v;
        ty2 = ty3 = ty0 + h;

        switch (m_softRenderer.GlobalTextTP) {
            case GPU::TexDepth::Tex4Bits:
                m_softRenderer.drawPoly4TEx4_S(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                               m_softRenderer.ly1, m_softRenderer.lx2, m_softRenderer.ly2,
                                               m_softRenderer.lx3, m_softRenderer.ly3, tx0, ty0, tx1, ty1, tx2, ty2,
                                               tx3, ty3, prim->clutX * 16, prim->clutY);
                break;
            case GPU::TexDepth::Tex8Bits:
                m_softRenderer.drawPoly4TEx8_S(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1,
                                               m_softRenderer.ly1, m_softRenderer.lx2, m_softRenderer.ly2,
                                               m_softRenderer.lx3, m_softRenderer.ly3, tx0, ty0, tx1, ty1, tx2, ty2,
                                               tx3, ty3, prim->clutX * 16, prim->clutY);
                break;
            case GPU::TexDepth::Tex16Bits:
                m_softRenderer.drawPoly4TD_S(
                    m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx1, m_softRenderer.ly1, m_softRenderer.lx2,
                    m_softRenderer.ly2, m_softRenderer.lx3, m_softRenderer.ly3, tx0, ty0, tx1, ty1, tx2, ty2, tx3, ty3);
                break;
        }
    } else {
        m_softRenderer.FillSoftwareAreaTrans(m_softRenderer.lx0, m_softRenderer.ly0, m_softRenderer.lx2,
                                             m_softRenderer.ly2, BGR24to16(prim->color));
    }

    bDoVSyncUpdate = true;
}

namespace PCSX::SoftGPU {
void impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Semi, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Off, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::On> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Off, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Off, Modulation::On> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Semi, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Semi, Modulation::On> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Off, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Off, Modulation::On> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::On> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Off, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Off, Modulation::On> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Semi, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Semi, Modulation::On> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Off, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Off, Modulation::On> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::Off> *prim) {
    polyExec(prim);
}
void impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::On> *prim) {
    polyExec(prim);
}

void impl::write0(Line<Shading::Flat, LineType::Simple, Blend::Off> *prim) { lineExec(prim); }
void impl::write0(Line<Shading::Flat, LineType::Simple, Blend::Semi> *prim) { lineExec(prim); }
void impl::write0(Line<Shading::Flat, LineType::Poly, Blend::Off> *prim) { lineExec(prim); }
void impl::write0(Line<Shading::Flat, LineType::Poly, Blend::Semi> *prim) { lineExec(prim); }
void impl::write0(Line<Shading::Gouraud, LineType::Simple, Blend::Off> *prim) { lineExec(prim); }
void impl::write0(Line<Shading::Gouraud, LineType::Simple, Blend::Semi> *prim) { lineExec(prim); }
void impl::write0(Line<Shading::Gouraud, LineType::Poly, Blend::Off> *prim) { lineExec(prim); }
void impl::write0(Line<Shading::Gouraud, LineType::Poly, Blend::Semi> *prim) { lineExec(prim); }

void impl::write0(Rect<Size::Variable, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::Variable, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::Variable, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::Variable, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S1, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S1, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S1, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S1, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S8, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S8, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S8, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S8, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S16, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S16, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S16, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S16, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::Variable, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::Variable, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::Variable, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::Variable, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S1, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S1, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S1, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S1, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S8, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S8, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S8, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S8, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S16, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S16, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S16, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void impl::write0(Rect<Size::S16, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }

}  // namespace PCSX::SoftGPU

void PCSX::SoftGPU::impl::write0(BlitVramVram *prim) {
    int16_t imageY0, imageX0, imageY1, imageX1, imageSX, imageSY, i, j;

    imageX0 = prim->sX;
    imageY0 = prim->sY;
    imageX1 = prim->dX;
    imageY1 = prim->dY;
    imageSX = prim->w;
    imageSY = prim->h;

    if ((imageX0 == imageX1) && (imageY0 == imageY1)) return;
    if (imageSX <= 0) return;
    if (imageSY <= 0) return;

    if ((imageY0 + imageSY) > iGPUHeight || (imageX0 + imageSX) > 1024 || (imageY1 + imageSY) > iGPUHeight ||
        (imageX1 + imageSX) > 1024) {
        int i, j;
        for (j = 0; j < imageSY; j++) {
            for (i = 0; i < imageSX; i++) {
                psxVuw[(1024 * ((imageY1 + j) & iGPUHeightMask)) + ((imageX1 + i) & 0x3ff)] =
                    psxVuw[(1024 * ((imageY0 + j) & iGPUHeightMask)) + ((imageX0 + i) & 0x3ff)];
            }
        }

        bDoVSyncUpdate = true;

        return;
    }

    if (imageSX & 1) {
        // not dword aligned? slower func
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
    } else {
        // dword aligned
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

    bDoVSyncUpdate = true;
}

void PCSX::SoftGPU::impl::write0(TPage *prim) { m_softRenderer.texturePage(prim); }
void PCSX::SoftGPU::impl::write0(TWindow *prim) { m_softRenderer.twindow(prim); }
void PCSX::SoftGPU::impl::write0(DrawingAreaStart *prim) { m_softRenderer.drawingAreaStart(prim); }
void PCSX::SoftGPU::impl::write0(DrawingAreaEnd *prim) { m_softRenderer.drawingAreaEnd(prim); }
void PCSX::SoftGPU::impl::write0(DrawingOffset *prim) { m_softRenderer.drawingOffset(prim); }
void PCSX::SoftGPU::impl::write0(MaskBit *prim) { m_softRenderer.maskBit(prim); }
