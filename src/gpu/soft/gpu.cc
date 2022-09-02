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

#include "core/debug.h"
#include "core/psxemulator.h"
#include "gpu/soft/interface.h"
#include "gpu/soft/soft.h"
#include "imgui.h"
#include "tracy/Tracy.hpp"

#define GPUSTATUS_DMABITS 0x60000000
#define GPUSTATUS_READYFORCOMMANDS 0x10000000
#define GPUSTATUS_IDLE 0x04000000
#define GPUSTATUS_DISPLAYDISABLED 0x00800000
#define GPUSTATUS_INTERLACED 0x00400000
#define GPUSTATUS_RGB24 0x00200000
#define GPUSTATUS_PAL 0x00100000
#define GPUSTATUS_DOUBLEHEIGHT 0x00080000
#define GPUSTATUS_WIDTHBITS 0x00070000

int32_t PCSX::SoftGPU::impl::initBackend(GUI *gui) {
    m_gui = gui;
    m_doVSyncUpdate = true;
    initDisplay();

    // always alloc one extra MB for soft drawing funcs security
    m_allocatedVRAM = new uint8_t[(GPU_HEIGHT * 2) * 1024 + (1024 * 1024)]();
    if (!m_allocatedVRAM) return -1;

    //!!! ATTENTION !!!
    m_vram = m_allocatedVRAM + 512 * 1024;  // security offset into double sized psx vram!
    m_vram16 = (uint16_t *)m_vram;

    m_textureWindowRaw = 0;
    m_drawingStartRaw = 0;
    m_drawingEndRaw = 0;
    m_drawingOffsetRaw = 0;

    m_softDisplay.RGB24 = false;  // init some stuff
    m_softDisplay.Interlaced = false;
    m_softDisplay.DrawOffset.x = 0;
    m_softDisplay.DrawOffset.y = 0;
    m_softDisplay.DisplayMode.x = 320;
    m_softDisplay.DisplayMode.y = 240;
    m_previousDisplay.DisplayMode.x = 320;
    m_previousDisplay.DisplayMode.y = 240;
    m_softDisplay.Disabled = false;
    m_previousDisplay.Range.x0 = 0;
    m_previousDisplay.Range.y0 = 0;
    m_softDisplay.Range.x0 = 0;
    m_softDisplay.Range.x1 = 0;
    m_previousDisplay.DisplayModeNew.y = 0;
    m_softDisplay.Double = 1;
    m_dataRet = 0x400;

    // device initialised already !
    m_statusRet = 0x14802000;
    m_statusRet |= GPUSTATUS_IDLE;
    m_statusRet |= GPUSTATUS_READYFORCOMMANDS;

    return 0;
}

int32_t PCSX::SoftGPU::impl::shutdown() {
    delete[] m_allocatedVRAM;
    return 0;
}

std::unique_ptr<PCSX::GPU> PCSX::GPU::getSoft() { return std::unique_ptr<PCSX::GPU>(new PCSX::SoftGPU::impl()); }

void PCSX::SoftGPU::impl::updateDisplay() {
    if (m_softDisplay.Disabled) {
        glClearColor(1, 0, 0, 0);
        glClear(GL_COLOR_BUFFER_BIT);
        return;
    }

    doBufferSwap();
}

////////////////////////////////////////////////////////////////////////
// roughly emulated screen centering bits... not complete !!!
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::impl::changeDispOffsetsX() {
    if (!m_softDisplay.Range.x1) return;

    int32_t l = m_previousDisplay.DisplayMode.x;

    l *= (int32_t)m_softDisplay.Range.x1;
    l /= 2560;
    int32_t lx = l;
    l &= 0xfffffff8;

    if (l == m_previousDisplay.Range.y1) return;  // abusing range.y1 for
    m_previousDisplay.Range.y1 = (int16_t)l;      // storing last x range and test

    if (lx >= m_previousDisplay.DisplayMode.x) {
        m_previousDisplay.Range.x1 = (int16_t)m_previousDisplay.DisplayMode.x;
        m_previousDisplay.Range.x0 = 0;
    } else {
        m_previousDisplay.Range.x1 = (int16_t)l;

        m_previousDisplay.Range.x0 = (m_softDisplay.Range.x0 - 500) / 8;

        if (m_previousDisplay.Range.x0 < 0) m_previousDisplay.Range.x0 = 0;

        if ((m_previousDisplay.Range.x0 + lx) > m_previousDisplay.DisplayMode.x) {
            m_previousDisplay.Range.x0 = (int16_t)(m_previousDisplay.DisplayMode.x - lx);
            m_previousDisplay.Range.x0 += 2;  //???

            m_previousDisplay.Range.x1 += (int16_t)(lx - l);
        }
        glClearColor(1, 0, 0, 0);
        glClear(GL_COLOR_BUFFER_BIT);
    }

    m_doVSyncUpdate = true;
}

void PCSX::SoftGPU::impl::changeDispOffsetsY() {
    int iT, iO = m_previousDisplay.Range.y0;
    int iOldYOffset = m_previousDisplay.DisplayModeNew.y;

    if ((m_previousDisplay.DisplayModeNew.x + m_softDisplay.DisplayModeNew.y) > GPU_HEIGHT) {
        int dy1 = GPU_HEIGHT - m_previousDisplay.DisplayModeNew.x;
        int dy2 = (m_previousDisplay.DisplayModeNew.x + m_softDisplay.DisplayModeNew.y) - GPU_HEIGHT;

        if (dy1 >= dy2) {
            m_previousDisplay.DisplayModeNew.y = -dy2;
        } else {
            m_softDisplay.DisplayPosition.y = 0;
            m_previousDisplay.DisplayModeNew.y = -dy1;
        }
    } else {
        m_previousDisplay.DisplayModeNew.y = 0;
    }

    if (m_previousDisplay.DisplayModeNew.y != iOldYOffset) {
        // if old offset!=new offset: recalc height
        m_softDisplay.Height = m_softDisplay.Range.y1 - m_softDisplay.Range.y0 + m_previousDisplay.DisplayModeNew.y;
        m_softDisplay.DisplayModeNew.y = m_softDisplay.Height * m_softDisplay.Double;
    }

    if (m_softDisplay.PAL) {
        iT = 48;
    } else {
        iT = 28;
    }

    if (m_softDisplay.Range.y0 >= iT) {
        m_previousDisplay.Range.y0 = (int16_t)((m_softDisplay.Range.y0 - iT - 4) * m_softDisplay.Double);
        if (m_previousDisplay.Range.y0 < 0) m_previousDisplay.Range.y0 = 0;
        m_softDisplay.DisplayModeNew.y += m_previousDisplay.Range.y0;
    } else {
        m_previousDisplay.Range.y0 = 0;
    }

    if (iO != m_previousDisplay.Range.y0) {
        glClearColor(1, 0, 0, 0);
        glClear(GL_COLOR_BUFFER_BIT);
    }
}

////////////////////////////////////////////////////////////////////////
// check if update needed
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::impl::updateDisplayIfChanged() {
    if ((m_softDisplay.DisplayMode.y == m_softDisplay.DisplayModeNew.y) &&
        (m_softDisplay.DisplayMode.x == m_softDisplay.DisplayModeNew.x)) {
        if ((m_softDisplay.RGB24 == m_softDisplay.RGB24New) &&
            (m_softDisplay.Interlaced == m_softDisplay.InterlacedNew))
            return;
    }

    m_softDisplay.RGB24 = m_softDisplay.RGB24New;  // get new infos

    m_softDisplay.DisplayMode.y = m_softDisplay.DisplayModeNew.y;
    m_softDisplay.DisplayMode.x = m_softDisplay.DisplayModeNew.x;
    m_previousDisplay.DisplayMode.x =                // previous will hold
        std::min(640, m_softDisplay.DisplayMode.x);  // max 640x512... that's
    m_previousDisplay.DisplayMode.y =                // the size of my
        std::min(512, m_softDisplay.DisplayMode.y);  // back buffer surface
    m_softDisplay.Interlaced = m_softDisplay.InterlacedNew;

    m_softDisplay.DisplayEnd.x =  // calc end of display
        m_softDisplay.DisplayPosition.x + m_softDisplay.DisplayMode.x;
    m_softDisplay.DisplayEnd.y =
        m_softDisplay.DisplayPosition.y + m_softDisplay.DisplayMode.y + m_previousDisplay.DisplayModeNew.y;
    m_previousDisplay.DisplayEnd.x = m_previousDisplay.DisplayPosition.x + m_softDisplay.DisplayMode.x;
    m_previousDisplay.DisplayEnd.y =
        m_previousDisplay.DisplayPosition.y + m_softDisplay.DisplayMode.y + m_previousDisplay.DisplayModeNew.y;

    changeDispOffsetsX();
}

void PCSX::SoftGPU::impl::vblank() {
    m_statusRet ^= 0x80000000;  // odd/even bit

    if (m_softDisplay.Interlaced) {
        // interlaced mode?
        if (m_doVSyncUpdate && m_softDisplay.DisplayMode.x > 0 && m_softDisplay.DisplayMode.y > 0) {
            updateDisplay();
        }
    } else {
        // non-interlaced?
        // some primitives drawn?
        if (m_doVSyncUpdate) updateDisplay();  // -> update display
    }

    m_doVSyncUpdate = false;  // vsync done
}

uint32_t PCSX::SoftGPU::impl::readStatusInternal() { return m_statusRet; }

void PCSX::SoftGPU::impl::restoreStatus(uint32_t status) { m_statusRet = status; }

bool PCSX::SoftGPU::impl::configure() {
    bool changed = false;
    ImGui::SetNextWindowPos(ImVec2(60, 60), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(300, 200), ImGuiCond_FirstUseEver);
    static const char *ditherValues[] = {"No dithering (fastest)", "Game-dependent dithering (slow)",
                                         "Always dither g-shaded polygons (slowest)"};

    if (ImGui::Begin(_("Soft GPU configuration"), &m_showCfg)) {
        if (ImGui::Combo("Dithering", &m_useDither, ditherValues, 3)) {
            changed = true;
            g_emulator->settings.get<Emulator::SettingDither>() = m_useDither;
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

void PCSX::SoftGPU::impl::write0(ClearCache *) {}

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

    fillSoftwareArea(sX, sY, sW, sH, BGR24to16(prim->color));

    m_doVSyncUpdate = true;
}

template <PCSX::GPU::Shading shading, PCSX::GPU::Shape shape, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend,
          PCSX::GPU::Modulation modulation>
void PCSX::SoftGPU::impl::polyExec(Poly<shading, shape, textured, blend, modulation> *prim) {
    m_x0 = prim->x[0];
    m_y0 = prim->y[0];
    m_x1 = prim->x[1];
    m_y1 = prim->y[1];
    m_x2 = prim->x[2];
    m_y2 = prim->y[2];
    if constexpr (shape == Shape::Quad) {
        m_x3 = prim->x[3];
        m_y3 = prim->y[3];
        if (checkCoord4()) return;
        applyOffset4();
    } else {
        if (checkCoord3()) return;
        applyOffset3();
    }

    m_drawSemiTrans = blend == Blend::Semi;

    if constexpr (modulation == Modulation::On) {
        m_m1 = (prim->colors[0] >> 0) & 0xff;
        m_m2 = (prim->colors[0] >> 8) & 0xff;
        m_m3 = (prim->colors[0] >> 16) & 0xff;
    } else {
        m_m1 = m_m2 = m_m3 = 128;
    }

    if constexpr (shading == Shading::Flat) {
        if constexpr (textured == Textured::Yes) {
            if (m_ditherMode) {
                prim->tpage.dither = true;
                prim->tpage.raw |= 0x200;
            }
            texturePage(&prim->tpage);
            if constexpr (shape == Shape::Quad) {
                switch (m_globalTextTP) {
                    case GPU::TexDepth::Tex4Bits:
                        drawPoly4TEx4(m_x0, m_y0, m_x1, m_y1, m_x3, m_y3, m_x2, m_y2, prim->u[0], prim->v[0],
                                      prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2], prim->v[2],
                                      prim->clutX() * 16, prim->clutY());
                        break;
                    case GPU::TexDepth::Tex8Bits:
                        drawPoly4TEx8(m_x0, m_y0, m_x1, m_y1, m_x3, m_y3, m_x2, m_y2, prim->u[0], prim->v[0],
                                      prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2], prim->v[2],
                                      prim->clutX() * 16, prim->clutY());
                        break;
                    case GPU::TexDepth::Tex16Bits:
                        drawPoly4TD(m_x0, m_y0, m_x1, m_y1, m_x3, m_y3, m_x2, m_y2, prim->u[0], prim->v[0], prim->u[1],
                                    prim->v[1], prim->u[3], prim->v[3], prim->u[2], prim->v[2]);
                        break;
                }
            } else {
                switch (m_globalTextTP) {
                    case GPU::TexDepth::Tex4Bits:
                        drawPoly3TEx4(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, prim->u[0], prim->v[0], prim->u[1],
                                      prim->v[1], prim->u[2], prim->v[2], prim->clutX() * 16, prim->clutY());
                        break;
                    case GPU::TexDepth::Tex8Bits:
                        drawPoly3TEx8(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, prim->u[0], prim->v[0], prim->u[1],
                                      prim->v[1], prim->u[2], prim->v[2], prim->clutX() * 16, prim->clutY());
                        break;
                    case GPU::TexDepth::Tex16Bits:
                        drawPoly3TD(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, prim->u[0], prim->v[0], prim->u[1], prim->v[1],
                                    prim->u[2], prim->v[2]);
                        break;
                }
            }
        } else {
            if constexpr (shape == Shape::Quad) {
                drawPolyFlat4(prim->colors[0]);
            } else {
                drawPolyFlat3(prim->colors[0]);
            }
        }
    } else {
        if constexpr (textured == Textured::Yes) {
            if (m_ditherMode) {
                prim->tpage.dither = true;
                prim->tpage.raw |= 0x200;
            }
            texturePage(&prim->tpage);
            if constexpr (shape == Shape::Quad) {
                switch (m_globalTextTP) {
                    case GPU::TexDepth::Tex4Bits:
                        drawPoly4TGEx4(m_x0, m_y0, m_x1, m_y1, m_x3, m_y3, m_x2, m_y2, prim->u[0], prim->v[0],
                                       prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2], prim->v[2],
                                       prim->clutX() * 16, prim->clutY(), prim->colors[0], prim->colors[1],
                                       prim->colors[2], prim->colors[3]);
                        break;
                    case GPU::TexDepth::Tex8Bits:
                        drawPoly4TGEx8(m_x0, m_y0, m_x1, m_y1, m_x3, m_y3, m_x2, m_y2, prim->u[0], prim->v[0],
                                       prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2], prim->v[2],
                                       prim->clutX() * 16, prim->clutY(), prim->colors[0], prim->colors[1],
                                       prim->colors[2], prim->colors[3]);
                        break;
                    case GPU::TexDepth::Tex16Bits:
                        drawPoly4TGD(m_x0, m_y0, m_x1, m_y1, m_x3, m_y3, m_x2, m_y2, prim->u[0], prim->v[0], prim->u[1],
                                     prim->v[1], prim->u[3], prim->v[3], prim->u[2], prim->v[2], prim->colors[0],
                                     prim->colors[1], prim->colors[2], prim->colors[3]);
                        break;
                }
            } else {
                switch (m_globalTextTP) {
                    case GPU::TexDepth::Tex4Bits:
                        drawPoly3TGEx4(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, prim->u[0], prim->v[0], prim->u[1],
                                       prim->v[1], prim->u[2], prim->v[2], prim->clutX() * 16, prim->clutY(),
                                       prim->colors[0], prim->colors[1], prim->colors[2]);
                        break;
                    case GPU::TexDepth::Tex8Bits:
                        drawPoly3TGEx8(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, prim->u[0], prim->v[0], prim->u[1],
                                       prim->v[1], prim->u[2], prim->v[2], prim->clutX() * 16, prim->clutY(),
                                       prim->colors[0], prim->colors[1], prim->colors[2]);
                        break;
                    case GPU::TexDepth::Tex16Bits:
                        drawPoly3TGD(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, prim->u[0], prim->v[0], prim->u[1], prim->v[1],
                                     prim->u[2], prim->v[2], prim->colors[0], prim->colors[1], prim->colors[2]);
                        break;
                }
            }
        } else {
            if constexpr (shape == Shape::Quad) {
                drawPolyShade4(prim->colors[0], prim->colors[1], prim->colors[2], prim->colors[3]);
            } else {
                drawPolyShade3(prim->colors[0], prim->colors[1], prim->colors[2]);
            }
        }
    }
    m_doVSyncUpdate = true;
}

static constexpr int CHKMAX_X = 1024;
static constexpr int CHKMAX_Y = 512;

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

    m_drawSemiTrans = blend == Blend::Semi;

    for (unsigned i = 1; i < count; i++) {
        auto x0 = prim->x[i - 1];
        auto x1 = prim->x[i];
        auto y0 = prim->y[i - 1];
        auto y1 = prim->y[i];
        auto c0 = prim->colors[i - 1];
        auto c1 = prim->colors[i];

        if (CheckCoordL(x0, y0, x1, y1)) continue;
        m_y0 = y0;
        m_x0 = x0;
        m_y1 = y1;
        m_x1 = x1;

        applyOffset2();
        if constexpr (shading == Shading::Gouraud) {
            drawSoftwareLineShade(c0, c1);
        } else {
            drawSoftwareLineFlat(c0);
        }
    }
    m_doVSyncUpdate = true;
}

template <PCSX::GPU::Size size, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend, PCSX::GPU::Modulation modulation>
void PCSX::SoftGPU::impl::rectExec(Rect<size, textured, blend, modulation> *prim) {
    int16_t w, h;

    m_x0 = prim->x;
    m_y0 = prim->y;

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

    m_drawSemiTrans = blend == Blend::Semi;

    if constexpr (modulation == Modulation::On) {
        m_m1 = (prim->color >> 0) & 0xff;
        m_m2 = (prim->color >> 8) & 0xff;
        m_m3 = (prim->color >> 16) & 0xff;
    } else {
        m_m1 = m_m2 = m_m3 = 128;
    }

    m_x1 = m_x2 = m_x0 + w + m_softDisplay.DrawOffset.x;
    m_x0 = m_x3 = m_x0 + m_softDisplay.DrawOffset.x;
    m_y2 = m_y3 = m_y0 + h + m_softDisplay.DrawOffset.y;
    m_y0 = m_y1 = m_y0 + m_softDisplay.DrawOffset.y;

    if constexpr (textured == Textured::Yes) {
        int16_t tx0, ty0, tx1, ty1, tx2, ty2, tx3, ty3;
        tx0 = tx3 = prim->u;
        tx1 = tx2 = tx0 + w;
        ty0 = ty1 = prim->v;
        ty2 = ty3 = ty0 + h;

        switch (m_globalTextTP) {
            case GPU::TexDepth::Tex4Bits:
                drawPoly4TEx4_S(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, m_x3, m_y3, tx0, ty0, tx1, ty1, tx2, ty2, tx3, ty3,
                                prim->clutX() * 16, prim->clutY());
                break;
            case GPU::TexDepth::Tex8Bits:
                drawPoly4TEx8_S(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, m_x3, m_y3, tx0, ty0, tx1, ty1, tx2, ty2, tx3, ty3,
                                prim->clutX() * 16, prim->clutY());
                break;
            case GPU::TexDepth::Tex16Bits:
                drawPoly4TD_S(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, m_x3, m_y3, tx0, ty0, tx1, ty1, tx2, ty2, tx3, ty3);
                break;
        }
    } else {
        fillSoftwareAreaTrans(m_x0, m_y0, m_x2, m_y2, BGR24to16(prim->color));
    }

    m_doVSyncUpdate = true;
}

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

    if ((imageY0 + imageSY) > GPU_HEIGHT || (imageX0 + imageSX) > 1024 || (imageY1 + imageSY) > GPU_HEIGHT ||
        (imageX1 + imageSX) > 1024) {
        int i, j;
        for (j = 0; j < imageSY; j++) {
            for (i = 0; i < imageSX; i++) {
                m_vram16[(1024 * ((imageY1 + j) & GPU_HEIGHT_MASK)) + ((imageX1 + i) & 0x3ff)] =
                    m_vram16[(1024 * ((imageY0 + j) & GPU_HEIGHT_MASK)) + ((imageX0 + i) & 0x3ff)];
            }
        }

        m_doVSyncUpdate = true;

        return;
    }

    if (imageSX & 1) {
        // not dword aligned? slower func
        uint16_t *SRCPtr, *DSTPtr;
        uint16_t LineOffset;

        SRCPtr = m_vram16 + (1024 * imageY0) + imageX0;
        DSTPtr = m_vram16 + (1024 * imageY1) + imageX1;

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

        SRCPtr = (uint32_t *)(m_vram16 + (1024 * imageY0) + imageX0);
        DSTPtr = (uint32_t *)(m_vram16 + (1024 * imageY1) + imageX1);

        LineOffset = 512 - dx;

        for (j = 0; j < imageSY; j++) {
            for (i = 0; i < dx; i++) *DSTPtr++ = *SRCPtr++;
            SRCPtr += LineOffset;
            DSTPtr += LineOffset;
        }
    }

    imageSX += imageX1;
    imageSY += imageY1;

    m_doVSyncUpdate = true;
}

void PCSX::SoftGPU::impl::write0(TPage *prim) { texturePage(prim); }
void PCSX::SoftGPU::impl::write0(TWindow *prim) { twindow(prim); }
void PCSX::SoftGPU::impl::write0(DrawingAreaStart *prim) { drawingAreaStart(prim); }
void PCSX::SoftGPU::impl::write0(DrawingAreaEnd *prim) { drawingAreaEnd(prim); }
void PCSX::SoftGPU::impl::write0(DrawingOffset *prim) { drawingOffset(prim); }
void PCSX::SoftGPU::impl::write0(MaskBit *prim) { maskBit(prim); }

PCSX::GPU::ScreenShot PCSX::SoftGPU::impl::takeScreenShot() {
    ScreenShot ss;
    auto startX = m_softDisplay.DisplayPosition.x;
    auto startY = m_softDisplay.DisplayPosition.y;
    auto width = m_softDisplay.DisplayEnd.x - m_softDisplay.DisplayPosition.x;
    auto height = m_softDisplay.DisplayEnd.y - m_softDisplay.DisplayPosition.y;
    ss.width = width;
    ss.height = height;
    unsigned factor = m_softDisplay.RGB24 ? 3 : 2;
    ss.bpp = m_softDisplay.RGB24 ? ScreenShot::BPP_24 : ScreenShot::BPP_16;
    unsigned size = width * height * factor;
    char *pixels = reinterpret_cast<char *>(malloc(size));
    ss.data.acquire(pixels, size);
    if (m_softDisplay.RGB24) {
        auto ptr = m_allocatedVRAM;
        ptr += (startY * 1024 + startX) * 3;
        for (int i = 0; i < height; i++) {
            std::memcpy(pixels, ptr, width * 3);
            ptr += 1024 * 3;
            pixels += width * 3;
        }
    } else {
        auto ptr = m_vram16;
        ptr += startY * 1024 + startX;
        for (int i = 0; i < height; i++) {
            std::memcpy(pixels, ptr, width * sizeof(uint16_t));
            ptr += 1024;
            pixels += width * 2;
        }
    }

    return ss;
}

void PCSX::SoftGPU::impl::write1(CtrlReset *) {
    m_textureWindowRaw = 0;
    m_drawingStartRaw = 0;
    m_drawingEndRaw = 0;
    m_drawingOffsetRaw = 0;
    m_statusRet = 0x14802000;
    m_softDisplay.Disabled = 1;
    m_softDisplay.DrawOffset.x = m_softDisplay.DrawOffset.y = 0;
    reset();
    acknowledgeIRQ1();
    m_softDisplay.RGB24 = false;
    m_softDisplay.Interlaced = false;
}

void PCSX::SoftGPU::impl::write1(CtrlClearFifo *) {}

void PCSX::SoftGPU::impl::write1(CtrlIrqAck *) { acknowledgeIRQ1(); }

void PCSX::SoftGPU::impl::write1(CtrlDisplayEnable *ctrl) {
    m_previousDisplay.Disabled = m_softDisplay.Disabled;
    m_softDisplay.Disabled = !ctrl->enable;

    if (m_softDisplay.Disabled) {
        m_statusRet |= GPUSTATUS_DISPLAYDISABLED;
    } else {
        m_statusRet &= ~GPUSTATUS_DISPLAYDISABLED;
    }
}

void PCSX::SoftGPU::impl::write1(CtrlDmaSetting *ctrl) {
    m_statusRet &= ~GPUSTATUS_DMABITS;
    m_statusRet |= magic_enum::enum_integer(ctrl->dma) << 29;
}

void PCSX::SoftGPU::impl::write1(CtrlDisplayStart *ctrl) {
    m_previousDisplay.DisplayPosition.x = m_softDisplay.DisplayPosition.x;
    m_previousDisplay.DisplayPosition.y = m_softDisplay.DisplayPosition.y;

    // new
    m_softDisplay.DisplayPosition.y = ctrl->y;

    // store the same val in some helper var, we need it on later compares
    m_previousDisplay.DisplayModeNew.x = m_softDisplay.DisplayPosition.y;

    if ((m_softDisplay.DisplayPosition.y + m_softDisplay.DisplayMode.y) > GPU_HEIGHT) {
        int dy1 = GPU_HEIGHT - m_softDisplay.DisplayPosition.y;
        int dy2 = (m_softDisplay.DisplayPosition.y + m_softDisplay.DisplayMode.y) - GPU_HEIGHT;

        if (dy1 >= dy2) {
            m_previousDisplay.DisplayModeNew.y = -dy2;
        } else {
            m_softDisplay.DisplayPosition.y = 0;
            m_previousDisplay.DisplayModeNew.y = -dy1;
        }
    } else {
        m_previousDisplay.DisplayModeNew.y = 0;
    }
    // eon

    m_softDisplay.DisplayPosition.x = ctrl->x;
    m_softDisplay.DisplayEnd.x = m_softDisplay.DisplayPosition.x + m_softDisplay.DisplayMode.x;
    m_softDisplay.DisplayEnd.y =
        m_softDisplay.DisplayPosition.y + m_softDisplay.DisplayMode.y + m_previousDisplay.DisplayModeNew.y;
    m_previousDisplay.DisplayEnd.x = m_previousDisplay.DisplayPosition.x + m_softDisplay.DisplayMode.x;
    m_previousDisplay.DisplayEnd.y =
        m_previousDisplay.DisplayPosition.y + m_softDisplay.DisplayMode.y + m_previousDisplay.DisplayModeNew.y;

    m_doVSyncUpdate = true;
}

void PCSX::SoftGPU::impl::write1(CtrlHorizontalDisplayRange *ctrl) {
    m_softDisplay.Range.x0 = ctrl->x0;
    m_softDisplay.Range.x1 = ctrl->x1;
    m_softDisplay.Range.x1 -= m_softDisplay.Range.x0;
    changeDispOffsetsX();
}

void PCSX::SoftGPU::impl::write1(CtrlVerticalDisplayRange *ctrl) {
    m_softDisplay.Range.y0 = ctrl->y0;
    m_softDisplay.Range.y1 = ctrl->y1;

    m_previousDisplay.Height = m_softDisplay.Height;

    m_softDisplay.Height = m_softDisplay.Range.y1 - m_softDisplay.Range.y0 + m_previousDisplay.DisplayModeNew.y;

    if (m_previousDisplay.Height != m_softDisplay.Height) {
        m_softDisplay.DisplayModeNew.y = m_softDisplay.Height * m_softDisplay.Double;

        changeDispOffsetsY();

        updateDisplayIfChanged();
    }
}

void PCSX::SoftGPU::impl::write1(CtrlDisplayMode *ctrl) {
    m_softDisplay.DisplayModeNew.x = s_displayWidths[magic_enum::enum_integer(ctrl->hres)];

    if (ctrl->vres == CtrlDisplayMode::VR_480) {
        m_softDisplay.Double = 2;
    } else {
        m_softDisplay.Double = 1;
    }

    m_softDisplay.DisplayModeNew.y = m_softDisplay.Height * m_softDisplay.Double;

    changeDispOffsetsY();

    m_softDisplay.PAL = ctrl->mode == CtrlDisplayMode::VM_PAL;
    m_softDisplay.RGB24New = ctrl->depth == CtrlDisplayMode::CD_24BITS;
    m_softDisplay.InterlacedNew = ctrl->interlace;

    if (g_emulator->settings.get<PCSX::Emulator::SettingAutoVideo>()) {
        if (m_softDisplay.PAL) {
            g_emulator->settings.get<Emulator::SettingVideo>() = Emulator::PSX_TYPE_PAL;
        } else {
            g_emulator->settings.get<Emulator::SettingVideo>() = Emulator::PSX_TYPE_NTSC;
        }
    }

    m_statusRet &= ~GPUSTATUS_WIDTHBITS;
    m_statusRet |= ctrl->widthRaw << 16;

    if (m_softDisplay.InterlacedNew) {
        if (!m_softDisplay.Interlaced) {
            m_previousDisplay.DisplayPosition.x = m_softDisplay.DisplayPosition.x;
            m_previousDisplay.DisplayPosition.y = m_softDisplay.DisplayPosition.y;
        }
        m_statusRet |= GPUSTATUS_INTERLACED;
    } else {
        m_statusRet &= ~GPUSTATUS_INTERLACED;
    }

    if (m_softDisplay.PAL) {
        m_statusRet |= GPUSTATUS_PAL;
    } else {
        m_statusRet &= ~GPUSTATUS_PAL;
    }

    if (m_softDisplay.Double == 2) {
        m_statusRet |= GPUSTATUS_DOUBLEHEIGHT;
    } else {
        m_statusRet &= ~GPUSTATUS_DOUBLEHEIGHT;
    }

    if (m_softDisplay.RGB24New) {
        m_statusRet |= GPUSTATUS_RGB24;
    } else {
        m_statusRet &= ~GPUSTATUS_RGB24;
    }

    updateDisplayIfChanged();
}

void PCSX::SoftGPU::impl::write1(CtrlQuery *ctrl) {
    switch (ctrl->type()) {
        case CtrlQuery::TextureWindow:
            m_dataRet = m_textureWindowRaw;
            return;
        case CtrlQuery::DrawAreaStart:
            m_dataRet = m_drawingStartRaw;
            return;
        case CtrlQuery::DrawAreaEnd:
            m_dataRet = m_drawingEndRaw;
            return;
        case CtrlQuery::DrawOffset:
            m_dataRet = m_drawingOffsetRaw;
            return;
    }
}

// clang-format off
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::SoftGPU::impl::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }

void PCSX::SoftGPU::impl::write0(Line<Shading::Flat, LineType::Simple, Blend::Off> *prim) { lineExec(prim); }
void PCSX::SoftGPU::impl::write0(Line<Shading::Flat, LineType::Simple, Blend::Semi> *prim) { lineExec(prim); }
void PCSX::SoftGPU::impl::write0(Line<Shading::Flat, LineType::Poly, Blend::Off> *prim) { lineExec(prim); }
void PCSX::SoftGPU::impl::write0(Line<Shading::Flat, LineType::Poly, Blend::Semi> *prim) { lineExec(prim); }
void PCSX::SoftGPU::impl::write0(Line<Shading::Gouraud, LineType::Simple, Blend::Off> *prim) { lineExec(prim); }
void PCSX::SoftGPU::impl::write0(Line<Shading::Gouraud, LineType::Simple, Blend::Semi> *prim) { lineExec(prim); }
void PCSX::SoftGPU::impl::write0(Line<Shading::Gouraud, LineType::Poly, Blend::Off> *prim) { lineExec(prim); }
void PCSX::SoftGPU::impl::write0(Line<Shading::Gouraud, LineType::Poly, Blend::Semi> *prim) { lineExec(prim); }

void PCSX::SoftGPU::impl::write0(Rect<Size::Variable, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::Variable, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::Variable, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::Variable, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S1, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S1, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S1, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S1, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S8, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S8, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S8, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S8, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S16, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S16, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S16, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S16, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::Variable, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::Variable, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::Variable, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::Variable, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S1, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S1, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S1, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S1, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S8, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S8, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S8, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S8, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S16, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S16, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S16, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::SoftGPU::impl::write0(Rect<Size::S16, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
