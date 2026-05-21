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
#include "gpu/soft/pixel-writer.h"
#include "gpu/soft/soft.h"
#include "gui/gui.h"
#include "imgui.h"
#include "support/imgui-helpers.h"
#include "tracy/Tracy.hpp"

// GP1 status-register bit definitions. Names are protocol-visible and
// must stay stable - logs and debugger expressions read them out.
static constexpr uint32_t GPUSTATUS_DMABITS = 0x60000000;
static constexpr uint32_t GPUSTATUS_READYFORCOMMANDS = 0x10000000;
static constexpr uint32_t GPUSTATUS_IDLE = 0x04000000;
static constexpr uint32_t GPUSTATUS_DISPLAYDISABLED = 0x00800000;
static constexpr uint32_t GPUSTATUS_INTERLACED = 0x00400000;
static constexpr uint32_t GPUSTATUS_RGB24 = 0x00200000;
static constexpr uint32_t GPUSTATUS_PAL = 0x00100000;
static constexpr uint32_t GPUSTATUS_DOUBLEHEIGHT = 0x00080000;
static constexpr uint32_t GPUSTATUS_WIDTHBITS = 0x00070000;

int32_t PCSX::SoftGPU::impl::initBackend(UI *ui) {
    m_ui = ui;
    m_doVSyncUpdate = true;
    initDisplay();

    // always alloc one extra MB for soft drawing funcs security
    m_allocatedVRAM = new uint8_t[(VRAM_HEIGHT * 2) * 1024 + (1024 * 1024)]();
    if (!m_allocatedVRAM) return -1;

    //!!! ATTENTION !!!
    m_vram = m_allocatedVRAM + 512 * 1024;  // security offset into double sized psx vram!
    m_vram16 = (uint16_t *)m_vram;

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

void PCSX::SoftGPU::impl::updateDisplay(bool fromGui) {
    GUI *gui = dynamic_cast<GUI *>(m_ui);
    if (!gui) return;
    if (m_softDisplay.Disabled) {
        glClearColor(1, 0, 0, 0);
        glClear(GL_COLOR_BUFFER_BIT);
        return;
    }

    doBufferSwap(fromGui);
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
        GUI *gui = dynamic_cast<GUI *>(m_ui);
        if (gui) {
            glClearColor(1, 0, 0, 0);
            glClear(GL_COLOR_BUFFER_BIT);
        }
    }

    m_doVSyncUpdate = true;
}

void PCSX::SoftGPU::impl::changeDispOffsetsY() {
    int iT, iO = m_previousDisplay.Range.y0;
    int iOldYOffset = m_previousDisplay.DisplayModeNew.y;

    if ((m_previousDisplay.DisplayModeNew.x + m_softDisplay.DisplayModeNew.y) > VRAM_HEIGHT) {
        int dy1 = VRAM_HEIGHT - m_previousDisplay.DisplayModeNew.x;
        int dy2 = (m_previousDisplay.DisplayModeNew.x + m_softDisplay.DisplayModeNew.y) - VRAM_HEIGHT;

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
        GUI *gui = dynamic_cast<GUI *>(m_ui);
        if (gui) {
            glClearColor(1, 0, 0, 0);
            glClear(GL_COLOR_BUFFER_BIT);
        }
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

void PCSX::SoftGPU::impl::vblank(bool fromGui) {
    m_statusRet ^= 0x80000000;  // odd/even bit

    if (m_softDisplay.Interlaced) {
        // interlaced mode?
        if (m_doVSyncUpdate && m_softDisplay.DisplayMode.x > 0 && m_softDisplay.DisplayMode.y > 0) {
            updateDisplay(fromGui);
        }
    } else {
        // non-interlaced?
        // some primitives drawn?
        if (m_doVSyncUpdate) updateDisplay(fromGui);  // -> update display
    }

    m_doVSyncUpdate = false;  // vsync done
}

uint32_t PCSX::SoftGPU::impl::readStatusInternal() { return m_statusRet; }

void PCSX::SoftGPU::impl::restoreStatus(uint32_t status) { m_statusRet = status; }

bool PCSX::SoftGPU::impl::configure() {
    bool changed = false;
    ImGui::SetNextWindowPos(ImVec2(60, 60), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(300, 200), ImGuiCond_FirstUseEver);
    const char *ditherValues[] = {_("No dithering (fastest)"), _("Game-dependent dithering (slow)"),
                                  _("Always dither g-shaded polygons (slowest)")};

    if (ImGui::Begin(_("Soft GPU configuration"), &m_showCfg)) {
        if (ImGui::Combo(_("Dithering"), &m_useDither, ditherValues, 3)) {
            changed = true;
            g_emulator->settings.get<Emulator::SettingDither>() = m_useDither;
        }

        if (ImGui::Checkbox(_("Use cached dithering tables"),
                            &g_emulator->settings.get<Emulator::SettingCachedDithering>().value)) {
            changed = true;
            setCachedDithering(g_emulator->settings.get<Emulator::SettingCachedDithering>());
        }
        ImGuiHelpers::ShowHelpMarker(
            _("Dithering tables are cached in memory for faster processing. Dithering will be done much faster, at the "
              "cost of a 512MB cache."));

        if (ImGui::Checkbox(_("Use linear filtering"),
                            &g_emulator->settings.get<Emulator::SettingLinearFiltering>().value)) {
            changed = true;
            setLinearFiltering();
        }

        ImGui::Checkbox(_("Disable textures for polygons"), &m_disableTexturesInPolygons);
        ImGui::Checkbox(_("Disable textures for sprites"), &m_disableTexturesInRectangles);

        ImGui::End();
    }

    return changed;
}

void PCSX::SoftGPU::impl::debug() {
    if (ImGui::Begin(_("Soft GPU debugger"), &m_showDebug)) {
        ImGui::TextUnformatted(
            _("Debugging features are not supported when using the software renderer yet\nConsider enabling the "
              "OpenGL "
              "GPU option instead."));
    }
    ImGui::End();
}

static constexpr inline uint16_t BGR24to16(uint32_t BGR) {
    return PCSX::SoftGPU::Channel555::fromCommandColor(BGR);
}

static constexpr inline uint16_t BGR24to16(PCSX::GPU::EmptyColor) { return 0; }

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
    int16_t x0 = prim->x[0];
    int16_t y0 = prim->y[0];
    int16_t x1 = prim->x[1];
    int16_t y1 = prim->y[1];
    int16_t x2 = prim->x[2];
    int16_t y2 = prim->y[2];
    int16_t x3 = 0;
    int16_t y3 = 0;
    if constexpr (shape == Shape::Quad) {
        x3 = prim->x[3];
        y3 = prim->y[3];
        if (checkCoord4(x0, y0, x1, y1, x2, y2, x3, y3)) return;
        applyOffset4(x0, y0, x1, y1, x2, y2, x3, y3);
    } else {
        if (checkCoord3(x0, y0, x1, y1, x2, y2)) return;
        applyOffset3(x0, y0, x1, y1, x2, y2);
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
        if ((textured == Textured::Yes) && !m_disableTexturesInPolygons) {
            if constexpr (textured == Textured::Yes) {
                if (m_ditherMode) {
                    prim->tpage.dither = true;
                    prim->tpage.raw |= 0x200;
                }
                texturePage(&prim->tpage);
                if constexpr (shape == Shape::Quad) {
                    // Decompose into two triangles using the (1,3,2)+(0,1,2)
                    // PSX vertex split that drawPolyFlat4 and drawPoly4TG
                    // already use. drawPoly3T carries the same pixel-centre
                    // bias as the retired 4-vertex flat-textured walker, so
                    // this split is bit-equivalent to the old sweep for
                    // QFD-class geometry.
                    switch (m_globalTextTP) {
                        case GPU::TexDepth::Tex4Bits:
                            drawPoly3T<TexMode::Clut4>(x1, y1, x3, y3, x2, y2, prim->u[1], prim->v[1], prim->u[3],
                                                       prim->v[3], prim->u[2], prim->v[2], prim->clutX(),
                                                       prim->clutY());
                            drawPoly3T<TexMode::Clut4>(x0, y0, x1, y1, x2, y2, prim->u[0], prim->v[0], prim->u[1],
                                                       prim->v[1], prim->u[2], prim->v[2], prim->clutX(),
                                                       prim->clutY());
                            break;
                        case GPU::TexDepth::Tex8Bits:
                            drawPoly3T<TexMode::Clut8>(x1, y1, x3, y3, x2, y2, prim->u[1], prim->v[1], prim->u[3],
                                                       prim->v[3], prim->u[2], prim->v[2], prim->clutX(),
                                                       prim->clutY());
                            drawPoly3T<TexMode::Clut8>(x0, y0, x1, y1, x2, y2, prim->u[0], prim->v[0], prim->u[1],
                                                       prim->v[1], prim->u[2], prim->v[2], prim->clutX(),
                                                       prim->clutY());
                            break;
                        case GPU::TexDepth::Tex16Bits:
                            drawPoly3T<TexMode::Direct15>(x1, y1, x3, y3, x2, y2, prim->u[1], prim->v[1], prim->u[3],
                                                          prim->v[3], prim->u[2], prim->v[2], 0, 0);
                            drawPoly3T<TexMode::Direct15>(x0, y0, x1, y1, x2, y2, prim->u[0], prim->v[0], prim->u[1],
                                                          prim->v[1], prim->u[2], prim->v[2], 0, 0);
                            break;
                    }
                } else {
                    switch (m_globalTextTP) {
                        case GPU::TexDepth::Tex4Bits:
                            drawPoly3T<TexMode::Clut4>(x0, y0, x1, y1, x2, y2, prim->u[0], prim->v[0], prim->u[1],
                                                       prim->v[1], prim->u[2], prim->v[2], prim->clutX(),
                                                       prim->clutY());
                            break;
                        case GPU::TexDepth::Tex8Bits:
                            drawPoly3T<TexMode::Clut8>(x0, y0, x1, y1, x2, y2, prim->u[0], prim->v[0], prim->u[1],
                                                       prim->v[1], prim->u[2], prim->v[2], prim->clutX(),
                                                       prim->clutY());
                            break;
                        case GPU::TexDepth::Tex16Bits:
                            drawPoly3T<TexMode::Direct15>(x0, y0, x1, y1, x2, y2, prim->u[0], prim->v[0], prim->u[1],
                                                          prim->v[1], prim->u[2], prim->v[2], 0, 0);
                            break;
                    }
                }
            }
        } else {
            if constexpr (shape == Shape::Quad) {
                drawPoly3F(x1, y1, x3, y3, x2, y2, prim->colors[0]);
                drawPoly3F(x0, y0, x1, y1, x2, y2, prim->colors[0]);
            } else {
                drawPoly3F(x0, y0, x1, y1, x2, y2, prim->colors[0]);
            }
        }
    } else {
        if ((textured == Textured::Yes) && !m_disableTexturesInPolygons) {
            if constexpr (textured == Textured::Yes) {
                if (m_ditherMode) {
                    prim->tpage.dither = true;
                    prim->tpage.raw |= 0x200;
                }
                texturePage(&prim->tpage);
                if constexpr (shape == Shape::Quad) {
                    switch (m_globalTextTP) {
                        case GPU::TexDepth::Tex4Bits:
                            drawPoly4TG<TexMode::Clut4>(x0, y0, x1, y1, x3, y3, x2, y2, prim->u[0], prim->v[0],
                                                        prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2],
                                                        prim->v[2], prim->clutX(), prim->clutY(), prim->colors[0],
                                                        prim->colors[1], prim->colors[2], prim->colors[3]);
                            break;
                        case GPU::TexDepth::Tex8Bits:
                            drawPoly4TG<TexMode::Clut8>(x0, y0, x1, y1, x3, y3, x2, y2, prim->u[0], prim->v[0],
                                                        prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2],
                                                        prim->v[2], prim->clutX(), prim->clutY(), prim->colors[0],
                                                        prim->colors[1], prim->colors[2], prim->colors[3]);
                            break;
                        case GPU::TexDepth::Tex16Bits:
                            drawPoly4TG<TexMode::Direct15>(x0, y0, x1, y1, x3, y3, x2, y2, prim->u[0], prim->v[0],
                                                           prim->u[1], prim->v[1], prim->u[3], prim->v[3], prim->u[2],
                                                           prim->v[2], 0, 0, prim->colors[0], prim->colors[1],
                                                           prim->colors[2], prim->colors[3]);
                            break;
                    }
                } else {
                    switch (m_globalTextTP) {
                        case GPU::TexDepth::Tex4Bits:
                            drawPoly3TG<TexMode::Clut4>(x0, y0, x1, y1, x2, y2, prim->u[0], prim->v[0], prim->u[1],
                                                        prim->v[1], prim->u[2], prim->v[2], prim->clutX(),
                                                        prim->clutY(), prim->colors[0], prim->colors[1],
                                                        prim->colors[2]);
                            break;
                        case GPU::TexDepth::Tex8Bits:
                            drawPoly3TG<TexMode::Clut8>(x0, y0, x1, y1, x2, y2, prim->u[0], prim->v[0], prim->u[1],
                                                        prim->v[1], prim->u[2], prim->v[2], prim->clutX(),
                                                        prim->clutY(), prim->colors[0], prim->colors[1],
                                                        prim->colors[2]);
                            break;
                        case GPU::TexDepth::Tex16Bits:
                            drawPoly3TG<TexMode::Direct15>(x0, y0, x1, y1, x2, y2, prim->u[0], prim->v[0], prim->u[1],
                                                           prim->v[1], prim->u[2], prim->v[2], 0, 0, prim->colors[0],
                                                           prim->colors[1], prim->colors[2]);
                            break;
                    }
                }
            }
        } else {
            if constexpr (shape == Shape::Quad) {
                drawPoly4G(x0, y0, x1, y1, x2, y2, x3, y3, prim->colors[0], prim->colors[1], prim->colors[2],
                           prim->colors[3]);
            } else {
                drawPoly3G(x0, y0, x1, y1, x2, y2, prim->colors[0], prim->colors[1], prim->colors[2]);
            }
        }
    }
    m_doVSyncUpdate = true;
}

static constexpr int CHKMAX_X = 1024;
static constexpr int CHKMAX_Y = 512;

// Hardware drops lines whose endpoint delta exceeds the same per-edge bounds
// that gate polygons: |dx| <= 1023, |dy| <= 511 (verified on SCPH-5501 via
// gpu-raster-phase14 ct_line_dx_1024_drop / ct_line_dx_2047_drop).
static constexpr inline bool CheckCoordL(int16_t slx0, int16_t sly0, int16_t slx1, int16_t sly1) {
    int dx = slx1 - slx0;
    int dy = sly1 - sly0;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    return dx >= CHKMAX_X || dy >= CHKMAX_Y;
}

template <PCSX::GPU::Shading shading, PCSX::GPU::LineType lineType, PCSX::GPU::Blend blend>
void PCSX::SoftGPU::impl::lineExec(Line<shading, lineType, blend> *prim) {
    auto count = prim->colors.size();

    m_drawSemiTrans = blend == Blend::Semi;

    for (unsigned i = 1; i < count; i++) {
        int16_t x0 = prim->x[i - 1];
        int16_t x1 = prim->x[i];
        int16_t y0 = prim->y[i - 1];
        int16_t y1 = prim->y[i];
        auto c0 = prim->colors[i - 1];
        auto c1 = prim->colors[i];

        if (CheckCoordL(x0, y0, x1, y1)) continue;

        applyOffset2(x0, y0, x1, y1);
        drawSoftwareLine<shading>(x0, y0, x1, y1, c0, c1);
    }
    m_doVSyncUpdate = true;
}

template <PCSX::GPU::Size size, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend, PCSX::GPU::Modulation modulation>
void PCSX::SoftGPU::impl::rectExec(Rect<size, textured, blend, modulation> *prim) {
    int16_t w, h;

    int16_t x0 = prim->x;
    int16_t y0 = prim->y;
    int16_t x1, y1, x2, y2, x3, y3;

    if constexpr (size == Size::Variable) {
        // Hardware masks the variable-rect dimensions to 10 bits (width) and
        // 9 bits (height); the effective extents are `w & 0x3FF` / `h & 0x1FF`,
        // not the documented `((w-1) & mask) + 1` shape. A width of 1024 maps
        // to 0 and silently drops the primitive on real silicon (verified via
        // gpu-raster-phase14 ct_rect_w1024 / ct_rect_h512 against SCPH-5501),
        // while 1025/513 fall through as 1-pixel wide/tall.
        w = static_cast<int16_t>(prim->w & 0x3FF);
        h = static_cast<int16_t>(prim->h & 0x1FF);
        if (w == 0 || h == 0) return;
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

    x1 = x2 = x0 + w + m_softDisplay.DrawOffset.x;
    x0 = x3 = x0 + m_softDisplay.DrawOffset.x;
    y2 = y3 = y0 + h + m_softDisplay.DrawOffset.y;
    y0 = y1 = y0 + m_softDisplay.DrawOffset.y;

    if ((textured == Textured::Yes) && !m_disableTexturesInRectangles) {
        if constexpr (textured == Textured::Yes) {
            switch (m_globalTextTP) {
                case GPU::TexDepth::Tex4Bits:
                    drawSprite<TexMode::Clut4>(x0, y0, w, h, prim->u, prim->v, prim->clutX(), prim->clutY());
                    break;
                case GPU::TexDepth::Tex8Bits:
                    drawSprite<TexMode::Clut8>(x0, y0, w, h, prim->u, prim->v, prim->clutX(), prim->clutY());
                    break;
                case GPU::TexDepth::Tex16Bits:
                    drawSprite<TexMode::Direct15>(x0, y0, w, h, prim->u, prim->v, 0, 0);
                    break;
            }
        }
    } else {
        fillSoftwareAreaTrans(x0, y0, x2, y2, BGR24to16(prim->color));
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

    if ((imageY0 + imageSY) > VRAM_HEIGHT || (imageX0 + imageSX) > 1024 || (imageY1 + imageSY) > VRAM_HEIGHT ||
        (imageX1 + imageSX) > 1024) {
        int i, j;
        for (j = 0; j < imageSY; j++) {
            for (i = 0; i < imageSX; i++) {
                m_vram16[(1024 * ((imageY1 + j) & VRAM_Y_MASK)) + ((imageX1 + i) & VRAM_X_MASK)] =
                    m_vram16[(1024 * ((imageY0 + j) & VRAM_Y_MASK)) + ((imageX0 + i) & VRAM_X_MASK)];
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
        ptr += startX * 3 + startY * 1024 * 2;
        for (int i = 0; i < height; i++) {
            std::memcpy(pixels, ptr, width * 3);
            ptr += 1024 * 2;
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
    m_statusRet = 0x14802000;
    m_softDisplay.Disabled = 1;
    m_softDisplay.DrawOffset.x = m_softDisplay.DrawOffset.y = 0;
    resetRenderer();
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

    if ((m_softDisplay.DisplayPosition.y + m_softDisplay.DisplayMode.y) > VRAM_HEIGHT) {
        int dy1 = VRAM_HEIGHT - m_softDisplay.DisplayPosition.y;
        int dy2 = (m_softDisplay.DisplayPosition.y + m_softDisplay.DisplayMode.y) - VRAM_HEIGHT;

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
