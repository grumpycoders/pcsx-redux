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

#define IMGUI_DEFINE_MATH_OPERATORS

#include "core/gpu.h"

#include "core/debug.h"
#include "core/gpulogger.h"
#include "core/pgxp_mem.h"
#include "core/psxdma.h"
#include "core/psxhw.h"
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "magic_enum/include/magic_enum/magic_enum_all.hpp"

#define GPUSTATUS_READYFORVRAM 0x08000000
#define GPUSTATUS_IDLE 0x04000000  // CMD ready
#define GPUSTATUS_MODE 0x02000000  // Data request mode

namespace PCSX {

// clang-format off
// clang-format doesn't understand duff's device pattern...
template <GPU::Shading shading, GPU::Shape shape, GPU::Textured textured, GPU::Blend blend, GPU::Modulation modulation>
void GPU::Poly<shading, shape, textured, blend, modulation>::processWrite(Buffer & buf, Logged::Origin origin, uint32_t origvalue, uint32_t length) {
    uint32_t value = buf.get();
    switch (m_state) {
        for (/* m_count = 0 */; m_count < count; m_count++) {
            if (shading == Shading::Gouraud) {
                m_state = READ_COLOR;
                if (buf.isEmpty()) return;
                value = buf.get();
                [[fallthrough]];
        case READ_COLOR:
                if constexpr ((textured == Textured::Yes) && (modulation == Modulation::Off)) {
                    colors[m_count] = 0x808080;
                } else {
                    colors[m_count] = value & 0xffffff;
                }
            } else {
                colors[m_count] = colors[0];
            }
            m_state = READ_XY;
            if (buf.isEmpty()) return;
            value = buf.get();
            [[fallthrough]];
        case READ_XY:
            x[m_count] = GPU::signExtend<int, 11>(value & 0xffff);
            y[m_count] = GPU::signExtend<int, 11>(value >> 16);
            if (textured == Textured::Yes) {
                m_state = READ_UV;
                if (buf.isEmpty()) return;
                value = buf.get();
                [[fallthrough]];
        case READ_UV:
                if constexpr (textured == Textured::Yes) {
                    u[m_count] = value & 0xff;
                    v[m_count] = (value >> 8) & 0xff;
                    value >>= 16;
                    if (m_count == 0) {
                        clutraw = value;
                    } else if (m_count == 1) {
                        value &= 0b0000100111111111;
                        tpage = TPage(value);
                        uint32_t lastTPage = m_gpu->m_lastTPage.raw & ~0b0000100111111111;
                        m_gpu->m_lastTPage = TPage(lastTPage | value);
                    }
                }
            }
        }
    }
    m_count = 0;
    m_state = READ_COLOR;
    if constexpr (textured == Textured::Yes) {
        twindow = TWindow(m_gpu->m_lastTWindow.raw);
    }
    offset = m_gpu->m_lastOffset;
    m_gpu->m_defaultProcessor.setActive();
    g_emulator->m_gpuLogger->addNode(*this, origin, origvalue, length);
    m_gpu->write0(this);
}

template <GPU::Shading shading, GPU::LineType lineType, GPU::Blend blend>
void GPU::Line<shading, lineType, blend>::processWrite(Buffer & buf, Logged::Origin origin, uint32_t origvalue, uint32_t length) {
    uint32_t value = buf.get();
    if constexpr (lineType == LineType::Poly) {
        while ((value & 0xf000f000) != 0x50005000) {
            switch (m_state) {
                case READ_COLOR:
                    colors.push_back(value & 0xffffff);
                    m_state = READ_XY;
                    if (buf.isEmpty()) return;
                    value = buf.get();
                    [[fallthrough]];
                case READ_XY:
                    if constexpr (shading == Shading::Flat) {
                        if (x.size() != 0) colors.push_back(colors[0]);
                    } else {
                        m_state = READ_COLOR;
                    }
                    x.push_back(GPU::signExtend<int, 11>(value & 0xffff));
                    y.push_back(GPU::signExtend<int, 11>(value >> 16));
                    if (buf.isEmpty()) return;
                    value = buf.get();
            }
        }
    } else {
        switch (m_state) {
            for (/* m_count = 0 */; m_count < 2; m_count++) {
                if (shading == Shading::Gouraud) {
                    m_state = READ_COLOR;
                    if (buf.isEmpty()) return;
                    value = buf.get();
                    [[fallthrough]];
            case READ_COLOR:
                    colors[m_count] = value & 0xffffff;
                } else {
                    colors[m_count] = colors[0];
                }
                m_state = READ_XY;
                if (buf.isEmpty()) return;
                value = buf.get();
                [[fallthrough]];
            case READ_XY:
                x[m_count] = GPU::signExtend<int, 11>(value & 0xffff);
                y[m_count] = GPU::signExtend<int, 11>(value >> 16);
            }
        }
    }
    if constexpr (lineType == LineType::Simple) {
        m_count = 0;
    }
    m_state = READ_COLOR;
    offset = m_gpu->m_lastOffset;
    m_gpu->m_defaultProcessor.setActive();
    if ((colors.size() >= 2) && ((colors.size() == x.size()))) {
        g_emulator->m_gpuLogger->addNode(*this, origin, origvalue, length);
        m_gpu->write0(this);
    } else {
        g_system->log(LogClass::GPU, "Got an invalid line command...\n");
    }
    if constexpr (lineType == LineType::Poly) {
        colors.clear();
        x.clear();
        y.clear();
    }
}

template <GPU::Size size, GPU::Textured textured, GPU::Blend blend, GPU::Modulation modulation>
void GPU::Rect<size, textured, blend, modulation>::processWrite(Buffer & buf, Logged::Origin origin, uint32_t origvalue, uint32_t length) {
    uint32_t value = buf.get();
    switch (m_state) {
        case READ_COLOR:
            if constexpr ((textured == Textured::No) || (modulation == Modulation::On)) {
                color = value & 0xffffff;
            }
            m_state = READ_XY;
            if (buf.isEmpty()) return;
            value = buf.get();
            [[fallthrough]];
        case READ_XY:
            x = GPU::signExtend<int, 11>(value & 0xffff);
            y = GPU::signExtend<int, 11>(value >> 16);
            if (textured == Textured::Yes) {
                m_state = READ_UV;
                if (buf.isEmpty()) return;
                value = buf.get();
                [[fallthrough]];
        case READ_UV:
                if constexpr (textured == Textured::Yes) {
                    u = value & 0xff;
                    v = (value >> 8) & 0xff;
                    value >>= 16;
                    clutraw = value;
                }
            }
            if constexpr (size == Size::S1) {
                h = 1;
                w = 1;
            } else if constexpr (size == Size::S8) {
                h = 8;
                w = 8;
            } else if constexpr (size == Size::S16) {
                h = 16;
                w = 16;
            }

            if (size == Size::Variable) {
                m_state = READ_HW;
                if (buf.isEmpty()) return;
                value = buf.get();
                [[fallthrough]];
        case READ_HW:
                w = value & 0xffff;
                h = value >> 16;
            }
    }
    m_state = READ_COLOR;
    if constexpr (textured == Textured::Yes) {
        tpage = TPage(m_gpu->m_lastTPage.raw);
        twindow = TWindow(m_gpu->m_lastTWindow.raw);
    }
    offset = m_gpu->m_lastOffset;
    m_gpu->m_defaultProcessor.setActive();
    g_emulator->m_gpuLogger->addNode(*this, origin, origvalue, length);
    m_gpu->write0(this);
}
// clang-format on

namespace {

GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_poly00;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_poly01;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_poly02;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_poly03;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_poly04;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_poly05;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_poly06;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_poly07;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_poly08;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_poly09;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_poly0a;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_poly0b;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_poly0c;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_poly0d;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_poly0e;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_poly0f;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_poly10;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_poly11;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_poly12;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_poly13;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_poly14;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_poly15;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_poly16;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_poly17;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_poly18;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_poly19;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_poly1a;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_poly1b;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_poly1c;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_poly1d;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_poly1e;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_poly1f;

GPU::Line<GPU::Shading::Flat, GPU::LineType::Simple, GPU::Blend::Off> s_line0;
GPU::Line<GPU::Shading::Flat, GPU::LineType::Simple, GPU::Blend::Semi> s_line1;
GPU::Line<GPU::Shading::Flat, GPU::LineType::Poly, GPU::Blend::Off> s_line2;
GPU::Line<GPU::Shading::Flat, GPU::LineType::Poly, GPU::Blend::Semi> s_line3;
GPU::Line<GPU::Shading::Gouraud, GPU::LineType::Simple, GPU::Blend::Off> s_line4;
GPU::Line<GPU::Shading::Gouraud, GPU::LineType::Simple, GPU::Blend::Semi> s_line5;
GPU::Line<GPU::Shading::Gouraud, GPU::LineType::Poly, GPU::Blend::Off> s_line6;
GPU::Line<GPU::Shading::Gouraud, GPU::LineType::Poly, GPU::Blend::Semi> s_line7;

GPU::Rect<GPU::Size::Variable, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_rect00;
GPU::Rect<GPU::Size::Variable, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_rect01;
GPU::Rect<GPU::Size::Variable, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_rect02;
GPU::Rect<GPU::Size::Variable, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_rect03;
GPU::Rect<GPU::Size::Variable, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_rect04;
GPU::Rect<GPU::Size::Variable, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_rect05;
GPU::Rect<GPU::Size::Variable, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_rect06;
GPU::Rect<GPU::Size::Variable, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_rect07;
GPU::Rect<GPU::Size::S1, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_rect08;
GPU::Rect<GPU::Size::S1, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_rect09;
GPU::Rect<GPU::Size::S1, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_rect0a;
GPU::Rect<GPU::Size::S1, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_rect0b;
GPU::Rect<GPU::Size::S1, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_rect0c;
GPU::Rect<GPU::Size::S1, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_rect0d;
GPU::Rect<GPU::Size::S1, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_rect0e;
GPU::Rect<GPU::Size::S1, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_rect0f;
GPU::Rect<GPU::Size::S8, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_rect10;
GPU::Rect<GPU::Size::S8, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_rect11;
GPU::Rect<GPU::Size::S8, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_rect12;
GPU::Rect<GPU::Size::S8, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_rect13;
GPU::Rect<GPU::Size::S8, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_rect14;
GPU::Rect<GPU::Size::S8, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_rect15;
GPU::Rect<GPU::Size::S8, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_rect16;
GPU::Rect<GPU::Size::S8, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_rect17;
GPU::Rect<GPU::Size::S16, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_rect18;
GPU::Rect<GPU::Size::S16, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_rect19;
GPU::Rect<GPU::Size::S16, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_rect1a;
GPU::Rect<GPU::Size::S16, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_rect1b;
GPU::Rect<GPU::Size::S16, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_rect1c;
GPU::Rect<GPU::Size::S16, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_rect1d;
GPU::Rect<GPU::Size::S16, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_rect1e;
GPU::Rect<GPU::Size::S16, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_rect1f;

}  // namespace

}  // namespace PCSX

PCSX::GPU::GPU() {
    m_polygons[0x00] = &s_poly00;
    m_polygons[0x01] = &s_poly01;
    m_polygons[0x02] = &s_poly02;
    m_polygons[0x03] = &s_poly03;
    m_polygons[0x04] = &s_poly04;
    m_polygons[0x05] = &s_poly05;
    m_polygons[0x06] = &s_poly06;
    m_polygons[0x07] = &s_poly07;
    m_polygons[0x08] = &s_poly08;
    m_polygons[0x09] = &s_poly09;
    m_polygons[0x0a] = &s_poly0a;
    m_polygons[0x0b] = &s_poly0b;
    m_polygons[0x0c] = &s_poly0c;
    m_polygons[0x0d] = &s_poly0d;
    m_polygons[0x0e] = &s_poly0e;
    m_polygons[0x0f] = &s_poly0f;
    m_polygons[0x10] = &s_poly10;
    m_polygons[0x11] = &s_poly11;
    m_polygons[0x12] = &s_poly12;
    m_polygons[0x13] = &s_poly13;
    m_polygons[0x14] = &s_poly14;
    m_polygons[0x15] = &s_poly15;
    m_polygons[0x16] = &s_poly16;
    m_polygons[0x17] = &s_poly17;
    m_polygons[0x18] = &s_poly18;
    m_polygons[0x19] = &s_poly19;
    m_polygons[0x1a] = &s_poly1a;
    m_polygons[0x1b] = &s_poly1b;
    m_polygons[0x1c] = &s_poly1c;
    m_polygons[0x1d] = &s_poly1d;
    m_polygons[0x1e] = &s_poly1e;
    m_polygons[0x1f] = &s_poly1f;

    m_lines[0x00] = &s_line0;
    m_lines[0x01] = &s_line0;
    m_lines[0x02] = &s_line1;
    m_lines[0x03] = &s_line1;
    m_lines[0x04] = &s_line0;
    m_lines[0x05] = &s_line0;
    m_lines[0x06] = &s_line1;
    m_lines[0x07] = &s_line1;
    m_lines[0x08] = &s_line2;
    m_lines[0x09] = &s_line2;
    m_lines[0x0a] = &s_line3;
    m_lines[0x0b] = &s_line3;
    m_lines[0x0c] = &s_line2;
    m_lines[0x0d] = &s_line2;
    m_lines[0x0e] = &s_line3;
    m_lines[0x0f] = &s_line3;
    m_lines[0x10] = &s_line4;
    m_lines[0x11] = &s_line4;
    m_lines[0x12] = &s_line5;
    m_lines[0x13] = &s_line5;
    m_lines[0x14] = &s_line4;
    m_lines[0x15] = &s_line4;
    m_lines[0x16] = &s_line5;
    m_lines[0x17] = &s_line5;
    m_lines[0x18] = &s_line6;
    m_lines[0x19] = &s_line6;
    m_lines[0x1a] = &s_line7;
    m_lines[0x1b] = &s_line7;
    m_lines[0x1c] = &s_line6;
    m_lines[0x1d] = &s_line6;
    m_lines[0x1e] = &s_line7;
    m_lines[0x1f] = &s_line7;

    m_rects[0x00] = &s_rect00;
    m_rects[0x01] = &s_rect01;
    m_rects[0x02] = &s_rect02;
    m_rects[0x03] = &s_rect03;
    m_rects[0x04] = &s_rect04;
    m_rects[0x05] = &s_rect05;
    m_rects[0x06] = &s_rect06;
    m_rects[0x07] = &s_rect07;
    m_rects[0x08] = &s_rect08;
    m_rects[0x09] = &s_rect09;
    m_rects[0x0a] = &s_rect0a;
    m_rects[0x0b] = &s_rect0b;
    m_rects[0x0c] = &s_rect0c;
    m_rects[0x0d] = &s_rect0d;
    m_rects[0x0e] = &s_rect0e;
    m_rects[0x0f] = &s_rect0f;
    m_rects[0x10] = &s_rect10;
    m_rects[0x11] = &s_rect11;
    m_rects[0x12] = &s_rect12;
    m_rects[0x13] = &s_rect13;
    m_rects[0x14] = &s_rect14;
    m_rects[0x15] = &s_rect15;
    m_rects[0x16] = &s_rect16;
    m_rects[0x17] = &s_rect17;
    m_rects[0x18] = &s_rect18;
    m_rects[0x19] = &s_rect19;
    m_rects[0x1a] = &s_rect1a;
    m_rects[0x1b] = &s_rect1b;
    m_rects[0x1c] = &s_rect1c;
    m_rects[0x1d] = &s_rect1d;
    m_rects[0x1e] = &s_rect1e;
    m_rects[0x1f] = &s_rect1f;
}

int PCSX::GPU::init(UI *ui) {
    for (auto poly : m_polygons) poly->setGPU(this);
    for (auto line : m_lines) line->setGPU(this);
    for (auto rect : m_rects) rect->setGPU(this);
    m_textureWindowRaw = 0;
    m_drawingStartRaw = 0;
    m_drawingEndRaw = 0;
    m_drawingOffsetRaw = 0;
    m_dataRet = 0x400;
    return initBackend(ui);
}

inline bool PCSX::GPU::CheckForEndlessLoop(uint32_t laddr) {
    if (laddr == s_usedAddr[1]) return true;
    if (laddr == s_usedAddr[2]) return true;

    if (laddr < s_usedAddr[0]) {
        s_usedAddr[1] = laddr;
    } else {
        s_usedAddr[2] = laddr;
    }

    s_usedAddr[0] = laddr;

    return false;
}

uint32_t PCSX::GPU::gpuDmaChainSize(uint32_t addr) {
    uint32_t size;
    uint32_t DMACommandCounter = 0;

    s_usedAddr[0] = s_usedAddr[1] = s_usedAddr[2] = 0xffffff;

    // initial linked list s_ptr (word)
    size = 1;

    do {
        addr &= 0x7ffffc;

        if (DMACommandCounter++ > 2000000) break;
        if (CheckForEndlessLoop(addr)) break;

        uint32_t head = SWAP_LEu32(*g_emulator->m_mem->getPointer<uint32_t>(addr));

        // # 32-bit blocks to transfer
        size += head >> 24;

        // next 32-bit pointer
        addr = head & 0xfffffc;
        size += 1;
    } while (!(addr & 0x800000));  // contrary to some documentation, the end-of-linked-list marker is not actually
                                   // 0xFF'FFFF any pointer with bit 23 set will do.
    return size;
}

uint32_t PCSX::GPU::readStatus() {
    uint32_t ret = readStatusInternal();  // Get status from GPU core

// Gameshark Lite - wants to see VRAM busy
// - Must enable GPU 'Fake Busy States' hack
#if 0
    if ((ret & GPUSTATUS_IDLE) == 0) ret &= ~GPUSTATUS_READYFORVRAM;
#endif
    if (m_readFifo->size() != 0) ret |= GPUSTATUS_READYFORVRAM;
    // Let's pretend our input fifo is always ready for more data.
    if ((ret & 0x60000000) == 0x20000000) ret |= 0x02000000;
    return ret;
}

void PCSX::GPU::dma(uint32_t madr, uint32_t bcr, uint32_t chcr) {  // GPU
    uint32_t *ptr;
    uint32_t size, bs;

    switch (chcr) {
        case 0x01000200:  // vram2mem
            PSXDMA_LOG("*** DMA2 GPU - vram2mem *** %lx addr = %lx size = %lx\n", chcr, madr, bcr);
            ptr = g_emulator->m_mem->getPointer<uint32_t>(madr);
            if (ptr == nullptr) {
                PSXDMA_LOG("*** DMA2 GPU - vram2mem *** NULL Pointer!!!\n");
                break;
            }
            // BA blocks * BS words (word = 32-bits)
            size = (bcr >> 16) * (bcr & 0xffff);
            directDMARead(ptr, size, madr);
            g_emulator->m_cpu->Clear(madr, size);
            if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::Debug>()) {
                g_emulator->m_debug->checkDMAwrite(2, madr, size * 4);
            }
#if 1
            // already 32-bit word size ((size * 4) / 4)
            scheduleGPUDMAIRQ(size);
#else
            // Experimental burst dma transfer (0.333x max)
            scheduleGPUDMAIRQ(size / 3);
#endif
            return;

        case 0x01000201:  // mem2vram
            bs = (bcr & 0xffff);
            size = (bcr >> 16) * bs;  // BA blocks * BS words (word = 32-bits)
            PSXDMA_LOG("*** DMA 2 - GPU mem2vram *** %lx addr = %lxh, BCR %lxh => size %d = BA(%d) * BS(%xh)\n", chcr,
                       madr, bcr, size, size / bs, size / (bcr >> 16));
            ptr = g_emulator->m_mem->getPointer<uint32_t>(madr);
            if (ptr == nullptr) {
                PSXDMA_LOG("*** DMA2 GPU - mem2vram *** NULL Pointer!!!\n");
                break;
            }
            if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::Debug>()) {
                g_emulator->m_debug->checkDMAread(2, madr, size * 4);
            }
            pgxpMemory(PGXP_ConvertAddress(madr), PGXP_GetMem());
            directDMAWrite(ptr, size, madr);

#if 0
            // already 32-bit word size ((size * 4) / 4)
            scheduleGPUDMAIRQ(size);
#else
            // X-Files video interlace. Experimental delay depending of BS.
            scheduleGPUDMAIRQ((7 * size) / bs);
#endif
            return;

        case 0x00000401:  // Vampire Hunter D: title screen linked list update (see psxhw.c)
        case 0x01000401:  // dma chain
            PSXDMA_LOG("*** DMA 2 - GPU dma chain *** %8.8lx addr = %lx size = %lx\n", chcr, madr, bcr);

            size = gpuDmaChainSize(madr);
            chainedDMAWrite((uint32_t *)PCSX::g_emulator->m_mem->m_wram, madr);

            // Tekken 3 = use 1.0 only (not 1.5x)

            // Einhander = parse linked list in pieces (todo)
            // Final Fantasy 4 = internal vram time (todo)
            // Rebel Assault 2 = parse linked list in pieces (todo)
            // Vampire Hunter D = allow edits to linked list (todo)
            scheduleGPUDMAIRQ(size);
            return;

        default:
            PSXDMA_LOG("*** DMA 2 - GPU unknown *** %lx addr = %lx size = %lx\n", chcr, madr, bcr);
            break;
    }

    gpuInterrupt();
}

void PCSX::GPU::gpuInterrupt() {
    auto &mem = g_emulator->m_mem;
    mem->clearDMABusy<2>();
    mem->dmaInterrupt<2>();
}

void PCSX::GPU::writeStatus(uint32_t value) {
    uint32_t cmd = (value >> 24) & 0xff;
    bool gotUnknown = false;

    m_statusControl[cmd] = value;

    switch (cmd) {
        case 0: {
            m_readFifo->reset();
            m_processor->reset();
            m_defaultProcessor.setActive();
            CtrlReset ctrl;
            g_emulator->m_gpuLogger->addNode(ctrl, Logged::Origin::CTRLWRITE, value, 1);
            write1(&ctrl);
            m_textureWindowRaw = 0;
            m_drawingStartRaw = 0;
            m_drawingEndRaw = 0;
            m_drawingOffsetRaw = 0;
            m_dataRet = 0x400;
        } break;
        case 1: {
            CtrlClearFifo ctrl;
            g_emulator->m_gpuLogger->addNode(ctrl, Logged::Origin::CTRLWRITE, value, 1);
            write1(&ctrl);
        } break;
        case 2: {
            CtrlIrqAck ctrl;
            g_emulator->m_gpuLogger->addNode(ctrl, Logged::Origin::CTRLWRITE, value, 1);
            write1(&ctrl);
        } break;
        case 3: {
            CtrlDisplayEnable ctrl(value);
            g_emulator->m_gpuLogger->addNode(ctrl, Logged::Origin::CTRLWRITE, value, 1);
            write1(&ctrl);
        } break;
        case 4: {
            CtrlDmaSetting ctrl(value);
            g_emulator->m_gpuLogger->addNode(ctrl, Logged::Origin::CTRLWRITE, value, 1);
            write1(&ctrl);
        } break;
        case 5: {
            CtrlDisplayStart ctrl(value);
            g_emulator->m_gpuLogger->addNode(ctrl, Logged::Origin::CTRLWRITE, value, 1);
            write1(&ctrl);
        } break;
        case 6: {
            CtrlHorizontalDisplayRange ctrl(value);
            g_emulator->m_gpuLogger->addNode(ctrl, Logged::Origin::CTRLWRITE, value, 1);
            write1(&ctrl);
        } break;
        case 7: {
            CtrlVerticalDisplayRange ctrl(value);
            g_emulator->m_gpuLogger->addNode(ctrl, Logged::Origin::CTRLWRITE, value, 1);
            write1(&ctrl);
        } break;
        case 8: {
            CtrlDisplayMode ctrl(value);
            g_emulator->m_gpuLogger->addNode(ctrl, Logged::Origin::CTRLWRITE, value, 1);
            write1(&ctrl);
        } break;
        case 16: {
            CtrlQuery ctrl(value);
            g_emulator->m_gpuLogger->addNode(ctrl, Logged::Origin::CTRLWRITE, value, 1);
            write1(&ctrl);
        } break;
        default: {
            gotUnknown = true;
        } break;
    }

    if (gotUnknown) {
        g_system->log(LogClass::GPU, "Got an unknown GPU control word: %08x\n", value);
    }
}

uint32_t PCSX::GPU::readData() {
    if (m_readFifo->size() == 0) {
        return m_dataRet;
    }
    return m_readFifo.asA<File>()->read<uint32_t>();
}

void PCSX::GPU::write1(CtrlQuery *ctrl) {
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

void PCSX::GPU::writeData(uint32_t value) {
    Buffer buf(value);
    m_processor->processWrite(buf, Logged::Origin::DATAWRITE, value, 1);
}

void PCSX::GPU::directDMAWrite(const uint32_t *feed, int transferSize, uint32_t hwAddr) {
    Buffer buf(feed, transferSize);
    while (!buf.isEmpty()) {
        m_processor->processWrite(buf, Logged::Origin::DIRECT_DMA, hwAddr, transferSize);
    }
}

void PCSX::GPU::directDMARead(uint32_t *dest, int transferSize, uint32_t hwAddr) {
    auto size = m_readFifo->size();
    m_readFifo->read(dest, transferSize * 4);
    transferSize -= size / 4;
    dest += size / 4;
    while (transferSize != 0) {
        *dest++ = m_dataRet;
    }
}

void PCSX::GPU::chainedDMAWrite(const uint32_t *memory, uint32_t hwAddr) {
    uint32_t addr = hwAddr;
    uint32_t DMACommandCounter = 0;

    s_usedAddr[0] = s_usedAddr[1] = s_usedAddr[2] = 0xffffff;

    do {
        addr &= g_emulator->getRamMask<4>();

        if (DMACommandCounter++ > 2000000) break;
        if (CheckForEndlessLoop(addr)) break;

        // # 32-bit blocks to transfer
        addr >>= 2;
        uint32_t header = memory[addr];
        uint32_t transferSize = header >> 24;
        const uint32_t *feed = memory + addr + 1;
        Buffer buf(feed, transferSize);
        while (!buf.isEmpty()) {
            m_processor->processWrite(buf, Logged::Origin::CHAIN_DMA, addr << 2, transferSize);
        }

        // next 32-bit pointer
        addr = header & 0xfffffc;
    } while (!(addr & 0x800000));  // contrary to some documentation, the end-of-linked-list marker is not actually
                                   // 0xFF'FFFF any pointer with bit 23 set will do.
}

void PCSX::GPU::Command::processWrite(Buffer &buf, Logged::Origin origin, uint32_t originValue, uint32_t length) {
    while (!buf.isEmpty()) {
        uint32_t value = buf.get();
        bool gotUnknown = false;
        const uint8_t cmdType = value >> 29;           // 3 topmost bits = command "type"
        const uint8_t command = (value >> 24) & 0x1f;  // 5 next bits = "command", which may be a bitfield

        const uint32_t packetInfo = value & 0xffffff;

        switch (cmdType) {
            case 0:  // GPU command
                switch (command) {
                    case 0x01: {  // clear cache
                        ClearCache prim;
                        m_gpu->write0(&prim);
                        g_emulator->m_gpuLogger->addNode(prim, origin, originValue, length);
                    } break;
                    case 0x02: {  // fast fill
                        buf.rewind();
                        m_gpu->m_fastFill.setActive();
                        m_gpu->m_fastFill.processWrite(buf, origin, originValue, length);
                    } break;
                    default: {
                        gotUnknown = true;
                    } break;
                }
                break;
            case 1: {  // Polygon primitive
                buf.rewind();
                m_gpu->m_polygons[command]->setActive();
                m_gpu->m_processor->processWrite(buf, origin, originValue, length);
            } break;
            case 2: {  // Line primitive
                buf.rewind();
                m_gpu->m_lines[command]->setActive();
                m_gpu->m_processor->processWrite(buf, origin, originValue, length);
            } break;
            case 3: {  // Rectangle primitive
                buf.rewind();
                m_gpu->m_rects[command]->setActive();
                m_gpu->m_processor->processWrite(buf, origin, originValue, length);
            } break;
            case 4: {  // Move data in VRAM
                m_gpu->m_blitVramVram.setActive();
                m_gpu->m_processor->processWrite(buf, origin, originValue, length);
            } break;
            case 5: {  // Write data to VRAM
                m_gpu->m_blitRamVram.setActive();
                m_gpu->m_processor->processWrite(buf, origin, originValue, length);
            } break;
            case 6: {  // Read data from VRAM
                m_gpu->m_blitVramRam.setActive();
                m_gpu->m_processor->processWrite(buf, origin, originValue, length);
            } break;
            case 7: {  // Environment command
                switch (command) {
                    case 1: {  // tpage
                        TPage prim(packetInfo);
                        m_gpu->m_lastTPage = TPage(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, originValue, length);
                        m_gpu->write0(&prim);
                    } break;
                    case 2: {  // twindow
                        TWindow prim(packetInfo);
                        m_gpu->m_lastTWindow = TWindow(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, originValue, length);
                        m_gpu->write0(&prim);
                        m_gpu->m_textureWindowRaw = packetInfo & 0xfffff;
                    } break;
                    case 3: {  // drawing area top left
                        DrawingAreaStart prim(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, originValue, length);
                        m_gpu->write0(&prim);
                        m_gpu->m_drawingStartRaw = packetInfo & 0xfffff;
                    } break;
                    case 4: {  // drawing area bottom right
                        DrawingAreaEnd prim(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, originValue, length);
                        m_gpu->write0(&prim);
                        m_gpu->m_drawingEndRaw = packetInfo & 0xfffff;
                    } break;
                    case 5: {  // drawing offset
                        DrawingOffset prim(packetInfo);
                        m_gpu->m_lastOffset = DrawingOffset(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, originValue, length);
                        m_gpu->write0(&prim);
                        m_gpu->m_drawingOffsetRaw = packetInfo & 0x3fffff;
                    } break;
                    case 6: {  // mask bit
                        MaskBit prim(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, originValue, length);
                        m_gpu->write0(&prim);
                    } break;
                    default: {
                        gotUnknown = true;
                    } break;
                }
            } break;
        }
        if (gotUnknown && (value != 0)) {
            g_system->log(LogClass::GPU, "Got an unknown GPU data word: %08x (cmdType: %hhu, command: %hhu)\n", value,
                          cmdType, command);
        }
    }
}

void PCSX::GPU::FastFill::processWrite(Buffer &buf, Logged::Origin origin, uint32_t origvalue, uint32_t length) {
    uint32_t value = buf.get();
    switch (m_state) {
        case READ_COLOR:
            color = value & 0xffffff;
            m_state = READ_XY;
            if (buf.isEmpty()) return;
            value = buf.get();
            [[fallthrough]];
        case READ_XY:
            x = value & 0xffff;
            y = value >> 16;
            m_state = READ_WH;
            if (buf.isEmpty()) return;
            value = buf.get();
            [[fallthrough]];
        case READ_WH:
            w = value & 0xffff;
            h = value >> 16;
            raw.x = x;
            raw.y = y;
            raw.w = w;
            raw.h = h;
            clipped = GPU::clip(x, y, w, h);
            m_state = READ_COLOR;
            m_gpu->m_defaultProcessor.setActive();
            g_emulator->m_gpuLogger->addNode(*this, origin, origvalue, length);
            m_gpu->write0(this);
            return;
    }
}

void PCSX::GPU::BlitVramVram::processWrite(Buffer &buf, Logged::Origin origin, uint32_t origvalue, uint32_t length) {
    uint32_t value;
    switch (m_state) {
        case READ_COMMAND:
            m_state = READ_SRC_XY;
            if (buf.isEmpty()) return;
            [[fallthrough]];
        case READ_SRC_XY:
            value = buf.get();
            sX = signExtend<int, 11>(value & 0xffff);
            sY = signExtend<int, 11>(value >> 16);
            m_state = READ_DST_XY;
            if (buf.isEmpty()) return;
            [[fallthrough]];
        case READ_DST_XY:
            value = buf.get();
            dX = signExtend<int, 11>(value & 0xffff);
            dY = signExtend<int, 11>(value >> 16);
            m_state = READ_HW;
            if (buf.isEmpty()) return;
            [[fallthrough]];
        case READ_HW:
            value = buf.get();
            w = value & 0xffff;
            h = value >> 16;
            raw.sX = sX;
            raw.sY = sY;
            raw.dX = dX;
            raw.dY = dY;
            raw.w = w;
            raw.h = h;
            clipped = GPU::clip(sX, sY, w, h);
            clipped |= GPU::clip(dX, dY, w, h);
            m_state = READ_COMMAND;
            m_gpu->m_defaultProcessor.setActive();
            g_emulator->m_gpuLogger->addNode(*this, origin, origvalue, length);
            m_gpu->write0(this);
            return;
    }
}

void PCSX::GPU::BlitRamVram::processWrite(Buffer &buf, Logged::Origin origin, uint32_t origvalue, uint32_t length) {
    uint32_t value;
    size_t size = (w * h + 1) / 2;
    bool done = false;
    switch (m_state) {
        case READ_COMMAND:
            m_state = READ_XY;
            if (buf.isEmpty()) return;
            [[fallthrough]];
        case READ_XY:
            value = buf.get();
            x = signExtend<int, 11>(value & 0xffff);
            y = signExtend<int, 11>(value >> 16);
            m_state = READ_HW;
            if (buf.isEmpty()) return;
            [[fallthrough]];
        case READ_HW:
            value = buf.get();
            w = value & 0xffff;
            h = value >> 16;
            size = (w * h + 1) / 2;
            m_data.clear();
            m_data.reserve(size * 4);
            m_state = READ_PIXELS;
            if (buf.isEmpty()) return;
            [[fallthrough]];
        case READ_PIXELS:
            if ((buf.size() >= size) && (m_data.empty())) {
                data.borrow(buf.data(), size * 4);
                buf.consume(size);
                done = true;
            } else {
                size_t toConsume = std::min(buf.size(), size - m_data.size() / 4);
                m_data.append(reinterpret_cast<const char *>(buf.data()), toConsume * 4);
                done = m_data.size() == size * 4;
                buf.consume(toConsume);
                if (done) {
                    data.acquire(std::move(m_data));
                    m_data.clear();
                }
            }
            break;
    }
    if (done) {
        raw.x = x;
        raw.y = y;
        raw.w = w;
        raw.h = h;
        clipped = GPU::clip(x, y, w, h);
        m_state = READ_COMMAND;
        m_gpu->m_defaultProcessor.setActive();
        g_emulator->m_gpuLogger->addNode(*this, origin, origvalue, length);
        m_gpu->partialUpdateVRAM(x, y, w, h, data.data<uint16_t>(), PartialUpdateVram::Synchronous);
    }
}

void PCSX::GPU::BlitRamVram::execute(GPU *gpu) { gpu->partialUpdateVRAM(x, y, w, h, data.data<uint16_t>()); }

void PCSX::GPU::BlitVramRam::processWrite(Buffer &buf, Logged::Origin origin, uint32_t origvalue, uint32_t length) {
    uint32_t value;
    switch (m_state) {
        case READ_COMMAND:
            m_gpu->m_readFifo->reset();
            m_state = READ_XY;
            if (buf.isEmpty()) return;
            [[fallthrough]];
        case READ_XY:
            value = buf.get();
            x = signExtend<int, 11>(value & 0xffff);
            y = signExtend<int, 11>(value >> 16);
            m_state = READ_HW;
            if (buf.isEmpty()) return;
            [[fallthrough]];
        case READ_HW:
            value = buf.get();
            w = value & 0xffff;
            h = value >> 16;
            raw.x = x;
            raw.y = y;
            raw.w = w;
            raw.h = h;
            clipped = GPU::clip(x, y, w, h);
            m_state = READ_COMMAND;
            m_gpu->m_defaultProcessor.setActive();
            g_emulator->m_gpuLogger->addNode(*this, origin, origvalue, length);
            m_gpu->m_vramReadSlice = m_gpu->getVRAM();
            for (auto l = y; l < y + h; l++) {
                Slice slice;
                slice.borrow(m_gpu->m_vramReadSlice, (l * 1024 + x) * 2, w * 2);
                m_gpu->m_readFifo->pushSlice(std::move(slice));
            }
            return;
    }
}

PCSX::GPU::TPage::TPage(uint32_t value) {
    raw = value;
    tx = value & 0x0f;
    ty = (value >> 4) & 1;
    blendFunction = magic_enum::enum_cast<BlendFunction>((value >> 5) & 3).value();
    auto depth = (value >> 7) & 3;
    texDepth = magic_enum::enum_cast<TexDepth>(depth == 3 ? 2 : depth).value();
    dither = (value >> 9) & 1;
    drawToDisplay = (value >> 10) & 1;
    texDisable = (value >> 11) & 1;
    xflip = (value >> 12) & 1;
    yflip = (value >> 13) & 1;
}

PCSX::GPU::TWindow::TWindow(uint32_t value) {
    x = value & 0x1f;
    y = (value >> 5) & 0x1f;
    w = (value >> 10) & 0x1f;
    h = (value >> 15) & 0x1f;

    raw = value;
}

PCSX::GPU::DrawingAreaStart::DrawingAreaStart(uint32_t value) {
    x = value & 0x3ff;
    y = (value >> 10) & 0x1ff;

    raw = value;
}

PCSX::GPU::DrawingAreaEnd::DrawingAreaEnd(uint32_t value) {
    x = value & 0x3ff;
    y = (value >> 10) & 0x1ff;

    raw = value;
}

PCSX::GPU::DrawingOffset::DrawingOffset(uint32_t value) {
    int ux = value & 0x7ff;
    int uy = (value >> 11) & 0x7ff;
    x = signExtend<int, 11>(ux);
    y = signExtend<int, 11>(uy);

    raw = value;
}

PCSX::GPU::MaskBit::MaskBit(uint32_t value) {
    set = value & 1;
    check = (value >> 1) & 1;
}

void PCSX::GPU::write0(BlitVramVram *prim) {
    auto inSlice = getVRAM();

    auto sX = prim->sX;
    auto sY = prim->sY;
    auto dX = prim->dX;
    auto dY = prim->dY;
    auto w = prim->w;
    auto h = prim->h;

    if (sX > 1024) {
        w -= sX - 1024;
        sX = 1024;
    }
    if (sY > 512) {
        h -= sY - 512;
        sY = 512;
    }
    if (dX > 1024) {
        w -= dX - 1024;
        dX = 1024;
    }
    if (dY > 512) {
        h -= dY - 512;
        dY = 512;
    }

    if ((w == 0) || (h == 0)) return;

    std::vector<uint16_t> rect;
    rect.resize(h * w);
    for (unsigned l = 0; l < h; l++) {
        Slice slice;
        slice.borrow(inSlice, ((l + sY) * 1024 + sX) * sizeof(uint16_t), w * sizeof(uint16_t));
        memcpy(rect.data() + l * w, slice.data(), slice.size());
    }
    partialUpdateVRAM(dX, dY, w, h, rect.data(), PartialUpdateVram::Synchronous);
}

// These technically belong to gpulogger.cc, but due to the template instanciation, they need to be here

void PCSX::GPU::Logged::drawColorBox(uint32_t color, unsigned itemIndex, unsigned colorIndex,
                                     const DrawLogSettings &settings) {
    auto R = (color >> 0) & 0xff;
    auto G = (color >> 8) & 0xff;
    auto B = (color >> 16) & 0xff;
    ImGui::ColorButton(fmt::format("##ColorBox%i%i", itemIndex, colorIndex).c_str(),
                       ImVec4{R / 255.0f, G / 255.0f, B / 255.0f, 1.0f}, ImGuiColorEditFlags_NoAlpha);

    switch (settings.colorFormat) {
        case DrawLogSettings::ColorFormat::None:
            break;
        case DrawLogSettings::ColorFormat::Expanded:
            ImGui::SameLine();
            ImGui::Text(" R: %i, G: %i, B: %i", R, G, B);
            break;
        case DrawLogSettings::ColorFormat::HTML: {
            ImGui::SameLine();
            ImGui::TextUnformatted(" ");
            ImGui::SameLine();
            std::string label = fmt::format("#{:02X}{:02X}{:02X}###ColorBox%i%i", R, G, B, itemIndex, colorIndex);
            if (ImGui::Button(label.c_str())) {
                ImGui::SetClipboardText(fmt::format("{:02X}{:02X}{:02X}", R, G, B).c_str());
            }
        } break;
    }
}

template <PCSX::GPU::Shading shading, PCSX::GPU::Shape shape, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend,
          PCSX::GPU::Modulation modulation>
void PCSX::GPU::Poly<shading, shape, textured, blend, modulation>::drawLogNode(unsigned itemIndex,
                                                                               const DrawLogSettings &settings) {
    if constexpr ((textured == Textured::No) || (modulation == Modulation::On)) {
        if constexpr (shading == Shading::Flat) {
            ImGui::TextUnformatted(_("Shading: Flat"));
            drawColorBox(colors[0], itemIndex, 0, settings);
        } else if constexpr (shading == Shading::Gouraud) {
            ImGui::TextUnformatted(_("Shading: Gouraud"));
        }
    }
    if constexpr (textured == Textured::Yes) {
        ImGui::TextUnformatted(_("Textured"));
    }
    if constexpr (blend == Blend::Semi) {
        ImGui::TextUnformatted(_("Semi-transparency blending"));
    }
    if constexpr (textured == Textured::Yes) {
        ImGui::Separator();
        tpage.drawLogNodeCommon();
        if (tpage.texDepth != TexDepth::Tex16Bits) {
            std::string label = fmt::format("  ClutX: {}, ClutY: {}", clutX(), clutY());
            if (ImGui::Button(label.c_str())) {
                g_system->m_eventBus->signal(Events::GUI::SelectClut{clutX(), clutY()});
            }
        }
    }
    int minX = 2048, minY = 1024, maxX = -1024, maxY = -512;
    int minU = 2048, minV = 1024, maxU = -1024, maxV = -512;
    for (unsigned i = 0; i < count; i++) {
        ImGui::Separator();
        ImGui::Text(_("Vertex %i"), i);
        ImGui::Text("  X: %i + %i = %i, Y: %i + %i = %i", x[i], offset.x, x[i] + offset.x, y[i], offset.y,
                    y[i] + offset.y);
        minX = std::min(minX, x[i] + offset.x);
        minY = std::min(minY, y[i] + offset.y);
        maxX = std::max(maxX, x[i] + offset.x);
        maxY = std::max(maxY, y[i] + offset.y);
        if constexpr ((shading == Shading::Gouraud) && ((textured == Textured::No) || (modulation == Modulation::On))) {
            drawColorBox(colors[i], itemIndex, i, settings);
        }
        if constexpr (textured == Textured::Yes) {
            unsigned tx = tpage.tx * 64;
            unsigned ty = tpage.ty * 256;
            unsigned shift = tpage.texDepth == TexDepth::Tex4Bits ? 2 : tpage.texDepth == TexDepth::Tex8Bits ? 1 : 0;
            ImGui::Text("  U: %i >> %i + %i = %i, V: %i + %i = %i", u[i], shift, tx, (u[i] >> shift) + tx, v[i], ty,
                        v[i] + ty);
            minU = std::min(minU, int(u[i] >> shift));
            minV = std::min(minV, int(v[i]));
            maxU = std::max(maxU, int(u[i] >> shift));
            maxV = std::max(maxV, int(v[i]));
        }
    }
    ImGui::Separator();
    std::string label = fmt::format(f_("Go to primitive##{}"), itemIndex);
    if (ImGui::Button(label.c_str())) {
        g_system->m_eventBus->signal(Events::GUI::VRAMFocus{minX, minY, maxX, maxY});
    }
    if constexpr (textured == Textured::Yes) {
        unsigned tx = tpage.tx * 64;
        unsigned ty = tpage.ty * 256;
        ImGui::SameLine();
        std::string label = fmt::format(f_("Go to texture##{}"), itemIndex);
        if (ImGui::Button(label.c_str())) {
            const auto mode = tpage.texDepth == TexDepth::Tex16Bits  ? Events::GUI::VRAM_16BITS
                              : tpage.texDepth == TexDepth::Tex8Bits ? Events::GUI::VRAM_8BITS
                                                                     : Events::GUI::VRAM_4BITS;
            g_system->m_eventBus->signal(Events::GUI::SelectClut{clutX(), clutY()});
            g_system->m_eventBus->signal(
                Events::GUI::VRAMFocus{int(minU + tx), int(minV + ty), int(maxU + tx), int(maxV + ty), mode});
        }
        if (tpage.texDepth != TexDepth::Tex16Bits) {
            ImGui::SameLine();
            std::string label = fmt::format(f_("Go to CLUT##{}"), itemIndex);
            if (ImGui::Button(label.c_str())) {
                int depth = tpage.texDepth == TexDepth::Tex4Bits ? 16 : 256;
                g_system->m_eventBus->signal(
                    Events::GUI::VRAMFocus{int(clutX()), int(clutY()), int(clutX() + depth), int(clutY() + 1)});
            }
        }
    }
}

template <PCSX::GPU::Shading shading, PCSX::GPU::LineType lineType, PCSX::GPU::Blend blend>
void PCSX::GPU::Line<shading, lineType, blend>::drawLogNode(unsigned itemIndex, const DrawLogSettings &settings) {
    int minX = x[0], minY = y[0], maxX = x[0], maxY = y[0];
    if constexpr (shading == Shading::Flat) {
        ImGui::TextUnformatted(_("Shading: Flat"));
        drawColorBox(colors[0], itemIndex, 0, settings);
    } else if constexpr (shading == Shading::Gouraud) {
        ImGui::TextUnformatted(_("Shading: Gouraud"));
    }
    if constexpr (blend == Blend::Semi) {
        ImGui::TextUnformatted(_("Semi-transparency blending"));
    }
    for (unsigned i = 1; i < colors.size(); i++) {
        ImGui::Separator();
        if constexpr (lineType == LineType::Poly) {
            ImGui::Text(_("Line %i"), i);
        }
        ImGui::Text("  X0: %i + %i = %i, Y0: %i + %i = %i", x[i - 1], offset.x, x[i - 1] + offset.x, y[i - 1], offset.y,
                    y[i - 1] + offset.y);
        if constexpr (shading == Shading::Gouraud) {
            drawColorBox(colors[i - 1], itemIndex, i * 2, settings);
        }
        ImGui::Text("  X1: %i + %i = %i, Y1: %i + %i = %i", x[i], offset.x, x[i] + offset.x, y[i], offset.y,
                    y[i] + offset.y);
        if constexpr (shading == Shading::Gouraud) {
            drawColorBox(colors[i], itemIndex, i * 2 + 1, settings);
        }
        minX = std::min(minX, x[i] + offset.x);
        minY = std::min(minY, y[i] + offset.y);
        maxX = std::max(maxX, x[i] + offset.x);
        maxY = std::max(maxY, y[i] + offset.y);
    }
    ImGui::Separator();
    std::string label = fmt::format(f_("Go to primitive##{}"), itemIndex);
    if (ImGui::Button(label.c_str())) {
        g_system->m_eventBus->signal(Events::GUI::VRAMFocus{minX, minY, maxX, maxY});
    }
}

template <PCSX::GPU::Size size, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend, PCSX::GPU::Modulation modulation>
void PCSX::GPU::Rect<size, textured, blend, modulation>::drawLogNode(unsigned itemIndex,
                                                                     const DrawLogSettings &settings) {
    ImGui::Text("  X0: %i + %i = %i, Y0: %i + %i = %i", x, offset.x, x + offset.x, y, offset.y, y + offset.y);
    ImGui::Text("  X1: %i + %i = %i, Y1: %i + %i = %i", x + w, offset.x, x + w + offset.x, y + h, offset.y,
                y + h + offset.y);
    ImGui::Text("  W: %i, H: %i", w, h);
    if constexpr ((textured == Textured::No) || (modulation == Modulation::On)) {
        drawColorBox(color, itemIndex, 0, settings);
    }
    if constexpr (blend == Blend::Semi) {
        ImGui::TextUnformatted(_("Semi-transparency blending"));
    }
    if constexpr (textured == Textured::Yes) {
        unsigned tx = tpage.tx * 64;
        unsigned ty = tpage.ty * 256;
        unsigned shift = tpage.texDepth == TexDepth::Tex4Bits ? 2 : tpage.texDepth == TexDepth::Tex8Bits ? 1 : 0;
        ImGui::Text("  U: %i >> %i + %i = %i, V: %i + %i = %i", u, shift, tx, (u >> shift) + tx, v, ty, v + ty);
        std::string label = fmt::format("  ClutX: {}, ClutY: {}", clutX(), clutY());
        if (ImGui::Button(label.c_str())) {
            g_system->m_eventBus->signal(Events::GUI::SelectClut{clutX(), clutY()});
        }
    }
    ImGui::Separator();
    std::string label = fmt::format(f_("Go to primitive##{}"), itemIndex);
    if (ImGui::Button(label.c_str())) {
        g_system->m_eventBus->signal(
            Events::GUI::VRAMFocus{x + offset.x, y + offset.y, x + w + offset.x, y + h + offset.y});
    }
    if constexpr (textured == Textured::Yes) {
        unsigned tx = tpage.tx * 64;
        unsigned ty = tpage.ty * 256;
        unsigned shift = tpage.texDepth == TexDepth::Tex4Bits ? 2 : tpage.texDepth == TexDepth::Tex8Bits ? 1 : 0;
        ImGui::SameLine();
        std::string label = fmt::format(f_("Go to texture##{}"), itemIndex);
        if (ImGui::Button(label.c_str())) {
            const auto mode = tpage.texDepth == TexDepth::Tex16Bits  ? Events::GUI::VRAM_16BITS
                              : tpage.texDepth == TexDepth::Tex8Bits ? Events::GUI::VRAM_8BITS
                                                                     : Events::GUI::VRAM_4BITS;
            g_system->m_eventBus->signal(Events::GUI::SelectClut{clutX(), clutY()});
            g_system->m_eventBus->signal(Events::GUI::VRAMFocus{int((u >> shift) + tx), int(v + ty),
                                                                int(((u + w) >> shift) + tx), int(v + h + ty), mode});
        }
        if (tpage.texDepth != TexDepth::Tex16Bits) {
            ImGui::SameLine();
            std::string label = fmt::format(f_("Go to CLUT##{}"), itemIndex);
            if (ImGui::Button(label.c_str())) {
                g_system->m_eventBus->signal(
                    Events::GUI::VRAMFocus{int(clutX()), int(clutY()), int(clutX() + 256), int(clutY() + 1)});
            }
        }
    }
}

static float triangleArea(float x1, float x2, float x3, float y1, float y2, float y3) {
    float adx = x1 - x2;
    float ady = y1 - y2;
    float bdx = x1 - x3;
    float bdy = y1 - y3;
    float cdx = x2 - x3;
    float cdy = y2 - y3;
    float a = sqrtf(adx * adx + ady * ady);
    float b = sqrtf(bdx * bdx + bdy * bdy);
    float c = sqrtf(cdx * cdx + cdy * cdy);
    float s = (a + b + c) / 2;
    return sqrtf(s * (s - a) * (s - b) * (s - c));
}

template <PCSX::GPU::Shading shading, PCSX::GPU::Shape shape, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend,
          PCSX::GPU::Modulation modulation>
void PCSX::GPU::Poly<shading, shape, textured, blend, modulation>::generateStatsInfo() {
    float pixelArea = 0.0f;
    float textureArea = 0.0f;

    pixelArea = triangleArea(x[0], x[1], x[2], y[0], y[1], y[2]);
    if constexpr (shape == Shape::Quad) {
        pixelArea += triangleArea(x[1], x[2], x[3], y[1], y[2], y[3]);
    }
    if constexpr (textured == Textured::Yes) {
        unsigned shift = tpage.texDepth == TexDepth::Tex4Bits ? 2 : tpage.texDepth == TexDepth::Tex8Bits ? 1 : 0;
        textureArea += triangleArea(u[0] >> shift, u[1] >> shift, u[2] >> shift, v[0], v[1], v[2]);
        if constexpr (shape == Shape::Quad) {
            textureArea += triangleArea(u[1] >> shift, u[2] >> shift, u[3] >> shift, v[1], v[2], v[3]);
        }
    }

    if constexpr (textured == Textured::Yes) {
        stats.texturedTriangles = shape == Shape::Quad ? 2 : 1;
    } else {
        stats.triangles = shape == Shape::Quad ? 2 : 1;
    }
    stats.pixelWrites = pixelArea;
    if constexpr (blend == Blend::Semi) {
        stats.pixelReads = pixelArea;
    }
    stats.texelReads = textureArea;
}

template <PCSX::GPU::Shading shading, PCSX::GPU::LineType lineType, PCSX::GPU::Blend blend>
void PCSX::GPU::Line<shading, lineType, blend>::generateStatsInfo() {
    unsigned pixels = 0;
    for (unsigned i = 1; i < colors.size(); i++) {
        auto dx = std::abs(x[i] - x[i - 1]);
        auto dy = std::abs(y[i] - y[i - 1]);
        if (dx > dy) {
            pixels += dx;
        } else {
            pixels += dy;
        }
    }

    stats.pixelWrites += pixels;
    if constexpr (blend == Blend::Semi) {
        stats.pixelReads += pixels;
    }
}

template <PCSX::GPU::Shading shading, PCSX::GPU::Shape shape, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend,
          PCSX::GPU::Modulation modulation>
void PCSX::GPU::Poly<shading, shape, textured, blend, modulation>::cumulateStats(GPUStats *accum) {
    *accum += stats;
}

template <PCSX::GPU::Shading shading, PCSX::GPU::LineType lineType, PCSX::GPU::Blend blend>
void PCSX::GPU::Line<shading, lineType, blend>::cumulateStats(GPUStats *accum) {
    *accum += stats;
}

template <PCSX::GPU::Size size, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend, PCSX::GPU::Modulation modulation>
void PCSX::GPU::Rect<size, textured, blend, modulation>::cumulateStats(GPUStats *stats) {
    auto s = h * w;
    stats->pixelWrites += s;
    if constexpr (textured == Textured::Yes) {
        unsigned shift = tpage.texDepth == TexDepth::Tex4Bits ? 2 : tpage.texDepth == TexDepth::Tex8Bits ? 1 : 0;
        stats->texelReads += s >> shift;
        stats->sprites++;
    } else {
        stats->rectangles++;
    }
    if constexpr (blend == Blend::Semi) {
        stats->pixelReads += s;
    }
}

template <PCSX::GPU::Shading shading, PCSX::GPU::Shape shape, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend,
          PCSX::GPU::Modulation modulation>
void PCSX::GPU::Poly<shading, shape, textured, blend, modulation>::getVertices(AddTri &&add, PixelOp op) {
    if (op == PixelOp::WRITE) {
        add({x[0] + offset.x, y[0] + offset.y}, {x[1] + offset.x, y[1] + offset.y}, {x[2] + offset.x, y[2] + offset.y});
        if constexpr (shape == Shape::Quad) {
            add({x[1] + offset.x, y[1] + offset.y}, {x[2] + offset.x, y[2] + offset.y},
                {x[3] + offset.x, y[3] + offset.y});
        }
    } else if (op == PixelOp::READ) {
        if constexpr (blend == Blend::Semi) {
            add({x[0] + offset.x, y[0] + offset.y}, {x[1] + offset.x, y[1] + offset.y},
                {x[2] + offset.x, y[2] + offset.y});
            if constexpr (shape == Shape::Quad) {
                add({x[1] + offset.x, y[1] + offset.y}, {x[2] + offset.x, y[2] + offset.y},
                    {x[3] + offset.x, y[3] + offset.y});
            }
        }
        if constexpr (textured == Textured::Yes) {
            unsigned tx = tpage.tx * 64;
            unsigned ty = tpage.ty * 256;
            unsigned shift = tpage.texDepth == TexDepth::Tex4Bits ? 2 : tpage.texDepth == TexDepth::Tex8Bits ? 1 : 0;
            add({int((u[0] >> shift) + tx), int(v[0] + ty)}, {int((u[1] >> shift) + tx), int(v[1] + ty)},
                {int((u[2] >> shift) + tx), int(v[2] + ty)});
            if constexpr (shape == Shape::Quad) {
                add({int((u[1] >> shift) + tx), int(v[1] + ty)}, {int((u[2] >> shift) + tx), int(v[2] + ty)},
                    {int((u[3] >> shift) + tx), int(v[3] + ty)});
            }
            if (tpage.texDepth == TexDepth::Tex4Bits) {
                addLine(std::move(add), clutX(), clutY(), clutX() + 16, clutY());
            } else if (tpage.texDepth == TexDepth::Tex8Bits) {
                addLine(std::move(add), clutX(), clutY(), clutX() + 256, clutY());
            }
        }
    }
}

template <PCSX::GPU::Shading shading, PCSX::GPU::LineType lineType, PCSX::GPU::Blend blend>
void PCSX::GPU::Line<shading, lineType, blend>::getVertices(AddTri &&add, PixelOp op) {
    if constexpr (blend == Blend::Off) {
        if (op == PixelOp::READ) return;
    }
    auto count = colors.size();
    for (unsigned i = 1; i < count; i++) {
        auto x0 = x[i - 1];
        auto x1 = x[i];
        auto y0 = y[i - 1];
        auto y1 = y[i];

        addLine(std::move(add), x0 + offset.x, y0 + offset.y, x1 + offset.x, y1 + offset.y);
    }
}

template <PCSX::GPU::Size size, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend, PCSX::GPU::Modulation modulation>
void PCSX::GPU::Rect<size, textured, blend, modulation>::getVertices(AddTri &&add, PixelOp op) {
    if (op == PixelOp::WRITE) {
        add({x + offset.x, y + offset.y}, {x + w + offset.x, y + offset.y}, {x + w + offset.x, y + h + offset.y});
        add({x + w + offset.x, y + h + offset.y}, {x + offset.x, y + h + offset.y}, {x + offset.x, y + offset.y});
    } else if (op == PixelOp::READ) {
        if constexpr (blend == Blend::Semi) {
            add({x + offset.x, y + offset.y}, {x + w + offset.x, y + offset.y}, {x + w + offset.x, y + h + offset.y});
            add({x + w + offset.x, y + h + offset.y}, {x + offset.x, y + h + offset.y}, {x + offset.x, y + offset.y});
        }
        if constexpr (textured == Textured::Yes) {
            unsigned tx = tpage.tx * 64;
            unsigned ty = tpage.ty * 256;
            unsigned shift = tpage.texDepth == TexDepth::Tex4Bits ? 2 : tpage.texDepth == TexDepth::Tex8Bits ? 1 : 0;
            unsigned minU = u >> shift;
            unsigned minV = v;
            unsigned maxU = (u + w) >> shift;
            unsigned maxV = v + h;
            add({int(minU + tx), int(minV + ty)}, {int(maxU + tx), int(minV + ty)}, {int(maxU + tx), int(maxV + ty)});
            add({int(maxU + tx), int(maxV + ty)}, {int(minU + tx), int(maxV + ty)}, {int(minU + tx), int(minV + ty)});
        }
    }
}

bool PCSX::GPU::Logged::isInsideTriangle(int x, int y, int x1, int y1, int x2, int y2, int x3, int y3) {
    int o1 = (x - x1) * (y2 - y1) - (y - y1) * (x2 - x1);
    int o2 = (x - x2) * (y3 - y2) - (y - y2) * (x3 - x2);
    int o3 = (x - x3) * (y1 - y3) - (y - y3) * (x1 - x3);
    return (o1 >= 0 && o2 >= 0 && o3 >= 0) || (o1 <= 0 && o2 <= 0 && o3 <= 0);
}

bool PCSX::GPU::Logged::isInsideLine(int x, int y, int x1, int y1, int x2, int y2) {
    int o1 = (x - x1) * (y2 - y1) - (y - y1) * (x2 - x1);
    return o1 == 0;
}
