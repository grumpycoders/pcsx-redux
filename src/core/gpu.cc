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

#include "core/gpu.h"

#include "core/debug.h"
#include "core/gpulogger.h"
#include "core/pgxp_mem.h"
#include "core/psxdma.h"
#include "core/psxhw.h"
#include "imgui/imgui.h"
#include "magic_enum/include/magic_enum.hpp"

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
                    }
                }
            }
        }
    }
    m_count = 0;
    m_state = READ_COLOR;
    m_gpu->m_defaultProcessor.setActive();
    g_emulator->m_gpuLogger->addNode(*this, origin, origvalue, length);
    m_gpu->write0(this);
}

template <GPU::Shading shading, GPU::LineType lineType, GPU::Blend blend>
void GPU::Line<shading, lineType, blend>::processWrite(Buffer & buf, Logged::Origin origin, uint32_t origvalue, uint32_t length) {
    uint32_t value = buf.get();
    if constexpr (lineType == LineType::Poly) {
        if ((value & 0xf000f000) != 0x50005000) {
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
                w = GPU::signExtend<int, 11>(value & 0xffff);
                h = GPU::signExtend<int, 11>(value >> 16);
            }
    }
    m_state = READ_COLOR;
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

int PCSX::GPU::init(GUI *gui) {
    for (auto poly : m_polygons) poly->setGPU(this);
    for (auto line : m_lines) line->setGPU(this);
    for (auto rect : m_rects) rect->setGPU(this);
    return initBackend(gui);
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
        addr &= 0x1ffffc;

        if (DMACommandCounter++ > 2000000) break;
        if (CheckForEndlessLoop(addr)) break;

        // # 32-bit blocks to transfer
        size += psxMu8(addr + 3);

        // next 32-bit pointer
        addr = psxMu32(addr & ~0x3) & 0xffffff;
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
    return ret;
}

void PCSX::GPU::dma(uint32_t madr, uint32_t bcr, uint32_t chcr) {  // GPU
    uint32_t *ptr;
    uint32_t size, bs;

    switch (chcr) {
        case 0x01000200:  // vram2mem
            PSXDMA_LOG("*** DMA2 GPU - vram2mem *** %lx addr = %lx size = %lx\n", chcr, madr, bcr);
            ptr = (uint32_t *)PSXM(madr);
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
            ptr = (uint32_t *)PSXM(madr);
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
            chainedDMAWrite((uint32_t *)PCSX::g_emulator->m_mem->m_psxM, madr & 0x1fffff);

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

    HW_DMA2_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT<2>();
}

void PCSX::GPU::gpuInterrupt() {
    HW_DMA2_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT<2>();
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

uint32_t PCSX::GPU::readData() { return m_readFifo.asA<File>()->read<uint32_t>(); }

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
    m_readFifo->read(dest, transferSize * 4);
}

void PCSX::GPU::chainedDMAWrite(const uint32_t *memory, uint32_t hwAddr) {
    uint32_t addr = hwAddr;
    uint32_t DMACommandCounter = 0;

    s_usedAddr[0] = s_usedAddr[1] = s_usedAddr[2] = 0xffffff;

    do {
        addr &= 0x1ffffc;

        if (DMACommandCounter++ > 2000000) break;
        if (CheckForEndlessLoop(addr)) break;

        // # 32-bit blocks to transfer
        uint32_t transferSize = psxMu8(addr + 3);
        uint32_t *feed = (uint32_t *)PSXM((addr + 4) & 0x1fffff);
        Buffer buf(feed, transferSize);
        while (!buf.isEmpty()) {
            m_processor->processWrite(buf, Logged::Origin::CHAIN_DMA, addr, transferSize);
        }

        // next 32-bit pointer
        addr = psxMu32(addr & ~0x3) & 0xffffff;
    } while (!(addr & 0x800000));  // contrary to some documentation, the end-of-linked-list marker is not actually
                                   // 0xFF'FFFF any pointer with bit 23 set will do.
}

void PCSX::GPU::Command::processWrite(Buffer &buf, Logged::Origin origin, uint32_t value, uint32_t length) {
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
                        g_emulator->m_gpuLogger->addNode(prim, origin, value, length);
                    } break;
                    case 0x02: {  // fast fill
                        buf.rewind();
                        m_gpu->m_fastFill.setActive();
                        m_gpu->m_fastFill.processWrite(buf, origin, value, length);
                    } break;
                    default: {
                        gotUnknown = true;
                    } break;
                }
                break;
            case 1: {  // Polygon primitive
                buf.rewind();
                m_gpu->m_polygons[command]->setActive();
                m_gpu->m_processor->processWrite(buf, origin, value, length);
            } break;
            case 2: {  // Line primitive
                buf.rewind();
                m_gpu->m_lines[command]->setActive();
                m_gpu->m_processor->processWrite(buf, origin, value, length);
            } break;
            case 3: {  // Rectangle primitive
                buf.rewind();
                m_gpu->m_rects[command]->setActive();
                m_gpu->m_processor->processWrite(buf, origin, value, length);
            } break;
            case 4: {  // Move data in VRAM
                m_gpu->m_blitVramVram.setActive();
                m_gpu->m_processor->processWrite(buf, origin, value, length);
            } break;
            case 5: {  // Write data to VRAM
                m_gpu->m_blitRamVram.setActive();
                m_gpu->m_processor->processWrite(buf, origin, value, length);
            } break;
            case 6: {  // Read data from VRAM
                m_gpu->m_blitVramRam.setActive();
                m_gpu->m_processor->processWrite(buf, origin, value, length);
            } break;
            case 7: {  // Environment command
                switch (command) {
                    case 1: {  // tpage
                        TPage prim(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, value, length);
                        m_gpu->write0(&prim);
                    } break;
                    case 2: {  // twindow
                        TWindow prim(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, value, length);
                        m_gpu->write0(&prim);
                    } break;
                    case 3: {  // drawing area top left
                        DrawingAreaStart prim(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, value, length);
                        m_gpu->write0(&prim);
                    } break;
                    case 4: {  // drawing area bottom right
                        DrawingAreaEnd prim(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, value, length);
                        m_gpu->write0(&prim);
                    } break;
                    case 5: {  // drawing offset
                        DrawingOffset prim(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, value, length);
                        m_gpu->write0(&prim);
                    } break;
                    case 6: {  // mask bit
                        MaskBit prim(packetInfo);
                        g_emulator->m_gpuLogger->addNode(prim, origin, value, length);
                        m_gpu->write0(&prim);
                    } break;
                    default: {
                        gotUnknown = true;
                    } break;
                }
            } break;
        }
        if (gotUnknown && (value != 0)) {
            g_system->log(LogClass::GPU, "Got an unknown GPU data word: %08x\n", value);
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
            w = signExtend<int, 11>(value & 0xffff);
            h = signExtend<int, 11>(value >> 16);
            m_state = READ_COMMAND;
            m_gpu->m_defaultProcessor.setActive();
            g_emulator->m_gpuLogger->addNode(*this, origin, origvalue, length);
            m_gpu->write0(this);
            return;
    }
}

void PCSX::GPU::BlitRamVram::processWrite(Buffer &buf, Logged::Origin origin, uint32_t origvalue, uint32_t length) {
    uint32_t value;
    size_t size;
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
            w = signExtend<int, 11>(value & 0xffff);
            h = signExtend<int, 11>(value >> 16);
            size = (w * h + 1) / 2;
            size *= 4;
            m_data.clear();
            m_data.reserve(size * 4);
            m_state = READ_PIXELS;
            if (buf.isEmpty()) return;
            [[fallthrough]];
        case READ_PIXELS:
            size = (w * h + 1) / 2;
            if ((buf.size() >= size) && (m_data.empty())) {
                data.borrow(buf.data(), size * 4);
                buf.consume(size);
                done = true;
            } else {
                size_t toConsume = std::min(buf.size(), size - (m_data.size() / 4));
                m_data.append(reinterpret_cast<const char *>(buf.data()), toConsume * 4);
                done = m_data.size() == (size * 4);
                buf.consume(toConsume);
                if (done) {
                    data.acquire(std::move(m_data));
                    m_data.clear();
                }
            }
            break;
    }
    if (done) {
        m_state = READ_COMMAND;
        m_gpu->m_defaultProcessor.setActive();
        g_emulator->m_gpuLogger->addNode(*this, origin, origvalue, length);
        m_gpu->partialUpdateVRAM(x, y, w, h, data.data<uint16_t>());
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
            w = signExtend<int, 11>(value & 0xffff);
            h = signExtend<int, 11>(value >> 16);
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
    partialUpdateVRAM(dX, dY, w, h, rect.data());
}

PCSX::GPU::CtrlDisplayMode::CtrlDisplayMode(uint32_t value) {
    if ((value >> 6) & 1) {
        switch (value & 3) {
            case 0:
                hres = HR_368;
                break;
            case 1:
                hres = HR_384;
                break;
            case 2:
                hres = HR_512;
                break;
            case 3:
                hres = HR_640;
                break;
        }
    } else {
        hres = magic_enum::enum_cast<decltype(hres)>(value & 3).value();
    }
    vres = magic_enum::enum_cast<decltype(vres)>((value >> 2) & 1).value();
    mode = magic_enum::enum_cast<decltype(mode)>((value >> 3) & 1).value();
    depth = magic_enum::enum_cast<decltype(depth)>((value >> 4) & 1).value();
    interlace = (value >> 5) & 1;
    widthRaw = ((value >> 6) & 1) | ((value & 3) << 1);
}

void PCSX::GPU::ClearCache::drawLogNode() {}

void PCSX::GPU::FastFill::drawLogNode() {
    ImGui::Text("  R: %i, G: %i, B: %i", (color >> 0) & 0xff, (color >> 8) & 0xff, (color >> 16) & 0xff);
    ImGui::Separator();
    ImGui::Text("  X0: %i, Y0: %i", x, y);
    ImGui::Text("  X1: %i, Y1: %i", x + w, y + h);
    ImGui::Text("  W: %i, H: %i", w, h);
}

void PCSX::GPU::BlitVramVram::drawLogNode() {
    ImGui::Text("  From X: %i, Y: %i", sX, sY);
    ImGui::Text("  To X: %i, Y: %i", dX, dY);
    ImGui::Text("  W: %i, H: %i", w, h);
}

void PCSX::GPU::BlitRamVram::drawLogNode() {
    ImGui::Text("  X: %i, Y: %i", x, y);
    ImGui::Text("  W: %i, H: %i", w, h);
}

void PCSX::GPU::BlitVramRam::drawLogNode() {
    ImGui::Text("  X: %i, Y: %i", x, y);
    ImGui::Text("  W: %i, H: %i", w, h);
}

void PCSX::GPU::TPage::drawLogNodeCommon() {
    ImGui::Text(_("Texture Page X: %i, Texture Page Y: %i"), tx, ty);
    ImGui::TextUnformatted(_("Blending:"));
    ImGui::SameLine();
    switch (blendFunction) {
        case BlendFunction::HalfBackAndHalfFront:
            ImGui::TextUnformatted(_("50% Back + 50% Front"));
            break;
        case BlendFunction::FullBackAndFullFront:
            ImGui::TextUnformatted(_("100% Back + 100% Front"));
            break;
        case BlendFunction::FullBackSubFullFront:
            ImGui::TextUnformatted(_("100% Back - 100% Front"));
            break;
        case BlendFunction::FullBackAndQuarterFront:
            ImGui::TextUnformatted(_("100% Back + 25% Front"));
            break;
    }
    ImGui::TextUnformatted(_("Texture depth:"));
    ImGui::SameLine();
    switch (texDepth) {
        case TexDepth::Tex4Bits:
            ImGui::TextUnformatted(_("4 bits"));
            break;
        case TexDepth::Tex8Bits:
            ImGui::TextUnformatted(_("8 bits"));
            break;
        case TexDepth::Tex16Bits:
            ImGui::TextUnformatted(_("16 bits"));
            break;
    }
}

void PCSX::GPU::TPage::drawLogNode() {
    drawLogNodeCommon();
    ImGui::Text(_("Dithering: %s"), dither ? _("Yes") : _("No"));
}

void PCSX::GPU::TWindow::drawLogNode() {
    ImGui::Text("  X: %i, Y: %i", x, y);
    ImGui::Text("  W: %i, H: %i", w, h);
}

void PCSX::GPU::DrawingAreaStart::drawLogNode() { ImGui::Text("  X: %i, Y: %i", x, y); }

void PCSX::GPU::DrawingAreaEnd::drawLogNode() { ImGui::Text("  X: %i, Y: %i", x, y); }

void PCSX::GPU::DrawingOffset::drawLogNode() { ImGui::Text("  X: %i, Y: %i", x, y); }

void PCSX::GPU::MaskBit::drawLogNode() {
    ImGui::Text(_("  Set: %s, Check: %s"), set ? _("Yes") : _("No"), check ? _("Yes") : _("No"));
}

template <PCSX::GPU::Shading shading, PCSX::GPU::Shape shape, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend,
          PCSX::GPU::Modulation modulation>
void PCSX::GPU::Poly<shading, shape, textured, blend, modulation>::drawLogNode() {
    if constexpr ((textured == Textured::No) || (modulation == Modulation::On)) {
        if constexpr (shading == Shading::Flat) {
            ImGui::TextUnformatted(_("Shading: Flat"));
            ImGui::Text("  R: %i, G: %i, B: %i", (colors[0] >> 0) & 0xff, (colors[0] >> 8) & 0xff,
                        (colors[0] >> 16) & 0xff);
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
            ImGui::Text("  ClutX: %i, ClutY: %i", clutX(), clutY());
        }
    }
    for (unsigned i = 0; i < count; i++) {
        ImGui::Separator();
        ImGui::Text(_("Vertex %i"), i);
        ImGui::Text("  X: %i, Y: %i", x[i], y[i]);
        if constexpr ((shading == Shading::Gouraud) && ((textured == Textured::No) || (modulation == Modulation::On))) {
            ImGui::Text("  R: %i, G: %i, B: %i", (colors[i] >> 0) & 0xff, (colors[i] >> 8) & 0xff,
                        (colors[i] >> 16) & 0xff);
        }
        if constexpr (textured == Textured::Yes) {
            ImGui::Text("  U: %i, V: %i", u[i], v[i]);
        }
    }
}

template <PCSX::GPU::Shading shading, PCSX::GPU::LineType lineType, PCSX::GPU::Blend blend>
void PCSX::GPU::Line<shading, lineType, blend>::drawLogNode() {
    if constexpr (shading == Shading::Flat) {
        ImGui::TextUnformatted(_("Shading: Flat"));
        ImGui::Text("  R: %i, G: %i, B: %i", (colors[0] >> 0) & 0xff, (colors[0] >> 8) & 0xff,
                    (colors[0] >> 16) & 0xff);
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
        ImGui::Text("  X0: %i, Y0: %i", x[i - 1], y[i - 1]);
        if constexpr (shading == Shading::Gouraud) {
            ImGui::Text("  R: %i, G: %i, B: %i", (colors[i - 1] >> 0) & 0xff, (colors[i - 1] >> 8) & 0xff,
                        (colors[i - 1] >> 16) & 0xff);
        }
        ImGui::Text("  X1: %i, Y1: %i", x[i], y[i]);
        if constexpr (shading == Shading::Gouraud) {
            ImGui::Text("  R: %i, G: %i, B: %i", (colors[i] >> 0) & 0xff, (colors[i] >> 8) & 0xff,
                        (colors[i] >> 16) & 0xff);
        }
    }
}

template <PCSX::GPU::Size size, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend, PCSX::GPU::Modulation modulation>
void PCSX::GPU::Rect<size, textured, blend, modulation>::drawLogNode() {
    ImGui::Text("  X0: %i, Y0: %i", x, y);
    ImGui::Text("  X1: %i, Y1: %i", x + w, y + h);
    ImGui::Text("  W: %i, H: %i", w, h);
    if constexpr ((textured == Textured::No) || (modulation == Modulation::On)) {
        ImGui::Text("  R: %i, G: %i, B: %i", (color >> 0) & 0xff, (color >> 8) & 0xff, (color >> 16) & 0xff);
    }
    if constexpr (blend == Blend::Semi) {
        ImGui::TextUnformatted(_("Semi-transparency blending"));
    }
    if constexpr (textured == Textured::Yes) {
        ImGui::Text("  U: %i, V: %i", u, v);
        ImGui::Text("  ClutX: %i, ClutY: %i", clutX(), clutY());
    }
}

void PCSX::GPU::CtrlReset::drawLogNode() {}
void PCSX::GPU::CtrlClearFifo::drawLogNode() {}
void PCSX::GPU::CtrlIrqAck::drawLogNode() {}

void PCSX::GPU::CtrlDisplayEnable::drawLogNode() {
    if (enable) {
        ImGui::TextUnformatted(_("Display Enabled"));
    } else {
        ImGui::TextUnformatted(_("Display Disabled"));
    }
}

void PCSX::GPU::CtrlDmaSetting::drawLogNode() {
    switch (dma) {
        case Dma::Off:
            ImGui::TextUnformatted(_("DMA Off"));
            break;
        case Dma::FifoQuery:
            ImGui::TextUnformatted(_("FIFO Query"));
            break;
        case Dma::Read:
            ImGui::TextUnformatted(_("DMA Read"));
            break;
        case Dma::Write:
            ImGui::TextUnformatted(_("DMA Write"));
            break;
    }
}

void PCSX::GPU::CtrlDisplayStart::drawLogNode() { ImGui::Text("  X: %i, Y: %i", x, y); }
void PCSX::GPU::CtrlHorizontalDisplayRange::drawLogNode() { ImGui::Text("  X0: %i, X1: %i", x0, x1); }
void PCSX::GPU::CtrlVerticalDisplayRange::drawLogNode() { ImGui::Text("  Y0: %i, Y1: %i", y0, y1); }

void PCSX::GPU::CtrlDisplayMode::drawLogNode() {
    ImGui::TextUnformatted(_("Horizontal resolution:"));
    ImGui::SameLine();
    switch (hres) {
        case HR_256:
            ImGui::TextUnformatted("256 pixels");
            break;
        case HR_320:
            ImGui::TextUnformatted("320 pixels");
            break;
        case HR_512:
            ImGui::TextUnformatted("512 pixels");
            break;
        case HR_640:
            ImGui::TextUnformatted("640 pixels");
            break;
        case HR_368:
            ImGui::TextUnformatted("368 pixels");
            break;
        case HR_384:
            ImGui::TextUnformatted("384 pixels");
            break;
    }
    ImGui::Text(_("Extended width mode: %s"), widthRaw & 1 ? _("Yes") : _("No"));
    ImGui::TextUnformatted(_("Vertical resolution:"));
    ImGui::SameLine();
    switch (vres) {
        case VR_240:
            ImGui::TextUnformatted("240 pixels");
            break;
        case VR_480:
            ImGui::TextUnformatted("480 pixels");
            break;
    }
    ImGui::Text(_("Output mode: %s"), mode == VM_NTSC ? "NTSC" : "PAL");
    ImGui::Text(_("Display depth: %s"), depth == CD_15BITS ? _("15 bits") : _("24 bits"));
    ImGui::Text(_("Interlaced: %s"), interlace ? _("Yes") : _("No"));
}

void PCSX::GPU::CtrlQuery::drawLogNode() {}
