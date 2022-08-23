/*  Copyright (c) 2010, shalma.
 *  Portions Copyright (c) 2002, Pete Bernert.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "core/gpu.h"

#include "core/debug.h"
#include "core/pgxp_mem.h"
#include "core/psxdma.h"
#include "core/psxhw.h"
#include "magic_enum/include/magic_enum.hpp"

#define GPUSTATUS_ODDLINES 0x80000000
#define GPUSTATUS_DMABITS 0x60000000           // Two bits
#define GPUSTATUS_READYFORCOMMANDS 0x10000000  // DMA block ready
#define GPUSTATUS_READYFORVRAM 0x08000000
#define GPUSTATUS_IDLE 0x04000000  // CMD ready
#define GPUSTATUS_MODE 0x02000000  // Data request mode

#define GPUSTATUS_DISPLAYDISABLED 0x00800000
#define GPUSTATUS_INTERLACED 0x00400000
#define GPUSTATUS_RGB24 0x00200000
#define GPUSTATUS_PAL 0x00100000
#define GPUSTATUS_DOUBLEHEIGHT 0x00080000
#define GPUSTATUS_WIDTHBITS 0x00070000  // Three bits
#define GPUSTATUS_MASKENABLED 0x00001000
#define GPUSTATUS_MASKDRAWN 0x00000800
#define GPUSTATUS_DRAWINGALLOWED 0x00000400
#define GPUSTATUS_DITHER 0x00000200

namespace PCSX {

template <GPU::Shading shading, GPU::Shape shape, GPU::Textured textured, GPU::Blend blend, GPU::Modulation modulation>
void GPU::Poly<shading, shape, textured, blend, modulation>::processWrite(uint32_t value) {
    switch (m_state) {
        for (m_count = 0; m_count < count; m_count++) {
            if (shading == Shading::Gouraud) {
                m_state = READ_COLOR;
                return;
                case READ_COLOR:
                    colors[m_count] = value;
            } else {
                colors[m_count] = colors[0];
            }
            m_state = READ_XY;
            return;
            case READ_XY:
                x[m_count] = GPU::signExtend<int, 11>(value & 0xffff);
                y[m_count] = GPU::signExtend<int, 11>(value >> 16);
                if (textured == Textured::Yes) {
                    m_state = READ_UV;
                    return;
                    case READ_UV:
                        if constexpr (textured == Textured::Yes) {
                            u[m_count] = value & 0xff;
                            v[m_count] = (value >> 8) & 0xff;
                            value >>= 16;
                            if (m_count == 0) {
                                clutX = value & 0x3f;
                                clutY = (value >> 6) & 0x7f;
                            } else if (m_count == 1) {
                                texturePageX = value & 0x0f;
                                texturePageY = (value >> 4) & 1;
                                if constexpr (blend == Blend::Semi) {
                                    blendFunction = magic_enum::enum_cast<BlendFunction>((value >> 5) & 3).value();
                                }
                                texDepth = magic_enum::enum_cast<TexDepth>((value >> 7) & 3).value();
                                texDisable = (value >> 11) & 1;
                            }
                        }
                }
        }
        m_count = 0;
        m_state = READ_COLOR;
        m_gpu->m_defaultProcessor.setActive();
        m_gpu->write0(this);
    }
}

template <GPU::Shading shading, GPU::LineType lineType, GPU::Blend blend>
void GPU::Line<shading, lineType, blend>::processWrite(uint32_t value) {
    __debugbreak();
    if constexpr (lineType == LineType::Poly) {
        switch (m_state) {
            case READ_COLOR:
                colors.push_back(value);
                m_state = READ_XY;
                return;
            case READ_XY:
                if ((value & 0xf000f000) == 0x50005000) break;
                x.push_back(GPU::signExtend<int, 11>(value & 0xffff));
                y.push_back(GPU::signExtend<int, 11>(value >> 16));
                if constexpr (shading == Shading::Flat) {
                    colors.push_back(colors[0]);
                } else {
                    m_state = READ_COLOR;
                    return;
                }
        }
    } else {
        switch (m_state) {
            for (m_count = 0; m_count < 2; m_count++) {
                case READ_COLOR:
                    colors[m_count] = value;
                    m_state = READ_XY;
                    return;
                case READ_XY:
                    x[m_count] = GPU::signExtend<int, 11>(value & 0xffff);
                    y[m_count] = GPU::signExtend<int, 11>(value >> 16);
                    if constexpr (shading == Shading::Flat) {
                        colors[m_count] = colors[0];
                    } else {
                        m_state = READ_COLOR;
                    }
                    return;
            }
        }
    }
    if constexpr (lineType == LineType::Simple) {
        m_count = 0;
    }
    m_state = READ_COLOR;
    m_gpu->m_defaultProcessor.setActive();
    m_gpu->write0(this);
}

template <GPU::Size size, GPU::Textured textured, GPU::Blend blend>
void GPU::Rect<size, textured, blend>::processWrite(uint32_t value) {
    switch (m_state) {
        case READ_COLOR:
            if constexpr (textured == Textured::No) {
                color = value;
            }
            m_state = READ_XY1;
            return;
        case READ_XY1:
            x1 = GPU::signExtend<int, 11>(value & 0xffff);
            y1 = GPU::signExtend<int, 11>(value >> 16);
            if (textured == Textured::Yes) {
                m_state = READ_UV;
                return;
                case READ_UV:
                    if constexpr (textured == Textured::Yes) {
                        u = value & 0xff;
                        v = (value >> 8) & 0xff;
                        value >>= 16;
                        clutX = value & 0x3f;
                        clutY = (value >> 6) & 0x7f;
                    }
            }
            if constexpr (size == Size::S1) {
                x2 = x1 + 1;
                y2 = y1 + 1;
            } else if constexpr (size == Size::S8) {
                x2 = x1 + 8;
                y2 = y1 + 8;
            } else if constexpr (size == Size::S16) {
                x2 = x1 + 16;
                y2 = y1 + 16;
            }

            if (size == Size::Variable) {
                m_state = READ_XY2;
                return;
                case READ_XY2:
                    x2 = GPU::signExtend<int, 11>(value & 0xffff);
                    y2 = GPU::signExtend<int, 11>(value >> 16);
            }
    }
    m_state = READ_COLOR;
    m_gpu->m_defaultProcessor.setActive();
    m_gpu->write0(this);
}

namespace {

GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_poly00;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_poly01;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_poly02;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_poly03;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_poly04;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_poly05;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_poly06;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_poly07;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_poly08;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_poly09;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_poly0a;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_poly0b;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_poly0c;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_poly0d;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_poly0e;
GPU::Poly<GPU::Shading::Flat, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_poly0f;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_poly10;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_poly11;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_poly12;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_poly13;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_poly14;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_poly15;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_poly16;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Tri, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_poly17;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::Off> s_poly18;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Off, GPU::Modulation::On> s_poly19;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::Off> s_poly1a;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::No, GPU::Blend::Semi, GPU::Modulation::On> s_poly1b;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::Off> s_poly1c;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Off, GPU::Modulation::On> s_poly1d;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::Off> s_poly1e;
GPU::Poly<GPU::Shading::Gouraud, GPU::Shape::Quad, GPU::Textured::Yes, GPU::Blend::Semi, GPU::Modulation::On> s_poly1f;

GPU::Line<GPU::Shading::Flat, GPU::LineType::Simple, GPU::Blend::Off> s_line0;
GPU::Line<GPU::Shading::Flat, GPU::LineType::Simple, GPU::Blend::Semi> s_line1;
GPU::Line<GPU::Shading::Flat, GPU::LineType::Poly, GPU::Blend::Off> s_line2;
GPU::Line<GPU::Shading::Flat, GPU::LineType::Poly, GPU::Blend::Semi> s_line3;
GPU::Line<GPU::Shading::Gouraud, GPU::LineType::Simple, GPU::Blend::Off> s_line4;
GPU::Line<GPU::Shading::Gouraud, GPU::LineType::Simple, GPU::Blend::Semi> s_line5;
GPU::Line<GPU::Shading::Gouraud, GPU::LineType::Poly, GPU::Blend::Off> s_line6;
GPU::Line<GPU::Shading::Gouraud, GPU::LineType::Poly, GPU::Blend::Semi> s_line7;

GPU::Rect<GPU::Size::Variable, GPU::Textured::No, GPU::Blend::Off> s_rect00;
GPU::Rect<GPU::Size::Variable, GPU::Textured::No, GPU::Blend::Semi> s_rect01;
GPU::Rect<GPU::Size::Variable, GPU::Textured::Yes, GPU::Blend::Off> s_rect02;
GPU::Rect<GPU::Size::Variable, GPU::Textured::Yes, GPU::Blend::Semi> s_rect03;
GPU::Rect<GPU::Size::S1, GPU::Textured::No, GPU::Blend::Off> s_rect04;
GPU::Rect<GPU::Size::S1, GPU::Textured::No, GPU::Blend::Semi> s_rect05;
GPU::Rect<GPU::Size::S1, GPU::Textured::Yes, GPU::Blend::Off> s_rect06;
GPU::Rect<GPU::Size::S1, GPU::Textured::Yes, GPU::Blend::Semi> s_rect07;
GPU::Rect<GPU::Size::S8, GPU::Textured::No, GPU::Blend::Off> s_rect08;
GPU::Rect<GPU::Size::S8, GPU::Textured::No, GPU::Blend::Semi> s_rect09;
GPU::Rect<GPU::Size::S8, GPU::Textured::Yes, GPU::Blend::Off> s_rect0a;
GPU::Rect<GPU::Size::S8, GPU::Textured::Yes, GPU::Blend::Semi> s_rect0b;
GPU::Rect<GPU::Size::S16, GPU::Textured::No, GPU::Blend::Off> s_rect0c;
GPU::Rect<GPU::Size::S16, GPU::Textured::No, GPU::Blend::Semi> s_rect0d;
GPU::Rect<GPU::Size::S16, GPU::Textured::Yes, GPU::Blend::Off> s_rect0e;
GPU::Rect<GPU::Size::S16, GPU::Textured::Yes, GPU::Blend::Semi> s_rect0f;

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
    m_rects[0x01] = &s_rect00;
    m_rects[0x02] = &s_rect01;
    m_rects[0x03] = &s_rect01;
    m_rects[0x04] = &s_rect02;
    m_rects[0x05] = &s_rect02;
    m_rects[0x06] = &s_rect03;
    m_rects[0x07] = &s_rect03;
    m_rects[0x08] = &s_rect04;
    m_rects[0x09] = &s_rect04;
    m_rects[0x0a] = &s_rect05;
    m_rects[0x0b] = &s_rect05;
    m_rects[0x0c] = &s_rect06;
    m_rects[0x0d] = &s_rect06;
    m_rects[0x0e] = &s_rect07;
    m_rects[0x0f] = &s_rect07;
    m_rects[0x10] = &s_rect08;
    m_rects[0x11] = &s_rect08;
    m_rects[0x12] = &s_rect09;
    m_rects[0x13] = &s_rect09;
    m_rects[0x14] = &s_rect0a;
    m_rects[0x15] = &s_rect0a;
    m_rects[0x16] = &s_rect0b;
    m_rects[0x17] = &s_rect0b;
    m_rects[0x18] = &s_rect0c;
    m_rects[0x19] = &s_rect0c;
    m_rects[0x1a] = &s_rect0d;
    m_rects[0x1b] = &s_rect0d;
    m_rects[0x1c] = &s_rect0e;
    m_rects[0x1d] = &s_rect0e;
    m_rects[0x1e] = &s_rect0f;
    m_rects[0x1f] = &s_rect0f;
}

int PCSX::GPU::init(GUI *gui) {
    s_poly00.setGPU(this);
    s_poly01.setGPU(this);
    s_poly02.setGPU(this);
    s_poly03.setGPU(this);
    s_poly04.setGPU(this);
    s_poly05.setGPU(this);
    s_poly06.setGPU(this);
    s_poly07.setGPU(this);
    s_poly08.setGPU(this);
    s_poly09.setGPU(this);
    s_poly0a.setGPU(this);
    s_poly0b.setGPU(this);
    s_poly0c.setGPU(this);
    s_poly0d.setGPU(this);
    s_poly0e.setGPU(this);
    s_poly0f.setGPU(this);
    s_poly10.setGPU(this);
    s_poly11.setGPU(this);
    s_poly12.setGPU(this);
    s_poly13.setGPU(this);
    s_poly14.setGPU(this);
    s_poly15.setGPU(this);
    s_poly16.setGPU(this);
    s_poly17.setGPU(this);
    s_poly18.setGPU(this);
    s_poly19.setGPU(this);
    s_poly1a.setGPU(this);
    s_poly1b.setGPU(this);
    s_poly1c.setGPU(this);
    s_poly1d.setGPU(this);
    s_poly1e.setGPU(this);
    s_poly1f.setGPU(this);

    s_line0.setGPU(this);
    s_line1.setGPU(this);
    s_line2.setGPU(this);
    s_line3.setGPU(this);
    s_line4.setGPU(this);
    s_line5.setGPU(this);
    s_line6.setGPU(this);
    s_line7.setGPU(this);

    s_rect00.setGPU(this);
    s_rect01.setGPU(this);
    s_rect02.setGPU(this);
    s_rect03.setGPU(this);
    s_rect04.setGPU(this);
    s_rect05.setGPU(this);
    s_rect06.setGPU(this);
    s_rect07.setGPU(this);
    s_rect08.setGPU(this);
    s_rect09.setGPU(this);
    s_rect0a.setGPU(this);
    s_rect0b.setGPU(this);
    s_rect0c.setGPU(this);
    s_rect0d.setGPU(this);
    s_rect0e.setGPU(this);
    s_rect0f.setGPU(this);

    return initBackend(gui);
}

inline bool PCSX::GPU::CheckForEndlessLoop(uint32_t laddr) {
    if (laddr == s_lUsedAddr[1]) return true;
    if (laddr == s_lUsedAddr[2]) return true;

    if (laddr < s_lUsedAddr[0])
        s_lUsedAddr[1] = laddr;
    else
        s_lUsedAddr[2] = laddr;

    s_lUsedAddr[0] = laddr;

    return false;
}

uint32_t PCSX::GPU::gpuDmaChainSize(uint32_t addr) {
    uint32_t size;
    uint32_t DMACommandCounter = 0;

    s_lUsedAddr[0] = s_lUsedAddr[1] = s_lUsedAddr[2] = 0xffffff;

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

void PCSX::GPU::writeStatus(uint32_t status) {
    uint32_t cmd = (status >> 24) & 0xff;

    m_statusControl[cmd] = status;

    writeStatusInternal(status);
}

uint32_t PCSX::GPU::readData() {
    return m_readFifo.asA<File>()->read<uint32_t>();
}

void PCSX::GPU::writeData(uint32_t value) { m_processor->processWrite(value); }

void PCSX::GPU::directDMAWrite(const uint32_t *feed, int transferSize, uint32_t hwAddr) {
    while (transferSize--) {
        m_processor->processWrite(*feed++);
    }
}

void PCSX::GPU::directDMARead(uint32_t *dest, int transferSize, uint32_t hwAddr) {
    __debugbreak();
    m_readFifo->read(dest, transferSize * 4);
}

void PCSX::GPU::chainedDMAWrite(const uint32_t *memory, uint32_t hwAddr) {
    uint32_t addr = hwAddr;
    uint32_t DMACommandCounter = 0;

    s_lUsedAddr[0] = s_lUsedAddr[1] = s_lUsedAddr[2] = 0xffffff;

    do {
        addr &= 0x1ffffc;

        if (DMACommandCounter++ > 2000000) break;
        if (CheckForEndlessLoop(addr)) break;

        // # 32-bit blocks to transfer
        uint32_t size = psxMu8(addr + 3);
        uint32_t *feed = (uint32_t *)PSXM((addr + 4) & 0x1fffff);
        while (size--) {
            m_processor->processWrite(*feed++);
        }

        // next 32-bit pointer
        addr = psxMu32(addr & ~0x3) & 0xffffff;
    } while (!(addr & 0x800000));  // contrary to some documentation, the end-of-linked-list marker is not actually
                                   // 0xFF'FFFF any pointer with bit 23 set will do.
}

void PCSX::GPU::Command::processWrite(uint32_t value) {
    bool gotUnknown = false;
    const uint8_t cmdType = value >> 29;           // 3 topmost bits = command "type"
    const uint8_t command = (value >> 24) & 0x1f;  // 5 next bits = "command", which may be a bitfield

    const uint32_t packetInfo = value & 0xffffff;
    const uint32_t color = packetInfo;
    GPU::Logged *logged = nullptr;

    switch (cmdType) {
        case 0:  // GPU command
            switch (command) {
                case 0x01:  // clear cache
                    break;
                case 0x02:  // fast fill
                    m_gpu->m_fastFill.setActive();
                    m_gpu->m_fastFill.processWrite(color);
                    break;
                default:
                    gotUnknown = true;
                    break;
            }
            break;
        case 1:  // Polygon primitive
            m_gpu->m_polygons[command]->setActive();
            m_gpu->m_processor->processWrite(packetInfo);
            break;
        case 2:  // Line primitive
            m_gpu->m_lines[command]->setActive();
            m_gpu->m_processor->processWrite(packetInfo);
            break;
        case 3:  // Rectangle primitive
            m_gpu->m_rects[command]->setActive();
            m_gpu->m_processor->processWrite(packetInfo);
            break;
        case 4:  // Move data in VRAM
            m_gpu->m_blitVramVram.setActive();
            m_gpu->m_processor->processWrite(packetInfo);
            break;
        case 5:  // Write data to VRAM
            m_gpu->m_blitRamVram.setActive();
            m_gpu->m_processor->processWrite(packetInfo);
            break;
        case 6:  // Read data from VRAM
            m_gpu->m_blitVramRam.setActive();
            m_gpu->m_processor->processWrite(packetInfo);
            break;
        case 7:  // Environment command
            switch (command) {
                case 1: {  // tpage
                    TPage tpage(packetInfo);
                    logged = &tpage;
                    m_gpu->write0(&tpage);
                } break;
                case 2: {  // twindow
                    TWindow twindow(packetInfo);
                    logged = &twindow;
                    m_gpu->write0(&twindow);
                } break;
                case 3: {  // drawing area top left
                    DrawingAreaStart start(packetInfo);
                    logged = &start;
                    m_gpu->write0(&start);
                } break;
                case 4: {  // drawing area bottom right
                    DrawingAreaEnd end(packetInfo);
                    logged = &end;
                    m_gpu->write0(&end);
                } break;
                case 5: {  // drawing offset
                    DrawingOffset offset(packetInfo);
                    logged = &offset;
                    m_gpu->write0(&offset);
                } break;
                case 6: {  // mask bit
                    MaskBit mask(packetInfo);
                    logged = &mask;
                    m_gpu->write0(&mask);
                } break;
                default: {
                    gotUnknown = true;
                } break;
            }
            break;
    }
    if (gotUnknown) {
    }
}

void PCSX::GPU::FastFill::processWrite(uint32_t value) {
    __debugbreak();
    switch (m_state) {
        case READ_COLOR:
            color = value;
            m_state = READ_XY;
            break;
        case READ_XY:
            x = value & 0xffff;
            y = value >> 16;
            m_state = READ_WH;
            break;
        case READ_WH:
            w = value & 0xffff;
            h = value >> 16;
            m_state = READ_COLOR;
            m_gpu->m_defaultProcessor.setActive();
            break;
    }
}

void PCSX::GPU::BlitVramVram::processWrite(uint32_t value) { __debugbreak(); }

void PCSX::GPU::BlitRamVram::processWrite(uint32_t value) {
    size_t size;
    switch (m_state) {
        case READ_COMMAND:
            m_state = READ_XY;
            return;
        case READ_XY:
            x = signExtend<int, 11>(value & 0xffff);
            y = signExtend<int, 11>(value >> 16);
            m_state = READ_HW;
            return;
        case READ_HW:
            w = signExtend<int, 11>(value & 0xffff);
            h = signExtend<int, 11>(value >> 16);
            size = (w * h + 1) / 2;
            size *= 4;
            m_data.clear();
            m_data.reserve(size * 4);
            m_state = READ_PIXELS;
            return;
        case READ_PIXELS:
            m_data.push_back((value >> 0) & 0xff);
            m_data.push_back((value >> 8) & 0xff);
            m_data.push_back((value >> 16) & 0xff);
            m_data.push_back((value >> 24) & 0xff);
            size = (w * h + 1) / 2;
            size *= 4;
            if (m_data.size() == size) {
                m_state = READ_COMMAND;
                m_gpu->m_defaultProcessor.setActive();
                m_gpu->partialUpdateVRAM(x, y, w, h, reinterpret_cast<uint16_t *>(m_data.data()));
            }
            return;
    }
}

void PCSX::GPU::BlitVramRam::processWrite(uint32_t value) {
    switch (m_state) {
        case READ_COMMAND:
            m_gpu->m_readFifo->reset();
            m_state = READ_XY;
            return;
        case READ_XY:
            x = signExtend<int, 11>(value & 0xffff);
            y = signExtend<int, 11>(value >> 16);
            m_state = READ_HW;
            return;
        case READ_HW:
            w = signExtend<int, 11>(value & 0xffff);
            h = signExtend<int, 11>(value >> 16);
            m_state = READ_COMMAND;
            m_gpu->m_defaultProcessor.setActive();
            m_gpu->m_vramReadSlice = m_gpu->getVRAM();
            for (auto l = y; l < y + h; l++) {
                const uint16_t *line = m_gpu->m_vramReadSlice.data<uint16_t>() + (l * 1024) + x;
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
