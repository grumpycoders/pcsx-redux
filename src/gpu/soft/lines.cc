/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "gpu/soft/soft.h"

template <PCSX::SoftGPU::Line::Axis MajorAxis, PCSX::SoftGPU::Line::MajorSign MaSign,
          PCSX::SoftGPU::Line::MinorSign MiSign, PCSX::SoftGPU::Line::Bias B, PCSX::GPU::Shading Shading>
void PCSX::SoftGPU::SoftRenderer::drawLineOctant(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1) {
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    // Major-axis distance for the gouraud interpolation denominator.
    int steps;
    if constexpr (MajorAxis == Line::Axis::X) {
        steps = x1 - x0;
    } else if constexpr (MaSign == Line::MajorSign::Plus) {
        steps = y1 - y0;
    } else {
        steps = y0 - y1;
    }

    LineStepper<MajorAxis, MaSign, MiSign, B> stepper(x0, y0, x1, y1);
    LineColorWalker<Shading> walker(rgb0, rgb1, steps);
    RasterState rs = makeBaseRasterState();

    auto plot = [&](int x, int y) {
        if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) {
            PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(rs, x, y, walker.current555());
        }
    };

    plot(stepper.x(), stepper.y());
    int stepIdx = 0;
    while (stepper.more()) {
        stepper.advance();
        ++stepIdx;
        walker.advanceTo(stepIdx);
        plot(stepper.x(), stepper.y());
    }
}

template <PCSX::SoftGPU::Line::Axis Iter, PCSX::GPU::Shading Shading>
void PCSX::SoftGPU::SoftRenderer::drawAxisLine(int constCoord, int varStart, int varEnd, uint32_t rgb0, uint32_t rgb1) {
    const int steps = varEnd - varStart;
    const int varStartOrig = varStart;

    LineColorWalker<Shading> walker(rgb0, rgb1, steps);

    if constexpr (Iter == Line::Axis::X) {
        if (varStart < m_drawX) varStart = m_drawX;
        if (varEnd > m_drawW) varEnd = m_drawW;
    } else {
        if (varStart < m_drawY) varStart = m_drawY;
        if (varEnd > m_drawH) varEnd = m_drawH;
    }

    RasterState rs = makeBaseRasterState();

    for (int v = varStart; v <= varEnd; ++v) {
        walker.advanceTo(v - varStartOrig);
        if constexpr (Iter == Line::Axis::X) {
            PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(rs, v, constCoord, walker.current555());
        } else {
            PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(rs, constCoord, v, walker.current555());
        }
    }
}

/* Bresenham Line drawing function */
template <PCSX::GPU::Shading Shading>
void PCSX::SoftGPU::SoftRenderer::drawLine(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int32_t rgb0, int32_t rgb1) {
    int16_t xt, yt;
    double m, dy, dx;

    if (x0 > m_drawW && x1 > m_drawW) return;
    if (y0 > m_drawH && y1 > m_drawH) return;
    if (x0 < m_drawX && x1 < m_drawX) return;
    if (y0 < m_drawY && y1 < m_drawY) return;
    if (m_drawY >= m_drawH) return;
    if (m_drawX >= m_drawW) return;

    dx = x1 - x0;
    dy = y1 - y0;

    if (dx == 0) {
        if (dy == 0) {
            // Zero-length line: hardware draws exactly one pixel at the vertex.
            // The GP0 command color arrives as a 24-bit BGR888 word; convert
            // to the BGR555 layout the writer expects before storing.
            if ((x0 >= m_drawX) && (x0 < m_drawW) && (y0 >= m_drawY) && (y0 < m_drawH)) {
                RasterState rs = makeBaseRasterState();
                PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(
                    rs, x0, y0, Channel555::fromCommandColor(rgb0));
            }
            return;
        } else if (dy > 0) {
            drawAxisLine<Line::Axis::Y, Shading>(x0, y0, y1, rgb0, rgb1);
        } else {
            drawAxisLine<Line::Axis::Y, Shading>(x0, y1, y0, rgb0, rgb1);
        }
    } else if (dy == 0) {
        if (dx > 0) {
            drawAxisLine<Line::Axis::X, Shading>(y0, x0, x1, rgb0, rgb1);
        } else {
            drawAxisLine<Line::Axis::X, Shading>(y0, x1, x0, rgb0, rgb1);
        }
    } else {
        if (dx < 0) {
            xt = x0;
            yt = y0;
            x0 = x1;
            y0 = y1;
            x1 = xt;
            y1 = yt;

            dx = x1 - x0;
            dy = y1 - y0;
        }

        m = dy / dx;

        if (m >= 0) {
            if (m > 1) {
                drawLineOctant<Line::Axis::Y, Line::MajorSign::Plus, Line::MinorSign::Plus, Line::Bias::Steep, Shading>(
                    x0, y0, x1, y1, rgb0, rgb1);
            } else {
                drawLineOctant<Line::Axis::X, Line::MajorSign::Plus, Line::MinorSign::Plus, Line::Bias::Shallow,
                               Shading>(x0, y0, x1, y1, rgb0, rgb1);
            }
        } else if (m < -1) {
            drawLineOctant<Line::Axis::Y, Line::MajorSign::Minus, Line::MinorSign::Plus, Line::Bias::Steep, Shading>(
                x0, y0, x1, y1, rgb0, rgb1);
        } else {
            drawLineOctant<Line::Axis::X, Line::MajorSign::Plus, Line::MinorSign::Minus, Line::Bias::Shallow, Shading>(
                x0, y0, x1, y1, rgb0, rgb1);
        }
    }
}

template void PCSX::SoftGPU::SoftRenderer::drawLine<PCSX::GPU::Shading::Flat>(int16_t x0, int16_t y0, int16_t x1,
                                                                              int16_t y1, int32_t rgb0, int32_t rgb1);
template void PCSX::SoftGPU::SoftRenderer::drawLine<PCSX::GPU::Shading::Gouraud>(int16_t x0, int16_t y0, int16_t x1,
                                                                                 int16_t y1, int32_t rgb0,
                                                                                 int32_t rgb1);
