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

#pragma once

#include <stdint.h>

#include "core/gpu.h"
#include "gpu/soft/pixel-writer.h"

namespace PCSX {

namespace SoftGPU {

// Bresenham line-octant axes for the soft GPU line rasterizer.
//
// MajorAxis  - which axis advances every iteration. X for shallow lines
//              (|slope| <= 1), Y for steep lines (|slope| > 1).
// MajorSign  - direction of the major-axis step. X-major lines always
//              advance left-to-right after the dispatcher's swap, so
//              MajorSign::Plus there is structural. Y-major lines run
//              either downward (Plus) or upward (Minus) depending on
//              whether the original slope was positive or negative.
// MinorSign  - direction the minor axis takes on the Bresenham diagonal
//              decision. Pairs with MajorAxis: for X-major it nudges Y,
//              for Y-major it nudges X.
// Bias       - the initial value of the Bresenham error term. Shallow
//              uses the pixel-centre-biased 3*dy - dx that matches the
//              PlayStation GPU's minor-axis tie-break at half-pixel
//              crossings (phase-2 / phase-10 hardware-verified, see
//              learnings/pcsx-redux/gpu.md). Steep uses the standard
//              midpoint 2*dx - dy which already matches hardware for
//              Y-major lines. The bias is hardware-load-bearing and
//              MUST track MajorAxis explicitly; do not unify the two
//              policies without re-running phase-2 and phase-10.
namespace Line {
enum class Axis { X, Y };
enum class MajorSign { Plus, Minus };
enum class MinorSign { Plus, Minus };
enum class Bias { Shallow, Steep };
}  // namespace Line

// Bresenham octant stepper. One template covers all four canonical octants
// the dispatcher emits after the negative-dx swap. See soft.h for the
// per-parameter contract; the bias choice is hardware-load-bearing and
// MUST track MajorAxis: shallow / X-major uses the pixel-centre 3*dy - dx,
// steep / Y-major uses the standard 2*dx - dy.
using Axis = PCSX::SoftGPU::Line::Axis;
using MajorSign = PCSX::SoftGPU::Line::MajorSign;
using MinorSign = PCSX::SoftGPU::Line::MinorSign;
using Bias = PCSX::SoftGPU::Line::Bias;

template <Axis MajorAxis, MajorSign MaSign, MinorSign MiSign, Bias B>
class LineStepper {
  public:
    LineStepper(int x0, int y0, int x1, int y1) : m_x(x0), m_y(y0) {
        int dx = x1 - x0;
        int dy = y1 - y0;
        // Historically the N_NE (Y-major negative slope) and E_NE
        // (X-major negative slope) octants each pre-negated dy so the
        // Bresenham bias and increment formulas could pretend the slope
        // was positive. The stepper does the same trick internally so
        // its callers don't have to. Whenever the minor axis steps in
        // the negative direction (X-major MinorSign::Minus, or Y-major
        // MajorSign::Minus where the minor axis is X but the steep-form
        // sign discipline routes through MajorSign), normalize dy to a
        // positive distance.
        if constexpr (MajorAxis == Axis::X && MiSign == MinorSign::Minus) {
            dy = -dy;
        } else if constexpr (MajorAxis == Axis::Y && MaSign == MajorSign::Minus) {
            dy = -dy;
        }
        if constexpr (B == Bias::Shallow) {
            // Shallow / X-major: pixel-centre biased initial.
            // Hardware-verified by phase-2 / phase-10; do not soften.
            m_d = 3 * dy - dx;
            m_incrMajor = 2 * dy;
            m_incrDiag = 2 * (dy - dx);
        } else {
            // Steep / Y-major: standard midpoint initial; already matches
            // hardware as-is.
            m_d = 2 * dx - dy;
            m_incrMajor = 2 * dx;
            m_incrDiag = 2 * (dx - dy);
        }
        m_endMajor = (MajorAxis == Axis::X) ? x1 : y1;
    }

    int x() const { return m_x; }
    int y() const { return m_y; }

    bool more() const {
        if constexpr (MajorAxis == Axis::X) {
            return m_x < m_endMajor;
        } else if constexpr (MaSign == MajorSign::Plus) {
            return m_y < m_endMajor;
        } else {
            return m_y > m_endMajor;
        }
    }

    void advance() {
        if (m_d <= 0) {
            m_d += m_incrMajor;
        } else {
            m_d += m_incrDiag;
            if constexpr (MajorAxis == Axis::X) {
                if constexpr (MiSign == MinorSign::Plus) {
                    ++m_y;
                } else {
                    --m_y;
                }
            } else {
                if constexpr (MiSign == MinorSign::Plus) {
                    ++m_x;
                } else {
                    --m_x;
                }
            }
        }
        if constexpr (MajorAxis == Axis::X) {
            ++m_x;
        } else if constexpr (MaSign == MajorSign::Plus) {
            ++m_y;
        } else {
            --m_y;
        }
    }

  private:
    int m_x;
    int m_y;
    int m_d;
    int m_incrMajor;
    int m_incrDiag;
    int m_endMajor;
};

// Per-step gouraud colour walker for shaded line rasterizers. Captures
// the per-channel deltas at construction; advanceTo(stepIdx) snaps the
// internal R/G/B back to the line-anchored linear interpolation, and
// current555() packs them into BGR555. Channels are kept in the same
// high-aligned 8.16-style layout the original octant bodies used so
// the >> 9 / >> 14 / >> 19 pack stays identical at the bit level.
// The steps==0 guard is hoisted into advanceTo() once instead of being
// repeated at every plot site.
class GouraudWalker {
  public:
    GouraudWalker(uint32_t rgb0, uint32_t rgb1, int steps)
        : m_r((rgb0 & 0x00ff0000)),
          m_g((rgb0 & 0x0000ff00) << 8),
          m_b((rgb0 & 0x000000ff) << 16),
          m_rInit(m_r),
          m_gInit(m_g),
          m_bInit(m_b),
          m_drFull((int32_t)(rgb1 & 0x00ff0000) - (int32_t)m_r),
          m_dgFull((int32_t)((rgb1 & 0x0000ff00) << 8) - (int32_t)m_g),
          m_dbFull((int32_t)((rgb1 & 0x000000ff) << 16) - (int32_t)m_b),
          m_steps(steps) {}

    void advanceTo(int stepIdx) {
        if (m_steps != 0) {
            m_r = m_rInit + (int64_t)m_drFull * stepIdx / m_steps;
            m_g = m_gInit + (int64_t)m_dgFull * stepIdx / m_steps;
            m_b = m_bInit + (int64_t)m_dbFull * stepIdx / m_steps;
        }
    }

    uint16_t current555() const { return (uint16_t)(PCSX::SoftGPU::Channel555::fromHighAlignedRGB(m_r, m_g, m_b)); }

  private:
    uint32_t m_r;
    uint32_t m_g;
    uint32_t m_b;
    uint32_t m_rInit;
    uint32_t m_gInit;
    uint32_t m_bInit;
    int32_t m_drFull;
    int32_t m_dgFull;
    int32_t m_dbFull;
    int m_steps;
};

struct FlatColor {
    FlatColor(uint16_t color_, uint16_t dummy, int dummy2) : color(color_) {}
    uint16_t current555() { return color; }
    void advanceTo(int) {}
    uint16_t color;
};

template <PCSX::GPU::Shading Shading>
using LineColorWalker = std::conditional_t<Shading == PCSX::GPU::Shading::Gouraud, GouraudWalker, FlatColor>;

}  // namespace SoftGPU

}  // namespace PCSX
