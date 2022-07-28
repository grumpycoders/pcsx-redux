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
#pragma once

#include "support/opengl.h"

namespace PCSX {
// TODO: Use this in soft GPU
struct Display {
    using ivec2 = OpenGL::ivec2;
    using vec2 = OpenGL::vec2;

    ivec2 m_start;  // Starting coords of the display area
    ivec2 m_size;   // Width and height of the display area
    vec2 m_startNormalized; // Starting coords of the display area normalized in the [0, 1] range
    vec2 m_sizeNormalized;  // Width and height of the display area normalized in the [0, 1] range

    uint32_t m_drawMode;
    bool m_rgb24;   // Is RGB24 mode enabled?
    bool m_interlace;
    bool m_pal;
    bool m_enabled;
    bool m_linearFiltering = true;

    int x1, x2, y1, y2;  // Display area range variables

    void reset();
    void setDisplayStart(uint32_t command);
    void setHorizontalRange(uint32_t command);
    void setVerticalRange(uint32_t command);
    void setMode(uint32_t command);
    void setLinearFiltering(bool setting);
    void updateDispArea();
};

}  // namespace PCSX
