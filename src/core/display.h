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

#include <algorithm>

#include "core/psxemulator.h"
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
    bool m_linearFiltering = true;

    int x1, x2, y1, y2;  // Display area range variables

    void reset() {
        x1 = 0x200;
        x2 = 0x200 + 256 * 10;
        y1 = 0x10;
        y2 = 0x10 + 0x240;
        setMode(0);
        setDisplayStart(0);
        updateDispArea();
    }

    void setDisplayStart(uint32_t command) {
        int startX = command & 0x3fe;
        int startY = (command >> 10) & 0x1ff;

        if (startX != m_start.x() || startY != m_start.y()) {
            // Store real, unedited coords in m_start
            m_start.x() = startX;
            m_start.y() = startY;

            // Adjust dimensions before normalizing if we have linear filtering on
            if (m_linearFiltering) {
                startX += 1;
                startY += 1;
            }
            float xRatio = m_rgb24 ? ((1.0f / 1.5f) * (1.0f / 1024.0f)) : (1.0f / 1024.0f);

            m_startNormalized.x() = (float)startX * xRatio;
            m_startNormalized.y() = (float)startY / 512.f;
        }
    }

    void setHorizontalRange(uint32_t command) {
        const auto newX1 = command & 0xfff;
        const auto newX2 = (command >> 12) & 0xfff;

        if (x1 != newX1 || x2 != newX2) {
            x1 = newX1;
            x2 = newX2;
            updateDispArea();
        }
    }

    void setVerticalRange(uint32_t command) {
        const auto newY1 = command & 0x3ff;
        const auto newY2 = (command >> 10) & 0x3ff;

        if (y1 != newY1 || y2 != newY2) {
            y1 = newY1;
            y2 = newY2;
            updateDispArea();
        }
    }

    void setMode(uint32_t command) {
        const uint32_t newMode = command & 0xff;

        if (m_drawMode != newMode) {
            m_drawMode = newMode;
            m_pal = (newMode & 0x8) != 0;
            m_interlace = (newMode & 0x20) != 0;

            if (g_emulator->settings.get<PCSX::Emulator::SettingAutoVideo>()) {
                if (m_pal) {
                    g_emulator->settings.get<Emulator::SettingVideo>() = Emulator::PSX_TYPE_PAL;
                } else {
                    g_emulator->settings.get<Emulator::SettingVideo>() = Emulator::PSX_TYPE_NTSC;
                }
            }

            updateDispArea();
        }
    }

    void updateDispArea() {
        for (int i = 0; i < 10; i++)
           PCSX::g_system->printf("henlo\n");
        static constexpr int dividers[] = {10, 7, 8, 7, 5, 7, 4, 7};
        const auto horizontalRes = ((m_drawMode >> 6) & 1) | ((m_drawMode & 3) << 1);
        const auto divider = dividers[horizontalRes];
        const auto cyclesPerScanline = m_pal ? 3406 : 3413;
        const auto totalScanlines = m_pal ? 314 : 263;

        auto horRangeStart = std::min<int>(x1, cyclesPerScanline);
        auto horRangeEnd = std::min<int>(x2, cyclesPerScanline);

        // Rounding
        horRangeStart = (horRangeStart / divider) * divider;
        horRangeEnd = (horRangeEnd / divider) * divider;

        const auto vertRangeStart = std::min<int>(y1, totalScanlines);
        const auto vertRangeEnd = std::min<int>(y2, totalScanlines);
        int height = std::min<int>(totalScanlines, vertRangeEnd - vertRangeStart);
        if (m_interlace) {
            height *= 2;
        }

        // Calculate display width and round to 4 pixels
        const uint32_t horizontalCycles = (horRangeEnd > horRangeStart) ? (horRangeEnd - horRangeStart) : 0;
        int width = ((horizontalCycles / divider) + 2) & ~3;

        // Store the true, unedited dimensions in m_size
        m_size.x() = width;
        m_size.y() = height;
        int startX = m_start.x();

        // Adjust dimensions before normalizing if we have linear filtering on
        if (m_linearFiltering) {
            width -= 1;
            height -= 1;
            startX += 1;
        }
        m_sizeNormalized.x() = (float)width / 1024.f;
        m_sizeNormalized.y() = (float)height / 512.f;

        float xRatio = m_rgb24 ? ((1.0f / 1.5f) * (1.0f / 1024.0f)) : (1.0f / 1024.0f);
        m_startNormalized.x() = (float)startX * xRatio;
    }

    void setLinearFiltering(bool setting) {
        m_linearFiltering = setting;
        // If linear filtering is on, crop 1 row from the top & bottom, and 1 column from the left & right
        const int width = m_size.x() - ((setting) ? 1 : 0);
        const int height = m_size.y() - ((setting) ? 1 : 0);
        const int startX = m_start.x() + ((setting) ? 1 : 0);
        const int startY = m_start.y() + ((setting) ? 1 : 0);

        m_sizeNormalized.x() = (float)width / 1024.f;
        m_sizeNormalized.y() = (float)height / 512.f;
        m_startNormalized.x() = (float)startX / 1024.f;
        m_startNormalized.y() = (float)startY / 512.f;
    }
};

}  // namespace PCSX
