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

#include "core/gpu.h"
#include "core/psxemulator.h"
#include "magic_enum/include/magic_enum.hpp"

void PCSX::GPU::Display::reset() {
    x1 = 0x200;
    x2 = 0x200 + 256 * 10;
    y1 = 0x10;
    y2 = 0x10 + 0x240;
    enabled = false;
    CtrlDisplayMode mode;
    set(&mode);
    CtrlDisplayStart start(0);
    set(&start);
    updateDispArea();
}

void PCSX::GPU::Display::set(CtrlDisplayStart* ctrl) {
    int startX = ctrl->x;
    int startY = ctrl->y;

    if (startX != start.x() || startY != start.y()) {
        // Store real, unedited coords in start
        start.x() = startX;
        start.y() = startY;

        // Adjust dimensions before normalizing if we have linear filtering on
        if (g_emulator->settings.get<Emulator::SettingLinearFiltering>()) {
            startX += 1;
            startY += 1;
        }

        startNormalized.x() = (float)startX / 1024.f;
        startNormalized.y() = (float)startY / 512.f;
    }
}

void PCSX::GPU::Display::set(CtrlHorizontalDisplayRange* ctrl) {
    const auto newX1 = ctrl->x0;
    const auto newX2 = ctrl->x1;

    if (x1 != newX1 || x2 != newX2) {
        x1 = newX1;
        x2 = newX2;
        updateDispArea();
    }
}

void PCSX::GPU::Display::set(CtrlVerticalDisplayRange* ctrl) {
    const auto newY1 = ctrl->y0;
    const auto newY2 = ctrl->y1;

    if (y1 != newY1 || y2 != newY2) {
        y1 = newY1;
        y2 = newY2;
        updateDispArea();
    }
}

void PCSX::GPU::Display::set(CtrlDisplayMode* ctrl) {
    if (ctrl->equals(info)) return;

    info = *ctrl;
    if (g_emulator->settings.get<PCSX::Emulator::SettingAutoVideo>()) {
        if (info.mode == CtrlDisplayMode::VM_PAL) {
            g_emulator->settings.get<Emulator::SettingVideo>() = Emulator::PSX_TYPE_PAL;
        } else {
            g_emulator->settings.get<Emulator::SettingVideo>() = Emulator::PSX_TYPE_NTSC;
        }
    }

    updateDispArea();
}

void PCSX::GPU::Display::updateDispArea() {
    static constexpr int dividers[] = {10, 8, 5, 4, 7, 7};
    const auto divider = dividers[magic_enum::enum_integer(info.hres)];
    const auto cyclesPerScanline = info.mode == CtrlDisplayMode::VM_PAL ? 3406 : 3413;
    const auto totalScanlines = info.mode == CtrlDisplayMode::VM_PAL ? 314 : 263;

    auto horRangeStart = std::min<int>(x1, cyclesPerScanline);
    auto horRangeEnd = std::min<int>(x2, cyclesPerScanline);

    // Rounding
    horRangeStart = (horRangeStart / divider) * divider;
    horRangeEnd = (horRangeEnd / divider) * divider;

    const auto vertRangeStart = std::min<int>(y1, totalScanlines);
    const auto vertRangeEnd = std::min<int>(y2, totalScanlines);
    int height = std::min<int>(totalScanlines, vertRangeEnd - vertRangeStart);
    if (info.interlace) {
        height *= 2;
    }

    // Calculate display width and round to 4 pixels
    const uint32_t horizontalCycles = (horRangeEnd > horRangeStart) ? (horRangeEnd - horRangeStart) : 0;
    int width = ((horizontalCycles / divider) + 2) & ~3;

    // Store the true, unedited dimensions in size
    size.x() = width;
    size.y() = height;

    // Adjust dimensions before normalizing if we have linear filtering on
    if (g_emulator->settings.get<Emulator::SettingLinearFiltering>()) {
        width -= 2;
        height -= 2;
    }
    sizeNormalized.x() = (float)width / 1024.f;
    sizeNormalized.y() = (float)height / 512.f;
}

void PCSX::GPU::Display::setLinearFiltering() {
    auto setting = g_emulator->settings.get<Emulator::SettingLinearFiltering>().value;
    // If linear filtering is on, crop 1 row from the top & bottom, and 1 column from the left & right
    const int width = size.x() - ((setting) ? 2 : 0);
    const int height = size.y() - ((setting) ? 2 : 0);
    const int startX = start.x() + ((setting) ? 1 : 0);
    const int startY = start.y() + ((setting) ? 1 : 0);

    sizeNormalized.x() = (float)width / 1024.f;
    sizeNormalized.y() = (float)height / 512.f;
    startNormalized.x() = (float)startX / 1024.f;
    startNormalized.y() = (float)startY / 512.f;
}
