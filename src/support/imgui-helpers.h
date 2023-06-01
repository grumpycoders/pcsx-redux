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

#define IMGUI_DEFINE_MATH_OPERATORS

#include "imgui.h"

namespace PCSX {
namespace ImGuiHelpers {

static void normalizeDimensions(ImVec2& vec, float ratio) {
    float r = vec.y / vec.x;
    if (r > ratio) {
        vec.y = vec.x * ratio;
    } else {
        vec.x = vec.y / ratio;
    }
    vec.x = roundf(vec.x);
    vec.y = roundf(vec.y);
    vec.x = std::max(vec.x, 1.0f);
    vec.y = std::max(vec.y, 1.0f);
}

}  // namespace ImGuiHelpers
}  // namespace PCSX
