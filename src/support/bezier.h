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

#include <cmath>
#include <numbers>

#include "support/imgui-helpers.h"

namespace PCSX {

namespace Bezier {

using vec2 = ImVec2;

template <typename T>
T cubic(const T& a, const T& b, const T& c, const T& d, float t) {
    float it = 1 - t;
    float it2 = it * it;
    float it3 = it2 * it;
    float t2 = t * t;
    float t3 = t2 * t;

    return a * it3 + b * it2 * t * 3.0f + c * it * t2 + d * t3 * 3.0f;
}

template <typename T>
T quadratic(const T& a, const T& b, const T& c, float t) {
    float it = 1 - t;
    float it2 = it * it;
    float t2 = t * t;

    return a * it2 + b * it * t * 2.0f + c * t2;
}

float angle(const vec2& a, const vec2& b, const vec2& c, const vec2& d, float t) {
    auto dir = quadratic(b - a, c - b, d - c, t);
    return std::atan2(dir.y, dir.x);
}

}  // namespace Bezier

}  // namespace PCSX
