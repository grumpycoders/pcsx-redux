/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

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
