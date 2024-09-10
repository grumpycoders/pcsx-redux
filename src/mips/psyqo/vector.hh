/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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

#include <concepts>

#include "psyqo/fixed-point.hh"
#include "psyqo/primitives/common.hh"

using namespace psyqo::fixed_point_literals;

namespace psyqo {

struct Vec2 {
    FixedPoint<> x, y;
    operator Vertex() const { return {{.x = x.integer<int16_t>(), .y = y.integer<int16_t>()}}; }
    Vec2& operator+=(const Vec2& rhs) {
        x += rhs.x;
        y += rhs.y;
        return *this;
    }
    Vec2& operator-=(const Vec2& rhs) {
        x -= rhs.x;
        y -= rhs.y;
        return *this;
    }
    Vec2& operator*=(const FixedPoint<>& rhs) {
        x *= rhs;
        y *= rhs;
        return *this;
    }
    Vec2& operator/=(const FixedPoint<>& rhs) {
        x /= rhs;
        y /= rhs;
        return *this;
    }
    template <std::integral U>
    Vec2& operator*=(U rhs) {
        x *= rhs;
        y *= rhs;
        return *this;
    }
    template <std::integral U>
    Vec2& operator/=(U rhs) {
        x /= rhs;
        y /= rhs;
        return *this;
    }
    Vec2 operator-() const { return {-x, -y}; }
    Vec2 operator+(const Vec2& rhs) const { return {x + rhs.x, y + rhs.y}; }
    Vec2 operator-(const Vec2& rhs) const { return {x - rhs.x, y - rhs.y}; }
    Vec2 operator*(const FixedPoint<>& rhs) const { return {x * rhs, y * rhs}; }
    Vec2 operator/(const FixedPoint<>& rhs) const { return {x / rhs, y / rhs}; }
    template <std::integral U>
    Vec2 operator*(U rhs) const {
        return {x * rhs, y * rhs};
    }
    template <std::integral U>
    Vec2 operator/(U rhs) const {
        return {x / rhs, y / rhs};
    }
    static const Vec2 ZERO;
    static const Vec2 ONE;
    static const Vec2 UP;
    static const Vec2 DOWN;
    static const Vec2 LEFT;
    static const Vec2 RIGHT;
};
const Vec2 Vec2::ZERO = { .x = 0.0_fp, .y = 0.0_fp };
const Vec2 Vec2::ONE = { .x = 1.0_fp, .y = 1.0_fp };
const Vec2 Vec2::UP = { .x = 0.0_fp, .y = 1.0_fp };
const Vec2 Vec2::DOWN = { .x = 0.0_fp, .y = -1.0_fp };
const Vec2 Vec2::LEFT = { .x = -1.0_fp, .y = 0.0_fp };
const Vec2 Vec2::RIGHT = { .x = 1.0_fp, .y = 0.0_fp };

struct Vec3 {
    FixedPoint<> x, y, z;
    Vec3& operator+=(const Vec3& rhs) {
        x += rhs.x;
        y += rhs.y;
        z += rhs.z;
        return *this;
    }
    Vec3& operator-=(const Vec3& rhs) {
        x -= rhs.x;
        y -= rhs.y;
        z -= rhs.z;
        return *this;
    }
    Vec3& operator*=(const FixedPoint<>& rhs) {
        x *= rhs;
        y *= rhs;
        z *= rhs;
        return *this;
    }
    Vec3& operator/=(const FixedPoint<>& rhs) {
        x /= rhs;
        y /= rhs;
        z /= rhs;
        return *this;
    }
    template <std::integral U>
    Vec3& operator*=(U rhs) {
        x *= rhs;
        y *= rhs;
        z *= rhs;
        return *this;
    }
    template <std::integral U>
    Vec3& operator/=(U rhs) {
        x /= rhs;
        y /= rhs;
        z /= rhs;
        return *this;
    }
    Vec3 operator-() const { return {-x, -y, -z}; }
    Vec3 operator+(const Vec3& rhs) const { return {x + rhs.x, y + rhs.y, z + rhs.z}; }
    Vec3 operator-(const Vec3& rhs) const { return {x - rhs.x, y - rhs.y, z - rhs.z}; }
    Vec3 operator*(const FixedPoint<>& rhs) const { return {x * rhs, y * rhs, z * rhs}; }
    Vec3 operator/(const FixedPoint<>& rhs) const { return {x / rhs, y / rhs, z / rhs}; }
    template <std::integral U>
    Vec3 operator*(U rhs) const {
        return {x * rhs, y * rhs, z * rhs};
    }
    template <std::integral U>
    Vec3 operator/(U rhs) const {
        return {x / rhs, y / rhs, z / rhs};
    }
    static const Vec3 ZERO;
    static const Vec3 ONE;
    static const Vec3 UP;
    static const Vec3 DOWN;
    static const Vec3 LEFT;
    static const Vec3 RIGHT;
    static const Vec3 FORWARD;
    static const Vec3 BACKWARD;
};
const Vec3 Vec3::ZERO = { .x = 0.0_fp, .y = 0.0_fp, .z = 0.0_fp };
const Vec3 Vec3::ONE = { .x = 1.0_fp, .y = 1.0_fp, .z = 1.0_fp };
const Vec3 Vec3::UP = { .x = 0.0_fp, .y = 1.0_fp, .z = 0.0_fp };
const Vec3 Vec3::DOWN = { .x = 0.0_fp, .y = -1.0_fp, .z = 0.0_fp };
const Vec3 Vec3::LEFT = { .x = -1.0_fp, .y = 0.0_fp, .z = 0.0_fp };
const Vec3 Vec3::RIGHT = { .x = 1.0_fp, .y = 0.0_fp, .z = 0.0_fp };
const Vec3 Vec3::FORWARD = { .x = 0.0_fp, .y = 0.0_fp, .z = 1.0_fp };
const Vec3 Vec3::BACKWARD = { .x = 0.0_fp, .y = 0.0_fp, .z = -1.0_fp };

struct Vec4 {
    FixedPoint<> x, y, z, w;
    Vec4& operator+=(const Vec4& rhs) {
        x += rhs.x;
        y += rhs.y;
        z += rhs.z;
        w += rhs.w;
        return *this;
    }
    Vec4& operator-=(const Vec4& rhs) {
        x -= rhs.x;
        y -= rhs.y;
        z -= rhs.z;
        w -= rhs.w;
        return *this;
    }
    Vec4& operator*=(const FixedPoint<>& rhs) {
        x *= rhs;
        y *= rhs;
        z *= rhs;
        w *= rhs;
        return *this;
    }
    Vec4& operator/=(const FixedPoint<>& rhs) {
        x /= rhs;
        y /= rhs;
        z /= rhs;
        w /= rhs;
        return *this;
    }
    template <std::integral U>
    Vec4& operator*=(U rhs) {
        x *= rhs;
        y *= rhs;
        z *= rhs;
        w *= rhs;
        return *this;
    }
    template <std::integral U>
    Vec4& operator/=(U rhs) {
        x /= rhs;
        y /= rhs;
        z /= rhs;
        w /= rhs;
        return *this;
    }
    Vec4 operator-() const { return {-x, -y, -z, -w}; }
    Vec4 operator+(const Vec4& rhs) const { return {x + rhs.x, y + rhs.y, z + rhs.z, w + rhs.w}; }
    Vec4 operator-(const Vec4& rhs) const { return {x - rhs.x, y - rhs.y, z - rhs.z, w - rhs.w}; }
    Vec4 operator*(const FixedPoint<>& rhs) const { return {x * rhs, y * rhs, z * rhs, w * rhs}; }
    Vec4 operator/(const FixedPoint<>& rhs) const { return {x / rhs, y / rhs, z / rhs, w / rhs}; }
    template <std::integral U>
    Vec4 operator*(U rhs) const {
        return {x * rhs, y * rhs, z * rhs, w * rhs};
    }
    template <std::integral U>
    Vec4 operator/(U rhs) const {
        return {x / rhs, y / rhs, z / rhs, w / rhs};
    }
};

}  // namespace psyqo
