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
    static constexpr Vec2 ZERO() {
        using namespace psyqo::fixed_point_literals;
        return Vec2 { .x = 0.0_fp, .y = 0.0_fp };
    }
    static constexpr Vec2 ONE() {
        using namespace psyqo::fixed_point_literals;
        return Vec2{ .x = 1.0_fp, .y = 1.0_fp };
    }
    static constexpr Vec2 UP() {
        using namespace psyqo::fixed_point_literals;
        return Vec2{ .x = 0.0_fp, .y = 1.0_fp };
    }
    static constexpr Vec2 DOWN() {
        using namespace psyqo::fixed_point_literals;
        return Vec2{ .x = 0.0_fp, .y = -1.0_fp };
    }
    static constexpr Vec2 LEFT() {
        using namespace psyqo::fixed_point_literals;
        return Vec2{ .x = -1.0_fp, .y = 0.0_fp };
    }
    static constexpr Vec2 RIGHT() {
        using namespace psyqo::fixed_point_literals;
        return Vec2{ .x = 1.0_fp, .y = 0.0_fp };
    }
};

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
    static constexpr Vec3 ZERO() {
        using namespace psyqo::fixed_point_literals;
        return Vec3 { .x = 0.0_fp, .y = 0.0_fp, .z = 0.0_fp };
    }
    static constexpr Vec3 ONE() {
        using namespace psyqo::fixed_point_literals;
        return Vec3 { .x = 1.0_fp, .y = 1.0_fp, .z = 1.0_fp };
    }
    static constexpr Vec3 UP() {
        using namespace psyqo::fixed_point_literals;
        return Vec3 { .x = 0.0_fp, .y = 1.0_fp, .z = 0.0_fp };
    }
    static constexpr Vec3 DOWN() {
        using namespace psyqo::fixed_point_literals;
        return Vec3 { .x = 0.0_fp, .y = -1.0_fp, .z = 0.0_fp };
    }
    static constexpr Vec3 LEFT() {
        using namespace psyqo::fixed_point_literals;
        return Vec3 { .x = -1.0_fp, .y = 0.0_fp, .z = 0.0_fp };
    }
    static constexpr Vec3 RIGHT() {
        using namespace psyqo::fixed_point_literals;
        return Vec3 { .x = 1.0_fp, .y = 0.0_fp, .z = 0.0_fp };
    }
    static constexpr Vec3 FORWARD() {
        using namespace psyqo::fixed_point_literals;
        return Vec3 { .x = 0.0_fp, .y = 0.0_fp, .z = 1.0_fp };
    }
    static constexpr Vec3 BACKWARD() {
        using namespace psyqo::fixed_point_literals;
        return Vec3 { .x = 0.0_fp, .y = 0.0_fp, .z = -1.0_fp };
    }
};

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
