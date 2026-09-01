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

#include "psyqo/bezier.hh"

psyqo::Vec2 psyqo::Bezier::cubic(const psyqo::Vec2& a, const psyqo::Vec2& b, const psyqo::Vec2& c, const psyqo::Vec2& d,
                                 psyqo::FixedPoint<> t) {
    using namespace psyqo::fixed_point_literals;
    FixedPoint<> t2 = t * t;
    FixedPoint<> t3 = t2 * t;

    FixedPoint<> mt = 1.0_fp - t;
    FixedPoint<> mt2 = mt * mt;
    FixedPoint<> mt3 = mt2 * mt;

    FixedPoint<> f1 = mt3;
    FixedPoint<> f2 = mt2 * t * 3;
    FixedPoint<> f3 = mt * t2 * 3;
    FixedPoint<> f4 = t3;

    FixedPoint<> x = a.x * f1 + b.x * f2 + c.x * f3 + d.x * f4;
    FixedPoint<> y = a.y * f1 + b.y * f2 + c.y * f3 + d.y * f4;

    return {x, y};
}

psyqo::Vec3 psyqo::Bezier::cubic(const psyqo::Vec3& a, const psyqo::Vec3& b, const psyqo::Vec3& c, const psyqo::Vec3& d,
                                 psyqo::FixedPoint<> t) {
    using namespace psyqo::fixed_point_literals;
    FixedPoint<> t2 = t * t;
    FixedPoint<> t3 = t2 * t;

    FixedPoint<> mt = 1.0_fp - t;
    FixedPoint<> mt2 = mt * mt;
    FixedPoint<> mt3 = mt2 * mt;

    FixedPoint<> f1 = mt3;
    FixedPoint<> f2 = mt2 * t * 3;
    FixedPoint<> f3 = mt * t2 * 3;
    FixedPoint<> f4 = t3;

    FixedPoint<> x = a.x * f1 + b.x * f2 + c.x * f3 + d.x * f4;
    FixedPoint<> y = a.y * f1 + b.y * f2 + c.y * f3 + d.y * f4;
    FixedPoint<> z = a.z * f1 + b.z * f2 + c.z * f3 + d.z * f4;

    return {x, y, z};
}
