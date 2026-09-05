/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

#include "psyqo/fixed-point.hh"

#include "snitch_all.hpp"

using namespace psyqo;
using namespace psyqo::fixed_point_literals;

// --- Construction ---

TEST_CASE("FixedPoint default construction is zero") {
    FixedPoint<> a;
    REQUIRE(a.raw() == 0);
}

TEST_CASE("FixedPoint integer-fraction construction") {
    FixedPoint<> a(3, 0);
    REQUIRE(a.raw() == 3 * 4096);
    FixedPoint<> b(1, 2048);  // 1.5
    REQUIRE(b.raw() == 4096 + 2048);
}

TEST_CASE("FixedPoint consteval float construction") {
    FixedPoint<> a = 1.0;
    REQUIRE(a.raw() == 4096);
    FixedPoint<> b = 0.5;
    REQUIRE(b.raw() == 2048);
    FixedPoint<> c = -2.5;
    REQUIRE(c.raw() == -10240);
    FixedPoint<> d = 0.0;
    REQUIRE(d.raw() == 0);
}

TEST_CASE("FixedPoint raw construction") {
    FixedPoint<> a(12345, FixedPoint<>::RAW);
    REQUIRE(a.raw() == 12345);
}

TEST_CASE("FixedPoint user-defined literal") {
    auto a = 3.14_fp;
    REQUIRE(a.raw() == static_cast<int32_t>(3.14L * 4096 + 0.5));
}

// --- Rounding ---

TEST_CASE("FixedPoint integer() rounds to nearest") {
    FixedPoint<> a = 1.5;
    REQUIRE(a.integer() == 2);
    FixedPoint<> b = 1.4;
    REQUIRE(b.integer() == 1);
    FixedPoint<> c = 2.5;
    REQUIRE(c.integer() == 3);
}

TEST_CASE("FixedPoint integer() negative rounding") {
    FixedPoint<> a = -1.5;
    REQUIRE(a.integer() == -2);
    FixedPoint<> b = -1.4;
    REQUIRE(b.integer() == -1);
}

TEST_CASE("FixedPoint floor()") {
    FixedPoint<> a = 3.7;
    REQUIRE(a.floor() == 3);
    FixedPoint<> b = -3.7;
    REQUIRE(b.floor() == -4);
    FixedPoint<> c = 4.0;
    REQUIRE(c.floor() == 4);
}

TEST_CASE("FixedPoint ceil()") {
    FixedPoint<> a = 3.2;
    REQUIRE(a.ceil() == 4);
    FixedPoint<> b = -3.2;
    REQUIRE(b.ceil() == -3);
    FixedPoint<> c = 4.0;
    REQUIRE(c.ceil() == 4);
}

// --- Arithmetic ---

TEST_CASE("FixedPoint addition") {
    FixedPoint<> a = 1.5;
    FixedPoint<> b = 2.25;
    auto c = a + b;
    REQUIRE(c.raw() == a.raw() + b.raw());
}

TEST_CASE("FixedPoint addition with integer") {
    FixedPoint<> a = 1.5;
    auto b = a + 3;
    REQUIRE(b.raw() == a.raw() + 3 * 4096);
    auto c = 3 + a;
    REQUIRE(c.raw() == b.raw());
}

TEST_CASE("FixedPoint subtraction") {
    FixedPoint<> a = 5.0;
    FixedPoint<> b = 2.25;
    auto c = a - b;
    REQUIRE(c.raw() == a.raw() - b.raw());
}

TEST_CASE("FixedPoint subtraction with integer") {
    FixedPoint<> a = 5.5;
    auto b = a - 2;
    REQUIRE(b.raw() == a.raw() - 2 * 4096);
    auto c = 10 - a;
    REQUIRE(c.raw() == 10 * 4096 - a.raw());
}

TEST_CASE("FixedPoint multiplication fp*fp") {
    FixedPoint<> a = 3.0;
    FixedPoint<> b = 4.0;
    auto c = a * b;
    REQUIRE(c.integer() == 12);

    FixedPoint<> d = 1.5;
    FixedPoint<> e = 2.0;
    auto f = d * e;
    REQUIRE(f.integer() == 3);
}

TEST_CASE("FixedPoint multiplication fp*int") {
    FixedPoint<> a = 2.5;
    auto b = a * 4;
    REQUIRE(b.integer() == 10);
    auto c = 4 * a;
    REQUIRE(c.integer() == 10);
}

TEST_CASE("FixedPoint division fp/fp") {
    FixedPoint<> a = 10.0;
    FixedPoint<> b = 2.0;
    auto c = a / b;
    REQUIRE(c.integer() == 5);
}

TEST_CASE("FixedPoint division fp/int") {
    FixedPoint<> a = 10.0;
    auto b = a / 4;
    REQUIRE(b.raw() == a.raw() / 4);
}

TEST_CASE("FixedPoint unary negation") {
    FixedPoint<> a = 5.0;
    auto b = -a;
    REQUIRE(b.raw() == -a.raw());
    REQUIRE((-b).raw() == a.raw());
}

TEST_CASE("FixedPoint abs()") {
    FixedPoint<> a = -5.0;
    REQUIRE(a.abs().raw() == FixedPoint<>(5.0).raw());
    FixedPoint<> b = 3.0;
    REQUIRE(b.abs().raw() == b.raw());
}

// --- Compound assignment ---

TEST_CASE("FixedPoint compound assignment operators") {
    FixedPoint<> a = 1.0;
    a += FixedPoint<>(2.0);
    REQUIRE(a.integer() == 3);
    a -= FixedPoint<>(1.0);
    REQUIRE(a.integer() == 2);
    a *= FixedPoint<>(3.0);
    REQUIRE(a.integer() == 6);
    a /= 2;
    REQUIRE(a.integer() == 3);
}

// --- Increment/Decrement ---

TEST_CASE("FixedPoint increment/decrement") {
    FixedPoint<> a = 5.0;
    ++a;
    REQUIRE(a.integer() == 6);
    a++;
    REQUIRE(a.integer() == 7);
    --a;
    REQUIRE(a.integer() == 6);
    a--;
    REQUIRE(a.integer() == 5);
}

// --- Comparisons ---

TEST_CASE("FixedPoint comparisons") {
    FixedPoint<> a = 1.0;
    FixedPoint<> b = 2.0;
    FixedPoint<> c = 1.0;
    REQUIRE(a < b);
    REQUIRE(b > a);
    REQUIRE(a == c);
    REQUIRE(a != b);
    REQUIRE(a <= c);
    REQUIRE(a >= c);
    REQUIRE(a <= b);
}

// --- Shifts ---

TEST_CASE("FixedPoint bit shifts") {
    FixedPoint<> a = 1.0;
    auto b = a << 1;
    REQUIRE(b.raw() == a.raw() * 2);
    auto c = b >> 1;
    REQUIRE(c.raw() == a.raw());
}

// --- Boolean ---

TEST_CASE("FixedPoint boolean not") {
    FixedPoint<> a;
    REQUIRE(!a);
    FixedPoint<> b = 1.0;
    REQUIRE_FALSE(!b);
}

// --- Precision conversion ---

TEST_CASE("FixedPoint precision conversion") {
    FixedPoint<12> a = 3.5;
    FixedPoint<8> b(a);
    // 12->8 precision: shift right by 4
    REQUIRE(b.raw() == (a.raw() >> 4));

    FixedPoint<8> c(128, FixedPoint<8>::RAW);  // ~0.5 at 8-bit
    FixedPoint<12> d(c);
    // 8->12 precision: shift left by 4
    REQUIRE(d.raw() == (c.raw() << 4));
}
