#include "psyqo/trigonometry.hh"

#include "snitch_all.hpp"

using namespace psyqo;
using namespace psyqo::trig_literals;

static Trig<> trig;

// --- Cosine at key angles ---

TEST_CASE("cos(0) = 1") {
    auto c = trig.cos(0.0_pi);
    REQUIRE(c.raw() == (1 << 12));
}

TEST_CASE("cos(pi/2) = 0") {
    auto c = trig.cos(0.5_pi);
    REQUIRE(c.raw() == 0);
}

TEST_CASE("cos(pi) = -1") {
    auto c = trig.cos(1.0_pi);
    // Table index is pi-1, negated. Should be close to -4096.
    auto diff = c.raw() - (-(1 << 12));
    REQUIRE(diff >= -2);
    REQUIRE(diff <= 2);
}

TEST_CASE("cos(3pi/2) = 0") {
    auto c = trig.cos(1.5_pi);
    // Symmetric to pi/2 via table[2pi-1-t]
    auto diff = c.raw();
    REQUIRE(diff >= -2);
    REQUIRE(diff <= 2);
}

// --- Sine at key angles ---

TEST_CASE("sin(0) = 0") {
    auto s = trig.sin(0.0_pi);
    // sin(0) = cos(-pi/2) = cos(3pi/2) due to unsigned modular arithmetic
    auto diff = s.raw();
    REQUIRE(diff >= -2);
    REQUIRE(diff <= 2);
}

TEST_CASE("sin(pi/2) = 1") {
    auto s = trig.sin(0.5_pi);
    // sin(pi/2) = cos(0) = 1
    REQUIRE(s.raw() == (1 << 12));
}

TEST_CASE("sin(pi) close to 0") {
    auto s = trig.sin(1.0_pi);
    auto diff = s.raw();
    REQUIRE(diff >= -2);
    REQUIRE(diff <= 2);
}

// --- Symmetry properties ---

TEST_CASE("sin/cos Pythagorean identity") {
    // sin^2(x) + cos^2(x) should be close to 1 for various angles
    Angle angles[] = {0.0_pi, 0.25_pi, 0.5_pi, 0.75_pi, 1.0_pi, 1.25_pi, 1.5_pi, 1.75_pi};
    for (auto a : angles) {
        auto s = trig.sin(a);
        auto c = trig.cos(a);
        auto sum = s * s + c * c;
        // 1.0 in 20.12 = 4096. Allow ~1% error for fixed-point accumulation.
        auto diff = sum.raw() - (1 << 12);
        REQUIRE(diff >= -50);
        REQUIRE(diff <= 50);
    }
}

TEST_CASE("cos is even: cos(-x) = cos(x)") {
    // Due to unsigned modular, -x mod 2pi = 2pi - x
    // cos(0.3pi) should equal cos(2pi - 0.3pi) = cos(1.7pi)
    // Different quadrant paths through the Chebyshev table
    // accumulate different error, so allow tolerance.
    auto a = trig.cos(0.3_pi);
    auto b = trig.cos(1.7_pi);
    auto diff = a.raw() - b.raw();
    REQUIRE(diff >= -15);
    REQUIRE(diff <= 15);
}

TEST_CASE("sin is odd: sin(2pi - x) = -sin(x)") {
    auto a = trig.sin(0.3_pi);
    auto b = trig.sin(1.7_pi);
    auto sum = a.raw() + b.raw();
    REQUIRE(sum >= -15);
    REQUIRE(sum <= 15);
}

// --- Angle literal ---

TEST_CASE("Angle literal _pi") {
    Angle a = 1.0_pi;
    REQUIRE(a.raw() == 1024);
    Angle b = 0.5_pi;
    REQUIRE(b.raw() == 512);
    Angle c = 2.0_pi;
    REQUIRE(c.raw() == 2048);
}
