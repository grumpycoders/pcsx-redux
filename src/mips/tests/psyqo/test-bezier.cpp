#include "psyqo/bezier.hh"

#include "snitch_all.hpp"

using namespace psyqo;
using namespace psyqo::fixed_point_literals;

// --- Endpoint interpolation ---

TEST_CASE("Bezier cubic at t=0 returns start point") {
    Vec2 a, b, c, d;
    a.x = 0.0; a.y = 0.0;
    b.x = 1.0; b.y = 2.0;
    c.x = 3.0; c.y = 4.0;
    d.x = 5.0; d.y = 6.0;
    auto p = Bezier::cubic(a, b, c, d, 0.0_fp);
    REQUIRE(p.x.raw() == a.x.raw());
    REQUIRE(p.y.raw() == a.y.raw());
}

TEST_CASE("Bezier cubic at t=1 returns end point") {
    Vec2 a, b, c, d;
    a.x = 0.0; a.y = 0.0;
    b.x = 1.0; b.y = 2.0;
    c.x = 3.0; c.y = 4.0;
    d.x = 5.0; d.y = 6.0;
    auto p = Bezier::cubic(a, b, c, d, 1.0_fp);
    auto dx = p.x.raw() - d.x.raw();
    auto dy = p.y.raw() - d.y.raw();
    REQUIRE(dx >= -5);
    REQUIRE(dx <= 5);
    REQUIRE(dy >= -5);
    REQUIRE(dy <= 5);
}

// --- Linear case ---

TEST_CASE("Bezier cubic with collinear control points is linear") {
    Vec2 a, b, c, d;
    a.x = 0.0; a.y = 0.0;
    b.x = 1.0; b.y = 1.0;
    c.x = 2.0; c.y = 2.0;
    d.x = 3.0; d.y = 3.0;
    auto mid = Bezier::cubic(a, b, c, d, 0.5_fp);
    auto diff_x = mid.x.raw() - FixedPoint<>(1.5).raw();
    auto diff_y = mid.y.raw() - FixedPoint<>(1.5).raw();
    REQUIRE(diff_x >= -5);
    REQUIRE(diff_x <= 5);
    REQUIRE(diff_y >= -5);
    REQUIRE(diff_y <= 5);
}

// --- 3D variant ---

TEST_CASE("Bezier 3D cubic at t=0 returns start") {
    Vec3 a, b, c, d;
    a.x = 1.0; a.y = 2.0; a.z = 3.0;
    b.x = 4.0; b.y = 5.0; b.z = 6.0;
    c.x = 7.0; c.y = 8.0; c.z = 9.0;
    d.x = 10.0; d.y = 11.0; d.z = 12.0;
    auto p = Bezier::cubic(a, b, c, d, 0.0_fp);
    REQUIRE(p.x.raw() == a.x.raw());
    REQUIRE(p.y.raw() == a.y.raw());
    REQUIRE(p.z.raw() == a.z.raw());
}

TEST_CASE("Bezier 3D cubic at t=1 returns end") {
    Vec3 a, b, c, d;
    a.x = 1.0; a.y = 2.0; a.z = 3.0;
    b.x = 4.0; b.y = 5.0; b.z = 6.0;
    c.x = 7.0; c.y = 8.0; c.z = 9.0;
    d.x = 10.0; d.y = 11.0; d.z = 12.0;
    auto p = Bezier::cubic(a, b, c, d, 1.0_fp);
    auto dx = p.x.raw() - d.x.raw();
    auto dy = p.y.raw() - d.y.raw();
    auto dz = p.z.raw() - d.z.raw();
    REQUIRE(dx >= -5);
    REQUIRE(dx <= 5);
    REQUIRE(dy >= -5);
    REQUIRE(dy <= 5);
    REQUIRE(dz >= -5);
    REQUIRE(dz <= 5);
}

// --- Midpoint with symmetric curve ---

TEST_CASE("Bezier symmetric curve midpoint") {
    // Symmetric curve: a=(0,0), b=(0,1), c=(1,1), d=(1,0)
    // At t=0.5, the midpoint should be approximately (0.5, 0.75)
    Vec2 a, b, c, d;
    a.x = 0.0; a.y = 0.0;
    b.x = 0.0; b.y = 1.0;
    c.x = 1.0; c.y = 1.0;
    d.x = 1.0; d.y = 0.0;
    auto mid = Bezier::cubic(a, b, c, d, 0.5_fp);
    auto dx = mid.x.raw() - FixedPoint<>(0.5).raw();
    auto dy = mid.y.raw() - FixedPoint<>(0.75).raw();
    REQUIRE(dx >= -10);
    REQUIRE(dx <= 10);
    REQUIRE(dy >= -10);
    REQUIRE(dy <= 10);
}
