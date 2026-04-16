#include "psyqo/vector.hh"

#include "snitch_all.hpp"

using namespace psyqo;

// --- Size assertions ---

TEST_CASE("Vector size assertions") {
    REQUIRE(sizeof(Vec2) == 8);
    REQUIRE(sizeof(Vec3) == 12);
    REQUIRE(sizeof(Vec4) == 16);
}

// --- Construction and access ---

TEST_CASE("Vec3 element access") {
    Vec3 v;
    v.x = 1.0;
    v.y = 2.0;
    v.z = 3.0;
    REQUIRE(v.get(0).raw() == v.x.raw());
    REQUIRE(v.get(1).raw() == v.y.raw());
    REQUIRE(v.get(2).raw() == v.z.raw());
    REQUIRE(v[0].raw() == v.x.raw());
}

// --- Static factories ---

TEST_CASE("Vec3 ZERO factory") {
    auto z = Vec3::ZERO();
    REQUIRE(z.x.raw() == 0);
    REQUIRE(z.y.raw() == 0);
    REQUIRE(z.z.raw() == 0);
}

TEST_CASE("Vec3 ONE factory") {
    auto o = Vec3::ONE();
    REQUIRE(o.x.integer() == 1);
    REQUIRE(o.y.integer() == 1);
    REQUIRE(o.z.integer() == 1);
}

TEST_CASE("Vec3 directional factories") {
    auto up = Vec3::UP();
    REQUIRE(up.x.raw() == 0);
    REQUIRE(up.y.integer() == 1);
    REQUIRE(up.z.raw() == 0);

    auto right = Vec3::RIGHT();
    REQUIRE(right.x.integer() == 1);
    REQUIRE(right.y.raw() == 0);
    REQUIRE(right.z.raw() == 0);

    auto fwd = Vec3::FORWARD();
    REQUIRE(fwd.x.raw() == 0);
    REQUIRE(fwd.y.raw() == 0);
    REQUIRE(fwd.z.integer() == 1);

    auto down = Vec3::DOWN();
    REQUIRE(down.y.integer() == -1);

    auto left = Vec3::LEFT();
    REQUIRE(left.x.integer() == -1);

    auto back = Vec3::BACKWARD();
    REQUIRE(back.z.integer() == -1);
}

// --- Arithmetic ---

TEST_CASE("Vec3 addition") {
    Vec3 a;
    a.x = 1.0; a.y = 2.0; a.z = 3.0;
    Vec3 b;
    b.x = 4.0; b.y = 5.0; b.z = 6.0;
    auto c = a + b;
    REQUIRE(c.x.integer() == 5);
    REQUIRE(c.y.integer() == 7);
    REQUIRE(c.z.integer() == 9);
}

TEST_CASE("Vec3 subtraction") {
    Vec3 a;
    a.x = 10.0; a.y = 20.0; a.z = 30.0;
    Vec3 b;
    b.x = 3.0; b.y = 7.0; b.z = 11.0;
    auto c = a - b;
    REQUIRE(c.x.integer() == 7);
    REQUIRE(c.y.integer() == 13);
    REQUIRE(c.z.integer() == 19);
}

TEST_CASE("Vec3 scalar multiplication") {
    Vec3 a;
    a.x = 2.0; a.y = 3.0; a.z = 4.0;
    auto b = a * 3;
    REQUIRE(b.x.integer() == 6);
    REQUIRE(b.y.integer() == 9);
    REQUIRE(b.z.integer() == 12);
}

TEST_CASE("Vec3 FixedPoint multiplication") {
    Vec3 a;
    a.x = 2.0; a.y = 4.0; a.z = 6.0;
    FixedPoint<> half = 0.5;
    auto b = a * half;
    REQUIRE(b.x.integer() == 1);
    REQUIRE(b.y.integer() == 2);
    REQUIRE(b.z.integer() == 3);
}

TEST_CASE("Vec3 scalar division") {
    Vec3 a;
    a.x = 6.0; a.y = 9.0; a.z = 12.0;
    auto b = a / 3;
    REQUIRE(b.x.integer() == 2);
    REQUIRE(b.y.integer() == 3);
    REQUIRE(b.z.integer() == 4);
}

TEST_CASE("Vec3 negation") {
    Vec3 a;
    a.x = 1.0; a.y = -2.0; a.z = 3.0;
    auto b = -a;
    REQUIRE(b.x.integer() == -1);
    REQUIRE(b.y.integer() == 2);
    REQUIRE(b.z.integer() == -3);
}

// --- Compound assignment ---

TEST_CASE("Vec3 compound assignment") {
    Vec3 a;
    a.x = 1.0; a.y = 2.0; a.z = 3.0;
    Vec3 b;
    b.x = 1.0; b.y = 1.0; b.z = 1.0;
    a += b;
    REQUIRE(a.x.integer() == 2);
    REQUIRE(a.y.integer() == 3);
    REQUIRE(a.z.integer() == 4);
    a -= b;
    REQUIRE(a.x.integer() == 1);
    REQUIRE(a.y.integer() == 2);
    REQUIRE(a.z.integer() == 3);
    a *= 2;
    REQUIRE(a.x.integer() == 2);
    REQUIRE(a.y.integer() == 4);
    REQUIRE(a.z.integer() == 6);
    a /= 2;
    REQUIRE(a.x.integer() == 1);
    REQUIRE(a.y.integer() == 2);
    REQUIRE(a.z.integer() == 3);
}

// --- Vec2 conversion to Vertex ---

TEST_CASE("Vec2 to Vertex conversion") {
    Vec2 v;
    v.x = 100.0;
    v.y = 200.0;
    Vertex vtx = v;
    REQUIRE(vtx.x == 100);
    REQUIRE(vtx.y == 200);
}
