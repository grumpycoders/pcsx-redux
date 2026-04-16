#include "psyqo/primitives/common.hh"

#include "snitch_all.hpp"

using namespace psyqo;

// --- Vertex ---

TEST_CASE("Vertex size is 32 bits") {
    REQUIRE(sizeof(Vertex) == 4);
}

TEST_CASE("Vertex field aliases share memory") {
    Vertex v;
    v.x = 42;
    REQUIRE(v.u == 42);
    REQUIRE(v.s == 42);
    REQUIRE(v.w == 42);
    v.y = 99;
    REQUIRE(v.v == 99);
    REQUIRE(v.t == 99);
    REQUIRE(v.h == 99);
}

TEST_CASE("Vertex packed representation") {
    Vertex v;
    v.x = 0x1234;
    v.y = 0x5678;
    // Little-endian MIPS: x in low 16 bits, y in high 16 bits
    REQUIRE(v.packed == 0x56781234u);
}

// --- Rect ---

TEST_CASE("Rect size is 64 bits") {
    REQUIRE(sizeof(Rect) == 8);
}

TEST_CASE("Rect isEmpty") {
    Rect r;
    r.pos.x = 10;
    r.pos.y = 20;
    r.size.w = 0;
    r.size.h = 0;
    REQUIRE(r.isEmpty());

    r.size.w = 100;
    REQUIRE_FALSE(r.isEmpty());
}

TEST_CASE("Rect alias accessors") {
    Rect r;
    r.a.x = 10;
    REQUIRE(r.pos.x == 10);
    r.b.y = 20;
    REQUIRE(r.size.h == 20);
}

// --- Color ---

TEST_CASE("Color size is 32 bits") {
    REQUIRE(sizeof(Color) == 4);
}

TEST_CASE("Color channel ordering") {
    Color c;
    c.r = 0x11;
    c.g = 0x22;
    c.b = 0x33;
    c.user = 0x00;
    // Little-endian: r is lowest byte
    REQUIRE(c.packed == 0x00332211u);
}

TEST_CASE("Color packed to channels") {
    Color c;
    c.packed = 0x00ff8040u;
    REQUIRE(c.r == 0x40);
    REQUIRE(c.g == 0x80);
    REQUIRE(c.b == 0xff);
    REQUIRE(c.user == 0x00);
}
