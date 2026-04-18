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

#include "psyqo/msf.hh"

#include "snitch_all.hpp"

using namespace psyqo;

// --- BCD conversion ---

TEST_CASE("btoi/itob round-trip") {
    for (uint8_t i = 0; i < 100; i++) {
        REQUIRE(btoi(itob(i)) == i);
    }
}

TEST_CASE("btoi known values") {
    REQUIRE(btoi(0x00) == 0);
    REQUIRE(btoi(0x09) == 9);
    REQUIRE(btoi(0x10) == 10);
    REQUIRE(btoi(0x59) == 59);
    REQUIRE(btoi(0x99) == 99);
}

TEST_CASE("itob known values") {
    REQUIRE(itob(0) == 0x00);
    REQUIRE(itob(9) == 0x09);
    REQUIRE(itob(10) == 0x10);
    REQUIRE(itob(59) == 0x59);
    REQUIRE(itob(99) == 0x99);
}

// --- MSF construction ---

TEST_CASE("MSF default construction is zero") {
    MSF msf;
    REQUIRE(msf.m == 0);
    REQUIRE(msf.s == 0);
    REQUIRE(msf.f == 0);
}

TEST_CASE("MSF component construction") {
    MSF msf(1, 30, 37);
    REQUIRE(msf.m == 1);
    REQUIRE(msf.s == 30);
    REQUIRE(msf.f == 37);
}

// --- LBA conversion ---

TEST_CASE("MSF toLBA at zero") {
    MSF msf(0, 0, 0);
    REQUIRE(msf.toLBA() == 0);
}

TEST_CASE("MSF toLBA at 1 second") {
    MSF msf(0, 1, 0);
    REQUIRE(msf.toLBA() == 75);
}

TEST_CASE("MSF toLBA at 1 minute") {
    MSF msf(1, 0, 0);
    REQUIRE(msf.toLBA() == 4500);
}

TEST_CASE("MSF toLBA at 1:30:0") {
    MSF msf(1, 30, 0);
    REQUIRE(msf.toLBA() == 6750);
}

TEST_CASE("MSF from LBA construction") {
    MSF msf(75u);
    REQUIRE(msf.m == 0);
    REQUIRE(msf.s == 1);
    REQUIRE(msf.f == 0);

    MSF msf2(4500u);
    REQUIRE(msf2.m == 1);
    REQUIRE(msf2.s == 0);
    REQUIRE(msf2.f == 0);
}

TEST_CASE("MSF LBA round-trip") {
    uint32_t lbas[] = {0, 1, 74, 75, 150, 4499, 4500, 4501, 6750, 33750};
    for (auto lba : lbas) {
        MSF msf(lba);
        REQUIRE(msf.toLBA() == lba);
    }
}

// --- BCD serialization ---

TEST_CASE("MSF toBCD/fromBCD round-trip") {
    MSF orig(1, 30, 37);
    uint8_t bcd[3];
    orig.toBCD(bcd);

    MSF restored;
    restored.fromBCD(bcd);
    REQUIRE(restored.m == orig.m);
    REQUIRE(restored.s == orig.s);
    REQUIRE(restored.f == orig.f);
}

// --- Comparison ---

TEST_CASE("MSF equality") {
    MSF a(1, 2, 3);
    MSF b(1, 2, 3);
    REQUIRE(a == b);
}

TEST_CASE("MSF ordering via LBA") {
    MSF a(0, 0, 0);
    MSF b(0, 0, 1);
    MSF c(0, 1, 0);
    MSF d(1, 0, 0);
    REQUIRE(a.toLBA() < b.toLBA());
    REQUIRE(b.toLBA() < c.toLBA());
    REQUIRE(c.toLBA() < d.toLBA());
}

// --- Increment ---

TEST_CASE("MSF increment within frame") {
    MSF msf(0, 0, 0);
    ++msf;
    REQUIRE(msf.m == 0);
    REQUIRE(msf.s == 0);
    REQUIRE(msf.f == 1);
}

TEST_CASE("MSF increment frame overflow") {
    MSF msf(0, 0, 74);
    ++msf;
    REQUIRE(msf.m == 0);
    REQUIRE(msf.s == 1);
    REQUIRE(msf.f == 0);
}

TEST_CASE("MSF increment second overflow") {
    MSF msf(0, 59, 74);
    ++msf;
    REQUIRE(msf.m == 1);
    REQUIRE(msf.s == 0);
    REQUIRE(msf.f == 0);
}

TEST_CASE("MSF post-increment returns old value") {
    MSF msf(0, 0, 5);
    MSF old = msf++;
    REQUIRE(old.f == 5);
    REQUIRE(msf.f == 6);
}

// --- Reset ---

TEST_CASE("MSF reset") {
    MSF msf(5, 30, 42);
    msf.reset();
    REQUIRE(msf.m == 0);
    REQUIRE(msf.s == 0);
    REQUIRE(msf.f == 0);
}
