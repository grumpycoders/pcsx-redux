/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#pragma once
#include <stddef.h>
#include <stdint.h>

#include <charconv>
#include <compare>
#include <string_view>

#include "core/misc.h"

namespace PCSX {

namespace IEC60908b {

static inline constexpr uint8_t btoi(uint8_t b) { return ((b / 16) * 10) + (b % 16); }
static inline constexpr uint8_t itob(uint8_t i) { return ((i / 10) * 16) + (i % 10); }

struct MSF {
    MSF() : m(0), s(0), f(0) {}
    MSF(uint8_t m, uint8_t s, uint8_t f) : m(m), s(s), f(f) {}
    explicit MSF(uint32_t lba) {
        m = lba / 75 / 60;
        lba = lba - m * 75 * 60;
        s = lba / 75;
        lba = lba - s * 75;
        f = lba;
    }
    explicit MSF(std::string_view msf) {
        m = s = f = 0;
        auto tokens = Misc::split(msf, ":");
        auto conv = [&tokens](int index) -> uint8_t {
            if (index >= tokens.size()) return 0;
            auto &sv = tokens[index];
            uint8_t r;
            auto result = std::from_chars(sv.data(), sv.data() + sv.size(), r);
            if (result.ec == std::errc::invalid_argument) return 0;
            return r;
        };
        m = conv(0);
        s = conv(1);
        f = conv(2);
    }
    auto operator<=>(const MSF &other) const {
        if (m != other.m) return m <=> other.m;
        if (s != other.s) return s <=> other.s;
        return f <=> other.f;
    }
    bool operator==(const MSF &other) const { return m == other.m && s == other.s && f == other.f; }
    MSF &operator++() {
        f++;
        if (f >= 75) {
            f = 0;
            s++;
            if (s >= 60) {
                s = 0;
                m++;
            }
        }
        return *this;
    }
    MSF operator++(int) {
        MSF tmp = *this;
        ++(*this);
        return tmp;
    }
    uint32_t toLBA() const { return (m * 60 + s) * 75 + f; }
    void toBCD(uint8_t *dst) const {
        dst[0] = itob(m);
        dst[1] = itob(s);
        dst[2] = itob(f);
    }
    void fromBCD(const uint8_t *src) {
        m = btoi(src[0]);
        s = btoi(src[1]);
        f = btoi(src[2]);
    }
    void reset() { m = s = f = 0; }
    union {
        struct {
            uint8_t m;
            uint8_t s;
            uint8_t f;
            uint8_t pad;
        };
        uint8_t data[4];
    };
};

// Write ECC P and Q codes for a sector
void computeECC(const uint8_t *address, const uint8_t *data, uint8_t *ecc);
// Compute EDC for a block
uint32_t computeEDC(uint32_t edc, const uint8_t *src, size_t size);

}  // namespace IEC60908b
}  // namespace PCSX

template <>
struct fmt::formatter<PCSX::IEC60908b::MSF> {
    template <typename ParseContext>
    constexpr auto parse(ParseContext &ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(PCSX::IEC60908b::MSF const &msf, FormatContext &ctx) {
        return fmt::format_to(ctx.out(), "{0}:{1}:{2}", msf.m, msf.s, msf.f);
    }
};
