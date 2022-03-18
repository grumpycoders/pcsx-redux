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
#include <string_view>

#include "core/misc.h"

namespace PCSX {

namespace IEC60908b {

struct MSF {
    MSF() : m(0), s(0), f(0) {}
    MSF(uint8_t m, uint8_t s, uint8_t f) : m(m), s(s), f(f) {}
    MSF(uint32_t lba) {
        m = lba / 75 / 60;
        lba = lba - m * 75 * 60;
        s = lba / 75;
        lba = lba - s * 75;
        f = lba;
    }
    MSF(std::string_view msf) {
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
    uint32_t toLBA() { return (m * 60 + s) * 75 + f; }
    uint8_t m, s, f;
};

// Write ECC P and Q codes for a sector
void computeECC(const uint8_t *address, const uint8_t *data, uint8_t *ecc);
// Compute EDC for a block
uint32_t computeEDC(uint32_t edc, const uint8_t *src, size_t size);

}  // namespace IEC60908b
}  // namespace PCSX
