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

#include "support/sjis_conv.h"

#include "mips/common/util/sjis-table.h"

std::string PCSX::Sjis::toUtf8(const std::string_view& str) {
    std::string ret;
    constexpr unsigned tableSize = sizeof(c_sjisToUnicodeConvTable) / sizeof(c_sjisToUnicodeConvTable[0]);
    for (size_t i = 0; i < str.length(); i++) {
        uint8_t c = str[i];
        uint32_t index = 0;
        switch (c >> 4) {
            case 8:
                index = 0x100;
                break;
            case 9:
                index = 0x1100;
                break;
            case 14:
                index = 0x2100;
                break;
        }

        if (index != 0) {
            index += (c & 0x0f) << 8;
            i++;
            if (i >= str.length()) break;
            c = str[i];
        }

        index += c;

        if (index >= tableSize) continue;
        uint16_t v = c_sjisToUnicodeConvTable[index];
        if (v < 0x80) {
            ret += v;
        } else if (v < 0x800) {
            ret += 0xc0 | (v >> 6);
            ret += 0x80 | (v & 0x3f);
        } else {
            ret += 0xe0 | (v >> 12);
            ret += 0x80 | ((v & 0xfff) >> 6);
            ret += 0x80 | (v & 0x3f);
        }
    }

    return ret;
}
