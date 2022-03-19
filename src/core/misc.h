/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

#include <string>
#include <vector>

#include "core/coff.h"

#undef s_addr

typedef struct {
    unsigned char id[8];
    uint32_t text;
    uint32_t data;
    uint32_t pc0;
    uint32_t gp0;
    uint32_t t_addr;
    uint32_t t_size;
    uint32_t d_addr;
    uint32_t d_size;
    uint32_t b_addr;
    uint32_t b_size;
    uint32_t s_addr;
    uint32_t s_size;
    uint32_t SavedSP;
    uint32_t SavedFP;
    uint32_t SavedGP;
    uint32_t SavedRA;
    uint32_t SavedS0;
} EXE_HEADER;

void trim(char *str);
uint16_t calcCrc(uint8_t *d, int len);

namespace PCSX {

namespace Misc {

static inline std::vector<std::string> split(const std::string &str, const std::string_view delims,
                                             bool keepEmpty = false) {
    std::vector<std::string> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delims, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string token = str.substr(prev, pos - prev);
        if (keepEmpty || !token.empty()) tokens.emplace_back(std::move(token));
        prev = pos + delims.length();
    } while (pos < str.length() && prev <= str.length());
    return tokens;
}

static inline std::vector<std::string_view> split(std::string_view str, std::string_view delims,
                                                  bool keepEmpty = false) {
    std::vector<std::string_view> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delims, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string_view token = str.substr(prev, pos - prev);
        if (keepEmpty || !token.empty()) tokens.push_back(token);
        prev = pos + delims.length();
    } while (pos < str.length() && prev <= str.length());
    return tokens;
}

static inline bool startsWith(const std::string &s1, const std::string &s2) { return s1.rfind(s2, 0) == 0; }

}  // namespace Misc

}  // namespace PCSX
