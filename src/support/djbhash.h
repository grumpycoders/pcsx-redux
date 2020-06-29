/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include <stdint.h>

#include <string>

namespace PCSX {

struct djbHash {
  private:
    static inline constexpr uint64_t djbProcess(uint64_t hash, const char str[], size_t n) {
        return n ? djbProcess(((hash << 5) + hash) ^ str[0], str + 1, n - 1) : hash;
    }

  public:
    template <size_t S>
    static inline constexpr uint64_t ctHash(const char (&str)[S]) {
        return djbProcess(5381, str, S - 1);
    }
    static inline constexpr uint64_t hash(const char *str, size_t n) { return djbProcess(5381, str, n); }
    static inline uint64_t hash(const std::string &str) { return djbProcess(5381, str.c_str(), str.length()); }
};

}  // namespace PCSX
