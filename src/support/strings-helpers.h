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

#include <algorithm>
#include <cctype>
#include <functional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace PCSX {

namespace StringsHelpers {

static inline std::vector<std::string> split(const std::string &str, const std::string_view &delims,
                                             bool keepEmpty = false) {
    std::vector<std::string> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find_first_of(delims, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string token = str.substr(prev, pos - prev);
        if (keepEmpty || !token.empty()) tokens.emplace_back(std::move(token));
        prev = pos + 1;
    } while (pos < str.length() && prev <= str.length());
    return tokens;
}

static inline std::vector<std::string_view> split(const std::string_view &str, const std::string_view &delims,
                                                  bool keepEmpty = false) {
    std::vector<std::string_view> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find_first_of(delims, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string_view token = str.substr(prev, pos - prev);
        if (keepEmpty || !token.empty()) tokens.emplace_back(std::move(token));
        prev = pos + 1;
    } while (pos < str.length() && prev <= str.length());
    return tokens;
}

static inline bool startsWith(const std::string &s1, const std::string_view &s2) { return s1.rfind(s2, 0) == 0; }
static inline bool startsWith(const std::string_view &s1, const std::string_view &s2) { return s1.rfind(s2, 0) == 0; }

static inline bool strcasecmp(const std::string_view &lhs, const std::string_view &rhs) {
    return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(),
                      [](const char x, const char y) -> bool { return std::tolower(x) == std::tolower(y); });
}

static inline std::string_view trim(std::string_view str, const std::string_view &totrim = " ") {
    str.remove_prefix(std::min(str.find_first_not_of(totrim), str.size()));
    str.remove_suffix(str.size() - (str.find_last_not_of(totrim) + 1));
    return str;
}

static inline std::string_view trim(const std::string &str, const std::string_view &totrim = " ") {
    return trim(std::string_view(str), totrim);
}

}  // namespace StringsHelpers

}  // namespace PCSX
