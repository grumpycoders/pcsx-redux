/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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
static inline bool endsWith(const std::string &s1, const std::string_view &s2) {
    return (s1.size() >= s2.size()) && (s1.find(s2, s1.size() - s2.size()) == s1.size() - s2.size());
}
static inline bool endsWith(const std::string_view &s1, const std::string_view &s2) {
    return (s1.size() >= s2.size()) && (s1.find(s2, s1.size() - s2.size()) == s1.size() - s2.size());
}

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
