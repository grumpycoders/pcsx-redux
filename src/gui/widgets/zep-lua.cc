/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include "gui/widgets/zep-lua.h"

static std::unordered_set<std::string> lua_keywords = {
    "and",   "break", "do",  "else", "elseif", "end",    "false", "for",  "function", "if",    "in",
    "local", "nil",   "not", "or",   "repeat", "return", "then",  "true", "until",    "while",
};

static std::unordered_set<std::string> lua_identifiers = {
    "assert",       "collectgarbage",
    "dofile",       "error",
    "getmetatable", "ipairs",
    "loadfile",     "load",
    "loadstring",   "next",
    "pairs",        "pcall",
    "print",        "rawequal",
    "rawlen",       "rawget",
    "rawset",       "select",
    "setmetatable", "tonumber",
    "tostring",     "type",
    "xpcall",       "_G",
    "_VERSION",     "arshift",
    "band",         "bnot",
    "bor",          "bxor",
    "btest",        "extract",
    "lrotate",      "lshift",
    "replace",      "rrotate",
    "rshift",       "create",
    "resume",       "running",
    "status",       "wrap",
    "yield",        "isyieldable",
    "debug",        "getuservalue",
    "gethook",      "getinfo",
    "getlocal",     "getregistry",
    "getmetatable", "getupvalue",
    "upvaluejoin",  "upvalueid",
    "setuservalue", "sethook",
    "setlocal",     "setmetatable",
    "setupvalue",   "traceback",
    "close",        "flush",
    "input",        "lines",
    "open",         "output",
    "popen",        "read",
    "tmpfile",      "type",
    "write",        "close",
    "flush",        "lines",
    "read",         "seek",
    "setvbuf",      "write",
    "__gc",         "__tostring",
    "abs",          "acos",
    "asin",         "atan",
    "ceil",         "cos",
    "deg",          "exp",
    "tointeger",    "floor",
    "fmod",         "ult",
    "log",          "max",
    "min",          "modf",
    "rad",          "random",
    "randomseed",   "sin",
    "sqrt",         "string",
    "tan",          "type",
    "atan2",        "cosh",
    "sinh",         "tanh",
    "pow",          "frexp",
    "ldexp",        "log10",
    "pi",           "huge",
    "maxinteger",   "mininteger",
    "loadlib",      "searchpath",
    "seeall",       "preload",
    "cpath",        "path",
    "searchers",    "loaded",
    "module",       "require",
    "clock",        "date",
    "difftime",     "execute",
    "exit",         "getenv",
    "remove",       "rename",
    "setlocale",    "time",
    "tmpname",      "byte",
    "char",         "dump",
    "find",         "format",
    "gmatch",       "gsub",
    "len",          "lower",
    "match",        "rep",
    "reverse",      "sub",
    "upper",        "pack",
    "packsize",     "unpack",
    "concat",       "maxn",
    "insert",       "pack",
    "unpack",       "remove",
    "move",         "sort",
    "offset",       "codepoint",
    "char",         "len",
    "codes",        "charpattern",
    "coroutine",    "table",
    "io",           "os",
    "string",       "uint8_t",
    "bit32",        "math",
    "debug",        "package",
};

PCSX::Widgets::ZepSyntax_Lua::ZepSyntax_Lua(Zep::ZepBuffer& buffer)
    : ZepSyntax(buffer, lua_keywords, lua_identifiers) {}

void PCSX::Widgets::ZepSyntax_Lua::UpdateSyntax() {
    auto& buffer = m_buffer.GetWorkingBuffer();
    auto itrCurrent = buffer.begin();
    auto itrEnd = buffer.begin() + m_targetChar;

    assert(std::distance(itrCurrent, itrEnd) < int(m_syntax.size()));
    assert(m_syntax.size() == buffer.size());

    static const std::string delim(" \t+-*/&|^!=~%#$<>@,\n;(){}[]=:");
    static const std::string lineEnd("\n");
    static const std::string whiteSpace(" \t");
    static const std::string delimWithDot = delim + ".";

    itrEnd = buffer.find_first_of(itrEnd, buffer.end(), lineEnd.begin(), lineEnd.end());

    // Mark a region of the syntax buffer with the correct marker
    auto mark = [&](GapBuffer<uint8_t>::const_iterator itrA, GapBuffer<uint8_t>::const_iterator itrB,
                    Zep::ThemeColor type, Zep::ThemeColor background) {
        std::fill(m_syntax.begin() + (itrA - buffer.begin()), m_syntax.begin() + (itrB - buffer.begin()),
                  Zep::SyntaxData{type, background});
    };

    auto markSingle = [&](GapBuffer<uint8_t>::const_iterator itrA, Zep::ThemeColor type, Zep::ThemeColor background) {
        (m_syntax.begin() + (itrA - buffer.begin()))->foreground = type;
        (m_syntax.begin() + (itrA - buffer.begin()))->background = background;
    };

    // Update start location
    m_processedChar = long(itrCurrent - buffer.begin());

    // Walk the buffer updating information about syntax coloring
    while (itrCurrent < itrEnd) {
        if (m_stop == true) {
            return;
        }

        auto ch = *itrCurrent;
        if (lineEnd.find_first_of(ch) != std::string::npos || ch == 0) {
            itrCurrent++;
            continue;
        }

        if (whiteSpace.find_first_of(ch) != std::string::npos) {
            mark(itrCurrent, itrCurrent + 1, Zep::ThemeColor::Whitespace, Zep::ThemeColor::None);
            itrCurrent++;
            continue;
        }

        auto itrFirst = itrCurrent;
        auto itrLast = buffer.find_first_of(itrFirst, buffer.end(), lineEnd.begin(), lineEnd.end());

        // comments & multiline strings and comments
        auto getFurther = [&](unsigned inc) -> decltype(ch) {
            auto itr = itrCurrent + inc;
            return itr < buffer.end() ? *itr : '\n';
        };
        auto isMultilineString = [&](unsigned inc) -> int {
            auto ch = getFurther(inc++);
            if (ch != '[') return -1;
            int ret = 0;
            while (true) {
                ch = getFurther(inc++);
                switch (ch) {
                    case '[':
                        return ret;
                        break;
                    case '=':
                        ret++;
                        break;
                    default:
                        return -1;
                        break;
                }
            }
        };
        std::function<int(unsigned, int, bool)> findEndMultiline = [&](unsigned inc, int level, bool isComment) -> int {
            if (isComment) {
                while ((inc + itrCurrent) < buffer.end()) {
                    auto ch = getFurther(inc++);
                    if (ch == '-' && (getFurther(inc) == '-')) {
                        inc++;
                        break;
                    }
                }
            }
            while ((inc + itrCurrent) < buffer.end()) {
                auto ch = getFurther(inc++);
                if (ch == ']') {
                    for (unsigned c = 0; c < level; c++) {
                        ch = getFurther(inc++);
                        if (ch != '=') return findEndMultiline(inc, level, isComment);
                    }
                    ch = getFurther(inc++);
                    if (ch != ']') return findEndMultiline(inc, level, isComment);
                    return inc - 1;
                }
            }
            return -1;
        };
        switch (ch) {
            case '-': {
                if (getFurther(1) == '-') {
                    auto mlc = isMultilineString(2);
                    if (mlc < 0) {
                        mark(itrCurrent, itrLast, Zep::ThemeColor::Comment, Zep::ThemeColor::None);
                        itrCurrent = itrLast + 1;
                        continue;
                    }
                    auto mlcEnd = findEndMultiline(4 + mlc, mlc, true);
                    if (mlcEnd >= 0) {
                        mark(itrCurrent, itrCurrent + mlcEnd, Zep::ThemeColor::Comment, Zep::ThemeColor::None);
                        itrCurrent += mlcEnd + 1;
                        continue;
                    }
                }
            } break;
            case '[': {
                auto mls = isMultilineString(0);
                if (mls < 0) break;
                auto mlsEnd = findEndMultiline(2 + mls, mls, true);
                if (mlsEnd >= 0) {
                    mark(itrCurrent, itrCurrent + mlsEnd, Zep::ThemeColor::String, Zep::ThemeColor::None);
                    itrCurrent += mlsEnd + 1;
                    continue;
                }
            } break;
        }

        static const std::string parenthesis("{}[]()");
        if (parenthesis.find_first_of(ch) != std::string::npos) {
            mark(itrCurrent, itrCurrent + 1, Zep::ThemeColor::Parenthesis, Zep::ThemeColor::None);
            itrCurrent++;
            continue;
        }

        // Find String
        auto findString = [&](uint8_t ch) -> bool {
            auto itrString = itrFirst;
            if (*itrString == ch) {
                itrString++;

                while (itrString < buffer.end()) {
                    // handle end of string
                    if (*itrString == ch) {
                        itrString++;
                        mark(itrFirst, itrString, Zep::ThemeColor::String, Zep::ThemeColor::None);
                        itrLast = itrString + 1;
                        return true;
                        break;
                    }

                    if (itrString < (buffer.end() - 1)) {
                        auto itrNext = itrString + 1;
                        // Ignore quoted
                        if (*itrString == '\\' && *itrNext == ch) {
                            itrString++;
                        }
                    }

                    itrString++;
                }
            }
            return false;
        };
        if (findString('\"')) {
            itrCurrent = itrLast + 1;
            continue;
        }
        if (findString('\'')) {
            itrCurrent = itrLast + 1;
            continue;
        }

        // Find a token, skipping delim <itrFirst, itrLast>
        itrFirst = buffer.find_first_not_of(itrCurrent, buffer.end(), delimWithDot.begin(), delimWithDot.end());
        if (itrFirst == buffer.end()) break;

        itrLast = buffer.find_first_of(itrFirst, buffer.end(), delimWithDot.begin(), delimWithDot.end());

        // Ensure we found a token
        assert(itrLast >= itrFirst);

        // Do I need to make a string here?
        auto token = std::string(itrFirst, itrLast);

        if (m_keywords.find(token) != m_keywords.end()) {
            mark(itrFirst, itrLast, Zep::ThemeColor::Keyword, Zep::ThemeColor::None);
        } else if (m_identifiers.find(token) != m_identifiers.end()) {
            mark(itrFirst, itrLast, Zep::ThemeColor::Identifier, Zep::ThemeColor::None);
        } else {
            mark(itrFirst, itrLast, Zep::ThemeColor::Normal, Zep::ThemeColor::None);
        }

        // Find numbers - very crude, but better than nothing
        // won't handle exponent numbers, nor C++17's hexadecimal floating points
        auto maybeParseHexa = [&](decltype(itrFirst) itr, decltype(itrFirst)& last) -> bool {
            auto first = itr;
            static const std::string hexa("0123456789abcdefABCDEF");
            while (itr < buffer.end()) {
                auto ch = *itr;
                if (delim.find_first_of(ch) != std::string::npos) {
                    break;
                }
                if (hexa.find_first_of(ch) == std::string::npos) {
                    return false;
                }
                itr++;
            }

            last = itr;
            return itr != first;
        };
        auto maybeParseOctal = [&](decltype(itrFirst) itr, decltype(itrFirst)& last) -> bool {
            auto first = itr;
            static const std::string octal("01234567");
            while (itr < buffer.end()) {
                auto ch = *itr;
                if (delim.find_first_of(ch) != std::string::npos) {
                    break;
                }
                if (octal.find_first_of(ch) == std::string::npos) {
                    return false;
                }
                itr++;
            }

            last = itr;
            return itr != first;
        };
        auto maybeParseFloat = [&](decltype(itrFirst) itr, decltype(itrFirst)& last) -> bool {
            auto first = itr;
            static const std::string numbers("0123456789");
            bool gotDot = false;
            bool gotF = false;
            bool gotSomething = false;
            while (itr < buffer.end()) {
                auto ch = *itr;
                if (delim.find_first_of(ch) != std::string::npos) {
                    break;
                } else if (gotF) {
                    return false;
                }
                if (ch == '.') {
                    if (!gotDot) {
                        gotDot = true;
                    } else {
                        return false;
                    }
                } else if (ch == 'f' && !gotF) {
                    gotF = true;
                } else if (numbers.find_first_of(ch) != std::string::npos) {
                    gotSomething = true;
                } else {
                    return false;
                }
                itr++;
            }

            last = itr;
            return itr != first && gotSomething;
        };
        if (std::isdigit(*itrFirst) || *itrFirst == '.') {
            auto itrNum = itrFirst;
            auto last = itrFirst;
            bool parsed = false;
            if (*itrFirst == '0') {
                itrNum++;
                switch (*itrNum) {
                    case 'x':
                        parsed = maybeParseHexa(itrFirst + 2, last);
                        break;
                    case '.':
                        parsed = maybeParseFloat(itrFirst, last);
                        break;
                    default:
                        parsed = maybeParseOctal(itrFirst, last);
                        break;
                }
            } else {
                parsed = maybeParseFloat(itrFirst, last);
            }

            if (parsed) {
                itrLast = last;
                mark(itrFirst, itrLast, Zep::ThemeColor::Number, Zep::ThemeColor::None);
            }
        }

        itrCurrent = itrLast;
    }

    // If we got here, we sucessfully completed
    // Reset the target to the beginning
    m_targetChar = long(0);
    m_processedChar = long(buffer.size() - 1);
}

void PCSX::Widgets::ZepSyntax_Lua::registerSyntax(std::unique_ptr<Zep::ZepEditor>& editor) {
    editor->RegisterSyntaxFactory({".lua"}, Zep::SyntaxProvider{"Lua", tSyntaxFactory([](Zep::ZepBuffer* pBuffer) {
                                                                    return std::make_shared<ZepSyntax_Lua>(*pBuffer);
                                                                })});
}
