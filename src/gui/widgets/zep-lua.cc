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
    auto itrCurrent = buffer.begin() + m_processedChar;
    auto itrEnd = buffer.begin() + m_targetChar;

    assert(std::distance(itrCurrent, itrEnd) < int(m_syntax.size()));
    assert(m_syntax.size() == buffer.size());

    std::string delim(" \t,.\n;(){}[]=:");
    std::string lineEnd("\n");

    // Walk backwards to previous delimiter
    while (itrCurrent > buffer.begin()) {
        if (std::find(delim.begin(), delim.end(), *itrCurrent) == delim.end()) {
            itrCurrent--;
        } else {
            break;
        }
    }

    // Back to the previous line
    while (itrCurrent > buffer.begin() && *itrCurrent != '\n') {
        itrCurrent--;
    }
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
    while (itrCurrent != itrEnd) {
        if (m_stop == true) {
            return;
        }

        // Find a token, skipping delim <itrFirst, itrLast>
        auto itrFirst = buffer.find_first_not_of(itrCurrent, buffer.end(), delim.begin(), delim.end());
        if (itrFirst == buffer.end()) break;

        auto itrLast = buffer.find_first_of(itrFirst, buffer.end(), delim.begin(), delim.end());

        // Ensure we found a token
        assert(itrLast >= itrFirst);

        // Mark whitespace
        for (auto& itr = itrCurrent; itr < itrFirst; itr++) {
            if (*itr == ' ') {
                mark(itr, itr + 1, Zep::ThemeColor::Whitespace, Zep::ThemeColor::None);
            } else if (*itr == '\t') {
                mark(itr, itr + 1, Zep::ThemeColor::Whitespace, Zep::ThemeColor::None);
            }
        }

        // Do I need to make a string here?
        auto token = std::string(itrFirst, itrLast);

        if (m_keywords.find(token) != m_keywords.end()) {
            mark(itrFirst, itrLast, Zep::ThemeColor::Keyword, Zep::ThemeColor::None);
        } else if (m_identifiers.find(token) != m_identifiers.end()) {
            mark(itrFirst, itrLast, Zep::ThemeColor::Identifier, Zep::ThemeColor::None);
        } else if (token.find_first_not_of("0123456789") == std::string::npos) {
            mark(itrFirst, itrLast, Zep::ThemeColor::Number, Zep::ThemeColor::None);
        } else if (token.find_first_not_of("{}()[]") == std::string::npos) {
            mark(itrFirst, itrLast, Zep::ThemeColor::Parenthesis, Zep::ThemeColor::None);
        } else {
            mark(itrFirst, itrLast, Zep::ThemeColor::Normal, Zep::ThemeColor::None);
        }

        // Find String
        auto findString = [&](uint8_t ch) {
            auto itrString = itrFirst;
            if (*itrString == ch) {
                itrString++;

                while (itrString < buffer.end()) {
                    // handle end of string
                    if (*itrString == ch) {
                        itrString++;
                        mark(itrFirst, itrString, Zep::ThemeColor::String, Zep::ThemeColor::None);
                        itrLast = itrString + 1;
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
        };
        findString('\"');
        findString('\'');

        // TODO: comments, multiline comments, and multiline strings

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
