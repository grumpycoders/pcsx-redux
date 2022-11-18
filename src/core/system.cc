/***************************************************************************
 *   Copyright (C) 2018 PCSX-Redux authors                                 *
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

#include "core/system.h"

#include <stddef.h>

#include <iomanip>
#include <sstream>

#include "support/file.h"

PCSX::System* PCSX::g_system = NULL;

static const ImWchar c_frenchRanges[] = {0x0020, 0x00ff, 0x0152, 0x0153, 0};
static const ImWchar c_greekRanges[] = {0x0020, 0x00ff, 0x0370, 0x03ff, 0};
static const ImWchar c_hindiSupplementalRanges[] = {0x0900, 0x097f, 0};
static const ImWchar c_malteseRanges[] = {0x0020, 0x00ff, 0x010a, 0x010b, 0x0120, 0x0121,
                                          0x0126, 0x0127, 0x017b, 0x017c, 0};

// locale names have to be written in basic latin or extended latin, in order
// to be properly displayed in the UI with the default range
const std::map<std::string, PCSX::System::LocaleInfo> PCSX::System::LOCALES = {
    {
        "Deutsch",
        {"de.po", {}, nullptr},
    },
    {
        "Ellinika",
        {"el.po", {}, c_greekRanges},
    },
    {
        "Español",
        {"es_ES.po", {}, nullptr},
    },
    {
        "Français",
        {"fr.po", {}, c_frenchRanges},
    },
    {
        "Hindi",
        {"hi.po", {{MAKEU8("NotoSansDevanagari-Regular.ttf"), c_hindiSupplementalRanges}}, nullptr},
    },
    {
        "Italiano",
        {"it.po", {}, nullptr},
    },
    {
        "Nihongo",
        {"jp.po", {}, nullptr},
    },
    {
        "Malti",
        {"mt.po", {}, c_malteseRanges},
    },
    {
        "Português Brasileiro",
        {"pt_BR.po", {}, nullptr},
    },
};

bool PCSX::System::loadLocale(const std::string& name, const std::filesystem::path& path) {
    IO<File> in(new PosixFile(path));
    int c;
    std::string currentString = "";
    std::string token = "";
    std::string singleChar = ".";
    bool newLine = true;
    bool inComment = false;
    bool inString = false;
    bool gotBackquote = false;
    unsigned inlineIndex = 0;
    unsigned shift = 0;
    uint8_t inlined = 0;
    enum : int {
        WAITING_MSGIDTOKEN,
        WAITING_MSGID,
        WAITING_MSGSTRTOKEN,
        WAITING_MSGSTR,
        STATE_MAX
    } state = WAITING_MSGIDTOKEN;
    uint64_t hashValue;
    std::map<uint64_t, std::string> locale;

    if (in->failed()) return false;

    std::string comment;
    bool fuzzy = false;

    while ((c = in->getc()) >= 0) {
        if (c == '\n' || c == '\r') {
            if (inString) return false;
            if (inComment) fuzzy = comment.find(", fuzzy") != std::string::npos;
            inComment = false;
            newLine = true;
            comment.clear();
            continue;
        }
        if (inComment) {
            comment += c;
            continue;
        }
        if (newLine) {
            newLine = false;
            if (c == '#') {
                inComment = true;
                continue;
            }
            if (c == '\"') {
                if (state != WAITING_MSGIDTOKEN && state != WAITING_MSGSTRTOKEN) return false;
                inString = true;
                continue;
            }
        }
        if (inString) {
            singleChar[0] = c;
            if (c == '\"' && !gotBackquote) {
                inString = false;
            } else if (gotBackquote) {
                if (inlineIndex) {
                    inlineIndex++;
                    inlined <<= shift;
                    if (c >= '0' && c <= '9') {
                        inlined += c - '0';
                    } else if (c >= 'a' && c <= 'f') {
                        inlined += c - 'a' + 10;
                    } else if (c >= 'A' && c <= 'F') {
                        inlined += c - 'A' + 10;
                    }
                    if (inlineIndex == 3) {
                        gotBackquote = false;
                        singleChar[0] = inlined;
                        currentString += singleChar;
                        inlineIndex = 0;
                    }
                } else {
                    if (c == 'x') {
                        inlineIndex = 1;
                        shift = 4;
                        inlined = 0;
                    } else if (c >= '0' && c <= '7') {
                        inlineIndex = 1;
                        shift = 3;
                        inlined = c - '0';
                    } else {
                        switch (c) {
                            case 'b':
                                singleChar[0] = '\b';
                                break;
                            case 't':
                                singleChar[0] = '\t';
                                break;
                            case 'n':
                                singleChar[0] = '\n';
                                break;
                            case 'f':
                                singleChar[0] = '\f';
                                break;
                            case 'r':
                                singleChar[0] = '\r';
                                break;
                            case '\\':
                                singleChar[0] = '\\';
                                break;
                            case '"':
                            case '\'':
                                singleChar[0] = c;
                                break;
                            default:
                                currentString += '\\';
                                singleChar[0] = c;
                                break;
                        }
                        currentString += singleChar;
                        gotBackquote = false;
                    }
                }
            } else {
                gotBackquote = c == '\\';
                if (!gotBackquote) currentString += singleChar;
            }
        } else {
            if (c == ' ' || c == '\t') continue;
            switch (state) {
                case WAITING_MSGID:
                case WAITING_MSGSTR:
                    if (c == '\"') {
                        inString = true;
                        (*reinterpret_cast<int*>(&state))++;
                        if (state == STATE_MAX) state = WAITING_MSGIDTOKEN;
                    } else {
                        return false;
                    }
                    break;
                case WAITING_MSGIDTOKEN:
                case WAITING_MSGSTRTOKEN:
                    if (token.empty()) {
                        switch (state) {
                            case WAITING_MSGIDTOKEN:
                                if (!currentString.empty() && !fuzzy) locale[hashValue] = currentString;
                                break;
                            case WAITING_MSGSTRTOKEN:
                                hashValue = djbHash::hash(currentString);
                                break;
                        }
                        currentString = "";
                    }
                    token += c;
                    switch (state) {
                        case WAITING_MSGIDTOKEN:
                            if (token.length() == 5) {
                                if (token != "msgid") {
                                    return false;
                                }
                                token = "";
                                state = WAITING_MSGID;
                            }
                            break;
                        case WAITING_MSGSTRTOKEN:
                            if (token.length() == 6) {
                                if (token != "msgstr") {
                                    return false;
                                }
                                token = "";
                                state = WAITING_MSGSTR;
                            }
                            break;
                    }
                    break;
            }
        }
    }

    if (inString || (state != WAITING_MSGIDTOKEN)) return false;

    if (!currentString.empty() && !fuzzy) locale[hashValue] = currentString;
    m_locales[name] = locale;
    return true;
}

bool PCSX::System::findResource(std::function<bool(const std::filesystem::path& path)> walker,
                                const std::filesystem::path& name, const std::filesystem::path& releasePath,
                                const std::filesystem::path& sourcePath) {
    // First, let's try the base filename from the same directory as our main binary.
    if (walker(m_binDir / name)) return true;

    // Then, let's search for our release folders...
    // Maybe in a subfolder next to our main binary? That's the Windows way.
    if (walker(m_binDir / releasePath / name)) return true;
    // Next up, the Unix way: binary is in /bin, and resources are in /share/pcsx-redux.
    if (walker(m_binDir / ".." / "share" / "pcsx-redux" / releasePath / name)) return true;
    // And finally, MacOS had to do differently, of course. The MacOS app has this layout:
    // binary is in Contents/MacOS/
    // rest is in Contents/Resources/share/pcsx-redux
    if (walker(m_binDir / ".." / "Resources" / "share" / "pcsx-redux" / releasePath / name)) return true;

    // And finally, let's try if we're running from sources.
    // If our main binary is at the root - that's the Unix way.
    if (walker(m_binDir / sourcePath / name)) return true;
    // And if it's in a subfolder - that's the Window / Visual Studio way.
    if (walker(m_binDir / ".." / ".." / sourcePath / name)) return true;
    if (walker(m_binDir / ".." / ".." / ".." / sourcePath / name)) return true;

    // No luck here...
    return false;
}
