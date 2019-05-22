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

#include <stddef.h>

#include <iomanip>
#include <sstream>

#include "core/file.h"
#include "core/system.h"

PCSX::System* PCSX::g_system = NULL;

bool PCSX::System::loadLocale(const std::string & name, const std::filesystem::path & path) {
    std::unique_ptr<File> in(new File(path));
    int c;
    std::stringstream ss;
    std::string currentString = "";
    std::string token = "";
    std::string singleChar = ".";
    bool newLine = true;
    bool inComment = false;
    bool inString = false;
    bool gotBackquote = false;
    enum : int {
        WAITING_MSGIDTOKEN,
        WAITING_MSGID,
        WAITING_MSGSTRTOKEN,
        WAITING_MSGSTR,
        STATE_MAX
    } state = WAITING_MSGIDTOKEN;
    uint64_t hashValue;
    std::map<uint64_t, std::string> locale;

    while ((c = in->getc()) >= 0) {
        if (c == '\n') {
            inComment = false;
            newLine = true;
            continue;
        }
        if (inComment) continue;
        if (newLine) {
            newLine = false;
            if (c == '#') {
                inComment = true;
                continue;
            }
            if (c == '\"') {
                if (state != WAITING_MSGIDTOKEN && state != WAITING_MSGSTRTOKEN) return false;
                ss << "\"";
                inString = true;
                continue;
            }
        }
        if (inString) {
            singleChar[0] = c;
            ss << singleChar;
            if (c == '\"' && !gotBackquote) {
                std::string quotedString;
                ss >> std::quoted(quotedString);
                currentString += quotedString;
                inString = false;
            }
            gotBackquote = c == '\\';
        } else {
            if (c == ' ' || c == '\t') continue;
            switch (state) {
                case WAITING_MSGID:
                case WAITING_MSGSTR:
                    if (c == '\"') {
                        ss << "\"";
                        inString = true;
                        (*reinterpret_cast<int*>(&state))++;
                        if (state == STATE_MAX) state = WAITING_MSGIDTOKEN;
                    } else {
                        return false;
                    }
                    break;
                case WAITING_MSGIDTOKEN:
                case WAITING_MSGSTRTOKEN:
                    if (token.length() == 0) {
                        switch (state) {
                            case WAITING_MSGIDTOKEN:
                                if (currentString.length()) locale[hashValue] = currentString;
                                break;
                            case WAITING_MSGSTRTOKEN:
                                hashValue = hash(currentString);
                                break;
                        }
                        currentString = "";
                    }
                    token += c;
                    switch (state) {
                        case WAITING_MSGIDTOKEN:
                            if (token.length() == 5) {
                                if (token != "msgid") return false;
                                token = "";
                                state = WAITING_MSGID;
                            }
                            break;
                        case WAITING_MSGSTRTOKEN:
                            if (token.length() == 6) {
                                if (token != "msgstr") return false;
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

    if (currentString != "") locale[hashValue] = currentString;
    m_locales[name] = locale;
    return true;
}
