/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace PCSX {

// The command line parser. Every flag the emulator understands is declared in the
// table in commandline.cc, and anything not in that table is an error. Flags use a
// single dash (-loadexe foo.ps-exe), but a double dash is accepted too. Values can
// be passed either as the next argument or packed with an equal sign.
class CommandLine {
  public:
    enum class Status { Ok, Help, Error };

    CommandLine(int argc, const char* const* argv);

    // Ok means the command line was parsed properly. Help means the user asked for it,
    // and Error means the command line was invalid. In both of these cases, message()
    // holds the text to display.
    Status status() const { return m_status; }
    const std::string& message() const { return m_message; }

    // True if the flag was present on the command line.
    bool has(std::string_view name) const;

    // The value of the flag, or nullopt if it wasn't set. When a flag is repeated, the
    // last occurrence wins. For a flag with an optional value, such as -portable, an
    // empty string means the flag was set without a value.
    std::optional<std::string> value(std::string_view name) const;
    std::string value(std::string_view name, std::string_view defaultValue) const;
    std::optional<int> number(std::string_view name) const;

    // All of the values given to a repeatable flag such as -dofile, in order. For any other
    // flag, this holds its value, if any.
    std::vector<std::string> values(std::string_view name) const;

  private:
    Status m_status = Status::Ok;
    std::string m_message;
    std::map<std::string, std::vector<std::string>, std::less<>> m_values;
};

}  // namespace PCSX
