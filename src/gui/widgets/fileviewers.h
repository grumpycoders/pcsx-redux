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

#include <string>

#include "support/file.h"
#include "support/list.h"

namespace PCSX {
namespace Widgets {

// Hosts the viewers defined in resources/fileviewers.lua. Each call to open()
// hands a file to PCSX.FileViewers.open and keeps the returned object alive
// in its own window until the user closes it.
class FileViewers {
  public:
    ~FileViewers();
    bool available();
    void open(const std::string& title, IO<File> file);
    void draw();

  private:
    struct Instance : public Intrusive::List<Instance>::Node {
        Instance(const std::string& title, int ref) : m_title(title), m_ref(ref) {}
        std::string m_title;
        int m_ref;
        bool m_open = true;
        bool m_failed = false;
    };
    Intrusive::List<Instance> m_instances;
    bool call(Instance& inst, const char* method);
    void release(Instance& inst);
};

}  // namespace Widgets
}  // namespace PCSX
