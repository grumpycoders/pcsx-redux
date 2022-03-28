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

#include <memory>
#include <optional>
#include <vector>

#include "cdrom/file.h"
#include "cdrom/iso9660-lowlevel.h"

namespace PCSX {

class CDRiso;

class ISO9660Reader {
  public:
    ISO9660Reader(std::shared_ptr<CDRiso>);
    bool failed() { return m_failed; }
    File* open(const std::string_view& filename);
    std::string_view getLabel() {
        if (m_failed) return "";
        return std::string_view(m_pvd.get<ISO9660LowLevel::PVD_VolumeIdent>());
    }

  private:
    std::shared_ptr<CDRiso> m_iso;
    bool m_failed = false;

    std::optional<ISO9660LowLevel::DirEntry> findEntry(const std::string_view& filename);
    std::vector<ISO9660LowLevel::DirEntry> listAllEntriesFrom(const ISO9660LowLevel::DirEntry& entry);
    ISO9660LowLevel::PVD m_pvd;
};

}  // namespace PCSX
