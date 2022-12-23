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

#include "cdrom/common.h"
#include "cdrom/iec-60908b.h"
#include "support/file.h"

namespace PCSX {

class ISO9660Builder {
  public:
    ISO9660Builder(IO<File> out) : m_out(out) {}
    bool failed() { return !m_out || m_out->failed(); }
    IEC60908b::MSF getCurrentLocation() { return m_location; }
    void writeLicense(IO<File> licenseFile = nullptr);
    IEC60908b::MSF writeSector(const uint8_t* sectorData, SectorMode mode) {
        return writeSectorAt(sectorData, m_location, mode);
    }
    IEC60908b::MSF writeSectorAt(const uint8_t* sectorData, IEC60908b::MSF msf, SectorMode mode);
    void close() {
        m_out->close();
        m_out = nullptr;
    }

  private:
    IO<File> m_out;
    IEC60908b::MSF m_location = {0, 2, 0};
};

}  // namespace PCSX
