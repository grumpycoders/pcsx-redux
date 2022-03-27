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

#include "cdrom/iso9660-reader.h"

#include "cdrom/file.h"
#include "cdrom/iso9660-lowlevel.h"
#include "support/strings-helpers.h"

PCSX::ISO9660Reader::ISO9660Reader(std::shared_ptr<CDRiso> iso) : m_iso(iso) {
    unsigned pvdSector = 16;

    while (true) {
        IO<File> pvdFile(new CDRIsoFile(iso, pvdSector++, 2048));
        if (pvdFile->failed()) {
            m_failed = true;
            return;
        }

        uint8_t vd[7];
        pvdFile->readAt(vd, 7, 0);
        if ((vd[1] != 'C') || (vd[2] != 'D') || (vd[3] != '0') || (vd[4] != '0') || (vd[5] != '1') || (vd[6] != 1)) {
            m_failed = true;
            return;
        }

        if (vd[0] == 255) {
            m_failed = true;
            return;
        }

        if (vd[0] != 1) continue;

        ISO9660LowLevel::PVD pvd;
        pvd.deserialize(pvdFile);

        m_root = pvd.get<ISO9660LowLevel::PVD_RootDir>();
        break;
    }
}

PCSX::File *PCSX::ISO9660Reader::open(const std::string_view &filename) {
    auto entry = findEntry(filename);
    if (!entry.has_value()) return new FailedFile();

    return new CDRIsoFile(m_iso, entry.value().get<ISO9660LowLevel::DirEntry_LBA>(),
                          entry.value().get<ISO9660LowLevel::DirEntry_Size>());
}

std::optional<PCSX::ISO9660LowLevel::DirEntry> PCSX::ISO9660Reader::findEntry(const std::string_view &filename) {
    if (m_failed) return {};
    auto parts = StringsHelpers::split(filename, "/");

    ISO9660LowLevel::DirEntry current = m_root;

    for (auto &part : parts) {
        auto entries = listAllEntriesFrom(current);
        for (auto &entry : entries) {
            const auto &entryFilename = entry.get<ISO9660LowLevel::DirEntry_Filename>().value;
            if (entryFilename == part) {
                current = entry;
                break;
            }
        }

        if (current.get<ISO9660LowLevel::DirEntry_Filename>() != part) return {};
    }

    return current;
}

std::vector<PCSX::ISO9660LowLevel::DirEntry> PCSX::ISO9660Reader::listAllEntriesFrom(
    const ISO9660LowLevel::DirEntry &dirEntry) {
    if (m_failed) return {};
    if ((dirEntry.get<ISO9660LowLevel::DirEntry_Flags>().value & 2) == 0) return {};

    IO<File> dir(new CDRIsoFile(m_iso, dirEntry.get<ISO9660LowLevel::DirEntry_LBA>(),
                                dirEntry.get<ISO9660LowLevel::DirEntry_Size>()));

    std::vector<ISO9660LowLevel::DirEntry> ret;
    while (!dir->eof()) {
        uint8_t peek = dir->byte();
        if (peek == 0) continue;
        dir->rSeek(-1, SEEK_CUR);
        ISO9660LowLevel::DirEntry entry;

        auto ptr = dir->rTell();
        entry.deserialize(dir);
        auto len = entry.get<ISO9660LowLevel::DirEntry_Length>().value;
        auto extLen = entry.get<ISO9660LowLevel::DirEntry_ExtLength>().value;
        dir->rSeek(ptr + len + extLen, SEEK_SET);

        ret.push_back(entry);
    }

    return ret;
}
