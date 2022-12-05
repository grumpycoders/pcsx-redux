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

#include "cdrom/cdriso.h"

// this function tries to get the .mds file of the given .mdf
// the necessary data is put into the ti (trackinformation)-array
bool PCSX::CDRIso::parsemds(const char *isofileString) {
    std::filesystem::path mdsname, isofile = MAKEU8(isofileString);
    unsigned int offset, extra_offset, l, i;
    unsigned short s;

    m_numtracks = 0;

    // copy name of the iso and change extension from .mdf to .mds
    mdsname = isofile;
    isofile.replace_extension("mds");

    IO<File> fi(new UvFile(mdsname));
    if (fi->failed()) return false;
    if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
        fi.asA<UvFile>()->startCaching();
    }

    for (auto &i : m_ti) {
        i = {};
    }

    // check if it's a valid mds file
    i = fi->read<uint32_t>();
    if (i != 0x4944454d) {
        // not an valid mds file
        return -1;
    }

    // get offset to session block
    fi->rSeek(0x50, SEEK_SET);
    offset = fi->read<uint32_t>();

    // get total number of tracks
    offset += 14;
    fi->rSeek(offset, SEEK_SET);
    s = fi->read<uint16_t>();
    m_numtracks = s;

    // get offset to track blocks
    fi->rSeek(4, SEEK_CUR);
    offset = fi->read<uint32_t>();

    // skip lead-in data
    while (1) {
        fi->rSeek(offset + 4, SEEK_SET);
        if (fi->getc() < 0xa0) break;
        offset += 0x50;
    }

    // check if the image contains mixed subchannel data
    fi->rSeek(offset + 1, SEEK_SET);
    m_subChanMixed = m_subChanRaw = (fi->getc() ? true : false);

    // read track data
    for (i = 1; i <= m_numtracks; i++) {
        fi->rSeek(offset, SEEK_SET);

        // get the track type
        m_ti[i].type = ((fi->getc() == 0xa9) ? TrackType::CDDA : TrackType::DATA);
        fi->rSeek(8, SEEK_CUR);

        // get the track starting point
        m_ti[i].start.m = fi->getc();
        m_ti[i].start.s = fi->getc();
        m_ti[i].start.f = fi->getc();

        extra_offset = fi->read<uint32_t>();

        // get track start offset (in .mdf)
        fi->rSeek(offset + 0x28, SEEK_SET);
        l = fi->read<uint32_t>();
        m_ti[i].start_offset = l;

        // get pregap
        fi->rSeek(extra_offset, SEEK_SET);
        l = fi->read<uint32_t>();
        if (l != 0 && i > 1) m_pregapOffset = m_ti[i].start.toLBA();

        // get the track length
        l = fi->read<uint32_t>();
        m_ti[i].length = IEC60908b::MSF(l);

        offset += 0x50;
    }

    return true;
}
