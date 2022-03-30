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
#include "core/cdrom.h"

// this function tries to get the .ccd file of the given .img
// the necessary data is put into the ti (trackinformation)-array
bool PCSX::CDRIso::parseccd(const char *isofileString) {
    std::filesystem::path ccdname, isofile = MAKEU8(isofileString);
    IO<File> fi;
    char linebuf[256];
    unsigned int t;

    m_numtracks = 0;

    // copy name of the iso and change extension from .img to .ccd
    ccdname = isofile;
    ccdname.replace_extension("ccd");

    fi.setFile(new UvFile(ccdname));
    if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
        fi.asA<UvFile>()->startCaching();
    }
    if (fi->failed()) return false;

    memset(&m_ti, 0, sizeof(m_ti));

    while (fi->gets(linebuf, sizeof(linebuf))) {
        if (!strncmp(linebuf, "[TRACK", 6)) {
            m_numtracks++;
        } else if (!strncmp(linebuf, "MODE=", 5)) {
            sscanf(linebuf, "MODE=%d", &t);
            m_ti[m_numtracks].type = ((t == 0) ? TrackType::CDDA : TrackType::DATA);
        } else if (!strncmp(linebuf, "INDEX 1=", 8)) {
            sscanf(linebuf, "INDEX 1=%d", &t);
            m_ti[m_numtracks].start = IEC60908b::MSF(t + 150);
            m_ti[m_numtracks].start_offset = t * 2352;

            // If we've already seen another track, this is its end
            if (m_numtracks > 1) {
                t = m_ti[m_numtracks].start.toLBA() - m_ti[m_numtracks - 1].start.toLBA();
                m_ti[m_numtracks - 1].length = IEC60908b::MSF(t);
            }
        }
    }

    // Fill out the last track's end based on size
    if (m_numtracks >= 1) {
        m_cdHandle->rSeek(0, SEEK_END);
        t = m_cdHandle->rTell() / PCSX::IEC60908b::FRAMESIZE_RAW - m_ti[m_numtracks].start.toLBA() + 150;
        m_ti[m_numtracks].length = IEC60908b::MSF(t);
    }

    return true;
}
