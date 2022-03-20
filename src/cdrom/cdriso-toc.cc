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

// this function tries to get the .toc file of the given .bin
// the necessary data is put into the ti (trackinformation)-array
int PCSX::CDRiso::parsetoc(const char *isofileStr) {
    std::filesystem::path isofile = MAKEU8(isofileStr);
    std::filesystem::path tocname, filename;
    IO<File> fi;
    char linebuf[256], tmp[256], name[256];
    char *token;
    char time[20], time2[20];
    unsigned int t, sector_offs, sector_size;
    unsigned int current_zero_gap = 0;

    m_numtracks = 0;

    // copy name of the iso and change extension from .bin to .toc
    tocname = isofile;
    tocname.replace_extension("toc");

    fi.setFile(new UvFile(tocname));
    if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
        fi.asA<UvFile>()->startCaching();
    }
    if (fi->failed()) {
        // try changing extension to .cue (to satisfy some stupid tutorials)
        tocname.replace_extension("cue");
        fi.setFile(new UvFile(tocname));
        if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
            fi.asA<UvFile>()->startCaching();
        }
        if (fi->failed()) {
            // if filename is image.toc.bin, try removing .bin (for Brasero)
            tocname = isofile;
            tocname.replace_extension("");
            if (tocname.extension() == ".toc") {
                fi.setFile(new UvFile(tocname));
                if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
                    fi.asA<UvFile>()->startCaching();
                }
                if (fi->failed()) {
                    return -1;
                }
            }
            return -1;
        }
    }

    filename = tocname.parent_path();

    memset(&m_ti, 0, sizeof(m_ti));
    m_cddaBigEndian = true;  // cdrdao uses big-endian for CD Audio

    sector_size = PCSX::IEC60908b::FRAMESIZE_RAW;
    sector_offs = 2 * 75;

    // parse the .toc file
    while (fi->gets(linebuf, sizeof(linebuf))) {
        // search for tracks
        strncpy(tmp, linebuf, sizeof(linebuf));
        token = strtok(tmp, " ");

        if (token == NULL) continue;

        if (!strcmp(token, "TRACK")) {
            sector_offs += current_zero_gap;
            current_zero_gap = 0;

            // get type of track
            token = strtok(NULL, " ");
            m_numtracks++;

            if (!strncmp(token, "MODE2_RAW", 9)) {
                m_ti[m_numtracks].type = TrackType::DATA;
                // assume data track on 0:2:0
                m_ti[m_numtracks].start = IEC60908b::MSF(0, 2, 0);

                // check if this image contains mixed subchannel data
                token = strtok(NULL, " ");
                if (token != NULL && !strncmp(token, "RW", 2)) {
                    sector_size = PCSX::IEC60908b::FRAMESIZE_RAW + PCSX::IEC60908b::SUB_FRAMESIZE;
                    m_subChanMixed = true;
                    if (!strncmp(token, "RW_RAW", 6)) m_subChanRaw = true;
                }
            } else if (!strncmp(token, "AUDIO", 5)) {
                m_ti[m_numtracks].type = TrackType::CDDA;
            }
        } else if (!strcmp(token, "DATAFILE")) {
            if (m_ti[m_numtracks].type == TrackType::CDDA) {
                sscanf(linebuf, "DATAFILE \"%[^\"]\" #%d %8s", name, &t, time2);
                m_ti[m_numtracks].start_offset = t;
                t = t / sector_size + sector_offs;
                m_ti[m_numtracks].start = IEC60908b::MSF(t);
                m_ti[m_numtracks].length = IEC60908b::MSF(time2);
            } else {
                sscanf(linebuf, "DATAFILE \"%[^\"]\" %8s", name, time);
                m_ti[m_numtracks].length = IEC60908b::MSF(time);
                m_ti[m_numtracks].handle.setFile(new UvFile(filename / name));
                if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
                    m_ti[m_numtracks].handle.asA<UvFile>()->startCaching();
                }
            }
        } else if (!strcmp(token, "FILE")) {
            sscanf(linebuf, "FILE \"%[^\"]\" #%d %8s %8s", name, &t, time, time2);
            m_ti[m_numtracks].start = IEC60908b::MSF(time);
            t += m_ti[m_numtracks].start.toLBA() * sector_size;
            m_ti[m_numtracks].start_offset = t;
            t = t / sector_size + sector_offs;
            m_ti[m_numtracks].start = IEC60908b::MSF(t);
            m_ti[m_numtracks].length = IEC60908b::MSF(time2);
        } else if (!strcmp(token, "ZERO") || !strcmp(token, "SILENCE")) {
            // skip unneeded optional fields
            while (token != NULL) {
                token = strtok(NULL, " ");
                if (strchr(token, ':') != NULL) break;
            }
            if (token != NULL) {
                current_zero_gap = IEC60908b::MSF(token).toLBA();
            }
            if (m_numtracks > 1) {
                t = m_ti[m_numtracks - 1].start_offset;
                t /= sector_size;
                m_pregapOffset = t + m_ti[m_numtracks - 1].length.toLBA();
            }
        } else if (!strcmp(token, "START")) {
            token = strtok(NULL, " ");
            if (token != NULL && strchr(token, ':')) {
                t = IEC60908b::MSF(token).toLBA();
                m_ti[m_numtracks].start_offset += (t - current_zero_gap) * sector_size;
                t += m_ti[m_numtracks].start.toLBA();
                m_ti[m_numtracks].start = IEC60908b::MSF(t);
            }
        }
    }
    if (m_numtracks > 0) m_cdHandle.setFile(new SubFile(m_ti[1].handle, 0, m_ti[1].handle->size()));

    return 0;
}
