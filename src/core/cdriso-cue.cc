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

#include "core/cdriso.h"
#include "core/cdrom.h"

// this function tries to get the .cue file of the given .bin
// the necessary data is put into the ti (trackinformation)-array
int PCSX::CDRiso::parsecue(const char *isofileString) {
    std::filesystem::path isofile = MAKEU8(isofileString);
    std::filesystem::path cuename, filepath;
    IO<File> fi;
    char *token;
    char time[20];
    char *tmp;
    char linebuf[256], tmpb[256], dummy[256];
    unsigned int t, file_len, mode, sector_offs;
    unsigned int sector_size = 2352;

    m_numtracks = 0;

    // copy name of the iso and change extension from .bin to .cue
    cuename = isofile;
    cuename.replace_extension("cue");

    fi.setFile(new UvFile(cuename));
    if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
        fi.asA<UvFile>()->startCaching();
    }
    if (fi->failed()) {
        return -1;
    }

    // Some stupid tutorials wrongly tell users to use cdrdao to rip a
    // "bin/cue" image, which is in fact a "bin/toc" image. So let's check
    // that...
    if (fi->gets(linebuf, sizeof(linebuf))) {
        if (!strncmp(linebuf, "CD_ROM_XA", 9)) {
            // Don't proceed further, as this is actually a .toc file rather
            // than a .cue file.
            return parsetoc(isofileString);
        }
        fi->rSeek(0, SEEK_SET);
    }

    // build a path for files referenced in .cue
    filepath = cuename.parent_path();

    memset(&m_ti, 0, sizeof(m_ti));

    file_len = 0;
    sector_offs = 2 * 75;

    while (fi->gets(linebuf, sizeof(linebuf))) {
        strncpy(dummy, linebuf, sizeof(linebuf));
        token = strtok(dummy, " ");

        if (token == NULL) {
            continue;
        }

        if (!strcmp(token, "TRACK")) {
            m_numtracks++;

            sector_size = 0;
            if (strstr(linebuf, "AUDIO") != NULL) {
                m_ti[m_numtracks].type = trackinfo::CDDA;
                sector_size = PCSX::CDRom::CD_FRAMESIZE_RAW;
                // Check if extension is mp3, etc, for compressed audio formats
                if (m_multifile &&
                    (m_ti[m_numtracks].cddatype = get_cdda_type(m_ti[m_numtracks].filepath)) > trackinfo::BIN) {
                    int seconds = get_compressed_cdda_track_length(m_ti[m_numtracks].filepath) + 0;
                    const bool lazy_decode = true;  // TODO: config param

                    // TODO: get frame length for compressed audio as well
                    m_ti[m_numtracks].len_decoded_buffer = 44100 * (16 / 8) * 2 * seconds;
                    file_len = m_ti[m_numtracks].len_decoded_buffer / PCSX::CDRom::CD_FRAMESIZE_RAW;

                    // Send to decoder if not lazy decoding
                    if (!lazy_decode) {
                        PCSX::g_system->printf("\n");
                        file_len = do_decode_cdda(&(m_ti[m_numtracks]), m_numtracks) / PCSX::CDRom::CD_FRAMESIZE_RAW;
                    }
                }
            } else if (sscanf(linebuf, " TRACK %u MODE%u/%u", &t, &mode, &sector_size) == 3) {
                int32_t accurate_len;
                // TODO: if 2048 frame length -> recalculate file_len?
                m_ti[m_numtracks].type = trackinfo::DATA;
                // detect if ECM or compressed & get accurate length
                if (handleecm(m_ti[m_numtracks].filepath, m_cdHandle, &accurate_len) == 0) {
                    file_len = accurate_len;
                }
            } else {
                PCSX::g_system->printf(".cue: failed to parse TRACK\n");
                m_ti[m_numtracks].type = m_numtracks == 1 ? trackinfo::DATA : trackinfo::CDDA;
            }
            if (sector_size == 0)  // TODO m_isMode1ISO?
                sector_size = PCSX::CDRom::CD_FRAMESIZE_RAW;
        } else if (!strcmp(token, "INDEX")) {
            if (sscanf(linebuf, " INDEX %02d %8s", &t, time) != 2)
                PCSX::g_system->printf(".cue: failed to parse INDEX\n");
            m_ti[m_numtracks].start = IEC60908b::MSF(time);

            t = m_ti[m_numtracks].start.toLBA();
            m_ti[m_numtracks].start_offset = t * sector_size;
            t += sector_offs;
            m_ti[m_numtracks].start = IEC60908b::MSF(t);

            // default track length to file length
            t = file_len - m_ti[m_numtracks].start_offset / sector_size;
            m_ti[m_numtracks].length = IEC60908b::MSF(t);

            if (m_numtracks > 1 && !m_ti[m_numtracks].handle) {
                // this track uses the same file as the last,
                // start of this track is last track's end
                t = m_ti[m_numtracks].start.toLBA() - m_ti[m_numtracks - 1].start.toLBA();
                m_ti[m_numtracks - 1].length = IEC60908b::MSF(t);
            }
            if (m_numtracks > 1 && m_pregapOffset == -1) m_pregapOffset = m_ti[m_numtracks].start_offset / sector_size;
        } else if (!strcmp(token, "PREGAP")) {
            if (sscanf(linebuf, " PREGAP %8s", time) == 1) {
                sector_offs += IEC60908b::MSF(time).toLBA();
            }
            m_pregapOffset = -1;  // mark to fill track start_offset
        } else if (!strcmp(token, "FILE")) {
            t = sscanf(linebuf, " FILE \"%255[^\"]\"", tmpb);
            if (t != 1) sscanf(linebuf, " FILE %255s", tmpb);

            // absolute path?
            m_ti[m_numtracks + 1].handle.setFile(new UvFile(tmpb));
            if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
                m_ti[m_numtracks + 1].handle.asA<UvFile>()->startCaching();
            }
            if (m_ti[m_numtracks + 1].handle->failed()) {
                m_ti[m_numtracks + 1].handle.setFile(new UvFile(filepath / tmpb));
                if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
                    m_ti[m_numtracks + 1].handle.asA<UvFile>()->startCaching();
                }
            }

            strcpy(m_ti[m_numtracks + 1].filepath,
                   reinterpret_cast<const char *>(m_ti[m_numtracks + 1].handle->filename().u8string().c_str()));

            // update global offset if this is not first file in this .cue
            if (m_numtracks + 1 > 1) {
                m_multifile = true;
                sector_offs += file_len;
            }

            file_len = 0;
            if (m_ti[m_numtracks + 1].handle->failed()) {
                PCSX::g_system->message(_("\ncould not open: %s\n"), m_ti[m_numtracks + 1].handle->filename().string());
                m_ti[m_numtracks + 1].handle.reset();
                continue;
            }

            // File length, compressed audio length will be calculated in AUDIO tag
            m_ti[m_numtracks + 1].handle->rSeek(0, SEEK_END);
            file_len = m_ti[m_numtracks + 1].handle->rTell() / PCSX::CDRom::CD_FRAMESIZE_RAW;

            if (m_numtracks == 0 && (isofile.extension() == ".cue")) {
                // user selected .cue as image file, use its data track instead
                m_cdHandle.setFile(new SubFile(m_ti[m_numtracks + 1].handle, 0, m_ti[m_numtracks + 1].handle->size()));
            }
        }
    }

    return 0;
}
