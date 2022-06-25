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

bool PCSX::CDRIso::LoadSBI(const char *filename) {
    IO<File> sbihandle;
    char buffer[16];

    sbihandle.setFile(new UvFile(filename));
    if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
        sbihandle.asA<UvFile>()->startCaching();
    }
    if (sbihandle->failed()) return false;

    // init
    sbicount = 0;

    // 4-byte SBI header
    sbihandle->read(buffer, 4);
    while (!sbihandle->eof()) {
        sbihandle->read(sbitime[sbicount++], 3);
        sbihandle->read(buffer, 11);
    }

    PCSX::g_system->printf(_("Loaded SBI file: %s.\n"), filename);

    return true;
}

bool PCSX::CDRIso::CheckSBI(const uint8_t *time) {
    int lcv;

    // both BCD format
    for (lcv = 0; lcv < sbicount; lcv++) {
        if (time[0] == sbitime[lcv][0] && time[1] == sbitime[lcv][1] && time[2] == sbitime[lcv][2]) return true;
    }

    return false;
}

void PCSX::CDRIso::UnloadSBI() { sbicount = 0; }

bool PCSX::CDRIso::opensbifile(const char *isoname) {
    char sbiname[MAXPATHLEN];

    strncpy(sbiname, isoname, sizeof(sbiname));
    sbiname[MAXPATHLEN - 1] = '\0';
    if (strlen(sbiname) >= 4) {
        strcpy(sbiname + strlen(sbiname) - 4, ".sbi");
    } else {
        return false;
    }

    return LoadSBI(sbiname);
}
