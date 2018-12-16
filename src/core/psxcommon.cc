/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

#include "core/cheat.h"
#include "core/ppf.h"
#include "core/psxcommon.h"
#include "core/psxbios.h"
#include "core/r3000a.h"

PcsxConfig g_config;
boolean g_netOpened = FALSE;

int g_log = 0;
FILE *g_emuLog = NULL;

// It is safe if these overflow
u32 g_rewind_counter = 0;
u8 g_vblank_count_hideafter = 0;

// Used for overclocking
u32 g_psxClockSpeed = 33868800;

int EmuInit() {
    int ret = psxInit();
    EmuSetPGXPMode(g_config.PGXP_Mode);
    return ret;
}

void EmuReset() {
    FreeCheatSearchResults();
    FreeCheatSearchMem();

    psxReset();
}

void EmuShutdown() {
    ClearAllCheats();
    FreeCheatSearchResults();
    FreeCheatSearchMem();

    FreePPFCache();

    psxShutdown();

    CleanupMemSaveStates();
}

void EmuUpdate() {
    // Do not allow hotkeys inside a softcall from HLE BIOS
    if (!g_config.HLE || !g_hleSoftCall) PCSX::system->SysUpdate();

    ApplyCheats();

    if (g_vblank_count_hideafter) {
        if (!(--g_vblank_count_hideafter)) {
            GPU_showScreenPic(NULL);
        }
    }

    if (g_config.RewindInterval > 0 && !(++g_rewind_counter % g_config.RewindInterval)) {
        CreateRewindState();
    }
}

void EmuSetPGXPMode(u32 pgxpMode) { psxSetPGXPMode(pgxpMode); }

void __Log(char *fmt, ...) {
    va_list list;
#ifdef LOG_STDOUT
    char tmp[1024];
#endif

    va_start(list, fmt);
#ifndef LOG_STDOUT
    vfprintf(g_emuLog, fmt, list);
#else
    vsprintf(tmp, fmt, list);
    PCSX::system->SysPrintf(tmp);
#endif
    va_end(list);
}
