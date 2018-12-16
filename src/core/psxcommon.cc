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
bool g_netOpened = false;

// It is safe if these overflow
uint32_t g_rewind_counter = 0;
uint8_t g_vblank_count_hideafter = 0;

// Used for overclocking
uint32_t g_psxClockSpeed = 33868800;

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

void EmuSetPGXPMode(uint32_t pgxpMode) { psxSetPGXPMode(pgxpMode); }
