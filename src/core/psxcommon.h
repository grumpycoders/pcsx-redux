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

/*
 * This file contains common definitions and includes for all parts of the
 * emulator core.
 */

#ifndef __PSXCOMMON_H__
#define __PSXCOMMON_H__

// System includes
#include <assert.h>
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <zlib.h>

#ifndef MAXPATHLEN
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#ifdef MAX_PATH
#define MAXPATHLEN MAX_PATH
#endif
#ifdef PATH_MAX
#define MAXPATHLEN PATH_MAX
#endif
#endif

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "0"
#endif

// Local includes
#include "core/debug.h"
#include "core/system.h"

#if defined(__linux__) || defined(__MACOSX__)
#define strnicmp strncasecmp
#endif

#define _(msgid) msgid
#define N_(msgid) msgid

extern FILE *g_emuLog;
extern int g_log;

void __Log(char *fmt, ...);

typedef struct {
    char Gpu[MAXPATHLEN];
    char Spu[MAXPATHLEN];
    char Cdr[MAXPATHLEN];
    char Pad1[MAXPATHLEN];
    char Pad2[MAXPATHLEN];
    char Net[MAXPATHLEN];
    char Sio1[MAXPATHLEN];
    char Mcd1[MAXPATHLEN];
    char Mcd2[MAXPATHLEN];
    char Bios[MAXPATHLEN];
    char BiosDir[MAXPATHLEN];
    char PluginsDir[MAXPATHLEN];
    char PatchesDir[MAXPATHLEN];
    char IsoImgDir[MAXPATHLEN];
    char PsxExeName[12];
    bool Xa;
    bool SioIrq;
    bool Mdec;
    bool PsxAuto;
    uint8_t Cdda;
    bool HLE;
    bool SlowBoot;
    bool Debug;
    bool PsxOut;
    bool SpuIrq;
    bool RCntFix;
    bool UseNet;
    bool VSyncWA;
    bool NoMemcard;
    bool PerGameMcd;
    bool Widescreen;
    bool HideCursor;
    bool SaveWindowPos;
    int32_t WindowPos[2];
    uint8_t Cpu;      // CPU_DYNAREC or CPU_INTERPRETER
    uint8_t PsxType;  // PSX_TYPE_NTSC or PSX_TYPE_PAL
    uint32_t RewindCount;
    uint32_t RewindInterval;
    uint32_t AltSpeed1;  // Percent relative to natural speed.
    uint32_t AltSpeed2;
    uint8_t HackFix;
    uint8_t MemHack;
    bool OverClock;  // enable overclocking
    float PsxClock;
    // PGXP variables
    bool PGXP_GTE;
    bool PGXP_Cache;
    bool PGXP_Texture;
    uint32_t PGXP_Mode;
} PcsxConfig;

extern PcsxConfig g_config;
extern bool g_netOpened;

// It is safe if these overflow
extern uint32_t g_rewind_counter;
extern uint8_t g_vblank_count_hideafter;

#define gzfreeze(ptr, size)                   \
    {                                         \
        if (Mode == 1) gzwrite(f, ptr, size); \
        if (Mode == 0) gzread(f, ptr, size);  \
    }

// Make the timing events trigger faster as we are currently assuming everything
// takes one cycle, which is not the case on real hardware.
// FIXME: Count the proper cycle and get rid of this
extern uint32_t g_psxClockSpeed;
#define BIAS 2
#define PSXCLK g_psxClockSpeed /* 33.8688 MHz */

enum { PSX_TYPE_NTSC = 0, PSX_TYPE_PAL };  // PSX Types

enum { CPU_DYNAREC = 0, CPU_INTERPRETER };  // CPU Types

enum { CDDA_ENABLED_LE = 0, CDDA_DISABLED, CDDA_ENABLED_BE };  // CDDA Types

int EmuInit();
void EmuReset();
void EmuShutdown();
void EmuUpdate();
void EmuSetPGXPMode(uint32_t pgxpMode);

#endif
