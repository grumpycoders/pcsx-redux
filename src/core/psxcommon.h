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

// Define types
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef intptr_t sptr;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uintptr_t uptr;

typedef uint8_t boolean;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
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
#define __inline inline

// Enables NLS/internationalization if active
#ifdef ENABLE_NLS

#include <libintl.h>

#undef _
#define _(String) gettext(String)
#ifdef gettext_noop
#define N_(String) gettext_noop(String)
#else
#define N_(String) (String)
#endif

// If running under Mac OS X, use the Localizable.strings file instead.
#elif defined(_MACOSX)
#ifdef PCSXRCORE
__private_extern char* Pcsxr_locale_text(char* toloc);
#define _(String) Pcsxr_locale_text(String)
#define N_(String) String
#else
#ifndef PCSXRPLUG
#warning please define the plug being built to use Mac OS X localization!
#define _(msgid) msgid
#define N_(msgid) msgid
#else
// Kludge to get the preprocessor to accept PCSXRPLUG as a variable.
#define PLUGLOC_x(x, y) x##y
#define PLUGLOC_y(x, y) PLUGLOC_x(x, y)
#define PLUGLOC PLUGLOC_y(PCSXRPLUG, _locale_text)
__private_extern char* PLUGLOC(char* toloc);
#define _(String) PLUGLOC(String)
#define N_(String) String
#endif
#endif
#else

#define _(msgid) msgid
#define N_(msgid) msgid

#endif

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
    boolean Xa;
    boolean SioIrq;
    boolean Mdec;
    boolean PsxAuto;
    u8 Cdda;
    boolean HLE;
    boolean SlowBoot;
    boolean Debug;
    boolean PsxOut;
    boolean SpuIrq;
    boolean RCntFix;
    boolean UseNet;
    boolean VSyncWA;
    boolean NoMemcard;
    boolean PerGameMcd;
    boolean Widescreen;
    boolean HideCursor;
    boolean SaveWindowPos;
    s32 WindowPos[2];
    u8 Cpu;      // CPU_DYNAREC or CPU_INTERPRETER
    u8 PsxType;  // PSX_TYPE_NTSC or PSX_TYPE_PAL
    u32 RewindCount;
    u32 RewindInterval;
    u32 AltSpeed1;  // Percent relative to natural speed.
    u32 AltSpeed2;
    u8 HackFix;
    u8 MemHack;
    boolean OverClock;  // enable overclocking
    float PsxClock;
    // PGXP variables
    boolean PGXP_GTE;
    boolean PGXP_Cache;
    boolean PGXP_Texture;
    u32 PGXP_Mode;
#ifdef _WIN32
    char Lang[256];
#endif
} PcsxConfig;

extern PcsxConfig g_config;
extern boolean g_netOpened;

// It is safe if these overflow
extern u32 g_rewind_counter;
extern u8 g_vblank_count_hideafter;

#define gzfreeze(ptr, size)                   \
    {                                         \
        if (Mode == 1) gzwrite(f, ptr, size); \
        if (Mode == 0) gzread(f, ptr, size);  \
    }

// Make the timing events trigger faster as we are currently assuming everything
// takes one cycle, which is not the case on real hardware.
// FIXME: Count the proper cycle and get rid of this
extern u32 g_psxClockSpeed;
#define BIAS 2
#define PSXCLK g_psxClockSpeed /* 33.8688 MHz */

enum { PSX_TYPE_NTSC = 0, PSX_TYPE_PAL };  // PSX Types

enum { CPU_DYNAREC = 0, CPU_INTERPRETER };  // CPU Types

enum { CDDA_ENABLED_LE = 0, CDDA_DISABLED, CDDA_ENABLED_BE };  // CDDA Types

int EmuInit();
void EmuReset();
void EmuShutdown();
void EmuUpdate();
void EmuSetPGXPMode(u32 pgxpMode);

#endif
