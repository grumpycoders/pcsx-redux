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

#pragma once

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

#include <string>

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

// Local includes - anything else is forbidden
#include "core/logger.h"
#include "core/system.h"

#if defined(__linux__) || defined(__MACOSX__)
#define strnicmp strncasecmp
#endif

#ifdef _WIN32
typedef intptr_t ssize_t;
#endif

#define _(msgid) msgid
#define N_(msgid) msgid

namespace PCSX {

class Memory;
class R3000Acpu;
class System;
class Counters;
class Bios;
class GTE;
class SIO;
class CDRom;
class Cheats;
class MDEC;

class Emulator {
  private:
    Emulator();
    ~Emulator();

  public:
    enum VideoType { PSX_TYPE_NTSC = 0, PSX_TYPE_PAL };                     // PSX Types
    enum CPUType { CPU_DYNAREC = 0, CPU_INTERPRETER };                      // CPU Types
    enum CDDAType { CDDA_ENABLED_LE = 0, CDDA_DISABLED, CDDA_ENABLED_BE };  // CDDA Types
    class PcsxConfig {
      public:
        std::string Mcd1;
        std::string Mcd2;
        std::string Bios;
        std::string BiosDir;
        std::string PatchesDir;
        std::string PsxExeName;
        bool Xa = false;
        bool SioIrq = false;
        bool Mdec = false;
        bool PsxAuto = false;
        CDDAType Cdda = CDDA_ENABLED_LE;
        bool HLE = false;
        bool SlowBoot = false;
        bool Debug = false;
        bool verbose = false;
        bool SpuIrq = false;
        bool RCntFix = false;
        bool UseNet = false;
        bool VSyncWA = false;
        bool NoMemcard = false;
        bool PerGameMcd = false;
        bool Widescreen = false;
        bool HideCursor = false;
        bool SaveWindowPos = false;
        int32_t WindowPos[2] = {0, 0};
        CPUType Cpu = CPU_DYNAREC;        // CPU_DYNAREC or CPU_INTERPRETER
        VideoType Video = PSX_TYPE_NTSC;  // PSX_TYPE_NTSC or PSX_TYPE_PAL
        uint32_t RewindCount = 0;
        uint32_t RewindInterval = 0;
        uint32_t AltSpeed1 = 0;  // Percent relative to natural speed.
        uint32_t AltSpeed2 = 0;
        uint8_t HackFix = 0;
        uint8_t MemHack = 0;
        bool OverClock = false;  // enable overclocking
        float PsxClock = 0.0f;
        // PGXP variables
        bool PGXP_GTE = false;
        bool PGXP_Cache = false;
        bool PGXP_Texture = false;
        uint32_t PGXP_Mode = 0;
    };

    // It is safe if these overflow
    uint32_t m_rewind_counter = 0;
    uint8_t m_vblank_count_hideafter = 0;

    // Used for overclocking
    // Make the timing events trigger faster as we are currently assuming everything
    // takes one cycle, which is not the case on real hardware.
    // FIXME: Count the proper cycle and get rid of this
    uint32_t m_psxClockSpeed = 33868800 /* 33.8688 MHz */;
    enum { BIAS = 2 };

    int EmuInit();
    void EmuReset();
    void EmuShutdown();
    void EmuUpdate();
    void EmuSetPGXPMode(uint32_t pgxpMode);

    PcsxConfig& config() { return m_config; }

    Memory* m_psxMem = NULL;
    R3000Acpu* m_psxCpu = NULL;
    Counters* m_psxCounters = NULL;
    Bios* m_psxBios = NULL;
    GTE* m_gte = NULL;
    SIO* m_sio = NULL;
    CDRom* m_cdrom = NULL;
    Cheats* m_cheats = NULL;
    MDEC* m_mdec = NULL;

    static Emulator& getEmulator() {
        static Emulator emulator;
        return emulator;
    }

  private:
    PcsxConfig m_config;
};

extern Emulator& g_emulator;

}  // namespace PCSX

#define gzfreeze(ptr, size)                   \
    {                                         \
        if (Mode == 1) gzwrite(f, ptr, size); \
        if (Mode == 0) gzread(f, ptr, size);  \
    }
