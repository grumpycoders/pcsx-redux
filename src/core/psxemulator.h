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

#include <filesystem>
#include <memory>
#include <string>

#include "main/settings.h"

#ifndef MAXPATHLEN
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
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

// Local includes from core - anything else from core is forbidden
#include "core/logger.h"
#include "core/misc.h"
#include "core/system.h"

#if defined(__linux__) || defined(__MACOSX__)
#define strnicmp strncasecmp
#endif

#ifdef _WIN32
typedef intptr_t ssize_t;
#endif

namespace PCSX {

class Bios;
class CDRom;
class Cheats;
class Counters;
class Debug;
class GPU;
class GTE;
class HW;
class MDEC;
class Memory;
class PAD;
class R3000Acpu;
class SIO;
class SPUInterface;
class System;

class Emulator {
  private:
    Emulator();
    ~Emulator();
    Emulator(const Emulator&) = delete;
    Emulator& operator=(const Emulator&) = delete;

  public:
    enum VideoType { PSX_TYPE_NTSC = 0, PSX_TYPE_PAL };                     // PSX Types
    enum CPUType { CPU_DYNAREC = 0, CPU_INTERPRETER };                      // CPU Types
    enum CDDAType { CDDA_DISABLED = 0, CDDA_ENABLED_LE, CDDA_ENABLED_BE };  // CDDA Types
    struct OverlaySetting {
        typedef SettingPath<TYPESTRING("Filename")> Filename;
        typedef Setting<uint32_t, TYPESTRING("FileOffset")> FileOffset;
        typedef Setting<uint32_t, TYPESTRING("LoadOffset")> LoadOffset;
        typedef Setting<uint32_t, TYPESTRING("LoadSize")> LoadSize;
        typedef Setting<bool, TYPESTRING("Enabled")> Enabled;
        typedef Settings<Filename, FileOffset, LoadOffset, LoadSize, Enabled> type;
    };
    typedef SettingArray<TYPESTRING("Overlay"), OverlaySetting::type> SettingBiosOverlay;
    typedef Setting<bool, TYPESTRING("Stdout")> SettingStdout;
    typedef SettingPath<TYPESTRING("Logfile")> SettingLogfile;
    typedef SettingPath<TYPESTRING("Mcd1")> SettingMcd1;
    typedef SettingPath<TYPESTRING("Mcd2")> SettingMcd2;
    typedef SettingPath<TYPESTRING("Bios")> SettingBios;
    typedef SettingPath<TYPESTRING("PpfDir")> SettingPpfDir;
    typedef SettingPath<TYPESTRING("PsxExe")> SettingPsxExe;
    typedef Setting<bool, TYPESTRING("Xa"), true> SettingXa;
    typedef Setting<bool, TYPESTRING("SioIrq")> SettingSioIrq;
    typedef Setting<bool, TYPESTRING("SpuIrq")> SettingSpuIrq;
    typedef Setting<bool, TYPESTRING("BnWMdec")> SettingBnWMdec;
    typedef Setting<bool, TYPESTRING("AutoVideo"), true> SettingAutoVideo;
    typedef Setting<VideoType, TYPESTRING("Video"), PSX_TYPE_NTSC> SettingVideo;
    typedef Setting<CDDAType, TYPESTRING("CDDA"), CDDA_ENABLED_LE> SettingCDDA;
    typedef Setting<bool, TYPESTRING("HLE"), true> SettingHLE;
    typedef Setting<bool, TYPESTRING("FastBoot"), true> SettingFastBoot;
    typedef Setting<bool, TYPESTRING("Debug")> SettingDebug;
    typedef Setting<bool, TYPESTRING("Verbose")> SettingVerbose;
    typedef Setting<bool, TYPESTRING("RCntFix")> SettingRCntFix;
    typedef SettingPath<TYPESTRING("IsoPath")> SettingIsoPath;
    typedef SettingString<TYPESTRING("Locale")> SettingLocale;
    typedef Setting<bool, TYPESTRING("Mcd1Inserted"), true> SettingMcd1Inserted;
    typedef Setting<bool, TYPESTRING("Mcd2Inserted"), true> SettingMcd2Inserted;
    Settings<SettingStdout, SettingLogfile, SettingMcd1, SettingMcd2, SettingBios, SettingPpfDir, SettingPsxExe,
             SettingXa, SettingSioIrq, SettingSpuIrq, SettingBnWMdec, SettingAutoVideo, SettingVideo, SettingCDDA,
             SettingHLE, SettingFastBoot, SettingDebug, SettingVerbose, SettingRCntFix, SettingIsoPath, SettingLocale,
             SettingMcd1Inserted, SettingMcd2Inserted, SettingBiosOverlay>
        settings;
    class PcsxConfig {
      public:
        bool VSyncWA = false;
        bool PerGameMcd = false;
        bool Widescreen = false;
        bool HideCursor = false;
        bool SaveWindowPos = false;
        int32_t WindowPos[2] = {0, 0};
        CPUType Cpu = CPU_DYNAREC;  // CPU_DYNAREC or CPU_INTERPRETER
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

    std::unique_ptr<Memory> m_psxMem;
    std::unique_ptr<R3000Acpu> m_psxCpu;
    std::unique_ptr<Counters> m_psxCounters;
    std::unique_ptr<Bios> m_psxBios;
    std::unique_ptr<GTE> m_gte;
    std::unique_ptr<SIO> m_sio;
    std::unique_ptr<CDRom> m_cdrom;
    std::unique_ptr<Cheats> m_cheats;
    std::unique_ptr<MDEC> m_mdec;
    std::unique_ptr<GPU> m_gpu;
    std::unique_ptr<Debug> m_debug;
    std::unique_ptr<HW> m_hw;
    std::unique_ptr<SPUInterface> m_spu;
    std::unique_ptr<PAD> m_pad1;
    std::unique_ptr<PAD> m_pad2;

    static Emulator& getEmulator() {
        static Emulator emulator;
        return emulator;
    }

    char m_cdromId[10] = "";
    char m_cdromLabel[33] = "";

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
