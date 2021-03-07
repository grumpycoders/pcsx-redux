/***************************************************************************
 *   Copyright (C) 2018 PCSX-Redux authors                                 *
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

#pragma once

#include <stdarg.h>

#include "core/system.h"

namespace PCSX {

struct LogName {
    const char *name;
};

template <const LogName &name, bool enabled>
struct Logger {
    static void Log(const char *fmt, ...) {
        if (!enabled) return;
        va_list a;
        va_start(a, fmt);
        g_system->log(name.name, fmt, a);
        va_end(a);
    }
    static void LogVA(const char *fmt, va_list a) {
        if (!enabled) return;
        g_system->log(name.name, fmt, a);
    }
    static constexpr bool c_enabled = enabled;
};

static constexpr LogName PadLogName = {"PAD"};
static constexpr LogName Sio1LogName = {"SIO1"};
static constexpr LogName GteLogName = {"GTE"};
static constexpr LogName CdrLogName = {"CDR"};
static constexpr LogName CdrIOLogName = {"CDR_IO"};
static constexpr LogName EmuLogName = {"EMU"};
static constexpr LogName PsxHWLogName = {"PSXHW"};
static constexpr LogName PsxBIOSLogName = {"PSXBIOS"};
static constexpr LogName PsxDMALogName = {"PSXDMA"};
static constexpr LogName PsxMEMLogName = {"PSXMEM"};
static constexpr LogName PsxCPULogName = {"PSXCPU"};
static constexpr LogName MiscLogName = {"MISC"};

/*
 * Specifies at compilation time which logs should be activated.
 */
typedef Logger<PadLogName, false> PAD_LOGGER;
typedef Logger<Sio1LogName, false> SIO1_LOGGER;
typedef Logger<GteLogName, false> GTE_LOGGER;
typedef Logger<CdrLogName, false> CDR_LOGGER;
typedef Logger<CdrIOLogName, false> CDRIO_LOGGER;
typedef Logger<EmuLogName, false> EMU_LOGGER;
typedef Logger<PsxHWLogName, false> PSXHW_LOGGER;
typedef Logger<PsxBIOSLogName, false> PSXBIOS_LOGGER;
typedef Logger<PsxDMALogName, false> PSXDMA_LOGGER;
typedef Logger<PsxMEMLogName, false> PSXMEM_LOGGER;
typedef Logger<PsxCPULogName, false> PSXCPU_LOGGER;
typedef Logger<MiscLogName, false> MISC_LOGGER;

}  // namespace PCSX

#define PAD_LOG(...)                                                                       \
    {                                                                                      \
        PCSX::PAD_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                              PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::PAD_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define SIO1_LOG PCSX::SIO1_LOGGER::Log
#define GTE_LOG PCSX::GTE_LOGGER::Log
#define CDR_LOG(...)                                                                       \
    {                                                                                      \
        PCSX::CDR_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                              PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::CDR_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define CDR_LOG_IO(...)                                                                      \
    {                                                                                        \
        PCSX::CDRIO_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::CDRIO_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define EMU_LOG PCSX::EMU_LOGGER::Log
#define PSXHW_LOG(...)                                                                       \
    {                                                                                        \
        PCSX::PSXHW_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::PSXHW_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define PSXHW_LOGV(fmt, va)                                                                  \
    {                                                                                        \
        PCSX::PSXHW_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::PSXHW_LOGGER::LogVA(fmt, va);                                                  \
    }
#define PSXBIOS_LOG(...)                                                                       \
    {                                                                                          \
        PCSX::PSXBIOS_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                  PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::PSXBIOS_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define PSXDMA_LOG(...)                                                                       \
    {                                                                                         \
        PCSX::PSXDMA_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                 PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::PSXDMA_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define PSXMEM_LOG(...)                                                                       \
    {                                                                                         \
        PCSX::PSXMEM_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                 PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::PSXMEM_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define PSXCPU_LOG PCSX::PSXCPU_LOGGER::Log
#define MISC_LOG PCSX::MISC_LOGGER::Log
