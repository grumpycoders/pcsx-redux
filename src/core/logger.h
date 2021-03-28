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
#include "fmt/printf.h"
#include "magic_enum/include/magic_enum.hpp"

namespace PCSX {

enum class LogClass : unsigned {
    UNCATEGORIZED,
    MIPS,
    UI,
    PAD,
    SIO1,
    GTE,
    CDR,
    CDR_IO,
    EMU,
    PSXHW,
    PSXBIOS,
    PSXDMA,
    PSXMEM,
    PSXCPU,
    MISC,
};

template <LogClass logClass, bool enabled>
struct Logger {
    template <typename... Args>
    static void Log(const char *format, const Args &...args) {
        if (!enabled) return;
        std::string s = fmt::sprintf(format, args...);
        g_system->log(logClass, s);
    }
    static void Log(const std::string & s) {
        if (!enabled) return;
        g_system->log(logClass, s);
    }
    static constexpr bool c_enabled = enabled;
    static constexpr LogClass c_logClass = logClass;
};

/*
 * Specifies at compilation time which logs should be activated.
 */
typedef Logger<LogClass::PAD, false> PAD_LOGGER;
typedef Logger<LogClass::SIO1, false> SIO1_LOGGER;
typedef Logger<LogClass::GTE, false> GTE_LOGGER;
typedef Logger<LogClass::CDR, false> CDR_LOGGER;
typedef Logger<LogClass::CDR_IO, false> CDRIO_LOGGER;
typedef Logger<LogClass::EMU, false> EMU_LOGGER;
typedef Logger<LogClass::PSXHW, false> PSXHW_LOGGER;
typedef Logger<LogClass::PSXBIOS, false> PSXBIOS_LOGGER;
typedef Logger<LogClass::PSXDMA, false> PSXDMA_LOGGER;
typedef Logger<LogClass::PSXMEM, false> PSXMEM_LOGGER;
typedef Logger<LogClass::PSXCPU, false> PSXCPU_LOGGER;
typedef Logger<LogClass::MISC, false> MISC_LOGGER;

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
#define PSXCPU_LOG(...)                                                                       \
    {                                                                                         \
        PCSX::PSXCPU_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                 PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::PSXCPU_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define MISC_LOG PCSX::MISC_LOGGER::Log
