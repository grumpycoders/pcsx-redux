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
    UNCATEGORIZED,  // anything printf that hasn't been converted yet
    MIPS,           // only the things coming from MIPS code
    UI,             // messages from the UI specifically
    SIO0,           // pad and memory card information
    SIO1,           // uart information
    GTE,            // gte information
    CDROM,          // low level cdrom information
    CDROM_IO,       // high level cdrom information (iso file access)
    CPU,            // CPU-related information
    HARDWARE,       // hardware-level (0x1f801000) information
    DMA,            // dma-related information
    MEMORY,         // memory access related information
    IRQ,            // irq scheduling and triggering information
};

template <LogClass logClass, bool enabled>
struct Logger {
    template <typename... Args>
    static void Log(const char *format, const Args &...args) {
        if (!enabled) return;
        std::string s = fmt::sprintf(format, args...);
        g_system->log(logClass, s);
    }
    static void Log(const std::string &s) {
        if (!enabled) return;
        g_system->log(logClass, s);
    }
    static constexpr bool c_enabled = enabled;
    static constexpr LogClass c_logClass = logClass;
};

// Specifies at compilation time which logs should be activated.
// The rule of thumb is they typically can be spammy or costly,
// and shouldn't be enabled on a retail build.
typedef Logger<LogClass::SIO0, false> SIO0_LOGGER;
typedef Logger<LogClass::SIO1, false> SIO1_LOGGER;
typedef Logger<LogClass::GTE, false> GTE_LOGGER;
typedef Logger<LogClass::CDROM, false> CDROM_LOGGER;
typedef Logger<LogClass::CDROM_IO, false> CDROM_IO_LOGGER;
typedef Logger<LogClass::HARDWARE, false> PSXHW_LOGGER;
typedef Logger<LogClass::DMA, false> PSXDMA_LOGGER;
typedef Logger<LogClass::MEMORY, false> PSXMEM_LOGGER;
typedef Logger<LogClass::IRQ, false> PSXIRQ_LOGGER;

}  // namespace PCSX

#define SIO0_LOG(...)                                                                       \
    {                                                                                       \
        PCSX::SIO0_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                               PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::SIO0_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define SIO1_LOG PCSX::SIO1_LOGGER::Log
#define GTE_LOG PCSX::GTE_LOGGER::Log
#define CDROM_LOG(...)                                                                       \
    {                                                                                        \
        PCSX::CDROM_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::CDROM_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define CDROM_IO_LOG(...)                                                                       \
    {                                                                                           \
        PCSX::CDROM_IO_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                   PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::CDROM_IO_LOGGER::Log(__VA_ARGS__);                                                \
    }
#define PSXHW_LOG(...)                                                                       \
    {                                                                                        \
        PCSX::PSXHW_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::PSXHW_LOGGER::Log(__VA_ARGS__);                                                \
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
#define PSXIRQ_LOG(...)                                                                       \
    {                                                                                         \
        PCSX::PSXIRQ_LOGGER::Log("%8.8lx %8.8lx: ", PCSX::g_emulator->m_psxCpu->m_psxRegs.pc, \
                                 PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle);                \
        PCSX::PSXIRQ_LOGGER::Log(__VA_ARGS__);                                                \
    }
