/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include <functional>
#include <string>

#include "core/psxemulator.h"
#include "core/system.h"
#include "fmt/format.h"
#include "support/list.h"
#include "support/tree.h"

namespace PCSX {

class Debug {
  public:
    static inline std::function<const char*()> s_breakpoint_type_names[] = {
        []() { return _("Exec"); }, []() { return _("Read"); }, []() { return _("Write"); }};
    enum class BreakpointType { Exec, Read, Write };

    void checkDMAread(unsigned c, uint32_t address, uint32_t len) {
        std::string cause = fmt::format("DMA channel {} read", c);
        checkBP(address, BreakpointType::Read, len, cause.c_str());
    }
    void checkDMAwrite(unsigned c, uint32_t address, uint32_t len) {
        std::string cause = fmt::format("DMA channel {} write", c);
        checkBP(address, BreakpointType::Write, len, cause.c_str());
    }

  private:
    void checkBP(uint32_t address, BreakpointType type, uint32_t width, const char* cause = "");

  public:
    // call this if PC is being set, like when the emulation is being reset, or when doing fastboot
    void updatedPC(uint32_t newPC);
    // call this as soon as possible after any instruction is run, with the oldPC, the newPC,
    // the opcode that was just executed, the next opcode to run, and a boolean to tell if we just
    // jumped around because of a previous "and link" opcode.
    void process(uint32_t oldPC, uint32_t newPC, uint32_t oldCode, uint32_t newCode, bool linked);
    std::string generateFlowIDC();
    std::string generateMarkIDC();

    class Breakpoint;
    typedef Intrusive::Tree<uint32_t, Breakpoint> BreakpointTreeType;
    typedef Intrusive::List<Breakpoint> BreakpointUserListType;

    typedef std::function<bool(const Breakpoint*, uint32_t address, unsigned width, const char* cause)>
        BreakpointInvoker;

    class Breakpoint : public BreakpointTreeType::Node, public BreakpointUserListType::Node {
      public:
        Breakpoint(BreakpointType type, const std::string& source, BreakpointInvoker invoker, uint32_t base)
            : m_type(type), m_source(source), m_invoker(invoker), m_base(base) {}
        std::string name() const;
        BreakpointType type() const { return m_type; }
        unsigned width() const { return getHigh() - getLow() + 1; }
        uint32_t address() const { return getLow(); }
        bool enabled() const { return m_enabled; }
        void enable() const { m_enabled = true; }
        void disable() const { m_enabled = false; }
        const std::string& source() const { return m_source; }
        uint32_t base() const { return m_base; }

      private:
        bool trigger(uint32_t address, unsigned width, const char* cause) {
            if (m_enabled) return m_invoker(this, address, width, strlen(cause) > 0 ? cause : m_source.c_str());
            return true;
        }

        const BreakpointType m_type;
        const std::string m_source;
        const BreakpointInvoker m_invoker;
        uint32_t m_base;
        mutable bool m_enabled = true;

        friend class Debug;
    };

    void stepIn() {
        m_step = STEP_IN;
        startStepping();
    }
    void stepOver() {
        m_step = STEP_OVER;
        startStepping();
    }
    void stepOut();

    bool m_mapping_e = false;
    bool m_mapping_r8 = false, m_mapping_r16 = false, m_mapping_r32 = false;
    bool m_mapping_w8 = false, m_mapping_w16 = false, m_mapping_w32 = false;
    bool m_breakmp_e = false;
    bool m_breakmp_r8 = false, m_breakmp_r16 = false, m_breakmp_r32 = false;
    bool m_breakmp_w8 = false, m_breakmp_w16 = false, m_breakmp_w32 = false;

  private:
    void startStepping();

  public:
    inline Breakpoint* addBreakpoint(
        uint32_t address, BreakpointType type, unsigned width, const std::string& source,
        BreakpointInvoker invoker = [](const Breakpoint* self, uint32_t address, unsigned width, const char* cause) {
            g_system->pause();
            return true;
        }) {
        uint32_t base = address & 0xe0000000;
        address &= ~0xe0000000;
        return &*m_breakpoints.insert(address, address + width - 1, new Breakpoint(type, source, invoker, base));
    }
    const BreakpointTreeType& getTree() { return m_breakpoints; }
    const Breakpoint* lastBP() { return m_lastBP; }
    void removeBreakpoint(const Breakpoint* bp) {
        if (m_lastBP == bp) m_lastBP = nullptr;
        delete const_cast<Breakpoint*>(bp);
    }

  private:
    bool triggerBP(Breakpoint* bp, uint32_t address, unsigned width, const char* reason = "");
    BreakpointTreeType m_breakpoints;

    uint8_t m_mainMemoryMap[0x00800000];
    uint8_t m_biosMemoryMap[0x00080000];
    uint8_t m_parpMemoryMap[0x00010000];
    uint8_t m_scratchPadMap[0x00000400];

    void markMap(uint32_t address, int mask);
    bool isMapMarked(uint32_t address, int mask);

    enum {
        STEP_NONE,
        STEP_IN,
        STEP_OVER,
        STEP_OUT,
    } m_step;

    bool m_stepperHasBreakpoint = false;

    bool m_wasInISR = false;
    Breakpoint* m_lastBP = nullptr;
    BreakpointUserListType m_todelete;
    std::optional<std::tuple<uint32_t, bool>> m_scheduledCop0;
};

}  // namespace PCSX
