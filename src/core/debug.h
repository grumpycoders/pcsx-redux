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
#include <map>
#include <string>

#include "core/psxemulator.h"
#include "core/system.h"

namespace PCSX {

class Debug {
  public:
    enum BreakpointType { BE, BR1, BR2, BR4, BW1, BW2, BW4 };
    static inline std::function<const char *()> s_breakpoint_type_names[] = {
      [](){ return _("Exec"); },
      [](){ return _("Read Byte"); },
      [](){ return _("Read Half"); },
      [](){ return _("Read Word"); },
      [](){ return _("Write Byte"); },
      [](){ return _("Write Half"); },
      [](){ return _("Write Word"); },
    };

    void processBefore();
    void processAfter();
    void checkBP(uint32_t address, BreakpointType type, const char * reason = nullptr);
    std::string generateFlowIDC();
    std::string generateMarkIDC();

    class Breakpoint {
      public:
        BreakpointType type() const { return m_type; }
        bool enabled() const { return m_enabled; }
        void enable() const { m_enabled = true; }
        void disable() const { m_enabled = false; }
        Breakpoint(BreakpointType type, bool temporary = false) : m_type(type), m_temporary(temporary) {}
        Breakpoint() : m_type(BE), m_temporary(true) {}

      private:
        BreakpointType m_type;
        bool m_temporary;
        mutable bool m_enabled = true;
        friend class Debug;
    };

    void stepIn() {
        m_stepType = STEP_IN;
        startStepping();
    }
    void stepOver() {
        m_stepType = STEP_OVER;
        startStepping();
    }
    void stepOut() {
        m_stepType = STEP_OUT;
        startStepping();
    }

    bool m_mapping_e = false;
    bool m_mapping_r8 = false, m_mapping_r16 = false, m_mapping_r32 = false;
    bool m_mapping_w8 = false, m_mapping_w16 = false, m_mapping_w32 = false;
    bool m_breakmp_e = false;
    bool m_breakmp_r8 = false, m_breakmp_r16 = false, m_breakmp_r32 = false;
    bool m_breakmp_w8 = false, m_breakmp_w16 = false, m_breakmp_w32 = false;

  private:
    void startStepping();
    typedef std::multimap<uint32_t, Breakpoint> BreakpointList;

  public:
    typedef BreakpointList::const_iterator bpiterator;
    inline void addBreakpoint(uint32_t address, BreakpointType type, bool temporary = false) {
        m_breakpoints.insert({address, {type, temporary}});
    }
    inline auto findBreakpoints(uint32_t address) { return m_breakpoints.equal_range(address); }
    inline void forEachBP(std::function<bool(bpiterator)> lambda) {
        for (auto i = m_breakpoints.begin(); i != m_breakpoints.end(); i++) {
            if (!lambda(i)) return;
        }
    }
    inline bool isValidBP(bpiterator pos) { return m_breakpoints.end() != pos; }
    inline void eraseBP(bpiterator pos) { m_breakpoints.erase(pos); }
    inline bpiterator lastBP() { return m_lastBP; }
    inline bpiterator endBP() { return m_breakpoints.end(); }

  private:
    BreakpointList m_breakpoints;
    bpiterator m_lastBP = m_breakpoints.end();

    uint8_t m_mainMemoryMap[0x00200000];
    uint8_t m_biosMemoryMap[0x00080000];
    uint8_t m_parpMemoryMap[0x00010000];
    uint8_t m_scratchPadMap[0x00000400];

    void markMap(uint32_t address, int mask);
    bool isMapMarked(uint32_t address, int mask);
    void triggerBP(bpiterator bp, const char * reason);

    enum {
        STEP_IN,
        STEP_OVER,
        STEP_OUT,
    } m_stepType;
    bool m_stepping = false;
    int m_steppingJumps = 0;
};

}  // namespace PCSX
