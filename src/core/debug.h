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
#include <list>
#include <string>

#include "core/psxemulator.h"
#include "core/system.h"

namespace PCSX {

class Debug {
  public:
    enum BreakpointType { BE, BR1, BR2, BR4, BW1, BW2, BW4 };
    static inline const char *s_breakpoint_type_names[] = {"E", "R1", "R2", "R4", "W1", "W2", "W4"};

    void ProcessDebug();
    void DebugCheckBP(uint32_t address, BreakpointType type);
    std::string GenerateFlowIDC();
    std::string GenerateMarkIDC();

    class Breakpoint {
      public:
        BreakpointType Type() const { return m_type; }
        uint32_t Address() const { return m_address; }
        Breakpoint(uint32_t address, BreakpointType type, bool temporary = false)
            : m_address(address), m_type(type), m_temporary(temporary) {}

      private:
        uint32_t m_address;
        BreakpointType m_type;
        bool m_temporary;
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

  private:
    void startStepping();
    typedef std::list<Breakpoint> BreakpointList;

  public:
    typedef BreakpointList::const_iterator bpiterator;
    inline void AddBreakpoint(uint32_t address, BreakpointType type, bool temporary = false) {
        m_breakpoints.emplace_back(address, type, temporary);
    }
    inline void ForEachBP(std::function<bool(bpiterator)> lambda) {
        for (auto i = m_breakpoints.begin(); i != m_breakpoints.end(); i++) {
            if (!lambda(i)) return;
        }
    }
    inline void EraseBP(bpiterator pos) { m_breakpoints.erase(pos); }
    inline bool HasLastBP() { return m_lastBP != m_breakpoints.end(); }
    inline bpiterator LastBP() { return m_lastBP; }

  private:
    BreakpointList m_breakpoints;
    bpiterator m_lastBP = m_breakpoints.end();

    bool m_mapping_e = false;
    bool m_mapping_r8 = false, m_mapping_r16 = false, m_mapping_r32 = false;
    bool m_mapping_w8 = false, m_mapping_w16 = false, m_mapping_w32 = false;
    bool m_breakmp_e = false;
    bool m_breakmp_r8 = false, m_breakmp_r16 = false, m_breakmp_r32 = false;
    bool m_breakmp_w8 = false, m_breakmp_w16 = false, m_breakmp_w32 = false;

    uint8_t m_mainMemoryMap[0x00200000];
    uint8_t m_biosMemoryMap[0x00080000];
    uint8_t m_parpMemoryMap[0x00010000];
    uint8_t m_scratchPadMap[0x00000400];

    void MarkMap(uint32_t address, int mask);
    bool IsMapMarked(uint32_t address, int mask);
    void triggerBP(bpiterator bp);

    enum {
        STEP_IN,
        STEP_OVER,
        STEP_OUT,
    } m_stepType;
    bool m_stepping = false;
    int m_steppingJumps = 0;
};

}  // namespace PCSX
