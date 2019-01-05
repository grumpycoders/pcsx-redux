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

#pragma once

#include "core/psxemulator.h"
#include "core/system.h"

namespace PCSX {

class Debug {
  public:
    enum breakpoint_types { BE, BR1, BR2, BR4, BW1, BW2, BW4 };

    void StartDebugger();
    void StopDebugger();

    void DebugVSync();
    void ProcessDebug();

    void DebugCheckBP(uint32_t address, enum breakpoint_types type);

    void PauseDebugger();
    void ResumeDebugger();

  private:
    int s_debugger_active = 0, s_paused = 0, s_trace = 0, s_printpc = 0, s_reset = 0, s_resetting = 0;
    int s_run_to = 0;
    uint32_t s_run_to_addr = 0;
    int s_step_over = 0;
    uint32_t s_step_over_addr = 0;
    int s_mapping_e = 0;
    int s_mapping_r8 = 0, s_mapping_r16 = 0, s_mapping_r32 = 0;
    int s_mapping_w8 = 0, s_mapping_w16 = 0, s_mapping_w32 = 0;
    int s_breakmp_e = 0;
    int s_breakmp_r8 = 0, s_breakmp_r16 = 0, s_breakmp_r32 = 0;
    int s_breakmp_w8 = 0, s_breakmp_w16 = 0, s_breakmp_w32 = 0;

    uint8_t *s_memoryMap = NULL;

    struct breakpoint_t {
        breakpoint_t *next, *prev;
        int number, type;
        uint32_t address;
    };

    breakpoint_t *s_firstBP = NULL;

    void ProcessCommands();
    int add_breakpoint(int type, uint32_t address);
    void delete_breakpoint(breakpoint_t *bp);
    breakpoint_t *next_breakpoint(breakpoint_t *bp);
    breakpoint_t *find_breakpoint(int number);
    void MarkMap(uint32_t address, int mask);
    int IsMapMarked(uint32_t address, int mask);
};

}  // namespace PCSX
