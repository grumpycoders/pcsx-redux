/*  Pcsx - Pc Psx Emulator
 *  Copyright (C) 1999-2003  Pcsx Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses>.
 */

#include "core/debug.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "core/socket.h"

/*
PCSXR Debug console protocol description, version 1.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Commands number are formatted using %03X (yes)
Registers number are formatted using %02X.
Breakpoints numbers are formatted using %X
All other values are formatted using %08X, unless specified.


Client inputs:
~~~~~~~~~~~~~
Basic commands (1xx):
--------------------
100 <message>
    Sends a dumb message. Will be replied with a 200 reply, followed by the message.
101
    Gets PCSXR version.
102
    Gets protocol version.
103
    Gets status
110
    Gets PC.
111 [reg]
    Gets GP register, or all, if no argument.
112
    Gets LO/HI registers.
113 [reg]
    Gets COP0 register, or all, if no argument.
114 [reg]
    Gets COP2 control register, or all, if no argument.
115 [reg]
    Gets COP2 data register, or all, if no argument.
119 [pc]
    Disassemble current PC, or given PC.
121 <reg>=<value>
    Sets a GP register. Will return a 221 message.
122 <LO|HI>=<value>
    Sets LO or HI register. Will return a 222 message.
123 <reg>=<value>
    Sets a COP0 register. Will return a 223 message.
124 <reg>=<value>
    Sets a COP2 control register. Will return a 224 message.
125 <reg>=<value>
    Sets a COP2 data register. Will return a 225 message.
130 <size>@<addr>
    Dumps a range of memory, of size bytes starting at addr.
140 <size>@<addr>
    Sets a range of memory, of size bytes starting at addr.
    Will have to send immediately exactly size bytes afterward.
150 [number]
    Starts/reset mapping execution flow, or stop it if number = 0
151 [number]
    Starts/reset mapping read8 flow, or stop it if number = 0
152 [number]
    Starts/reset mapping read16 flow, or stop it if number = 0
153 [number]
    Starts/reset mapping read32 flow, or stop it if number = 0
154 [number]
    Starts/reset mapping write8 flow, or stop it if number = 0
155 [number]
    Starts/reset mapping write16 flow, or stop it if number = 0
156 [number]
    Starts/reset mapping write32 flow, or stop it if number = 0
160 [number]
    Breaks on map exec flow, or stop it if number = 0
161 [number]
    Breaks on map read8 flow, or stop it if number = 0
162 [number]
    Breaks on map read16 flow, or stop it if number = 0
163 [number]
    Breaks on map read32 flow, or stop it if number = 0
164 [number]
    Breaks on map write8 flow, or stop it if number = 0
165 [number]
    Breaks on map write16 flow, or stop it if number = 0
166 [number]
    Breaks on map write32 flow, or stop it if number = 0
170
    Dumps the execution flow map in an IDC file

Execution flow control commands (3xx):
-------------------------------------
300 [number]
    Get a list of the actual breakpoints. Will get '400' answers.
301 [number]
    Deletes a breakpoint, or all, if no arguments.
310 <address>
    Sets an exec breakpoint.
320 <address>
    Sets a read breakpoint, 1 byte / 8 bits.
321 <address>
    Sets a read breakpoint, 2 bytes / 16 bits, has to be on an even address.
322 <address>
    Sets a read breakpoint, 4 bytes / 32 bits, address has to be 4-bytes aligned.
330 <address>
    Sets a write breakpoint, 1 byte / 8 bits.
331 <address>
    Sets a write breakpoint, 2 bytes / 16 bits, has to be on an even address.
332 <address>
    Sets a write breakpoint, 4 bytes / 32 bits, address has to be 4-bytes aligned.
390
    Pauses execution. Equivalents to a breakpoint.
391
    Restarts execution.
395 [number]
    Traces execution, 1 instruction by default. Formatted using %i.
396 [number]
    Disassemble and print current PC in trace mode.
398
    Soft (quick) resets.
399
    Resets.


Server outputs:
~~~~~~~~~~~~~~
Spontaneous messages (0xx):
--------------------------
000 <message>
    Greeting banner.
010 / 011 / 012 / 013 / 014 / 015 / 016
    Execution hit mapping flow automatic breakpoint.
030 <number>@<PC>
    Execution hit breakpoint, PCSXR is paused. Displays PC's value.

Basic commands acknowledge (2xx):
--------------------------------
200 <message>
    Sends a dumb message.
201 <message>
    Returns PCSXR version.
202 <message>
    Returns protocol version.
203 <status>
    status = 0: running; = 1: paused; = 2: trace
210 PC=<value>
    Displays current PC value.
211 <reg>=<value>
    Displays one GP register value.
212 LO=<value> HI=<value>
    Displays LO/HI registers.
213 <reg>=<value>
    Displays one COP0 register value.
214 <reg>=<value>
    Displays one COP2 control register value.
215 <reg>=<value>
    Displays one COP2 data register value.
219 <message>
    Displays one line of disassembled code.
221 <reg>=<value>
    Displays one GP register value, ack for modification.
222 LO=<value> HI=<value>
    Displays LO/HI registers, ack for modification.
223 <reg>=<value>
    Displays one COP0 register value, ack for modification.
224 <reg>=<value>
    Displays one COP2 control register value, ack for modification.
225 <reg>=<value>
    Displays one COP2 data register value, ack for modification.
230 <size>@<addr>
    Dumping memory. Will then raw outputs size bytes.
240 <size>@<addr>
    Memory set acknowledge.
250 / 251 / 252 / 253 / 254 / 255 / 256
    Acknolwedge of 15x commands.
260 / 261 / 262 / 263 / 264 / 265 / 266
    Acknolwedge of 16x commands.
270
    Acknolwedge of 170 command.

Execution flow control commands acknowledge (4xx):
-------------------------------------------------
400 <number>@<address>-<type>
    Displays a breakpoint, where 'type' can be of BE, BR1, BR2, BR4, BW1, BW2 or BW4.
401 <message>
    Breakpoint deleting acknowledge.
410, 420, 421, 422, 430, 431, 432 <number>
    Breakpoint adding acknowledge. Returns the number of the added breakpoint.
490 <message>
    Pausing.
491 <message>
    Resuming.
495 <message>
    Tracing.
496 <message>
    Printing.
498 <message>
    Soft resetting.
499 <message>
    Resetting.

Error messages (5xx):
--------------------
500 <message>
    Command not understood.
511 <message>
    Invalid GPR register.
512 <message>
    Invalid LO/HI register.
513, 514 <message>
    Invalid range or address.
530 <message>
    Non existant breakpoint.
531, 532, 533 <message>
    Invalid breakpoint address.
*/

static int s_debugger_active = 0, s_paused = 0, s_trace = 0, s_printpc = 0, s_reset = 0, s_resetting = 0;
static int s_run_to = 0;
static uint32_t s_run_to_addr = 0;
static int s_step_over = 0;
static uint32_t s_step_over_addr = 0;
static int s_mapping_e = 0, s_mapping_r8 = 0, s_mapping_r16 = 0, s_mapping_r32 = 0, s_mapping_w8 = 0, s_mapping_w16 = 0,
           s_mapping_w32 = 0;
static int s_breakmp_e = 0, s_breakmp_r8 = 0, s_breakmp_r16 = 0, s_breakmp_r32 = 0, s_breakmp_w8 = 0, s_breakmp_w16 = 0,
           s_breakmp_w32 = 0;

static void ProcessCommands();

static uint8_t *s_memoryMap = NULL;

enum {
    MAP_EXEC = 1,
    MAP_R8 = 2,
    MAP_R16 = 4,
    MAP_R32 = 8,
    MAP_W8 = 16,
    MAP_W16 = 32,
    MAP_W32 = 64,
    MAP_EXEC_JAL = 128,
};

static const char *s_breakpoint_type_names[] = {"E", "R1", "R2", "R4", "W1", "W2", "W4"};

typedef struct breakpoint_s {
    struct breakpoint_s *next, *prev;
    int number, type;
    uint32_t address;
} breakpoint_t;

static breakpoint_t *s_firstBP = NULL;

int add_breakpoint(int type, uint32_t address) {
    breakpoint_t *bp = (breakpoint_t *)malloc(sizeof(breakpoint_t));

    bp->type = type;
    bp->address = address;

    if (s_firstBP) {
        bp->number = s_firstBP->prev->number + 1;
        bp->next = s_firstBP;
        bp->prev = s_firstBP->prev;
        s_firstBP->prev = bp;
        bp->prev->next = bp;
    } else {
        s_firstBP = bp;
        bp->number = 1;
        bp->next = bp;
        bp->prev = bp;
    }

    return bp->number;
}

void delete_breakpoint(breakpoint_t *bp) {
    if (bp == s_firstBP) {
        if (bp->next == bp) {
            s_firstBP = NULL;
        } else {
            s_firstBP = bp->next;
        }
    }

    bp->next->prev = bp->prev;
    bp->prev->next = bp->next;

    free(bp);
}

breakpoint_t *next_breakpoint(breakpoint_t *bp) { return bp->next != s_firstBP ? bp->next : 0; }

breakpoint_t *find_breakpoint(int number) {
    breakpoint_t *p;

    for (p = s_firstBP; p; p = next_breakpoint(p)) {
        if (p->number == number) return p;
    }

    return 0;
}

void StartDebugger() {
    if (s_debugger_active) return;

    s_memoryMap = (uint8_t *)malloc(0x200000);
    if (s_memoryMap == NULL) {
        PCSX::g_system->SysMessage("%s", _("Error allocating memory"));
        return;
    }

    if (StartServer() == -1) {
        PCSX::g_system->SysPrintf("%s", _("Unable to start debug server.\n"));
        return;
    }

    PCSX::g_system->SysPrintf("%s", _("Debugger started.\n"));
    s_debugger_active = 1;
}

void StopDebugger() {
    if (s_debugger_active) {
        StopServer();
        PCSX::g_system->SysPrintf("%s", _("Debugger stopped.\n"));
    }

    if (s_memoryMap != NULL) {
        free(s_memoryMap);
        s_memoryMap = NULL;
    }

    while (s_firstBP != NULL) delete_breakpoint(s_firstBP);

    s_debugger_active = 0;
}

void PauseDebugger() {
    s_trace = 0;
    s_paused = 1;
}

void ResumeDebugger() {
    s_trace = 0;
    s_paused = 0;
}

void DebugVSync() {
    if (!s_debugger_active || s_resetting) return;

    if (s_reset) {
        s_resetting = 1;
        CheckCdrom();
        PCSX::g_system->SysReset();
        if (s_reset == 2) LoadCdrom();
        s_reset = s_resetting = 0;
        return;
    }

    GetClient();
    ProcessCommands();
}

void MarkMap(uint32_t address, int mask) {
    if ((address & 0xff000000) != 0x80000000) return;
    s_memoryMap[address & 0x001fffff] |= mask;
}

int IsMapMarked(uint32_t address, int mask) { return (s_memoryMap[address & 0x001fffff] & mask) != 0; }

void ProcessDebug() {
    if (!s_debugger_active || s_reset || s_resetting) return;
    if (s_trace) {
        if (!(--s_trace)) {
            s_paused = 1;
        }
    }
    if (!s_paused) {
        if (s_trace && s_printpc) {
            char reply[256];
            sprintf(reply, "219 %s\r\n",
                    disR3000AF(psxMemRead32(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc),
                               PCSX::g_emulator.m_psxCpu->m_psxRegs.pc));
            WriteSocket(reply, strlen(reply));
        }

        if (s_step_over) {
            if (PCSX::g_emulator.m_psxCpu->m_psxRegs.pc == s_step_over_addr) {
                char reply[256];
                s_step_over = 0;
                s_step_over_addr = 0;
                sprintf(reply, "050 @%08X\r\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
                WriteSocket(reply, strlen(reply));
                s_paused = 1;
            }
        }

        if (s_run_to) {
            if (PCSX::g_emulator.m_psxCpu->m_psxRegs.pc == s_run_to_addr) {
                char reply[256];
                s_run_to = 0;
                s_run_to_addr = 0;
                sprintf(reply, "040 @%08X\r\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
                WriteSocket(reply, strlen(reply));
                s_paused = 1;
            }
        }

        DebugCheckBP(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc, BE);
    }
    if (s_mapping_e) {
        MarkMap(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc, MAP_EXEC);
        if ((PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26) == 3) {
            MarkMap(_JumpTarget_, MAP_EXEC_JAL);
        }
        if (((PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26) == 0) &&
            ((PCSX::g_emulator.m_psxCpu->m_psxRegs.code & 0x3F) == 9)) {
            MarkMap(_Rd_, MAP_EXEC_JAL);
        }
    }
    while (s_paused) {
        GetClient();
        ProcessCommands();
        GPU_updateLace();
        PCSX::g_system->SysUpdate();
    }
}

static void ProcessCommands() {
    int code, i, dumping;
    FILE *sfile;
    char cmd[257], *arguments, *p, reply[10240], *save, *dump = NULL;
    uint32_t reg, value, size = 0, address;
    breakpoint_t *bp;

    if (!HasClient()) return;
    if (ReadSocket(cmd, 256) > 0) {
        arguments = NULL;
        if (strlen(cmd) <= 2) {
            code = 0;
        } else if (strlen(cmd) == 3) {
            code = strtol(cmd, 0, 16);
        } else if (!(isxdigit(cmd[0]) && isxdigit(cmd[1]) && isxdigit(cmd[2]) && (cmd[3] == 0x20))) {
            code = 0;
        } else if (sscanf(cmd, "%3X ", &code) != 1) {
            code = 0;
        } else {
            arguments = cmd + 4;
        }
        code = strtol(cmd, &arguments, 16);
        while (arguments && *arguments && *arguments == 0x20) arguments++;

        if (*arguments == '\0') arguments = NULL;

        dumping = 0;
        save = NULL;

        switch (code) {
            case 0x100:
                sprintf(reply, "200 %s\r\n", arguments == NULL ? "OK" : arguments);
                break;
            case 0x101:
                sprintf(reply, "201 %s\r\n", PACKAGE_VERSION);
                break;
            case 0x102:
                sprintf(reply, "202 1.0\r\n");
                break;
            case 0x103:
                sprintf(reply, "203 %i\r\n", s_paused ? 1 : s_trace ? 2 : 0);
                break;
            case 0x110:
                sprintf(reply, "210 PC=%08X\r\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
                break;
            case 0x111:
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "511 Malformed 111 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (!arguments) {
                    reply[0] = 0;
                    for (i = 0; i < 32; i++) {
                        sprintf(reply, "%s211 %02X(%2.2s)=%08X\r\n", reply, i, g_disRNameGPR[i],
                                PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[i]);
                    }
                } else {
                    if ((code >= 0) && (code < 32)) {
                        sprintf(reply, "211 %02X(%2.2s)=%08X\r\n", code, g_disRNameGPR[code],
                                PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[code]);
                    } else {
                        sprintf(reply, "511 Invalid GPR register: %X\r\n", code);
                    }
                }
                break;
            case 0x112:
                sprintf(reply, "212 LO=%08X HI=%08X\r\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo,
                        PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi);
                break;
            case 0x113:
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "511 Malformed 113 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (!arguments) {
                    reply[0] = 0;
                    for (i = 0; i < 32; i++) {
                        sprintf(reply, "%s213 %02X(%8.8s)=%08X\r\n", reply, i, g_disRNameCP0[i],
                                PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[i]);
                    }
                } else {
                    if ((code >= 0) && (code < 32)) {
                        sprintf(reply, "213 %02X(%8.8s)=%08X\r\n", code, g_disRNameCP0[code],
                                PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[code]);
                    } else {
                        sprintf(reply, "511 Invalid COP0 register: %X\r\n", code);
                    }
                }
                break;
            case 0x114:
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "511 Malformed 114 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (!arguments) {
                    reply[0] = 0;
                    for (i = 0; i < 32; i++) {
                        sprintf(reply, "%s214 %02X(%6.6s)=%08X\r\n", reply, i, g_disRNameCP2C[i],
                                PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2C.r[i]);
                    }
                } else {
                    if ((code >= 0) && (code < 32)) {
                        sprintf(reply, "214 %02X(%6.6s)=%08X\r\n", code, g_disRNameCP2C[code],
                                PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2C.r[code]);
                    } else {
                        sprintf(reply, "511 Invalid COP2C register: %X\r\n", code);
                    }
                }
                break;
            case 0x115:
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "511 Malformed 111 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (!arguments) {
                    reply[0] = 0;
                    for (i = 0; i < 32; i++) {
                        sprintf(reply, "%s215 %02X(%4.4s)=%08X\r\n", reply, i, g_disRNameCP2D[i],
                                PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[i]);
                    }
                } else {
                    if ((code >= 0) && (code < 32)) {
                        sprintf(reply, "215 %02X(%4.4s)=%08X\r\n", code, g_disRNameCP2D[code],
                                PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[code]);
                    } else {
                        sprintf(reply, "511 Invalid COP2D register: %X\r\n", code);
                    }
                }
                break;
            case 0x119:
                if (arguments) {
                    if (sscanf(arguments, "%08X", &code) != 1) {
                        sprintf(reply, "511 Malformed 119 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (!arguments) code = PCSX::g_emulator.m_psxCpu->m_psxRegs.pc;

                sprintf(reply, "219 %s\r\n", disR3000AF(psxMemRead32(code), code));
                break;
            case 0x121:
                if (!arguments || sscanf(arguments, "%02X=%08X", &reg, &value) != 2) {
                    sprintf(reply, "500 Malformed 121 command '%s'\r\n", arguments);
                    break;
                }

                if (reg < 32) {
                    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[reg] = value;
                    sprintf(reply, "221 %02X=%08X\r\n", reg, value);
                } else {
                    sprintf(reply, "512 Invalid GPR register: %02X\r\n", reg);
                }
                break;
            case 0x122:
                if (!arguments || strncmp(arguments, "HI=", 3) == 0) {
                    reg = 33;
                } else if (arguments && strncmp(arguments, "LO=", 3) == 0) {
                    reg = 32;
                } else {
                    arguments[2] = 0;
                    sprintf(reply, "512 Invalid LO/HI register: '%s'\r\n", arguments);
                    break;
                }

                if (sscanf(arguments + 3, "%08X", &value) != 1) {
                    sprintf(reply, "500 Malformed 122 command '%s'\r\n", arguments);
                } else {
                    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[reg] = value;
                    sprintf(reply, "222 LO=%08X HI=%08X\r\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo,
                            PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi);
                }
                break;
            case 0x123:
                if (!arguments || sscanf(arguments, "%02X=%08X", &reg, &value) != 2) {
                    sprintf(reply, "500 Malformed 123 command '%s'\r\n", arguments);
                    break;
                }

                if (reg < 32) {
                    PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[reg] = value;
                    sprintf(reply, "223 %02X=%08X\r\n", reg, value);
                } else {
                    sprintf(reply, "512 Invalid COP0 register: %02X\r\n", reg);
                }
                break;
            case 0x124:
                if (!arguments || sscanf(arguments, "%02X=%08X", &reg, &value) != 2) {
                    sprintf(reply, "500 Malformed 124 command '%s'\r\n", arguments);
                    break;
                }

                if (reg < 32) {
                    PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2C.r[reg] = value;
                    sprintf(reply, "224 %02X=%08X\r\n", reg, value);
                } else {
                    sprintf(reply, "512 Invalid COP2C register: %02X\r\n", reg);
                }
                break;
            case 0x125:
                if (!arguments || sscanf(arguments, "%02X=%08X", &reg, &value) != 2) {
                    sprintf(reply, "500 Malformed 121 command '%s'\r\n", arguments);
                    break;
                }

                if (reg < 32) {
                    PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[reg] = value;
                    sprintf(reply, "225 %02X=%08X\r\n", reg, value);
                } else {
                    sprintf(reply, "512 Invalid COP2D register: %02X\r\n", reg);
                }
                break;
            case 0x130:
                if (!arguments || sscanf(arguments, "%08X@%08X", &size, &address) != 2) {
                    sprintf(reply, "500 Malformed 130 command '%s'\r\n", arguments);
                    break;
                }

                if ((address >= 0x80000000) && ((address + size) <= 0x80200000)) {
                    sprintf(reply, "230 %08X@%08X\r\n", size, address);
                    dump = (char *)PSXM(address);
                    dumping = 1;
                } else {
                    sprintf(reply, "513 Invalid address or range: '%s'\r\n", arguments);
                }
                break;
            case 0x140:
                if (!arguments || sscanf(arguments, "%08X@%08X", &size, &address) != 2) {
                    sprintf(reply, "500 Malformed 140 command '%s'\r\n", arguments);
                    break;
                }

                if ((address >= 0x80000000) && ((address + size) <= 0x80200000)) {
                    sprintf(reply, "240 %08X@%08X\r\n", size, address);
                    RawReadSocket((char *)PSXM(address), size);
                } else {
                    sprintf(reply, "514 Invalid address or range: '%s'\r\n", arguments);
                }
                break;
            case 0x150:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 150 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_mapping_e = 1;
                    for (i = 0; i < 0x00200000; i++) {
                        s_memoryMap[i] &= ~MAP_EXEC;
                        s_memoryMap[i] &= ~MAP_EXEC_JAL;
                    }
                } else {
                    s_mapping_e = 0;
                }
                sprintf(reply, "250 Mapping of exec flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x151:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 151 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_mapping_r8 = 1;
                    for (i = 0; i < 0x00200000; i++) {
                        s_memoryMap[i] &= ~MAP_R8;
                    }
                } else {
                    s_mapping_r8 = 0;
                }
                sprintf(reply, "251 Mapping of read8 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x152:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 152 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_mapping_r16 = 1;
                    for (i = 0; i < 0x00200000; i++) {
                        s_memoryMap[i] &= ~MAP_R16;
                    }
                } else {
                    s_mapping_r16 = 0;
                }
                sprintf(reply, "252 Mapping of read16 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x153:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 153 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_mapping_r32 = 1;
                    for (i = 0; i < 0x00200000; i++) {
                        s_memoryMap[i] &= ~MAP_R32;
                    }
                } else {
                    s_mapping_r32 = 0;
                }
                sprintf(reply, "253 Mapping of read32 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x154:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 154 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_mapping_w8 = 1;
                    for (i = 0; i < 0x00200000; i++) {
                        s_memoryMap[i] &= ~MAP_W8;
                    }
                } else {
                    s_mapping_w8 = 0;
                }
                sprintf(reply, "254 Mapping of write8 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x155:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 155 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_mapping_w16 = 1;
                    for (i = 0; i < 0x00200000; i++) {
                        s_memoryMap[i] &= ~MAP_W16;
                    }
                } else {
                    s_mapping_w16 = 0;
                }
                sprintf(reply, "255 Mapping of write16 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x156:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 156 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_mapping_w32 = 1;
                    for (i = 0; i < 0x00200000; i++) {
                        s_memoryMap[i] &= ~MAP_W32;
                    }
                } else {
                    s_mapping_w32 = 0;
                }
                sprintf(reply, "256 Mapping of write32 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x160:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 160 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_breakmp_e = 1;
                } else {
                    s_breakmp_e = 0;
                }
                sprintf(reply, "260 Break on map of exec flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x161:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 161 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_breakmp_r8 = 1;
                } else {
                    s_breakmp_r8 = 0;
                }
                sprintf(reply, "261 Break on map of read8 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x162:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 162 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_breakmp_r16 = 1;
                } else {
                    s_breakmp_r16 = 0;
                }
                sprintf(reply, "262 Break on map of read16 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x163:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 163 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_breakmp_r32 = 1;
                } else {
                    s_breakmp_r32 = 0;
                }
                sprintf(reply, "263 Break on map of read32 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x164:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 164 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_breakmp_w8 = 1;
                } else {
                    s_breakmp_w8 = 0;
                }
                sprintf(reply, "264 Break on map of write8 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x165:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 165 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_breakmp_w16 = 1;
                } else {
                    s_breakmp_w16 = 0;
                }
                sprintf(reply, "265 Break on map of write16 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x166:
                code = 1;
                if (arguments) {
                    if (sscanf(arguments, "%02X", &code) != 1) {
                        sprintf(reply, "500 Malformed 166 command '%s'\r\n", cmd);
                        break;
                    }
                }
                if (code) {
                    s_breakmp_w32 = 1;
                } else {
                    s_breakmp_w32 = 0;
                }
                sprintf(reply, "266 Break on map of write32 flow %s\r\n", code ? "started" : "stopped");
                break;
            case 0x170:
                sfile = fopen("flow.idc", "wb");
                fprintf(sfile, "#include <idc.idc>\r\n\r\n");
                fprintf(sfile, "static main(void) {\r\n");
                for (i = 0; i < 0x00200000; i++) {
                    if (IsMapMarked(i, MAP_EXEC_JAL)) {
                        fprintf(sfile, "\tMakeFunction(0X8%07X,BADADDR);\r\n", i);
                    }
                }
                fprintf(sfile, "}\r\n");
                fclose(sfile);
                sfile = fopen("markcode.idc", "wb");
                fprintf(sfile, "#include <idc.idc>\r\n\r\n");
                fprintf(sfile, "static main(void) {\r\n");
                for (i = 0; i < 0x00200000; i++) {
                    if (IsMapMarked(i, MAP_EXEC)) {
                        fprintf(sfile, "\tMakeCode(0X8%07X);\r\n", i);
                    }
                }
                fprintf(sfile, "}\r\n");
                fclose(sfile);
                sprintf(reply, "270 flow.idc and markcode.idc dumped\r\n");
                break;
            case 0x300:
                p = arguments;
                if (arguments) {
                    code = strtol(arguments, &p, 16);
                }
                if (p == arguments) {
                    if (s_firstBP) {
                        reply[0] = 0;
                        for (bp = s_firstBP; bp; bp = next_breakpoint(bp)) {
                            sprintf(reply, "%s400 %X@%08X-%s\r\n", reply, bp->number, bp->address,
                                    s_breakpoint_type_names[bp->type]);
                        }
                    } else {
                        sprintf(reply, "530 No breakpoint\r\n");
                    }
                } else {
                    if ((bp = find_breakpoint(code))) {
                        sprintf(reply, "400 %X@%08X-%s\r\n", bp->number, bp->address,
                                s_breakpoint_type_names[bp->type]);
                    } else {
                        sprintf(reply, "530 Invalid breakpoint number: %X\r\n", code);
                    }
                }
                break;
            case 0x301:
                p = arguments;
                if (arguments) {
                    code = strtol(arguments, &p, 16);
                }
                if (p == arguments) {
                    while (s_firstBP != NULL) delete_breakpoint(s_firstBP);
                    sprintf(reply, "401 All breakpoints deleted.\r\n");
                } else {
                    if ((bp = find_breakpoint(code))) {
                        delete_breakpoint(bp);
                        sprintf(reply, "401 Breakpoint %X deleted.\r\n", code);
                    } else {
                        sprintf(reply, "530 Invalid breakpoint number: %X\r\n", code);
                    }
                }
                break;
            case 0x310:
                if (!arguments || sscanf(arguments, "%08X", &address) != 1) {
                    sprintf(reply, "500 Malformed 310 command '%s'\r\n", arguments);
                    break;
                }
                //            if ((address & 3) || (address < 0x80000000) || (address >= 0x80200000)) {
                //                sprintf(reply, "531 Invalid address %08X\r\n", address);
                //                break;
                //            }
                code = add_breakpoint(BE, address);
                sprintf(reply, "410 %X\r\n", code);
                break;
            case 0x320:
                if (!arguments || sscanf(arguments, "%08X", &address) != 1) {
                    sprintf(reply, "500 Malformed 320 command '%s'\r\n", arguments);
                    break;
                }
                if ((address < 0x80000000) || (address >= 0x80200000)) {
                    sprintf(reply, "532 Invalid address %08X\r\n", address);
                    break;
                }
                code = add_breakpoint(BR1, address);
                sprintf(reply, "420 %X\r\n", code);
                break;
            case 0x321:
                if (!arguments || sscanf(arguments, "%08X", &address) != 1) {
                    sprintf(reply, "500 Malformed 321 command '%s'\r\n", arguments);
                    break;
                }
                if ((address & 1) || (address < 0x80000000) || (address >= 0x80200000)) {
                    sprintf(reply, "532 Invalid address %08X\r\n", address);
                    break;
                }
                code = add_breakpoint(BR2, address);
                sprintf(reply, "421 %X\r\n", code);
                break;
            case 0x322:
                if (!arguments || sscanf(arguments, "%08X", &address) != 1) {
                    sprintf(reply, "500 Malformed 322 command '%s'\r\n", arguments);
                    break;
                }
                if ((address & 3) || (address < 0x80000000) || (address >= 0x80200000)) {
                    sprintf(reply, "532 Invalid address %08X\r\n", address);
                    break;
                }
                code = add_breakpoint(BR4, address);
                sprintf(reply, "422 %X\r\n", code);
                break;
            case 0x330:
                if (!arguments || sscanf(arguments, "%08X", &address) != 1) {
                    sprintf(reply, "500 Malformed 330 command '%s'\r\n", arguments);
                    break;
                }
                if ((address < 0x80000000) || (address >= 0x80200000)) {
                    sprintf(reply, "533 Invalid address %08X\r\n", address);
                    break;
                }
                code = add_breakpoint(BW1, address);
                sprintf(reply, "430 %X\r\n", code);
                break;
            case 0x331:
                if (!arguments || sscanf(arguments, "%08X", &address) != 1) {
                    sprintf(reply, "500 Malformed 331 command '%s'\r\n", arguments);
                    break;
                }
                if ((address & 1) || (address < 0x80000000) || (address >= 0x80200000)) {
                    sprintf(reply, "533 Invalid address %08X\r\n", address);
                    break;
                }
                code = add_breakpoint(BW2, address);
                sprintf(reply, "431 %X\r\n", code);
                break;
            case 0x332:
                if (!arguments || sscanf(arguments, "%08X", &address) != 1) {
                    sprintf(reply, "500 Malformed 332 command '%s'\r\n", arguments);
                    break;
                }
                if ((address & 3) || (address < 0x80000000) || (address >= 0x80200000)) {
                    sprintf(reply, "533 Invalid address %08X\r\n", address);
                    break;
                }
                code = add_breakpoint(BW4, address);
                sprintf(reply, "432 %X\r\n", code);
                break;
            case 0x390:
                s_paused = 1;
                sprintf(reply, "490 Paused\r\n");
                break;
            case 0x391:
                s_paused = 0;
                sprintf(reply, "491 Resumed\r\n");
                break;
            case 0x395:
                p = arguments;
                if (arguments) {
                    s_trace = strtol(arguments, &p, 10);
                }
                if (p == arguments) {
                    s_trace = 1;
                }
                s_paused = 0;
                sprintf(reply, "495 Tracing\r\n");
                break;
            case 0x396:
                p = arguments;
                if (arguments) {
                    s_printpc = strtol(arguments, &p, 10);
                }
                if (p == arguments) {
                    s_printpc = !s_printpc;
                }
                sprintf(reply, "496 Printing %s\r\n", s_printpc ? "enabled" : "disabled");
                break;
            case 0x398:
                s_paused = 0;
                s_trace = 0;
                s_reset = 2;
                sprintf(reply, "498 Soft resetting\r\n");
                break;
            case 0x399:
                s_paused = 0;
                s_trace = 0;
                s_reset = 1;
                sprintf(reply, "499 Resetting\r\n");
                break;
            case 0x3A0:
                // run to
                p = arguments;
                if (arguments) {
                    s_run_to = 1;
                    s_run_to_addr = strtol(arguments, &p, 16);
                    s_paused = 0;
                }
                if (p == arguments) {
                    sprintf(reply, "500 Malformed 3A0 command '%s'\r\n", arguments);
                    break;
                }
                sprintf(reply, "4A0 run to addr %08X\r\n", s_run_to_addr);
                break;
            case 0x3A1:
                // step over (jal)
                if (s_paused) {
                    uint32_t opcode = psxMemRead32(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
                    if ((opcode >> 26) == 3) {
                        s_step_over = 1;
                        s_step_over_addr = PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 8;
                        s_paused = 0;

                        sprintf(reply, "4A1 step over addr %08X\r\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
                    } else {
                        s_trace = 1;
                        s_paused = 0;
                    }
                }
                break;
            default:
                sprintf(reply, "500 Unknown command '%s'\r\n", cmd);
                break;
        }
        WriteSocket(reply, strlen(reply));

        if (dumping) {
            WriteSocket(dump, size);
        }

        if (save) {
            free(save);
        }
    }
}

void DebugCheckBP(uint32_t address, enum breakpoint_types type) {
    breakpoint_t *bp;
    char reply[512];

    if (!s_debugger_active || s_reset) return;

    for (bp = s_firstBP; bp; bp = next_breakpoint(bp)) {
        if ((bp->type == type) && (bp->address == address)) {
            sprintf(reply, "030 %X@%08X\r\n", bp->number, PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
            WriteSocket(reply, strlen(reply));
            s_paused = 1;
            return;
        }
    }
    if (s_breakmp_e && type == BE) {
        if (!IsMapMarked(address, MAP_EXEC)) {
            sprintf(reply, "010 %08X@%08X\r\n", address, PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
            WriteSocket(reply, strlen(reply));
            s_paused = 1;
        }
    }
    if (s_breakmp_r8 && type == BR1) {
        if (!IsMapMarked(address, MAP_R8)) {
            sprintf(reply, "011 %08X@%08X\r\n", address, PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
            WriteSocket(reply, strlen(reply));
            s_paused = 1;
        }
    }
    if (s_breakmp_r16 && type == BR2) {
        if (!IsMapMarked(address, MAP_R16)) {
            sprintf(reply, "012 %08X@%08X\r\n", address, PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
            WriteSocket(reply, strlen(reply));
            s_paused = 1;
        }
    }
    if (s_breakmp_r32 && type == BR4) {
        if (!IsMapMarked(address, MAP_R32)) {
            sprintf(reply, "013 %08X@%08X\r\n", address, PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
            WriteSocket(reply, strlen(reply));
            s_paused = 1;
        }
    }
    if (s_breakmp_w8 && type == BW1) {
        if (!IsMapMarked(address, MAP_W8)) {
            sprintf(reply, "014 %08X@%08X\r\n", address, PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
            WriteSocket(reply, strlen(reply));
            s_paused = 1;
        }
    }
    if (s_breakmp_w16 && type == BW2) {
        if (!IsMapMarked(address, MAP_W16)) {
            sprintf(reply, "015 %08X@%08X\r\n", address, PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
            WriteSocket(reply, strlen(reply));
            s_paused = 1;
        }
    }
    if (s_breakmp_w32 && type == BW4) {
        if (!IsMapMarked(address, MAP_W32)) {
            sprintf(reply, "016 %08X@%08X\r\n", address, PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);
            WriteSocket(reply, strlen(reply));
            s_paused = 1;
        }
    }
    if (s_mapping_r8 && type == BR1) MarkMap(address, MAP_R8);
    if (s_mapping_r16 && type == BR2) MarkMap(address, MAP_R16);
    if (s_mapping_r32 && type == BR4) MarkMap(address, MAP_R32);
    if (s_mapping_w8 && type == BW1) MarkMap(address, MAP_W8);
    if (s_mapping_w16 && type == BW2) MarkMap(address, MAP_W16);
    if (s_mapping_w32 && type == BW4) MarkMap(address, MAP_W32);
}
