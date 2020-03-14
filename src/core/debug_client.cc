/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include "core/debug_client.h"

/* clang-format off

PCSX-Redux Debug console protocol description, version 2.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Command numbers are formatted using %03X (yes)
Register numbers are formatted using %02X.
Breakpoint numbers are formatted using %X
All other values are formatted using %08X, unless specified.

Commands usually have a reply that is +100 from its number,
All commands should have one or more replies.

All lines end with CRLF "\r\n"

Some commands are only available on certain versions of the protocol.
Check version protocol to be certain of what you can expect to use.

The protocol is fairly lenient, and will not close the connection if
something invalid is sent. The protocol is meant to be as stateless
as possible. The emulation is a state machine however, and the client
is advised to try and refresh its state as much as possible. The
architecture means that more than one client is possible. However,
it isn't recommended at this time.

Version 1.0 of the protocol is what I wrote back in 2004. Version 2.0
tries to address some of the mistakes done then, and add some more
functions, based on the newest features of PCSX-Redux now.

Client inputs:
~~~~~~~~~~~~~
Basic commands (1xx):
--------------------
100 <message>
    Sends a message. Will be replied with a 200 reply, followed by the message.
    Use it as a test.
101
    Get PCSX-Redux version. Will reply with a 201 message.
102
    Get protocol version. Returns "1.0" or "2.0" at the moment, in a 202
    message. Semantic versionning rules should apply.
103
    Get status.
    Will reply with a 203 message.
110
    Get PC.
    Will reply with a 210 message.
111 [reg]
    Get GP register, or all, if no argument.
    Will reply with one or more 211 messages.
112
    Get LO/HI registers.
    Will reply with 212 messages.
113 [reg]
    Get COP0 register, or all, if no argument.
    Will reply with one or more 213 messages.
114 [reg]
    Get COP2 control register, or all, if no argument.
    Will reply with one or more 214 messages.
115 [reg]
    Get COP2 data register, or all, if no argument.
    Will reply with one or more 215 messages.
119 [pc]
    Disassemble current PC, or given PC.
    Will reply with 219 message.
121 <reg>=<value>
    Set a GP register.
    Will return a 221 message.
122 <LO|HI>=<value>
    Set LO or HI register.
    Will return a 222 message.
123 <reg>=<value>
    Set a COP0 register.
    Will return a 223 message.
124 <reg>=<value>
    Set a COP2 control register.
    Will return a 224 message.
125 <reg>=<value>
    Set a COP2 data register.
    Will return a 225 message.
130 <size>@<addr>
    Dumps a range of memory, of size bytes starting at addr.
    Will reply with a 230 message.
140 <size>@<addr>
    Set a range of memory, of size bytes starting at addr.
    Will have to send immediately exactly size bytes afterward.
    Will reply a 240 message.
150 [number]
    Start/reset mapping execution flow, or stop it if number = 0
151 [number]
    Start/reset mapping read8 flow, or stop it if number = 0
152 [number]
    Start/reset mapping read16 flow, or stop it if number = 0
153 [number]
    Start/reset mapping read32 flow, or stop it if number = 0
154 [number]
    Start/reset mapping write8 flow, or stop it if number = 0
155 [number]
    Start/reset mapping write16 flow, or stop it if number = 0
156 [number]
    Start/reset mapping write32 flow, or stop it if number = 0
160 [number]
    Break on map exec flow, or stop it if number = 0
161 [number]
    Break on map read8 flow, or stop it if number = 0
162 [number]
    Break on map read16 flow, or stop it if number = 0
163 [number]
    Break on map read32 flow, or stop it if number = 0
164 [number]
    Break on map write8 flow, or stop it if number = 0
165 [number]
    Break on map write16 flow, or stop it if number = 0
166 [number]
    Break on map write32 flow, or stop it if number = 0
170
    Dump the execution flow map in an IDC file

Execution flow control commands (3xx):
-------------------------------------
300 [number]
    Get a list of the actual breakpoints. Will get '400' answers.
301 [number]
    Delete a breakpoint, or all, if no arguments.
310 <address>
    Set an exec breakpoint.
320 <address>
    Set a read breakpoint, 1 byte / 8 bits.
321 <address>
    Set a read breakpoint, 2 bytes / 16 bits, has to be on an even address.
322 <address>
    Set a read breakpoint, 4 bytes / 32 bits, address has to be 4-bytes aligned.
330 <address>
    Set a write breakpoint, 1 byte / 8 bits.
331 <address>
    Set a write breakpoint, 2 bytes / 16 bits, has to be on an even address.
332 <address>
    Set a write breakpoint, 4 bytes / 32 bits, address has to be 4-bytes aligned.
390
    Pause execution. Equivalent to a breakpoint.
391
    Restart execution.
395 [number]
    Trace execution, 1 instruction by default. Formatted using %i.
396 [number]
    Disassemble and print current PC in trace mode.
398
    Soft (quick) reset.
399
    Reset.

Server outputs:
~~~~~~~~~~~~~~
Spontaneous messages (0xx):
--------------------------
000 <message>
    Greeting banner.
010 / 011 / 012 / 013 / 014 / 015 / 016
    Execution hit mapping flow automatic breakpoint.
030 <number>@<PC>
    Execution hit breakpoint, emulation is paused. Display PC's value.

Basic commands acknowledge (2xx):
--------------------------------
200 <message>
    Pong reply.
201 <message>
    Reply with PCSX-Redux version.
202 <message>
    Reply protocol version. Currently, 2.0
203 <status>
    status = 0: running; = 1: paused; = 2: trace
210 PC=<value>
    Display current program counter.
211 <reg>=<value>
    Display one GP register value.
212 LO=<value> HI=<value>
    Display LO/HI registers.
213 <reg>=<value>
    Display one COP0 register value.
214 <reg>=<value>
    Display one COP2 control register value.
215 <reg>=<value>
    Display one COP2 data register value.
219 <message>
    Display one line of disassembled code.
221 <reg>=<value>
    Display one GP register value, ack for modification.
222 LO=<value> HI=<value>
    Display LO/HI registers, ack for modification.
223 <reg>=<value>
    Display one COP0 register value, ack for modification.
224 <reg>=<value>
    Display one COP2 control register value, ack for modification.
225 <reg>=<value>
    Display one COP2 data register value, ack for modification.
230 <size>@<addr>
    Memory dump. Will then raw outputs size bytes, after the \r\n
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
    Display breakpoint, where 'type' can be of BE, BR1, BR2, BR4, BW1, BW2 or BW4.
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

clang-format on
*/

static bool isWhitespace(char c) {
    switch (c) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            return true;
    }
    return false;
}

static int fromHex(char c) {
    if ((c >= '0') && (c <= '9')) return c - '0';
    if ((c >= 'A') && (c <= 'F')) return c + 10 - 'A';
    if ((c >= 'a') && (c <= 'f')) return c + 10 - 'a';
    return -1;
}

void PCSX::DebugClient::processData(const Slice& slice) {
    const char* ptr = reinterpret_cast<const char*>(slice.data());
    auto size = slice.size();
    int v = 0;
    while (size) {
        if (m_state == DATA_PASSTHROUGH) {
            Slice passthrough;
            passthrough.borrow(ptr, size);
            passthrough = passthroughData(passthrough);
            ptr = reinterpret_cast<const char*>(passthrough.data());
            size = passthrough.size();
            continue;
        }
        char c = *ptr++;
        size--;
        if (!((c == '\r') || (c == '\n'))) m_fullCmd += c;
        switch (m_state) {
            case FIRST_CHAR:
                if (isWhitespace(c)) break;
                v = fromHex(c);
                if (v < 0) {
                    m_state = FAILED_CMD;
                } else {
                    m_state = SECOND_CHAR;
                    m_cmd |= (v << 8);
                }
                break;
            case SECOND_CHAR:
                v = fromHex(c);
                if (v < 0) {
                    m_state = FAILED_CMD;
                } else {
                    m_state = THIRD_CHAR;
                    m_cmd |= (v << 4);
                }
                break;
            case THIRD_CHAR:
                v = fromHex(c);
                if (v < 0) {
                    m_state = FAILED_CMD;
                } else {
                    m_state = CMD_WHITESPACE;
                    m_cmd |= v;
                }
                break;
            case CMD_WHITESPACE:
                if (c == ' ' || c == '\t') break;
                m_state = ARGUMENT1;
                m_argument1 += c;
                break;
            case ARGUMENT1:
                if (c == '@' || c == '=') {
                    m_separator = c;
                    m_state = ARGUMENT2;
                    break;
                }
                if (c == '\r') break;
                if (c == '\n') {
                    processCommand();
                } else {
                    m_argument1 += c;
                }
                break;
            case ARGUMENT2:
                if (c == '\r') break;
                if (c == '\n') {
                    processCommand();
                } else {
                    m_argument2 += c;
                }
                break;
            case FAILED_CMD:
                if (c == '\r') break;
                if (c == '\n') {
                    writef("500 Invalid command '%s'\r\n", m_fullCmd.c_str());
                    m_cmd = 0;
                    m_fullCmd.clear();
                    m_argument1.clear();
                    m_argument2.clear();
                    m_separator = 0;
                    m_state = FIRST_CHAR;
                }
                break;
        }
    }
}

void PCSX::DebugClient::processCommand() {
    switch (m_cmd) {
        case 0x100:
            if (m_separator) {
                writef("200 %s%c%s\r\n", m_argument1.c_str(), m_separator, m_argument2.c_str());
            } else {
                writef("200 %s\r\n", m_argument1.c_str());
            }
            break;
        case 0x101:
            write("201 PCSX-Redux\r\n");
            break;
        case 0x102:
            write("202 2.0\r\n");
            break;
        default:
            writef("500 Unknown command '%s'\r\n", m_fullCmd.c_str());
            break;
    }
    m_cmd = 0;
    m_fullCmd.clear();
    m_argument1.clear();
    m_argument2.clear();
    m_separator = 0;
    m_state = FIRST_CHAR;
}

PCSX::Slice PCSX::DebugClient::passthroughData(const Slice& slice) { return slice; }
