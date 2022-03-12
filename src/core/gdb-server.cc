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

#include "core/gdb-server.h"

#include <assert.h>

#include "core/debug.h"
#include "core/misc.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "fmt/format.h"
#include "magic_enum/include/magic_enum.hpp"

const char PCSX::GdbClient::toHex[] = "0123456789ABCDEF";

PCSX::GdbServer::GdbServer() : m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) {
        if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::GdbServer>() &&
            (m_serverStatus != SERVER_STARTED)) {
            startServer(&g_emulator->m_loop, g_emulator->settings.get<Emulator::SettingDebugSettings>()
                                                 .get<Emulator::DebugSettings::GdbServerPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto& event) {
        if (m_serverStatus == SERVER_STARTED) stopServer();
    });
}

void PCSX::GdbServer::stopServer() {
    assert(m_serverStatus == SERVER_STARTED);
    m_serverStatus = SERVER_STOPPING;
    for (auto& client : m_clients) client.close();
    uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
}

void PCSX::GdbServer::startServer(uv_loop_t* loop, int port) {
    assert(m_serverStatus == SERVER_STOPPED);

    uv_tcp_init(loop, &m_server);
    m_server.data = this;

    struct sockaddr_in bindAddr;
    int result = uv_ip4_addr("0.0.0.0", port, &bindAddr);
    if (result != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
        return;
    }
    result = uv_tcp_bind(&m_server, reinterpret_cast<const sockaddr*>(&bindAddr), 0);
    if (result != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
        return;
    }
    result = uv_listen((uv_stream_t*)&m_server, 16, onNewConnectionTrampoline);
    if (result != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
        return;
    }
    m_serverStatus = SERVER_STARTED;
}

void PCSX::GdbServer::closeCB(uv_handle_t* handle) {
    GdbServer* self = static_cast<GdbServer*>(handle->data);
    self->m_serverStatus = SERVER_STOPPED;
}

void PCSX::GdbServer::onNewConnectionTrampoline(uv_stream_t* handle, int status) {
    GdbServer* self = static_cast<GdbServer*>(handle->data);
    self->onNewConnection(status);
}

void PCSX::GdbServer::onNewConnection(int status) {
    if (status < 0) return;
    GdbClient* client = new GdbClient(&m_server);
    if (client->accept(&m_server)) {
        m_clients.push_back(client);
    } else {
        delete client;
    }
}

PCSX::GdbClient::GdbClient(uv_tcp_t* srv) : m_listener(g_system->m_eventBus) {
    m_loop = srv->loop;
    uv_tcp_init(m_loop, &m_tcp);
    m_tcp.data = this;
    m_listener.listen<Events::ExecutionFlow::Run>([this](const auto& event) { m_exception = false; });
    m_listener.listen<Events::ExecutionFlow::Pause>([this](const auto& event) {
        m_exception = event.exception;
        if (m_waitingForShell) {
            // This is a bit of a problem. If there's any remaining
            // breakpoint, we just blow past them. I'm not sure
            // how or where to wipe all breakpoints. The gdb
            // protocol doesn't seem to have a command to list them.
            g_system->resume();
        }
        // we technically should specify here why we stopped, but we don't have
        // the architecture for this just yet. Maybe that'll be part of the pause
        // event later on.
        if (m_waitingForTrap) write("T05");
        m_waitingForTrap = false;
    });
    m_listener.listen<Events::ExecutionFlow::ShellReached>([this](const auto& event) {
        if (!m_waitingForShell) return;
        g_system->log(LogClass::GDB, "Shell reached in gdb-server, pausing execution now.\n");
        m_waitingForShell = false;
        g_system->pause();
        write("OK");
    });
    m_listener.listen<Events::LogMessage>([this](const auto& event) {
        auto& emuSettings = PCSX::g_emulator->settings;
        auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();
        auto gdbLog = debugSettings.get<Emulator::DebugSettings::GdbLogSetting>().value;
        if (gdbLog == Emulator::DebugSettings::GdbLog::None) return;
        if ((gdbLog == Emulator::DebugSettings::GdbLog::TTY) && (event.logClass != LogClass::MIPS)) return;
        if (event.logClass == LogClass::GDB) return;
        auto msg = fmt::format("PCSX::{}>{}", magic_enum::enum_name(event.logClass), event.message);
        writeEscaped(std::move(msg));
    });
}

static int fromHexChar(char c) {
    if ((c >= '0') && (c <= '9')) return c - '0';
    if ((c >= 'A') && (c <= 'F')) return c + 10 - 'A';
    if ((c >= 'a') && (c <= 'f')) return c + 10 - 'a';
    return -1;
}

void PCSX::GdbClient::processData(const Slice& slice) {
    const char* ptr = reinterpret_cast<const char*>(slice.data());
    auto size = slice.size();
    int v = 0;
    while (size) {
        if (m_passthrough) {  // passthrough
            Slice passthrough;
            passthrough.borrow(ptr, size);
            passthrough = passthroughData(passthrough);
            ptr = reinterpret_cast<const char*>(passthrough.data());
            size = passthrough.size();
            continue;
        }
        char c = *ptr++;
        size--;
        switch (m_state) {
            case WAIT_FOR_ACK:
                if (m_ackEnabled) {
                    if (c != '+') {
                        close();
                        break;
                    }
                }
            case WAIT_FOR_DOLLAR:
                if (c == '+') sendAck();
                if (c == 3) g_system->pause();
                if (c != '$') break;
                m_state = READING_COMMAND;
                break;
            case READING_COMMAND:
                if (c == '$') {
                    processCommand();
                    m_cmd.clear();
                    break;
                }
                if (c == '}') {
                    m_state = ESCAPE;
                    break;
                }
                if (c == '#') {
                    m_state = READING_CRC_FIRST_CHAR;
                    break;
                }
                m_cmd += c;
                break;
            case ESCAPE:
                m_cmd += c ^ ' ';
                m_state = READING_COMMAND;
                break;
            case READING_CRC_FIRST_CHAR:
                if (c == '$') {
                    processCommand();
                    m_cmd.clear();
                    m_state = READING_COMMAND;
                    break;
                } else {
                    m_state = READING_CRC_SECOND_CHAR;
                    m_crc = fromHexChar(c) << 4;
                }
                break;
            case READING_CRC_SECOND_CHAR:
                if (c == '$') {
                    m_state = READING_COMMAND;
                } else {
                    m_state = WAIT_FOR_DOLLAR;
                    m_crc |= fromHexChar(c);
                }
                processCommand();
                m_cmd.clear();
                break;
        }
    }
}

static std::pair<uint32_t, bool> parseHexNumber(const char* str) {
    uint64_t value = 0;
    char c;

    while ((c = *str++)) {
        int v = fromHexChar(c);
        if (v < 0) return std::pair<uint32_t, bool>(0, false);
        value <<= 4;
        value |= v;
        if (value > std::numeric_limits<uint32_t>::max()) return std::pair<uint32_t, bool>(0, false);
    }

    return std::pair<uint32_t, bool>(value, true);
}

static std::pair<uint32_t, bool> parseHexNumber(const std::string& str) { return parseHexNumber(str.c_str()); }

static const std::string memoryMap = R"(<?xml version="1.0"?>
<memory-map>
  <!-- Everything here is described as RAM, because we don't really
       have any better option. -->

  <!-- Main memory bloc: let's go with 8MB straight off the bat. -->
  <memory type="ram" start="0x0000000000000000" length="0x800000"/>
  <memory type="ram" start="0xffffffff80000000" length="0x800000"/>
  <memory type="ram" start="0xffffffffa0000000" length="0x800000"/>

  <!-- EXP1 can go up to 8MB too. -->
  <memory type="ram" start="0x000000001f000000" length="0x800000"/>
  <memory type="ram" start="0xffffffff9f000000" length="0x800000"/>
  <memory type="ram" start="0xffffffffbf000000" length="0x800000"/>

  <!-- Scratchpad -->
  <memory type="ram" start="0x000000001f800000" length="0x400"/>
  <memory type="ram" start="0xffffffff9f800000" length="0x400"/>

  <!-- Hardware registers -->
  <memory type="ram" start="0x000000001f801000" length="0x2000"/>
  <memory type="ram" start="0xffffffff9f801000" length="0x2000"/>
  <memory type="ram" start="0xffffffffbf801000" length="0x2000"/>

  <!-- DTL BIOS SRAM -->
  <memory type="ram" start="0x000000001fa00000" length="0x200000"/>
  <memory type="ram" start="0xffffffff9fa00000" length="0x200000"/>
  <memory type="ram" start="0xffffffffbfa00000" length="0x200000"/>

  <!-- BIOS -->
  <memory type="ram" start="0x000000001fc00000" length="0x80000"/>
  <memory type="ram" start="0xffffffff9fc00000" length="0x80000"/>
  <memory type="ram" start="0xffffffffbfc00000" length="0x80000"/>

  <!-- This really is only for 0xfffe0130 -->
  <memory type="ram" start="0xfffffffffffe0000" length="0x200"/>
</memory-map>
)";

static const std::string targetXML = R"(<?xml version="1.0"?>
<!DOCTYPE feature SYSTEM "gdb-target.dtd">
<target version="1.0">

<!-- Helping GDB -->
<architecture>mips:3000</architecture>
<osabi>none</osabi>

<!-- Mapping ought to be flexible, but there seems to be some
     hardcoded parts in gdb, so let's use the same mapping. -->
<feature name="org.gnu.gdb.mips.cpu">
  <reg name="r0" bitsize="32" regnum="0"/>
  <reg name="r1" bitsize="32"/>
  <reg name="r2" bitsize="32"/>
  <reg name="r3" bitsize="32"/>
  <reg name="r4" bitsize="32"/>
  <reg name="r5" bitsize="32"/>
  <reg name="r6" bitsize="32"/>
  <reg name="r7" bitsize="32"/>
  <reg name="r8" bitsize="32"/>
  <reg name="r9" bitsize="32"/>
  <reg name="r10" bitsize="32"/>
  <reg name="r11" bitsize="32"/>
  <reg name="r12" bitsize="32"/>
  <reg name="r13" bitsize="32"/>
  <reg name="r14" bitsize="32"/>
  <reg name="r15" bitsize="32"/>
  <reg name="r16" bitsize="32"/>
  <reg name="r17" bitsize="32"/>
  <reg name="r18" bitsize="32"/>
  <reg name="r19" bitsize="32"/>
  <reg name="r20" bitsize="32"/>
  <reg name="r21" bitsize="32"/>
  <reg name="r22" bitsize="32"/>
  <reg name="r23" bitsize="32"/>
  <reg name="r24" bitsize="32"/>
  <reg name="r25" bitsize="32"/>
  <reg name="r26" bitsize="32"/>
  <reg name="r27" bitsize="32"/>
  <reg name="r28" bitsize="32"/>
  <reg name="r29" bitsize="32"/>
  <reg name="r30" bitsize="32"/>
  <reg name="r31" bitsize="32"/>

  <reg name="lo" bitsize="32" regnum="33"/>
  <reg name="hi" bitsize="32" regnum="34"/>
  <reg name="pc" bitsize="32" regnum="37"/>
</feature>
<feature name="org.gnu.gdb.mips.cp0">
  <reg name="status" bitsize="32" regnum="32"/>
  <reg name="badvaddr" bitsize="32" regnum="35"/>
  <reg name="cause" bitsize="32" regnum="36"/>
</feature>

<!-- We don't have an FPU, but gdb hardcodes one, and will choke
     if this section isn't present. -->
<feature name="org.gnu.gdb.mips.fpu">
  <reg name="f0" bitsize="32" type="ieee_single" regnum="38"/>
  <reg name="f1" bitsize="32" type="ieee_single"/>
  <reg name="f2" bitsize="32" type="ieee_single"/>
  <reg name="f3" bitsize="32" type="ieee_single"/>
  <reg name="f4" bitsize="32" type="ieee_single"/>
  <reg name="f5" bitsize="32" type="ieee_single"/>
  <reg name="f6" bitsize="32" type="ieee_single"/>
  <reg name="f7" bitsize="32" type="ieee_single"/>
  <reg name="f8" bitsize="32" type="ieee_single"/>
  <reg name="f9" bitsize="32" type="ieee_single"/>
  <reg name="f10" bitsize="32" type="ieee_single"/>
  <reg name="f11" bitsize="32" type="ieee_single"/>
  <reg name="f12" bitsize="32" type="ieee_single"/>
  <reg name="f13" bitsize="32" type="ieee_single"/>
  <reg name="f14" bitsize="32" type="ieee_single"/>
  <reg name="f15" bitsize="32" type="ieee_single"/>
  <reg name="f16" bitsize="32" type="ieee_single"/>
  <reg name="f17" bitsize="32" type="ieee_single"/>
  <reg name="f18" bitsize="32" type="ieee_single"/>
  <reg name="f19" bitsize="32" type="ieee_single"/>
  <reg name="f20" bitsize="32" type="ieee_single"/>
  <reg name="f21" bitsize="32" type="ieee_single"/>
  <reg name="f22" bitsize="32" type="ieee_single"/>
  <reg name="f23" bitsize="32" type="ieee_single"/>
  <reg name="f24" bitsize="32" type="ieee_single"/>
  <reg name="f25" bitsize="32" type="ieee_single"/>
  <reg name="f26" bitsize="32" type="ieee_single"/>
  <reg name="f27" bitsize="32" type="ieee_single"/>
  <reg name="f28" bitsize="32" type="ieee_single"/>
  <reg name="f29" bitsize="32" type="ieee_single"/>
  <reg name="f30" bitsize="32" type="ieee_single"/>
  <reg name="f31" bitsize="32" type="ieee_single"/>

  <reg name="fcsr" bitsize="32" group="float"/>
  <reg name="fir" bitsize="32" group="float"/>
</feature>
</target>
)";

std::pair<uint64_t, uint64_t> PCSX::GdbClient::parseCursor(const std::string& cursorStr) {
    auto cursorStrs = Misc::split(cursorStr, ",");
    uint64_t off = 0;
    uint64_t len = 0;
    if (cursorStrs.size() == 2) {
        auto [pOff, properOff] = parseHexNumber(cursorStrs[0]);
        auto [pLen, properLen] = parseHexNumber(cursorStrs[1]);
        if (properOff) off = pOff;
        if (properLen) len = pLen;
    }

    return std::make_pair(off, len);
}

void PCSX::GdbClient::writePaged(const std::string& out, const std::string& cursorStr) {
    auto [off, len] = parseCursor(cursorStr);
    if (len < (out.length() - off)) {
        writef("m%s", out.substr(off, len).c_str());
    } else if (off != 0) {
        writef("l%s", out.substr(off, len).c_str());
    } else {
        writef("l%s", out.c_str());
    }
}

void PCSX::GdbClient::writeEscaped(const std::string& out) {
    std::string escaped;
    escaped.reserve(out.length() * 2 + 1);
    escaped += 'O';
    for (auto& c : out) {
        escaped += toHex[(c >> 4) & 0x0f];
        escaped += toHex[c & 0x0f];
    }

    write(std::move(escaped));
}

std::string PCSX::GdbClient::dumpValue(uint32_t value) {
    std::string ret = "";

    for (int i = 0; i < 4; i++) {
        ret += toHex[(value & 0xf0) >> 4];
        ret += toHex[(value & 0x0f)];
        value >>= 8;
    }

    return ret;
}

std::string PCSX::GdbClient::dumpOneRegister(int n) {
    // All registers are transferred as thirty-two bit quantities in the order:
    // 32 general-purpose; sr; lo; hi; bad; cause; pc;
    auto& regs = g_emulator->m_psxCpu->m_psxRegs;
    uint32_t value = 0;
    if (n < 32) {
        value = regs.GPR.r[n];
    } else if (n == 32) {
        value = regs.CP0.n.Status;
    } else if (n == 33) {
        value = regs.GPR.n.lo;
    } else if (n == 34) {
        value = regs.GPR.n.hi;
    } else if (n == 35) {
        value = regs.CP0.n.BadVAddr;
    } else if (n == 36) {
        value = regs.CP0.n.Cause;
    } else if (n == 37) {
        value = m_exception ? regs.CP0.n.EPC : regs.pc;
    }

    return dumpValue(value);
}

void PCSX::GdbClient::setOneRegister(int n, uint32_t value) {
    // All registers are transferred as thirty-two bit quantities in the order:
    // 32 general-purpose; sr; lo; hi; bad; cause; pc;
    value = ((value & 0xff000000) >> 24) | ((value & 0x00ff0000) >> 8) | ((value & 0x0000ff00) << 8) |
            ((value & 0x000000ff) << 24);
    auto& regs = g_emulator->m_psxCpu->m_psxRegs;
    if (n < 32) {
        regs.GPR.r[n] = value;
    } else if (n == 32) {
        regs.CP0.n.Status = value;
    } else if (n == 33) {
        regs.GPR.n.lo = value;
    } else if (n == 34) {
        regs.GPR.n.hi = value;
    } else if (n == 35) {
        regs.CP0.n.BadVAddr = value;
    } else if (n == 36) {
        regs.CP0.n.Cause = value;
    } else if (n == 37) {
        regs.pc = value;
    }
}

void PCSX::GdbClient::processCommand() {
    if (m_ackEnabled) sendAck();
    if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::GdbServerTrace>()) {
        g_system->log(LogClass::GDB, "GDB --> PCSX %s\n", m_cmd.c_str());
    }
    static const std::string qSupported = "qSupported:";
    static const std::string qXferFeatures = "qXfer:features:read:target.xml:";
    static const std::string qXferThreads = "qXfer:threads:read::";
    static const std::string qXferMemMap = "qXfer:memory-map:read::";
    static const std::string qSymbol = "qSymbol:";
    if (m_cmd == "!") {
        // extended mode?
        write("OK");
    } else if (m_cmd == "?") {
        // query reason for stop
        if (g_system->running()) {
            write("S00");
        } else {  // we may need one for 02 ? SIGINT
            write("S05");
        }
    } else if (m_cmd == "D") {
        // detach
        write("OK");
        close();
    } else if (m_cmd == "qC") {
        // return current thread id - always 00
        write("QC00");
    } else if (m_cmd == "qAttached") {
        // query if attached to existing process - always true
        write("1");
    } else if (m_cmd == "g") {
        // read general register
        // replies with all registers
        std::string all = "";
        startStream();
        // the protocol really wants 72 registers:
        // 32 gpr + status + lo + hi + badv + cause + 32 fpr + 3 fpu registers
        for (int i = 0; i < 72; i++) stream(dumpOneRegister(i));
        stopStream();
    } else if (Misc::startsWith(m_cmd, "p")) {
        if (m_cmd.size() != 3) {
            write("E00");
            close();
            return;
        }
        uint8_t n = fromHexChar(m_cmd[1]);
        n <<= 4;
        n |= fromHexChar(m_cmd[2]);
        dumpOneRegister(n);
    } else if (Misc::startsWith(m_cmd, "P")) {
        if ((m_cmd.length() != 12) || (m_cmd[3] != '=')) {
            write("E00");
            close();
            return;
        }
        uint8_t n = fromHexChar(m_cmd[1]);
        n <<= 4;
        n |= fromHexChar(m_cmd[2]);
        auto [value, valid] = parseHexNumber(m_cmd.substr(4));
        if (!valid) {
            write("E00");
            close();
            return;
        }
        setOneRegister(n, value);
        write("OK");
    } else if (m_cmd == "c") {
        // continue - this doesn't technically have a reply, only when the target stops later, using T05.
        g_system->resume();
        m_waitingForTrap = true;
    } else if (m_cmd[0] == 'M') {
        // write memory
        auto elements = Misc::split(m_cmd, ":");
        auto [off, len] = parseCursor(elements[0].substr(1));
        if (((off == 0x8000f800) && (len == 0x800)) || ((off == 0x8000ffea) && (len == 22))) {
            // heuristic for our ps-exe.ld and cpe.ld
            write("OK");
            return;
        }
        size_t i = 0;
        while (len--) {
            uint8_t* d = PSXM(off);
            off++;
            if (d) {
                uint8_t c = fromHexChar(elements[1][i * 2 + 0]);
                c <<= 4;
                c |= fromHexChar(elements[1][i * 2 + 1]);
                *d = c;
            }
            i++;
        }
        write("OK");
    } else if (m_cmd[0] == 'm') {
        // read memory
        auto [off, len] = parseCursor(m_cmd.substr(1));
        startStream();
        while (len--) {
            uint8_t* d = PSXM(off);
            off++;
            if (d) {
                uint8_t v = *d;
                char s[3] = {0, 0, 0};
                s[0] = toHex[v >> 4];
                s[1] = toHex[(v & 0x0f)];
                stream(s);
            } else {
                break;
            }
        }
        stopStream();
    } else if ((m_cmd[0] == 'z') || (m_cmd[0] == 'Z')) {
        // insert or remove breakpoint
        enum class Action {
            ADD,
            REMOVE,
        } action = m_cmd[0] == 'z' ? Action::REMOVE : Action::ADD;
        if (m_cmd.find(';') != std::string::npos) {
            // we're not going to support advanced conditional breakpoints
            write("");
            return;
        }
        auto breakpointData = Misc::split(m_cmd.substr(1), ",");
        if (breakpointData.size() != 3) {
            // wrong number of arguments
            write("");
            return;
        }
        auto [type, vtype] = parseHexNumber(breakpointData[0]);
        auto [addr, vaddr] = parseHexNumber(breakpointData[1]);
        auto [kind, vkind] = parseHexNumber(breakpointData[2]);
        if (!vtype || !vaddr || !vkind) {
            // didn't manage to parse breapoint data properly.
            write("E00");
            close();
            return;
        }
        const auto bpActionExec = [action, this](uint32_t addr, Debug::BreakpointType type, unsigned width) -> void {
            if (action == Action::ADD) {
                auto bp = g_emulator->m_debug->addBreakpoint(addr, type, 4, _("GDB client"));
                m_breakpoints.push_back(bp);
            } else {
                addr &= ~0xe0000000;
                auto& tree = g_emulator->m_debug->getTree();
                auto bp = tree.find(addr, Debug::BreakpointTreeType::INTERVAL_SEARCH);
                while (bp != tree.end()) {
                    if (bp->type() == type &&
                        !bp->Debug::BreakpointUserListType::Node::isLinked()) {
                        bp++;
                    } else {
                        g_emulator->m_debug->removeBreakpoint(&*bp);
                        bp = tree.find(addr, Debug::BreakpointTreeType::INTERVAL_SEARCH);
                    }
                }
            }
        };
        switch (type) {
            case 0:  // software breakpoint - meh, why?
            case 1:  // exec breakpoint
                // kind:
                //  2 = 16-bits MIPS16
                //  3 = 16-bits microMIPS
                //  4 = 32-bits MIPS
                //  5 = 32-bits microMIPS
                bpActionExec(addr, Debug::BreakpointType::Exec, 4);
                write("OK");
                break;
                // kind = number of bytes
            case 2:  // write breakpoint
                bpActionExec(addr, Debug::BreakpointType::Write, kind);
                write("OK");
                break;
            case 3:  // read breakpoint
                bpActionExec(addr, Debug::BreakpointType::Read, kind);
                write("OK");
                break;
            case 4:  // access breakpoint, aka both read and write
                bpActionExec(addr, Debug::BreakpointType::Read, kind);
                bpActionExec(addr, Debug::BreakpointType::Write, kind);
                write("OK");
                break;
            default:
                write("");
                return;
        }
    } else if (m_cmd == "s") {
        if (g_system->running()) g_system->pause();
        m_waitingForTrap = true;
        g_emulator->m_debug->stepIn();
    } else if (m_cmd == "Hc0") {
        // thread stuff
        write("OK");
    } else if (m_cmd == "Hc-1") {
        write("OK");
    } else if (m_cmd == "Hg0") {
        write("OK");
    } else if (Misc::startsWith(m_cmd, "vKill;")) {
        write("OK");
    } else if (Misc::startsWith(m_cmd, qSupported)) {
        // do we care about any features gdb supports?
        // auto elements = split(m_cmd.substr(qSupported.length()), ";");
        if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::GdbManifest>()) {
            write("PacketSize=4000;qXfer:features:read+;qXfer:threads:read+;qXfer:memory-map:read+;QStartNoAckMode+");
        } else {
            write("PacketSize=4000;qXfer:threads:read+;QStartNoAckMode+");
        }
    } else if (Misc::startsWith(m_cmd, "QStartNoAckMode")) {
        m_ackEnabled = false;
        write("OK");
    } else if (Misc::startsWith(m_cmd, "qRcmd,")) {
        // this is the "monitor" command
        size_t len = m_cmd.length() - 6;
        std::string monitor;
        monitor.reserve(len / 2);
        for (size_t i = 0; i < len; i += 2) {
            char c = fromHexChar(m_cmd[i + 6]);
            c <<= 4;
            c |= fromHexChar(m_cmd[i + 7]);
            monitor += c;
        }
        processMonitorCommand(monitor);
    } else if (Misc::startsWith(m_cmd, qXferMemMap) &&
               g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::GdbManifest>()) {
        writePaged(memoryMap, m_cmd.substr(qXferMemMap.length()));
    } else if (Misc::startsWith(m_cmd, qXferFeatures) &&
               g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::GdbManifest>()) {
        writePaged(targetXML, m_cmd.substr(qXferFeatures.length()));
    } else if (Misc::startsWith(m_cmd, qXferThreads)) {
        writePaged("<?xml version=\"1.0\"?><threads></threads>", m_cmd.substr(qXferThreads.length()));
    } else {
        g_system->log(LogClass::GDB, "Unknown GDB command: %s\n", m_cmd.c_str());
        write("");
    }
}

void PCSX::GdbClient::processMonitorCommand(const std::string& cmd) {
    if (Misc::startsWith(cmd, "reset")) {
        g_system->softReset();
        writeEscaped("Emulation reset\n");
        auto words = Misc::split(cmd, " ");
        if (words.size() == 2) {
            if (words[1] == "halt") {
                writeEscaped("Emulation paused\n");
                g_system->pause();
            } else if (words[1] == "shellhalt") {
                writeEscaped("Emulation running until shell\n");
                m_waitingForShell = true;
                g_system->start();
                // let's not reply to gdb just yet, until we've reached the shell
                // and are ready to load a binary.
                return;
            } else if (words[1] == "hard") {
                writeEscaped("Emulation hard-reset\n");
                g_system->hardReset();
            }
        }
    }
    write("OK");
}

PCSX::Slice PCSX::GdbClient::passthroughData(Slice slice) { return slice; }
