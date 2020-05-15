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
#include <uv.h>

#include <vector>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "core/uv_wrapper.h"

const char PCSX::GdbClient::toHex[] = "0123456789ABCDEF";

PCSX::GdbServer::GdbServer() : m_listener(g_system->getEventBus()) {
    m_listener.listen([this](const Events::SettingsLoaded& event) {
        if (g_emulator->settings.get<Emulator::SettingGdbServer>()) {
            startServer(g_emulator->settings.get<Emulator::SettingGdbServerPort>());
        }
    });
    m_listener.listen([this](const Events::Quitting& event) {
        if (m_serverStatus == SERVER_STARTED) stopServer();
    });
}

void PCSX::GdbServer::stopServer() {
    assert(m_serverStatus == SERVER_STARTED);
    for (auto& client : m_clients) client.close();
    uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
}

void PCSX::GdbServer::startServer(int port) {
    assert(m_serverStatus == SERVER_STOPPED);
    uv_tcp_init(&PCSX::g_emulator->m_uv->m_loop, &m_server);

    m_server.data = this;

    struct sockaddr_in bindAddr;
    int result = uv_ip4_addr("0.0.0.0", port, &bindAddr);
    assert(result == 0);
    result = uv_tcp_bind(&m_server, reinterpret_cast<const sockaddr*>(&bindAddr), 0);
    assert(result == 0);
    result = uv_listen((uv_stream_t*)&m_server, 16, onNewConnectionTrampoline);

    m_serverStatus = SERVER_STARTED;
}

void PCSX::GdbServer::onNewConnectionTrampoline(uv_stream_t* server, int status) {
    GdbServer* self = static_cast<GdbServer*>(server->data);
    self->onNewConnection(status);
}

void PCSX::GdbServer::onNewConnection(int status) {
    if (status < 0) return;
    GdbClient* client = new GdbClient(m_server.loop);
    if (client->accept(&m_server)) {
        m_clients.push_back(client);
    } else {
        delete client;
    }
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

static std::vector<std::string> split(const std::string& str, const std::string& delim) {
    std::vector<std::string> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string token = str.substr(prev, pos - prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());
    return std::move(tokens);
}

static bool startsWith(const std::string& s1, const std::string& s2) { return s1.rfind(s2, 0) == 0; }

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
  <memory type="ram" start="0x00000000" length="0x200000"/>
  <memory type="ram" start="0x80000000" length="0x200000"/>
  <memory type="ram" start="0xa0000000" length="0x200000"/>
  <memory type="ram" start="0x1f800000" length="0x400"/>
  <memory type="ram" start="0x9f800000" length="0x400"/>
  <memory type="ram" start="0x1f801000" length="0x1000"/>
  <memory type="ram" start="0x9f801000" length="0x1000"/>
  <memory type="ram" start="0xbf801000" length="0x1000"/>
  <memory type="rom" start="0x1fc00000" length="0x80000"/>
  <memory type="rom" start="0x9fc00000" length="0x80000"/>
  <memory type="rom" start="0xbfc00000" length="0x80000"/>
  <memory type="ram" start="0xfffe0000" length="0x200"/>
</memory-map>
)";

static const std::string targetXML = R"(<?xml version="1.0"?>
<!DOCTYPE feature SYSTEM "gdb-target.dtd">
<target version="1.0">
<architecture>mips:3000</architecture>
<osabi>none</osabi>
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

  <reg name="lo" bitsize="32" regnum="32"/>
  <reg name="hi" bitsize="32" regnum="33"/>
  <reg name="pc" bitsize="32" regnum="34"/>
</feature>
<feature name="org.gnu.gdb.mips.cp0">
  <reg name="status" bitsize="32" regnum="35"/>
  <reg name="badvaddr" bitsize="32" regnum="36"/>
  <reg name="cause" bitsize="32" regnum="37"/>
</feature>
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
    auto cursorStrs = split(cursorStr, ",");
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

std::string PCSX::GdbClient::dumpValue(uint32_t value) {
    std::string ret = "";

    for (int i = 0; i < 4; i++) {
        ret += toHex[(value & 0xf0) >> 4];
        ret += toHex[(value & 0x0f)];
        value >>= 8;
    }

    return std::move(ret);
}

std::string PCSX::GdbClient::dumpOneRegister(int n) {
    auto& regs = g_emulator->m_psxCpu->m_psxRegs;
    uint32_t value = 0;
    if (n <= 33) {
        value = regs.GPR.r[n];
    } else if (n == 34) {
        value = regs.pc;
    } else if (n == 35) {
        value = regs.CP0.n.Status;
    } else if (n == 36) {
        value = regs.CP0.n.BadVAddr;
    } else if (n == 37) {
        value = regs.CP0.n.Cause;
    }

    return dumpValue(value);
}

void PCSX::GdbClient::processCommand() {
    if (m_ackEnabled) sendAck();
    static const std::string qSupported = "qSupported:";
    static const std::string qXferFeatures = "qXfer:features:read:target.xml:";
    static const std::string qXferThreads = "qXfer:threads:read::";
    static const std::string qXferMemMap = "qXfer:memory-map:read::";
    if (m_cmd == "?") {
        if (g_system->running()) {
            write("S00");
        } else {
            write("S05");
        }
    } else if (m_cmd == "D") {
        write("OK");
    } else if (m_cmd == "qC") {
        write("QC00");
    } else if (m_cmd == "qAttached") {
        write("1");
    } else if (m_cmd == "g") {
        std::string all = "";
        startStream();
        for (int i = 0; i < 38; i++) stream(dumpOneRegister(i));
        stopStream();
    } else if (m_cmd[0] == 'm') {
        auto [off, len] = parseCursor(m_cmd.substr(1, std::string::npos));
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
    } else if (m_cmd == "vCont?") {
        write("vCont;c;s;t");
    } else if (startsWith(m_cmd, qSupported)) {
        // do we care about any features gdb supports?
        // auto elements = split(m_cmd.substr(qSupported.length()), ";");
        write("PacketSize=4000;qXfer:features:read+;qXfer:threads:read+;QStartNoAckMode+");
    } else if (startsWith(m_cmd, "QStartNoAckMode")) {
        m_ackEnabled = false;
        write("OK");
    } else if (startsWith(m_cmd, qXferMemMap)) {
        writePaged(memoryMap, m_cmd.substr(qXferMemMap.length(), std::string::npos));
    } else if (startsWith(m_cmd, qXferFeatures)) {
        writePaged(targetXML, m_cmd.substr(qXferFeatures.length(), std::string::npos));
    } else if (startsWith(m_cmd, qXferThreads)) {
        writePaged("<?xml version=\"1.0\"?><threads></threads>",
                   m_cmd.substr(qXferThreads.length(), std::string::npos));
    } else {
        g_system->printf("Unknown GDB command: %s\n", m_cmd.c_str());
        write("");
    }
}

PCSX::Slice PCSX::GdbClient::passthroughData(Slice slice) { return slice; }
