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

#pragma once

#include <assert.h>

#include <cstdarg>
#include <string>

#include "support/eventbus.h"
#include "support/list.h"
#include "support/slice.h"
#include "uvw.hpp"

namespace PCSX {

class GdbClient : public Intrusive::List<GdbClient>::Node {
  public:
    GdbClient(std::shared_ptr<uvw::TCPHandle> srv);
    ~GdbClient() { assert(m_requests.size() == 0); }
    typedef Intrusive::List<GdbClient> ListType;

    void accept(std::shared_ptr<uvw::TCPHandle> srv) {
        assert(m_status == CLOSED);
        m_tcp->on<uvw::CloseEvent>([this](const uvw::CloseEvent&, uvw::TCPHandle&) { delete this; });
        m_tcp->on<uvw::EndEvent>([this](const uvw::EndEvent&, uvw::TCPHandle&) { close(); });
        m_tcp->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent&, uvw::TCPHandle&) { close(); });
        m_tcp->on<uvw::DataEvent>([this](const uvw::DataEvent& event, uvw::TCPHandle&) { read(event); });
        m_tcp->on<uvw::WriteEvent>([this](const uvw::WriteEvent&, uvw::TCPHandle&) {
            auto top = m_requests.begin();
            if (top == m_requests.end()) return;
            top->gotWriteEvent();
        });
        srv->accept(*m_tcp);
        m_tcp->read();
        m_status = OPEN;
    }
    void close() {
        if (m_status != OPEN) return;
        m_status = CLOSING;
        m_tcp->close();
        m_requests.destroyAll();
    }

  private:
    void write(const Slice& slice) {
        auto* req = new WriteRequest();
        req->m_slice = slice;
        req->enqueue(this);
    }
    void write(const std::string& msg) {
        auto* req = new WriteRequest();
        assert(msg.size() <= std::numeric_limits<uint32_t>::max());
        req->m_slice.copy(msg);
        req->enqueue(this);
    }
    void write(std::string&& msg) {
        auto* req = new WriteRequest();
        assert(msg.size() <= std::numeric_limits<uint32_t>::max());
        req->m_slice.acquire(std::move(msg));
        req->enqueue(this);
    }
    template <size_t L>
    void write(const char (&str)[L]) {
        auto* req = new WriteRequest();
        static_assert((L - 1) <= std::numeric_limits<uint32_t>::max());
        req->m_slice.borrow(str, L - 1);
        req->enqueue(this);
    }
    void writef(const char* fmt, ...) {
        va_list a;
        va_start(a, fmt);
        auto* req = new WriteRequest();
        size_t len;
        char* msg;
#ifdef _WIN32
        len = _vscprintf(fmt, a);
        msg = (char*)malloc(len + 1);
        vsnprintf(msg, len + 1, fmt, a);
#else
        len = vasprintf(&msg, fmt, a);
#endif
        req->m_slice.acquire(msg, len);
        req->enqueue(this);
        va_end(a);
    }
    void writePaged(const std::string& out, const std::string& cursorStr);
    void writeEscaped(const std::string& out);
    void sendAck() {
        auto* req = new WriteRequest();
        req->m_slice.copy("+", 1);
        req->enqueueRaw(this);
    }

    void startStream() {
        m_crc = 0;
        auto* req = new WriteRequest();
        req->m_slice.copy("$", 1);
        req->enqueueRaw(this);
    }

    void stream(const std::string& data) {
        for (int i = 0; i < data.length(); i++) {
            m_crc += data[i];
        }
        auto* req = new WriteRequest();
        req->m_slice.copy(data.data(), data.size());
        req->enqueueRaw(this);
    }

    void stopStream() {
        auto* req = new WriteRequest();
        char end[3] = {'#'};
        end[1] = toHex[m_crc >> 4];
        end[2] = toHex[m_crc & 0x0f];
        req->m_slice.copy(end, 3);
        req->enqueueRaw(this);
    }

    static const char toHex[];
    struct WriteRequest : public Intrusive::List<WriteRequest>::Node {
        void enqueue(GdbClient* client) {
            uint8_t chksum = 0;
            auto data = static_cast<const char*>(m_slice.data());
            auto len = m_slice.size();
            for (int i = 0; i < len; i++) {
                chksum += *data++;
            }
            m_after[1] = toHex[chksum >> 4];
            m_after[2] = toHex[chksum & 0x0f];
            m_outstanding = 3;
            client->m_requests.push_back(this);
            client->m_tcp->write(&m_before, 1);
            client->m_tcp->write(static_cast<char*>(const_cast<void*>(m_slice.data())), m_slice.size());
            client->m_tcp->write(m_after, 3);
        }
        void enqueueRaw(GdbClient* client) {
            m_outstanding = 1;
            client->m_requests.push_back(this);
            client->m_tcp->write(static_cast<char*>(const_cast<void*>(m_slice.data())), m_slice.size());
        }
        void gotWriteEvent() {
            if (--m_outstanding == 0) delete this;
        }
        uv_write_t m_req;
        char m_before = '$';
        char m_after[3] = {'#'};
        Slice m_slice;
        unsigned m_outstanding;
    };
    friend struct WriteRequest;
    Intrusive::List<WriteRequest> m_requests;
    void read(const uvw::DataEvent& event) {
        Slice slice;
        slice.borrow(event.data.get(), event.length);

        processData(slice);
    }
    void processData(const Slice& slice);
    void processCommand();
    void processMonitorCommand(const std::string&);
    Slice passthroughData(Slice slice);
    std::pair<uint64_t, uint64_t> parseCursor(const std::string& cursorStr);

    std::string dumpOneRegister(int n);
    static std::string dumpValue(uint32_t value);

    std::shared_ptr<uvw::TCPHandle> m_tcp;
    enum { CLOSED, OPEN, CLOSING } m_status = CLOSED;

    enum {
        WAIT_FOR_ACK,
        WAIT_FOR_DOLLAR,
        READING_COMMAND,
        ESCAPE,
        READING_CRC_FIRST_CHAR,
        READING_CRC_SECOND_CHAR,
    } m_state = WAIT_FOR_DOLLAR;
    bool m_passthrough = false;
    bool m_ackEnabled = true;
    bool m_waitingForTrap = false;
    bool m_sentBanner = false;
    enum {
        QSYMBOL_IDLE,
        QSYMBOL_WAITING_FOR_START,
        QSYMBOL_WAITING_FOR_RESET,
    } m_qsymbolState = QSYMBOL_IDLE;
    uint32_t m_startLocation = 0;
    bool m_waitingForShell = false;
    std::string m_cmd;
    uint8_t m_crc;
    EventBus::Listener m_listener;
};

class GdbServer {
  public:
    GdbServer();
    enum GdbServerStatus {
        SERVER_STOPPED,
        SERVER_STARTED,
    };
    GdbServerStatus getServerStatus() { return m_serverStatus; }

    void startServer(int port = 3333);
    void stopServer();

  private:
    void onNewConnection();
    GdbServerStatus m_serverStatus = SERVER_STOPPED;
    std::shared_ptr<uvw::TCPHandle> m_server;
    GdbClient::ListType m_clients;
    EventBus::Listener m_listener;
};

}  // namespace PCSX
