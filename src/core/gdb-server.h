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

#include "core/psxemulator.h"
#include "support/eventbus.h"
#include "support/hashtable.h"
#include "support/list.h"
#include "support/slice.h"

namespace PCSX {

class GdbClient : public Intrusive::List<GdbClient>::Node {
  public:
    GdbClient(uv_tcp_t* srv);
    ~GdbClient() { assert(m_requests.size() == 0); }
    typedef Intrusive::List<GdbClient> ListType;

    bool accept(uv_tcp_t* srv) {
        assert(m_status == CLOSED);
        if (uv_accept(reinterpret_cast<uv_stream_t*>(srv), reinterpret_cast<uv_stream_t*>(&m_tcp)) == 0) {
            uv_read_start(reinterpret_cast<uv_stream_t*>(&m_tcp), allocTrampoline, readTrampoline);
            m_status = OPEN;
        }
        return m_status == OPEN;
    }
    void close() {
        if (m_status != OPEN) return;
        m_status = CLOSING;
        uv_close(reinterpret_cast<uv_handle_t*>(&m_tcp), closeCB);
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
    struct WriteRequest : public Intrusive::HashTable<uintptr_t, WriteRequest>::Node {
        void enqueue(GdbClient* client) {
            if (g_emulator->settings.get<Emulator::SettingDebugSettings>()
                    .get<Emulator::DebugSettings::GdbServerTrace>()) {
                std::string msg((const char*)m_slice.data(), m_slice.size());
                g_system->log(LogClass::GDB, "GDB <-- PCSX %s\n", msg.c_str());
            }
            m_bufs[0].base = &m_before;
            m_bufs[0].len = 1;
            m_bufs[1].base = static_cast<char*>(const_cast<void*>(m_slice.data()));
            m_bufs[1].len = m_slice.size();
            m_bufs[2].base = m_after;
            m_bufs[2].len = 3;
            uint8_t chksum = 0;
            auto data = m_bufs[1].base;
            auto len = m_bufs[1].len;
            for (int i = 0; i < len; i++) {
                chksum += *data++;
            }
            m_after[1] = toHex[chksum >> 4];
            m_after[2] = toHex[chksum & 0x0f];
            client->m_requests.insert(reinterpret_cast<uintptr_t>(&m_req), this);
            uv_write(&m_req, reinterpret_cast<uv_stream_t*>(&client->m_tcp), m_bufs, 3, writeCB);
        }
        void enqueueRaw(GdbClient* client) {
            if (g_emulator->settings.get<Emulator::SettingDebugSettings>()
                    .get<Emulator::DebugSettings::GdbServerTrace>()) {
                std::string msg((const char*)m_slice.data(), m_slice.size());
                g_system->log(LogClass::GDB, "GDB <-- PCSX %s\n", msg.c_str());
            }
            m_bufs[0].base = static_cast<char*>(const_cast<void*>(m_slice.data()));
            m_bufs[0].len = m_slice.size();
            client->m_requests.insert(reinterpret_cast<uintptr_t>(&m_req), this);
            uv_write(&m_req, reinterpret_cast<uv_stream_t*>(&client->m_tcp), m_bufs, 1, writeCB);
        }
        static void writeCB(uv_write_t* request, int status) {
            GdbClient* client = static_cast<GdbClient*>(request->handle->data);
            auto self = client->m_requests.find(reinterpret_cast<uintptr_t>(request));
            delete &*self;
            if (status != 0) client->close();
        }
        uv_write_t m_req;
        char m_before = '$';
        char m_after[3] = {'#'};
        uv_buf_t m_bufs[3];
        Slice m_slice;
    };
    friend struct WriteRequest;
    Intrusive::HashTable<uintptr_t, WriteRequest> m_requests;
    static constexpr size_t BUFFER_SIZE = 256;
    static void allocTrampoline(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf) {
        GdbClient* client = static_cast<GdbClient*>(handle->data);
        client->alloc(suggestedSize, buf);
    }
    void alloc(size_t suggestedSize, uv_buf_t* buf) {
        assert(!m_allocated);
        m_allocated = true;
        buf->base = m_buffer;
        buf->len = sizeof(m_buffer);
    }
    static void readTrampoline(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
        GdbClient* client = static_cast<GdbClient*>(stream->data);
        client->read(nread, buf);
    }
    void read(ssize_t nread, const uv_buf_t* buf) {
        m_allocated = false;
        if (nread <= 0) {
            close();
            return;
        }
        Slice slice;
        slice.borrow(m_buffer, nread);
        processData(slice);
    }
    static void closeCB(uv_handle_t* handle) {
        GdbClient* client = static_cast<GdbClient*>(handle->data);
        delete client;
    }
    void processData(const Slice& slice);
    void processCommand();
    void processMonitorCommand(const std::string&);
    Slice passthroughData(Slice slice);
    std::pair<uint64_t, uint64_t> parseCursor(const std::string& cursorStr);

    std::string dumpOneRegister(int n);
    void setOneRegister(int n, uint32_t value);
    static std::string dumpValue(uint32_t value);

    uv_tcp_t m_tcp;
    enum { CLOSED, OPEN, CLOSING } m_status = CLOSED;

    char m_buffer[BUFFER_SIZE];
    bool m_allocated = false;
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
    enum {
        QSYMBOL_IDLE,
        QSYMBOL_WAITING_FOR_START,
        QSYMBOL_WAITING_FOR_RESET,
    } m_qsymbolState = QSYMBOL_IDLE;
    bool m_waitingForShell = false;
    bool m_exception = false;
    std::string m_cmd;
    uint8_t m_crc;
    EventBus::Listener m_listener;
    uv_loop_t* m_loop;
};

class GdbServer {
  public:
    GdbServer();
    enum GdbServerStatus {
        SERVER_STOPPED,
        SERVER_STOPPING,
        SERVER_STARTED,
    };
    GdbServerStatus getServerStatus() { return m_serverStatus; }

    void startServer(uv_loop_t* loop, int port = 3333);
    void stopServer();

  private:
    static void onNewConnectionTrampoline(uv_stream_t* server, int status);
    void onNewConnection(int status);
    static void closeCB(uv_handle_t* handle);
    GdbServerStatus m_serverStatus = SERVER_STOPPED;
    uv_tcp_t m_server;
    GdbClient::ListType m_clients;
    EventBus::Listener m_listener;
    std::string m_gotError;
};

}  // namespace PCSX
