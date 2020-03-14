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

#include <stdarg.h>
#include <stdio.h>
#include <uv.h>

#include <limits>
#include <string>

#include "support/hashtable.h"
#include "support/list.h"
#include "support/slice.h"

namespace PCSX {

class DebugClient : public Intrusive::List<DebugClient>::Node {
  public:
    DebugClient(uv_loop_t* loop) {
        uv_tcp_init(loop, &m_tcp);
        m_tcp.data = this;
    }
    typedef Intrusive::List<DebugClient> ListType;

    bool accept(uv_tcp_t* server) {
        assert(m_status == CLOSED);
        if (uv_accept(reinterpret_cast<uv_stream_t*>(server), reinterpret_cast<uv_stream_t*>(&m_tcp)) == 0) {
            uv_read_start(reinterpret_cast<uv_stream_t*>(&m_tcp), allocTrampoline, readTrampoline);
            m_status = OPEN;
            write("000 PCSX-Redux Debug Console\r\n");
        }
        return m_status == OPEN;
    }
    void close() {
        assert(m_status == OPEN);
        m_status = CLOSING;
        uv_close(reinterpret_cast<uv_handle_t*>(&m_tcp), closeCB);
    }
    void write(const std::string& msg) {
        auto* req = new WriteRequest();
        assert(msg.size() <= std::numeric_limits<uint32_t>::max());
        req->m_slice.copy(msg.data(), msg.size());
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
#ifdef _WIN32
        size_t len = _vscprintf(fmt, a);
        char* msg = (char*)malloc(len + 1);
        vsnprintf(msg, len + 1, fmt, a);
#else
        char* msg = vasprintf(fmt, a);
        size_t len = strlen(msg);
#endif
        req->m_slice.acquire(msg, len);
        req->enqueue(this);
        va_end(a);
    }

  private:
    struct WriteRequest : public Intrusive::HashTable<uintptr_t, WriteRequest>::Node {
        void enqueue(DebugClient* client) {
            m_buf.base = static_cast<char*>(const_cast<void*>(m_slice.data()));
            m_buf.len = m_slice.size();
            client->m_requests.insert(reinterpret_cast<uintptr_t>(&m_req), this);
            uv_write(&m_req, reinterpret_cast<uv_stream_t*>(&client->m_tcp), &m_buf, 1, writeCB);
        }
        static void writeCB(uv_write_t* request, int status) {
            DebugClient* client = static_cast<DebugClient*>(request->handle->data);
            auto self = client->m_requests.find(reinterpret_cast<uintptr_t>(request));
            delete &*self;
            if (status != 0) client->close();
        }
        uv_write_t m_req;
        uv_buf_t m_buf;
        Slice m_slice;
    };
    friend struct WriteRequest;
    Intrusive::HashTable<uintptr_t, WriteRequest> m_requests;
    static constexpr size_t BUFFER_SIZE = 256;
    static void allocTrampoline(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf) {
        DebugClient* client = static_cast<DebugClient*>(handle->data);
        client->alloc(suggestedSize, buf);
    }
    void alloc(size_t suggestedSize, uv_buf_t* buf) {
        assert(!m_allocated);
        m_allocated = true;
        buf->base = m_buffer;
        buf->len = sizeof(m_buffer);
    }
    static void readTrampoline(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
        DebugClient* client = static_cast<DebugClient*>(stream->data);
        client->read(nread, buf);
    }
    void read(ssize_t nread, const uv_buf_t* buf) {
        m_allocated = false;
        if (nread < 0) {
            close();
            return;
        } else if (nread == 0) {
            return;
        }

        Slice slice;
        slice.borrow(m_buffer, nread);

        processData(slice);
    }
    static void closeCB(uv_handle_t* handle) {
        DebugClient* client = static_cast<DebugClient*>(handle->data);
        delete client;
    }
    void processData(const Slice& slice);
    void processCommand();
    Slice passthroughData(const Slice& slice);

    uv_tcp_t m_tcp;
    enum { CLOSED, OPEN, CLOSING } m_status = CLOSED;

    char m_buffer[BUFFER_SIZE];
    bool m_allocated = false;

    enum {
        FIRST_CHAR,
        SECOND_CHAR,
        THIRD_CHAR,
        CMD_WHITESPACE,
        ARGUMENT1,
        ARGUMENT2,
        FAILED_CMD,
        DATA_PASSTHROUGH
    } m_state = FIRST_CHAR;
    uint32_t m_cmd = 0;
    std::string m_fullCmd;
    char m_separator = 0;
    std::string m_argument1, m_argument2;
};

}  // namespace PCSX
