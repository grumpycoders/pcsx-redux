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

#include <uv.h>

#include <string>

#include "support/hashtable.h"
#include "support/list.h"
#include "support/slice.h"

namespace PCSX {

class DebugClient : public Intrusive::List<DebugClient>::Node {
  public:
    DebugClient(uv_loop_t* loop);
    typedef Intrusive::List<DebugClient> ListType;

    bool accept(uv_tcp_t* server);
    void close();
    void write(const std::string& msg);

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
    void alloc(size_t suggestedSize, uv_buf_t* buf);
    static void readTrampoline(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
        DebugClient* client = static_cast<DebugClient*>(stream->data);
        client->read(nread, buf);
    }
    static void closeCB(uv_handle_t* handle) {
        DebugClient* client = static_cast<DebugClient*>(handle->data);
        delete client;
    }
    void read(ssize_t nread, const uv_buf_t* buf);
    uv_tcp_t m_tcp;
    enum { CLOSED, OPEN, CLOSING } m_status = CLOSED;

    char m_buffer[BUFFER_SIZE];
    bool m_allocated = false;
};

}  // namespace PCSX
