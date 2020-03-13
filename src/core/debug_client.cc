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

#include <assert.h>

PCSX::DebugClient::DebugClient(uv_loop_t* loop) {
    uv_tcp_init(loop, &m_tcp);
    m_tcp.data = this;
}

bool PCSX::DebugClient::accept(uv_tcp_t* server) {
    assert(m_status == CLOSED);
    if (uv_accept(reinterpret_cast<uv_stream_t*>(server), reinterpret_cast<uv_stream_t*>(&m_tcp)) == 0) {
        uv_read_start(reinterpret_cast<uv_stream_t*>(&m_tcp), allocTrampoline, readTrampoline);
        m_status = OPEN;
        write("000 PCSX-Redux Debug Console\r\n");
    }
    return m_status == OPEN;
}

void PCSX::DebugClient::close() {
    assert(m_status == OPEN);
    m_status = CLOSING;
    uv_close(reinterpret_cast<uv_handle_t*>(&m_tcp), closeCB);
}

void PCSX::DebugClient::alloc(size_t suggestedSize, uv_buf_t* buf) {
    assert(!m_allocated);
    m_allocated = true;
    buf->base = m_buffer;
    buf->len = sizeof(m_buffer);
}

void PCSX::DebugClient::read(ssize_t nread, const uv_buf_t* buf) {
    m_allocated = false;
    if (nread < 0) {
        close();
        return;
    } else if (nread == 0) {
        return;
    }

    // processData()
}

void PCSX::DebugClient::write(const std::string& msg) {
    auto* req = new WriteRequest();
    req->m_slice.copy(msg.data(), msg.size());
    req->enqueue(this);
}
