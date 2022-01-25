/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include "core/sio1-server.h"

#include "core/psxemulator.h"
#include "core/sio1.h"

PCSX::SIO1Client::SIO1Client(uv_tcp_t* server) : m_listener(g_system->m_eventBus) {
    m_loop = server->loop;
    uv_tcp_init(m_loop, &m_tcp);
    m_tcp.data = this;
}

bool PCSX::SIO1Client::accept(uv_tcp_t* server) {
    assert(m_status == SIO1ClientStatus::CLOSED);
    if (uv_accept(reinterpret_cast<uv_stream_t*>(server), reinterpret_cast<uv_stream_t*>(&m_tcp)) == 0) {
        uv_read_start(reinterpret_cast<uv_stream_t*>(&m_tcp), allocTrampoline, readTrampoline);
        m_status = SIO1ClientStatus::OPEN;
    }
    return m_status == SIO1ClientStatus::OPEN;
}

void PCSX::SIO1Client::alloc(size_t suggestedSize, uv_buf_t* buf) {
    assert(!m_allocated);
    m_allocated = true;
    buf->base = m_buffer;
    buf->len = sizeof(m_buffer);
}

void PCSX::SIO1Client::allocTrampoline(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf) {
    SIO1Client* client = static_cast<SIO1Client*>(handle->data);
    client->alloc(suggestedSize, buf);
}

void PCSX::SIO1Client::close() {
    if (m_status != SIO1ClientStatus::OPEN) return;
    m_status = SIO1ClientStatus::CLOSING;
    uv_close(reinterpret_cast<uv_handle_t*>(&m_tcp), closeCB);
}

void PCSX::SIO1Client::closeCB(uv_handle_t* handle) {
    SIO1Client* client = static_cast<SIO1Client*>(handle->data);
    delete client;
}

void PCSX::SIO1Client::processData(const Slice& slice) {
    PCSX::g_emulator->m_sio1->pushSlice(slice);
    PCSX::g_emulator->m_sio1->receiveCallback();
}

void PCSX::SIO1Client::read(ssize_t nread, const uv_buf_t* buf) {
    m_allocated = false;
    if (nread <= 0) {
        close();
        return;
    }

    if (nread > BUFFER_SIZE) {
        g_system->log(LogClass::SIO1SERVER,
                      "SIO1Server: Received more data[%i] than buffer[%i] can store, data truncated.\n", nread,
                      BUFFER_SIZE);
        nread = BUFFER_SIZE;
    }

    Slice slice;
    slice.borrow(m_buffer, static_cast<uint32_t>(nread));
    processData(slice);
}

void PCSX::SIO1Client::readTrampoline(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    SIO1Client* client = static_cast<SIO1Client*>(stream->data);
    client->read(nread, buf);
}

void PCSX::SIO1Client::write(unsigned char c) {
    auto* req = new WriteRequest();
    req->m_slice.copy(static_cast<void*>(&c), 1);
    req->enqueue(this);
}

void PCSX::SIO1Client::WriteRequest::enqueue(SIO1Client* client) {
    m_buf.base = static_cast<char*>(const_cast<void*>(m_slice.data()));
    m_buf.len = m_slice.size();
    client->m_requests.insert(reinterpret_cast<uintptr_t>(&m_req), this);
    uv_write(&m_req, reinterpret_cast<uv_stream_t*>(&client->m_tcp), &m_buf, 1, writeCB);
}

void PCSX::SIO1Client::WriteRequest::writeCB(uv_write_t* request, int status) {
    SIO1Client* client = static_cast<SIO1Client*>(request->handle->data);
    auto self = client->m_requests.find(reinterpret_cast<uintptr_t>(request));
    delete &*self;
    if (status != 0) client->close();
}

PCSX::SIO1Server::SIO1Server() : m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) {
        if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::SIO1Server>() &&
            (m_serverStatus != SIO1ServerStatus::SERVER_STARTED)) {
            startServer(&g_emulator->m_loop, g_emulator->settings.get<Emulator::SettingDebugSettings>()
                                                 .get<Emulator::DebugSettings::SIO1ServerPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto& event) {
        if (m_serverStatus == SIO1ServerStatus::SERVER_STARTED) stopServer();
    });
}

void PCSX::SIO1Server::closeCB(uv_handle_t* handle) {
    SIO1Server* self = static_cast<SIO1Server*>(handle->data);
    self->m_serverStatus = SIO1ServerStatus::SERVER_STOPPED;
}

void PCSX::SIO1Server::onNewConnection(int status) {
    if (status < 0) return;
    SIO1Client* client = new SIO1Client(&m_server);
    if (client->accept(&m_server)) {
        m_clients.push_back(client);
    } else {
        delete client;
    }
}

void PCSX::SIO1Server::onNewConnectionTrampoline(uv_stream_t* handle, int status) {
    SIO1Server* self = static_cast<SIO1Server*>(handle->data);
    self->onNewConnection(status);
}

void PCSX::SIO1Server::startServer(uv_loop_t* loop, int port) {
    assert(m_serverStatus == SIO1ServerStatus::SERVER_STOPPED);

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
    m_serverStatus = SIO1ServerStatus::SERVER_STARTED;
}

void PCSX::SIO1Server::stopServer() {
    assert(m_serverStatus == SIO1ServerStatus::SERVER_STARTED);
    m_serverStatus = SIO1ServerStatus::SERVER_STOPPING;
    for (auto& client : m_clients) client.close();
    uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
}
