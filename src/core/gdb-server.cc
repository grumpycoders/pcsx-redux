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

#include "core/psxemulator.h"
#include "core/system.h"
#include "core/uv_wrapper.h"

PCSX::GdbServer::GdbServer() : m_listener(g_system->getEventBus()) {
    m_listener.listen([this](const Events::SettingsLoaded& event) {
        if (g_emulator->settings.get<Emulator::SettingGdbServer>()) {
            startServer(g_emulator->settings.get<Emulator::SettingGdbServerPort>());
        }
    });
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
        // process `c` now
    }
}

PCSX::Slice PCSX::GdbClient::passthroughData(Slice slice) { return slice; }
