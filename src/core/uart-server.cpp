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

#include "core/uart-server.h"

#include "core/psxemulator.h"
#include "core/uart.h"

PCSX::UARTServer::UARTServer() : m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) {
        if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::UARTServer>() &&
            (m_serverStatus != SERVER_STARTED)) {
            startServer(&g_emulator->m_loop, g_emulator->settings.get<Emulator::SettingDebugSettings>()
                                                 .get<Emulator::DebugSettings::UARTServerPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto& event) {
        if (m_serverStatus == SERVER_STARTED) stopServer();
    });
}

void PCSX::UARTServer::stopServer() {
    assert(m_serverStatus == SERVER_STARTED);
    m_serverStatus = SERVER_STOPPING;
    for (auto& client : m_clients) client.close();
    uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
}

void PCSX::UARTServer::startServer(uv_loop_t* loop, int port) {
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


void PCSX::UARTServer::closeCB(uv_handle_t* handle) {
    UARTServer* self = static_cast<UARTServer*>(handle->data);
    self->m_serverStatus = SERVER_STOPPED;
}

void PCSX::UARTServer::onNewConnectionTrampoline(uv_stream_t* handle, int status) {
    UARTServer* self = static_cast<UARTServer*>(handle->data);
    self->onNewConnection(status);
}

void PCSX::UARTServer::onNewConnection(int status) {
    if (status < 0) return;
    UARTClient* client = new UARTClient(&m_server);
    if (client->accept(&m_server)) {
        m_clients.push_back(client);
    } else {
        delete client;
    }
}

PCSX::UARTClient::UARTClient(uv_tcp_t* server) : m_listener(g_system->m_eventBus) {
    m_loop = server->loop;
    uv_tcp_init(m_loop, &m_tcp);
    m_tcp.data = this;
}

void PCSX::UARTClient::processData(const Slice& slice) {
    const char* ptr = reinterpret_cast<const char*>(slice.data());
    auto size = slice.size();

    PCSX::g_emulator->m_uart->m_slices.pushSlice(slice);
    //while (size) {
    //    char c = *ptr++;
    //    //UART buffered write
    //    size--;
    //}
}
