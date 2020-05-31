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

#include "core/web-server.h"

#include "core/psxemulator.h"
#include "core/system.h"

PCSX::WebServer::WebServer() : m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) {
        if (g_emulator->settings.get<Emulator::SettingGdbServer>()) {
            startServer(g_emulator->settings.get<Emulator::SettingGdbServerPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto& event) {
        if (m_serverStatus == SERVER_STARTED) stopServer();
    });
}

void PCSX::WebServer::stopServer() {
    assert(m_serverStatus == SERVER_STARTED);
    for (auto& client : m_clients) client.close();
}

void PCSX::WebServer::startServer(int port) {
    assert(m_serverStatus == SERVER_STOPPED);
    m_server = g_emulator->m_loop->resource<uvw::TCPHandle>();
    m_server->on<uvw::ListenEvent>([this](const uvw::ListenEvent&, uvw::TCPHandle& srv) { onNewConnection(); });
    m_server->bind("0.0.0.0", port);
    m_server->listen();

    m_serverStatus = SERVER_STARTED;
}

void PCSX::WebServer::onNewConnection() {
    WebClient* client = new WebClient(m_server);
    m_clients.push_back(client);
    client->accept(m_server);
}

void PCSX::WebClient::processData(const Slice& slice) {
    const char* ptr = reinterpret_cast<const char*>(slice.data());
    auto size = slice.size();
}

PCSX::WebClient::WebClient(std::shared_ptr<uvw::TCPHandle> srv) : m_tcp(srv->loop().resource<uvw::TCPHandle>()) {}
