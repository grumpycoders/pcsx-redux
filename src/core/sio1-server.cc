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

PCSX::SIO1Server::SIO1Server() : m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) {
        if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::SIO1Server>() &&
            (m_serverStatus != SIO1ServerStatus::SERVER_STARTED)) {
            startServer(g_system->getLoop(), g_emulator->settings.get<Emulator::SettingDebugSettings>()
                                                 .get<Emulator::DebugSettings::SIO1ServerPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto& event) {
        if (m_serverStatus == SIO1ServerStatus::SERVER_STARTED) stopServer();
    });
}
void PCSX::SIO1Server::startServer(uv_loop_t* loop, int port) {
    if (m_serverStatus == SIO1ServerStatus::SERVER_STARTED) {
        throw std::runtime_error("Server already started");
    }

    m_serverStatus = SIO1ServerStatus::SERVER_STARTED;

    m_fifoListener.start(port, loop, &m_async, [this](auto fifo) {
        if (fifo) {
            g_emulator->m_sio1->m_fifo.setFile(fifo);
        } else {
            g_emulator->m_sio1->m_fifo.reset();
            m_async.data = this;
            uv_close(reinterpret_cast<uv_handle_t*>(&m_async), [](uv_handle_t* handle) {
                SIO1Server* server = reinterpret_cast<SIO1Server*>(handle->data);
                server->m_serverStatus = SIO1ServerStatus::SERVER_STOPPED;
            });
        }
    });
}

void PCSX::SIO1Server::stopServer() {
    m_serverStatus = SIO1ServerStatus::SERVER_STOPPING;
    m_fifoListener.stop();
}
