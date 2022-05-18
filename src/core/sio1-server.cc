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
    auto& emuSettings = PCSX::g_emulator->settings;
    auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();
    auto SIO1ModeSettings = debugSettings.get<Emulator::DebugSettings::SIO1ModeSetting>().value;
    if (SIO1ModeSettings == Emulator::DebugSettings::SIO1Mode::Raw) {
        g_emulator->m_sio1->m_sio1Mode = SIO1::SIO1Mode::Raw;
    } else {
        g_emulator->m_sio1->m_sio1Mode = SIO1::SIO1Mode::Protobuf;
    }

    m_serverStatus = SIO1ServerStatus::SERVER_STARTED;
    g_emulator->m_counters->m_pollSIO1 = true;
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
    g_emulator->m_counters->m_pollSIO1 = false;
    m_fifoListener.stop();
}

PCSX::SIO1Client::SIO1Client() : m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) {
        if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::SIO1Client>() &&
            (m_clientStatus != SIO1ClientStatus::CLIENT_STARTED)) {
                startClient(std::string_view(g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::SIO1ClientHost>().value),
                        g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::SIO1ClientPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto& event) {
        if (m_clientStatus == SIO1ClientStatus::CLIENT_STARTED) stopClient();
    });
}

void PCSX::SIO1Client::startClient(std::string_view address, unsigned port) {
    if (m_clientStatus == SIO1ClientStatus::CLIENT_STARTED) {
        throw std::runtime_error("Client already started");
    }
    auto& emuSettings = PCSX::g_emulator->settings;
    auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();
    auto SIO1ModeSettings = debugSettings.get<Emulator::DebugSettings::SIO1ModeSetting>().value;
    if (SIO1ModeSettings == Emulator::DebugSettings::SIO1Mode::Raw) {
        g_emulator->m_sio1->m_sio1Mode = SIO1::SIO1Mode::Raw;
    } else {
        g_emulator->m_sio1->m_sio1Mode = SIO1::SIO1Mode::Protobuf;
    }

    m_clientStatus = SIO1ClientStatus::CLIENT_STARTED;
    g_emulator->m_sio1->m_fifo.setFile(new UvFifo(address, port));
    if (g_emulator->m_sio1->fifoError()) {
        m_clientStatus = SIO1ClientStatus::CLIENT_STOPPING;
        g_emulator->m_counters->m_pollSIO1 = false;
        stopClient();
    }

    g_system->printf("%s", _("SIO1 client connecting...\n"));
    if (!g_emulator->m_sio1->m_fifo.asA<UvFifo>()->isConnecting())
        g_system->printf("%s", _("SIO1 client connected\n"));

    g_emulator->m_counters->m_pollSIO1 = true;
}

void PCSX::SIO1Client::stopClient() {
    m_clientStatus = SIO1ClientStatus::CLIENT_STOPPED;
    g_emulator->m_counters->m_pollSIO1 = false;
    g_emulator->m_sio1->stopSIO1Connection();
    g_system->printf("%s", _("SIO1 client disconnected\n"));
}
