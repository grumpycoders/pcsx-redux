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

namespace {

// Both halves pick the wire format out of the same setting.
PCSX::SIO1::SIO1Mode currentSIO1Mode() {
    auto &debugSettings = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>();
    auto setting = debugSettings.get<PCSX::Emulator::DebugSettings::SIO1ModeSetting>().value;
    return setting == PCSX::Emulator::DebugSettings::SIO1Mode::Raw ? PCSX::SIO1::SIO1Mode::Raw
                                                                   : PCSX::SIO1::SIO1Mode::Protobuf;
}

}  // namespace

PCSX::SIO1Server::SIO1Server() : Network::Server("SIO1 Server"), m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::SettingsLoaded>([this](const auto &event) {
        auto &debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();
        if (debugSettings.get<Emulator::DebugSettings::SIO1Server>() && !isRunning()) {
            start(g_system->getLoop(), debugSettings.get<Emulator::DebugSettings::SIO1ServerPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto &event) {
        if (isRunning()) stop();
    });
}

void PCSX::SIO1Server::onStarting() {
    g_emulator->m_sio1->m_sio1Mode = currentSIO1Mode();
    g_emulator->m_counters->m_pollSIO1 = true;
}

void PCSX::SIO1Server::onConnection(IO<File> connection) { g_emulator->m_sio1->setFifo(connection); }

void PCSX::SIO1Server::onStopped() {
    g_emulator->m_counters->m_pollSIO1 = false;
    g_emulator->m_sio1->stopSIO1Connection();
}

PCSX::SIO1Client::SIO1Client() : Network::Client("SIO1 Client"), m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::SettingsLoaded>([this](const auto &event) {
        auto &debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();
        if (debugSettings.get<Emulator::DebugSettings::SIO1Client>() && (status() == Network::Status::Stopped)) {
            start(g_system->getLoop(),
                  std::string_view(debugSettings.get<Emulator::DebugSettings::SIO1ClientHost>().value),
                  debugSettings.get<Emulator::DebugSettings::SIO1ClientPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto &event) {
        if (status() != Network::Status::Stopped) stop();
    });
}

void PCSX::SIO1Client::onStarting() {
    auto mode = currentSIO1Mode();
    g_emulator->m_sio1->m_sio1Mode = mode;
    if (mode == SIO1::SIO1Mode::Raw) {
        // This used to throw std::runtime_error straight out of an ImGui
        // checkbox callback. It is a configuration the client does not support,
        // not an exceptional condition, so say so and leave the endpoint alone.
        g_system->printf("%s", _("SIO1 client does not support raw mode\n"));
        return;
    }
    g_emulator->m_counters->m_pollSIO1 = true;
}

void PCSX::SIO1Client::onStarted(IO<File> connection) { g_emulator->m_sio1->setFifo(connection); }

void PCSX::SIO1Client::onStopped() {
    g_emulator->m_counters->m_pollSIO1 = false;
    g_emulator->m_sio1->stopSIO1Connection();
    g_system->printf("%s", _("SIO1 client disconnected\n"));
}

void PCSX::SIO1Client::reconnect(std::string_view address, unsigned port) {
    stop();
    start(g_system->getLoop(), address, port);
}
