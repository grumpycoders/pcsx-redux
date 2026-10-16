/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

// SIO1 over TCP needs a socket. Both halves exist and stay Stopped; the fifo
// side is already covered by uvfile-wasm.h, whose UvFifo is a failed file.
#ifdef __EMSCRIPTEN__

#include "core/psxemulator.h"
#include "core/sio1-server.h"
#include "core/system.h"

PCSX::SIO1Server::SIO1Server() : Network::Server("SIO1 Server"), m_listener(g_system->m_eventBus) {}

void PCSX::SIO1Server::onStarting() {}

void PCSX::SIO1Server::onConnection(IO<File> connection) {}

void PCSX::SIO1Server::onStopped() {}

void PCSX::SIO1Server::onFailed() {}

int PCSX::SIO1Server::configuredPort() const {
    return g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::SIO1ServerPort>();
}

PCSX::SIO1Client::SIO1Client() : Network::Client("SIO1 Client"), m_listener(g_system->m_eventBus) {}

bool PCSX::SIO1Client::onStarting() { return false; }

void PCSX::SIO1Client::onStarted(IO<File> connection) {}

void PCSX::SIO1Client::onStopped() {}

int PCSX::SIO1Client::configuredPort() const {
    return g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::SIO1ClientPort>();
}

void PCSX::SIO1Client::reconnect(std::string_view address, unsigned port) {}

#endif
