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

// No libuv on wasm, so there is no listening socket to put a GDB server on.
// Network::Server comes from network-none.cc there and stays Stopped, so none
// of the hooks below can ever be reached.
#ifdef __EMSCRIPTEN__

#include "core/gdb-server.h"
#include "core/psxemulator.h"
#include "core/system.h"

PCSX::GdbServer::GdbServer() : Network::Server("GDB Server"), m_listener(g_system->m_eventBus) {}

void PCSX::GdbServer::onConnection(IO<File> connection) {}

void PCSX::GdbServer::onStopped() {}

void PCSX::GdbServer::onFailed() {}

int PCSX::GdbServer::configuredPort() const {
    return g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::GdbServerPort>();
}

#endif
