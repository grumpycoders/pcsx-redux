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
// The object exists and reports SERVER_STOPPED forever; startServer does not
// pretend to have started anything, which is what getServerStatus tells any
// caller that asks.
#ifdef __EMSCRIPTEN__

#include "core/gdb-server.h"

#include "core/system.h"

PCSX::GdbServer::GdbServer() : m_listener(g_system->m_eventBus) {}

PCSX::GdbServer::~GdbServer() {}

void PCSX::GdbServer::startServer(uv_loop_t *loop, int port) {}

void PCSX::GdbServer::stopServer() {}

void PCSX::GdbServer::onNewConnectionTrampoline(uv_stream_t *handle, int status) {}

void PCSX::GdbServer::onNewConnection(int status) {}

void PCSX::GdbServer::closeCB(uv_handle_t *handle) {}

#endif
