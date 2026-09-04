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

// The REST server needs libuv, llhttp and multipart-parser, none of which are
// in the wasm build. Same shape as gdb-server-none.cc: the object exists, and
// it stays SERVER_STOPPED.
#ifdef __EMSCRIPTEN__

#include "core/web-server.h"

#include "core/system.h"

PCSX::WebServer::WebServer() : m_listener(g_system->m_eventBus) {}

void PCSX::WebServer::startServer(uv_loop_t *loop, int port) {}

void PCSX::WebServer::stopServer() {}

void PCSX::WebServer::onNewConnection(int status) {}

void PCSX::WebServer::closeCB(uv_handle_t *handle) {}

#endif
