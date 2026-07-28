/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "support/network.h"

#include <algorithm>

namespace PCSX::Network {

const char* toString(Status status) {
    switch (status) {
        case Status::Stopped:
            return "Stopped";
        case Status::Starting:
            return "Starting";
        case Status::Running:
            return "Running";
        case Status::Failed:
            return "Failed";
    }
    return "Unknown";
}

// Function-local so registration during static construction is safe regardless
// of translation unit ordering.
static std::vector<Endpoint*>& registry() {
    static std::vector<Endpoint*> s_registry;
    return s_registry;
}

const std::vector<Endpoint*>& Endpoint::all() { return registry(); }

Endpoint::Endpoint(std::string_view name) : m_name(name) { registry().push_back(this); }

Endpoint::~Endpoint() {
    auto& all = registry();
    all.erase(std::remove(all.begin(), all.end(), this), all.end());
}

void Endpoint::restart() {
    if (!m_loop) return;
    m_restartPending = true;
    stop();
}

void Endpoint::settled() {
    if (!m_restartPending) return;
    m_restartPending = false;
    restartNow(m_loop, m_port);
}

//
// Server
//

void Server::start(uv_loop_t* loop, int port) {
    if (status() == Status::Running) return;
    m_loop = loop;
    m_port = port;
    m_async = new uv_async_t();
    m_listener.start(port, loop, m_async, [this](UvFifo* fifo) { onListenerEvent(fifo); });
}

void Server::onListenerEvent(UvFifo* fifo) {
    if (fifo) {
        onConnection(IO<File>(fifo));
        return;
    }
    // nullptr means the listener is finished, whether that was an orderly stop
    // or a bind/listen failure. status() distinguishes them; both land here so
    // there is exactly one teardown path.
    if (m_async) {
        uv_close(reinterpret_cast<uv_handle_t*>(m_async),
                 [](uv_handle_t* handle) { delete reinterpret_cast<uv_async_t*>(handle); });
        m_async = nullptr;
    }
    onStopped();
    settled();
}

void Server::stop() {
    auto listenerStatus = m_listener.status();
    if ((listenerStatus == UvFifoListener::Status::Listening) ||
        (listenerStatus == UvFifoListener::Status::Starting)) {
        m_listener.stop();
        return;  // onListenerEvent(nullptr) finishes the teardown
    }
    // Already down - a failed bind has torn itself down and delivered its
    // nullptr already, so nothing further is going to call back. Settle here
    // rather than waiting for an event that will never arrive, which is what
    // would strand a pending restart.
    onListenerEvent(nullptr);
}

Status Server::status() const {
    switch (m_listener.status()) {
        case UvFifoListener::Status::Stopped:
            return Status::Stopped;
        case UvFifoListener::Status::Starting:
            return Status::Starting;
        case UvFifoListener::Status::Listening:
            return Status::Running;
        case UvFifoListener::Status::Failed:
            return Status::Failed;
    }
    return Status::Stopped;
}

//
// Client
//

void Client::start(uv_loop_t* loop, std::string_view host, int port) {
    m_connection.reset();
    m_fifo = nullptr;
    m_loop = loop;
    m_host = host;
    m_port = port;
    auto fifo = new UvFifo(host, port);
    m_fifo = fifo;
    m_connection = IO<File>(fifo);
}

void Client::stop() {
    m_connection.reset();
    m_fifo = nullptr;
    settled();
}

Status Client::status() const {
    if (!m_fifo) return Status::Stopped;
    // Order matters: a failed connect leaves the fifo both failed and closed,
    // and "failed" is the answer that carries information.
    if (m_fifo->failed()) return Status::Failed;
    if (m_fifo->isConnecting()) return Status::Starting;
    if (m_fifo->isClosed()) return Status::Stopped;
    return Status::Running;
}

const char* Client::lastError() const { return m_fifo ? m_fifo->connectError() : ""; }

}  // namespace PCSX::Network
