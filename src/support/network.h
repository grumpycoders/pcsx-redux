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

#pragma once

#include <uv.h>

#include <string>
#include <vector>

#include "support/file.h"
#include "support/uvfile.h"

namespace PCSX {

namespace Network {

// One vocabulary for every network endpoint in the emulator, so the UI can draw
// a bullet without knowing whether it is looking at a listening socket or an
// outgoing connection. Previously each server declared its own three-state enum
// - GdbServerStatus, WebServerStatus, SIO1ServerStatus, SIO1ClientStatus,
// ATConsServer::ServerStatus - none of which agreed on spelling, none of which
// had a way to say "failed", and none of which anything ever read.
enum class Status {
    Stopped,   // idle, by choice
    Starting,  // bind or connect in flight on the uv worker thread
    Running,   // listening, or connected
    Failed,    // bind, listen, or connect failed; lastError() says why
};

const char* toString(Status status);

// Common surface for anything the Network window renders a row for.
class Endpoint {
  public:
    Endpoint(std::string_view name);
    virtual ~Endpoint();

    Endpoint(const Endpoint&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;

    std::string_view name() const { return m_name; }
    int port() const { return m_port; }

    virtual Status status() const = 0;
    virtual const char* lastError() const = 0;

    bool isRunning() const { return status() == Status::Running; }

    // Every endpoint remembers the loop and port it was last asked to use, so
    // the UI's restart button does not have to know either.
    virtual void stop() = 0;
    void restart();

    // Registered endpoints, in construction order. The Network window iterates
    // this rather than hard-coding a row per service, so a new endpoint shows
    // up with a status bullet for free.
    static const std::vector<Endpoint*>& all();

  protected:
    virtual void restartNow(uv_loop_t* loop, int port) = 0;
    // Called by subclasses once a teardown has completed, so a restart that was
    // requested while the endpoint was still shutting down can proceed.
    void settled();

    std::string m_name;
    uv_loop_t* m_loop = nullptr;
    int m_port = 0;
    bool m_restartPending = false;
};

// A listening endpoint. Owns a UvFifoListener, which owns the socket; every
// accepted connection arrives as an IO<File>, so subclasses never touch libuv.
//
// This replaces four hand-written copies of the same uv_tcp_init / uv_ip4_addr
// / uv_tcp_bind / uv_listen sequence.
class Server : public Endpoint {
  public:
    Server(std::string_view name) : Endpoint(name) {}

    void start(uv_loop_t* loop, int port);
    void stop() override;

    Status status() const override;
    const char* lastError() const override { return m_listener.lastError(); }

  protected:
    // A client connected. The endpoint takes ownership.
    virtual void onConnection(IO<File> connection) = 0;
    // The listener is finished - either an orderly stop, or a bind/listen
    // failure. Check status() to tell which. Subclasses use this to drop any
    // connection state they were holding.
    virtual void onStopped() {}

    void restartNow(uv_loop_t* loop, int port) override { start(loop, port); }

  private:
    void onListenerEvent(UvFifo* fifo);

    UvFifoListener m_listener;
    // Heap allocated per start() and deleted by its own close callback. A value
    // member would have to be uv_async_init'd again while the previous close was
    // still in flight, which is exactly the handle-reuse hazard a restart would
    // walk into. m_server inside the listener has no such problem: its status
    // only reaches Stopped/Failed from inside its close callback, so by the time
    // anything downstream reacts the handle is fully closed.
    uv_async_t* m_async = nullptr;
};

// An outgoing endpoint: SIO1's client half, and anything else that dials out.
// The connection itself is a UvFifo, so status is derived from it rather than
// tracked separately - there is no second copy of the truth to go stale.
class Client : public Endpoint {
  public:
    Client(std::string_view name) : Endpoint(name) {}

    void start(uv_loop_t* loop, std::string_view host, int port);
    void stop() override;

    Status status() const override;
    const char* lastError() const override;

    std::string_view host() const { return m_host; }

    // The connection, valid once status() reads Running. Deliberately polled
    // rather than delivered by callback: the connect completes on the uv worker
    // thread and UvFifo exposes its progress as flags, so a "connected" event
    // would be a second copy of the truth that could disagree with the first.
    // Consumers that want to be woken on traffic install a notifier on it.
    IO<File> connection() { return m_connection; }

  protected:
    void restartNow(uv_loop_t* loop, int port) override { start(loop, m_host, port); }

    IO<File> m_connection;
    UvFifo* m_fifo = nullptr;  // non-owning view of m_connection, for status

  private:
    std::string m_host;
};

}  // namespace Network

}  // namespace PCSX
