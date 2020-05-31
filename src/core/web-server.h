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

#pragma once

#include <assert.h>

#include "support/eventbus.h"
#include "support/list.h"
#include "support/slice.h"
#include "uvw.hpp"

namespace PCSX {

class WebClient : public Intrusive::List<WebClient>::Node {
  public:
    WebClient(std::shared_ptr<uvw::TCPHandle> srv);
    typedef Intrusive::List<WebClient> ListType;
    void close() {
        assert(m_status == OPEN);
        m_status = CLOSING;
        m_tcp->close();
    }
    void accept(std::shared_ptr<uvw::TCPHandle> srv) {
        assert(m_status == CLOSED);
        m_tcp->on<uvw::CloseEvent>([this](const uvw::CloseEvent&, uvw::TCPHandle&) { delete this; });
        m_tcp->on<uvw::EndEvent>([this](const uvw::EndEvent&, uvw::TCPHandle&) { close(); });
        m_tcp->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent&, uvw::TCPHandle&) { close(); });
        m_tcp->on<uvw::DataEvent>([this](const uvw::DataEvent& event, uvw::TCPHandle&) { read(event); });
        m_tcp->on<uvw::WriteEvent>([this](const uvw::WriteEvent&, uvw::TCPHandle&) {});
        srv->accept(*m_tcp);
        m_tcp->read();
        m_status = OPEN;
    }
    void read(const uvw::DataEvent& event) {
        Slice slice;
        slice.borrow(event.data.get(), event.length);

        processData(slice);
    }
    void processData(const Slice& slice);

  private:
    std::shared_ptr<uvw::TCPHandle> m_tcp;
    enum { CLOSED, OPEN, CLOSING } m_status = CLOSED;
};

class WebServer {
  public:
    WebServer();
    enum WebServerStatus {
        SERVER_STOPPED,
        SERVER_STARTED,
    };
    WebServerStatus getServerStatus() { return m_serverStatus; }

    void startServer(int port = 8080);
    void stopServer();

  private:
    void onNewConnection();
    WebServerStatus m_serverStatus;
    std::shared_ptr<uvw::TCPHandle> m_server;
    WebClient::ListType m_clients;
    EventBus::Listener m_listener;
};

}  // namespace PCSX
