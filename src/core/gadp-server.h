/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

class GadpClient : public Intrusive::List<GadpClient>::Node {
  public:
    GadpClient(std::shared_ptr<uvw::TCPHandle> srv);
    ~GadpClient() { assert(m_requests.size() == 0); }
    typedef Intrusive::List<GadpClient> ListType;

    void accept(std::shared_ptr<uvw::TCPHandle> srv) {
        assert(m_status == CLOSED);
        m_tcp->on<uvw::CloseEvent>([this](const uvw::CloseEvent&, uvw::TCPHandle&) { delete this; });
        m_tcp->on<uvw::EndEvent>([this](const uvw::EndEvent&, uvw::TCPHandle&) { close(); });
        m_tcp->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent&, uvw::TCPHandle&) { close(); });
        m_tcp->on<uvw::DataEvent>([this](const uvw::DataEvent& event, uvw::TCPHandle&) { read(event); });
        m_tcp->on<uvw::WriteEvent>([this](const uvw::WriteEvent&, uvw::TCPHandle&) {
            auto top = m_requests.begin();
            if (top == m_requests.end()) return;
            top->gotWriteEvent();
        });
        srv->accept(*m_tcp);
        m_tcp->read();
        m_status = OPEN;
    }
    void close() {
        if (m_status != OPEN) return;
        m_status = CLOSING;
        m_tcp->close();
        m_requests.destroyAll();
    }

  private:
    void write(const Slice& slice) {
        auto* req = new WriteRequest();
        req->m_slice = slice;
        req->enqueue(this);
    }

    struct WriteRequest : public Intrusive::List<WriteRequest>::Node {
        void enqueue(GadpClient* client) {
            m_outstanding = 1;
            client->m_requests.push_back(this);
            client->m_tcp->write(static_cast<char*>(const_cast<void*>(m_slice.data())), m_slice.size());
        }
        void gotWriteEvent() {
            if (--m_outstanding == 0) delete this;
        }
        uv_write_t m_req;
        Slice m_slice;
        unsigned m_outstanding;
    };
    friend struct WriteRequest;
    Intrusive::List<WriteRequest> m_requests;
    void read(const uvw::DataEvent& event) {
        Slice slice;
        slice.borrow(event.data.get(), event.length);

        processData(slice);
    }
    void processData(const Slice& slice);

    std::shared_ptr<uvw::TCPHandle> m_tcp;
    enum { CLOSED, OPEN, CLOSING } m_status = CLOSED;

    EventBus::Listener m_listener;

    std::string m_protoBuffer;
    enum {
        WAIT_FOR_LEN,
        READING_DATA,
    } m_state = WAIT_FOR_LEN;
    uint8_t m_lenBuffer[4];
    uint32_t m_length = 0;
};

class GadpServer {
  public:
    GadpServer();
    enum GadpServerStatus {
        SERVER_STOPPED,
        SERVER_STARTED,
    };
    GadpServerStatus getServerStatus() { return m_serverStatus; }

    void startServer(int port = 15432);
    void stopServer();

  private:
    void onNewConnection();
    GadpServerStatus m_serverStatus = SERVER_STOPPED;
    std::shared_ptr<uvw::TCPHandle> m_server;
    GadpClient::ListType m_clients;
    EventBus::Listener m_listener;
    std::string m_gotError;
};

}  // namespace PCSX
