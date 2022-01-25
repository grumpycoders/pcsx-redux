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

#pragma once

#include <queue>
#include <string>

#include "core/debug.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "support/eventbus.h"
#include "support/hashtable.h"
#include "support/list.h"
#include "support/slice.h"

namespace PCSX {
class SIO1Client;
class SIO1Server;

class SIO1Client : public Intrusive::List<SIO1Client>::Node {
  public:
    typedef Intrusive::List<SIO1Client> ListType;

    SIO1Client(uv_tcp_t* server);

    bool accept(uv_tcp_t* server);
    void close();

  private:
    enum class SIO1ClientStatus { CLOSED, OPEN, CLOSING };

    struct WriteRequest : public Intrusive::HashTable<uintptr_t, WriteRequest>::Node {
        uv_buf_t m_buf = {};
        Slice m_slice;
        uv_write_t m_req = {};

        WriteRequest() {}
        WriteRequest(Slice&& slice) : m_slice(std::move(slice)) {}
        void enqueue(SIO1Client* client);
        static void writeCB(uv_write_t* request, int status);
    };

    SIO1ClientStatus m_status = SIO1ClientStatus::CLOSED;

    static constexpr size_t BUFFER_SIZE = 4096;

    void alloc(size_t suggestedSize, uv_buf_t* buf);
    static void allocTrampoline(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf);
    static void closeCB(uv_handle_t* handle);
    void processData(const Slice& slice);
    void read(ssize_t nread, const uv_buf_t* buf);
    static void readTrampoline(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
    void write(unsigned char c);

    bool m_allocated = false;
    char m_buffer[BUFFER_SIZE] = {};
    EventBus::Listener m_listener;
    uv_loop_t* m_loop = NULL;
    Intrusive::HashTable<uintptr_t, WriteRequest> m_requests;
    uv_tcp_t m_tcp;

    friend SIO1Server;
};

class SIO1Server {
  public:
    enum class SIO1ServerStatus {
        SERVER_STOPPED,
        SERVER_STOPPING,
        SERVER_STARTED,
    };

    SIO1ServerStatus getServerStatus() { return m_serverStatus; }

    SIO1Server();
    void startServer(uv_loop_t* loop, int port = 6699);
    void stopServer();

    void write(unsigned char c) {
        for (auto& client : m_clients) client.write(c);
    }

  private:
    static void closeCB(uv_handle_t* handle);
    void onNewConnection(int status);
    static void onNewConnectionTrampoline(uv_stream_t* server, int status);

    SIO1Client::ListType m_clients;
    std::string m_gotError;
    EventBus::Listener m_listener;
    uv_loop_t* m_loop = NULL;
    uv_tcp_t m_server = {};
    SIO1ServerStatus m_serverStatus = SIO1ServerStatus::SERVER_STOPPED;
};

}  // namespace PCSX
