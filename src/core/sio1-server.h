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

#include <string>
#include <queue>

#include "core/debug.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "support/eventbus.h"
#include "support/hashtable.h"
#include "support/slice.h"
#include "support/list.h"


namespace PCSX {
    class SIO1Client;
    class SIO1Server;

    class SIO1Client : public Intrusive::List<SIO1Client>::Node {
    public:
        SIO1Client(uv_tcp_t* server);
        typedef Intrusive::List<SIO1Client> ListType;

    bool accept(uv_tcp_t* server) {
            assert(m_status == CLOSED);
            if (uv_accept(reinterpret_cast<uv_stream_t*>(server), reinterpret_cast<uv_stream_t*>(&m_tcp)) == 0) {
                uv_read_start(reinterpret_cast<uv_stream_t*>(&m_tcp), allocTrampoline, readTrampoline);
                m_status = OPEN;
            }
            return m_status == OPEN;
        }
        void close() {
            if (m_status != OPEN) return;
            m_status = CLOSING;
            uv_close(reinterpret_cast<uv_handle_t*>(&m_tcp), closeCB);
        }

    private:

        uv_tcp_t m_tcp;
        enum { CLOSED, OPEN, CLOSING } m_status = CLOSED;
        bool m_allocated = false;

        EventBus::Listener m_listener;
        uv_loop_t* m_loop;
        friend SIO1Server;
        static constexpr size_t BUFFER_SIZE = 256;

        static void allocTrampoline(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf) {
            SIO1Client* client = static_cast<SIO1Client*>(handle->data);
            client->alloc(suggestedSize, buf);
        }

        void alloc(size_t suggestedSize, uv_buf_t* buf) {
            assert(!m_allocated);
            m_allocated = true;
            buf->base = m_buffer;
            buf->len = sizeof(m_buffer);
        }

        static void readTrampoline(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
            SIO1Client* client = static_cast<SIO1Client*>(stream->data);
            client->read(nread, buf);
        }
        void read(ssize_t nread, const uv_buf_t* buf) {
            m_allocated = false;
            if (nread <= 0) {
                close();
                return;
            }

            Slice slice;
            slice.borrow(m_buffer, nread);
            processData(slice);
        }

        void write(unsigned char c)
        {
            auto* req = new WriteRequest();
            req->m_slice.copy(static_cast<void*>(&c), 1);
            req->enqueue(this);            
        }
        static void closeCB(uv_handle_t* handle) {
            SIO1Client* client = static_cast<SIO1Client*>(handle->data);
            delete client;
        }

        void processData(const Slice& slice);

        struct WriteRequest : public Intrusive::HashTable<uintptr_t, WriteRequest>::Node {
            WriteRequest() {}
            WriteRequest(Slice&& slice) : m_slice(std::move(slice)) {}
            void enqueue(SIO1Client* client) {
                m_buf.base = static_cast<char*>(const_cast<void*>(m_slice.data()));
                m_buf.len = m_slice.size();
                client->m_requests.insert(reinterpret_cast<uintptr_t>(&m_req), this);
                uv_write(&m_req, reinterpret_cast<uv_stream_t*>(&client->m_tcp), &m_buf, 1, writeCB);
            }
            static void writeCB(uv_write_t* request, int status) {
                SIO1Client* client = static_cast<SIO1Client*>(request->handle->data);
                auto self = client->m_requests.find(reinterpret_cast<uintptr_t>(request));
                delete &*self;
                if (status != 0) client->close();
            }
            uv_buf_t m_buf;
            uv_write_t m_req;
            Slice m_slice;
        };
        Intrusive::HashTable<uintptr_t, WriteRequest> m_requests;

        char m_buffer[BUFFER_SIZE];
    };

    class SIO1Server {
    public:
        SIO1Server();
        //~SIO1Server() { }
        enum SIO1ServerStatus {
            SERVER_STOPPED,
            SERVER_STOPPING,
            SERVER_STARTED,
        };
        SIO1ServerStatus getServerStatus() { return m_serverStatus; }

        void startServer(uv_loop_t* loop, int port = 6699);
        void stopServer();


        void write(unsigned char c) {
            for (auto& client : m_clients) client.write(c);
        }

    private:
        static void onNewConnectionTrampoline(uv_stream_t* server, int status);
        void onNewConnection(int status);
        static void closeCB(uv_handle_t* handle);
        SIO1ServerStatus m_serverStatus = SERVER_STOPPED;
        uv_tcp_t m_server;
        uv_loop_t* m_loop;
        SIO1Client::ListType m_clients;
        EventBus::Listener m_listener;

        std::string m_gotError;
    };

}  // namespace PCSX
