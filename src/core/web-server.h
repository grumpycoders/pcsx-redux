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

#include <uv.h>

#include <map>
#include <memory>
#include <string>

#include "support/eventbus.h"
#include "support/list.h"
#include "support/slice.h"

namespace PCSX {

struct UrlData {
    std::string schema;
    std::string host;
    std::string port;
    std::string path;
    std::string query;
    std::string fragment;
    std::string userInfo;
};

struct RequestData {
    UrlData urlData;
    enum Method {
        HTTP_DELETE,
        HTTP_HTTP_GET,
        HTTP_HEAD,
        HTTP_POST,
        HTTP_PUT,
        HTTP_CONNECT,
        HTTP_OPTIONS,
        HTTP_TRACE,
        HTTP_COPY,
        HTTP_LOCK,
        HTTP_MKCOL,
        HTTP_MOVE,
        HTTP_PROPFIND,
        HTTP_PROPPATH,
        HTTP_SEARCH,
        HTTP_UNLOCK,
        HTTP_BIND,
        HTTP_REBIND,
        HTTP_UNBIND,
        HTTP_ACL,
        HTTP_REPORT,
        HTTP_MKACTIVITY,
        HTTP_CHECKOUT,
        HTTP_MERGE,
        HTTP_MSEARCH,
        HTTP_NOTIFY,
        HTTP_SUBSCRIBE,
        HTTP_UNSUBSCRIBE,
        HTTP_PATCH,
        HTTP_PURGE,
        HTTP_MKCALENDAR,
        HTTP_LINK,
        HTTP_UNLINK,
        HTTP_SOURCE,
    } method;
    std::multimap<std::string, std::string> headers;
};

class WebClient;
class WebServer;

class WebExecutor : public Intrusive::List<WebExecutor>::Node {
  public:
    virtual bool match(WebClient* client, const UrlData&) = 0;
    virtual bool execute(WebClient* client, const RequestData&) = 0;
};

class WebClient : public Intrusive::List<WebClient>::Node {
  public:
    WebClient(WebServer* server);
    typedef Intrusive::List<WebClient> ListType;
    void close();
    bool accept(uv_tcp_t* srv);
    void write(Slice&& slice);
    template <size_t L>
    void write(const char (&str)[L]) {
        static_assert((L - 1) <= std::numeric_limits<uint32_t>::max());
        Slice slice;
        slice.borrow(str, L - 1);
        write(std::move(slice));
    }
    void write(std::string&& str);
    void write(const std::string& str);

  private:
    struct WebClientImpl;
    std::unique_ptr<WebClientImpl> m_impl;
    friend WebServer;
};

class WebServer {
  public:
    WebServer();
    ~WebServer() { m_executors.destroyAll(); }
    enum WebServerStatus {
        SERVER_STOPPED,
        SERVER_STOPPING,
        SERVER_STARTED,
    };
    WebServerStatus getServerStatus() { return m_serverStatus; }

    void startServer(uv_loop_t* loop, int port = 8080);
    void stopServer();

  private:
    static void onNewConnectionTrampoline(uv_stream_t* server, int status);
    void onNewConnection(int status);
    static void closeCB(uv_handle_t* handle);
    WebServerStatus m_serverStatus = SERVER_STOPPED;
    uv_tcp_t m_server;
    uv_loop_t* m_loop;
    WebClient::ListType m_clients;
    EventBus::Listener m_listener;
    Intrusive::List<WebExecutor> m_executors;

    std::string m_gotError;

    friend struct WebClient::WebClientImpl;
};

}  // namespace PCSX
