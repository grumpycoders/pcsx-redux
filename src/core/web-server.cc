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

#include "core/web-server.h"

#include <map>
#include <string>

#include "core/psxemulator.h"
#include "core/system.h"
#include "http-parser/http_parser.h"

PCSX::WebServer::WebServer() : m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) {
        if (g_emulator->settings.get<Emulator::SettingWebServer>()) {
            startServer(g_emulator->settings.get<Emulator::SettingWebServerPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto& event) {
        if (m_serverStatus == SERVER_STARTED) stopServer();
    });
}

void PCSX::WebServer::stopServer() {
    assert(m_serverStatus == SERVER_STARTED);
    for (auto& client : m_clients) client.close();
}

void PCSX::WebServer::startServer(int port) {
    assert(m_serverStatus == SERVER_STOPPED);
    m_server = g_emulator->m_loop->resource<uvw::TCPHandle>();
    m_server->on<uvw::ListenEvent>([this](const uvw::ListenEvent&, uvw::TCPHandle& srv) { onNewConnection(); });
    m_server->bind("0.0.0.0", port);
    m_server->listen();

    m_serverStatus = SERVER_STARTED;
}

void PCSX::WebServer::onNewConnection() {
    WebClient* client = new WebClient(m_server);
    m_clients.push_back(client);
    client->accept(m_server);
}

struct PCSX::WebClient::WebClientImpl {
    WebClientImpl(std::shared_ptr<uvw::TCPHandle> srv) : m_tcp(srv->loop().resource<uvw::TCPHandle>()) {
        m_httpParserSettings.on_message_begin = WebClientImpl::onMessageBeginTrampoline;
        m_httpParserSettings.on_url = WebClientImpl::onUrlTrampoline;
        m_httpParserSettings.on_status = WebClientImpl::onStatusTrampoline;
        m_httpParserSettings.on_header_field = WebClientImpl::onHeaderFieldTrampoline;
        m_httpParserSettings.on_header_value = WebClientImpl::onHeaderValueTrampoline;
        m_httpParserSettings.on_headers_complete = WebClientImpl::onHeadersCompleteTrampoline;
        m_httpParserSettings.on_body = WebClientImpl::onBodyTrampoline;
        m_httpParserSettings.on_message_complete = WebClientImpl::onMessageCompleteTrampoline;
        m_httpParserSettings.on_chunk_header = WebClientImpl::onChunkHeaderTrampoline;
        m_httpParserSettings.on_chunk_complete = WebClientImpl::onChunkCompleteTrampoline;
        http_parser_init(&m_httpParser, HTTP_REQUEST);
        m_httpParser.data = this;
    }
    void close() {
        assert(m_status == OPEN);
        m_status = CLOSING;
        m_tcp->close();
    }
    void accept(std::shared_ptr<uvw::TCPHandle> srv) {
        assert(m_status == CLOSED);
        m_tcp->on<uvw::CloseEvent>([this](const uvw::CloseEvent&, uvw::TCPHandle&) { delete this; });
        m_tcp->on<uvw::EndEvent>([this](const uvw::EndEvent&, uvw::TCPHandle&) { onEOF(); });
        m_tcp->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent&, uvw::TCPHandle&) { close(); });
        m_tcp->on<uvw::DataEvent>([this](const uvw::DataEvent& event, uvw::TCPHandle&) { read(event); });
        m_tcp->on<uvw::WriteEvent>([this](const uvw::WriteEvent&, uvw::TCPHandle&) {});
        srv->accept(*m_tcp);
        m_tcp->read();
        m_status = OPEN;
    }

    void onEOF() {
        http_parser_execute(&m_httpParser, &m_httpParserSettings, nullptr, 0);
        if (m_httpParser.upgrade) {
            onUpgrade();
        }
        close();
    }

    void onUpgrade() {}
    int onMessageBegin() { return 0; }
    int onUrl(const Slice& slice) {
        const char* data = static_cast<const char*>(slice.data());
        int connect = m_httpParser.method == HTTP_CONNECT;
        struct http_parser_url urlParser;
        http_parser_url_init(&urlParser);
        int result = http_parser_parse_url(data, slice.size(), connect, &urlParser);
        if (result) return result;
        auto copyField = [this, data, &urlParser](std::string& str, int field) {
            if (urlParser.field_set & (1 << field)) {
                str = std::string(data + urlParser.field_data[field].off, urlParser.field_data[field].len);
            } else {
                str.clear();
            }
        };
        copyField(m_urlSchema, UF_SCHEMA);
        copyField(m_urlHost, UF_HOST);
        copyField(m_urlPort, UF_PORT);
        copyField(m_urlPath, UF_PATH);
        copyField(m_urlQuery, UF_QUERY);
        copyField(m_urlFragment, UF_FRAGMENT);
        copyField(m_urlUserInfo, UF_USERINFO);
        return validateUrl();
    }
    int onStatus(const Slice& slice) { return 0; }
    int onHeaderField(const Slice& slice) {
        m_currentHeader = slice.toString();
        return 0;
    }
    int onHeaderValue(const Slice& slice) {
        m_headers.insert(std::pair(m_currentHeader, slice.toString()));
        return 0;
    }
    int onHeadersComplete() { return 0; }
    int onBody(const Slice& slice) { return 0; }
    int onMessageComplete() { return executeRequest(); }
    int onChunkHeader() { return 0; }
    int onChunkComplete() { return 0; }
    static int onMessageBeginTrampoline(http_parser* parser) {
        return static_cast<WebClientImpl*>(parser->data)->onMessageBegin();
    }
    static int onUrlTrampoline(http_parser* parser, const char* data, size_t size) {
        Slice slice;
        slice.borrow(data, size);
        return static_cast<WebClientImpl*>(parser->data)->onUrl(slice);
    }
    static int onStatusTrampoline(http_parser* parser, const char* data, size_t size) {
        Slice slice;
        slice.borrow(data, size);
        return static_cast<WebClientImpl*>(parser->data)->onStatus(slice);
    }
    static int onHeaderFieldTrampoline(http_parser* parser, const char* data, size_t size) {
        Slice slice;
        slice.borrow(data, size);
        return static_cast<WebClientImpl*>(parser->data)->onHeaderField(slice);
    }
    static int onHeaderValueTrampoline(http_parser* parser, const char* data, size_t size) {
        Slice slice;
        slice.borrow(data, size);
        return static_cast<WebClientImpl*>(parser->data)->onHeaderValue(slice);
    }
    static int onHeadersCompleteTrampoline(http_parser* parser) {
        return static_cast<WebClientImpl*>(parser->data)->onHeadersComplete();
    }
    static int onBodyTrampoline(http_parser* parser, const char* data, size_t size) {
        Slice slice;
        slice.borrow(data, size);
        return static_cast<WebClientImpl*>(parser->data)->onBody(slice);
    }
    static int onMessageCompleteTrampoline(http_parser* parser) {
        return static_cast<WebClientImpl*>(parser->data)->onMessageComplete();
    }
    static int onChunkHeaderTrampoline(http_parser* parser) {
        return static_cast<WebClientImpl*>(parser->data)->onChunkHeader();
    }
    static int onChunkCompleteTrampoline(http_parser* parser) {
        return static_cast<WebClientImpl*>(parser->data)->onChunkComplete();
    }
    void read(const uvw::DataEvent& event) {
        Slice slice;
        slice.borrow(event.data.get(), event.length);

        processData(slice);
    }
    void processData(const Slice& slice) {
        const char* ptr = reinterpret_cast<const char*>(slice.data());
        auto size = slice.size();

        auto parsed = http_parser_execute(&m_httpParser, &m_httpParserSettings, ptr, size);
        if (parsed != size) close();
        if (m_httpParser.upgrade) {
            onUpgrade();
        }
    }

    template <size_t L>
    void write(const char (&str)[L]) {
        m_tcp->write(const_cast<char*>(str), L - 1);
    }

    void send404() {
        write("HTTP/1.1 404 Not Found\r\n\r\nURL Not found\r\n");
        close();
    }

    int validateUrl() { return 0; }
    int executeRequest() {
        write("HTTP/1.1 200 OK\r\n\r\nData.\r\n");
        close();
        return 0;
    }

    std::shared_ptr<uvw::TCPHandle> m_tcp;
    enum { CLOSED, OPEN, CLOSING } m_status = CLOSED;
    http_parser_settings m_httpParserSettings;
    http_parser m_httpParser;

    std::string m_urlSchema;
    std::string m_urlHost;
    std::string m_urlPort;
    std::string m_urlPath;
    std::string m_urlQuery;
    std::string m_urlFragment;
    std::string m_urlUserInfo;

    std::string m_currentHeader;
    std::multimap<std::string, std::string> m_headers;
};

PCSX::WebClient::WebClient(std::shared_ptr<uvw::TCPHandle> srv) : m_impl(std::make_unique<WebClientImpl>(srv)) {}
void PCSX::WebClient::close() { m_impl->close(); }
void PCSX::WebClient::accept(std::shared_ptr<uvw::TCPHandle> srv) { m_impl->accept(srv); }
