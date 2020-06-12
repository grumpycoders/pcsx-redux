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
#include <memory>
#include <string>

#include "GL/gl3w.h"
#include "core/psxemulator.h"
#include "core/system.h"
#include "http-parser/http_parser.h"

namespace {

class VramExecutor : public PCSX::WebExecutor {
    virtual bool match(PCSX::WebClient* client, const PCSX::UrlData& urldata) final {
        return urldata.path == "/api/v1/vram/raw";
    }
    virtual bool execute(PCSX::WebClient* client, const PCSX::RequestData& request) final {
        client->write("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1048576\r\n\r\n");
        static constexpr uint32_t texSize = 1024 * 512 * sizeof(uint16_t);
        uint16_t* pixels = (uint16_t*)malloc(texSize);
        int oldTexture;
        glGetIntegerv(GL_TEXTURE_BINDING_2D, &oldTexture);
        glBindTexture(GL_TEXTURE_2D, m_VRAMTexture);
        glGetTexImage(GL_TEXTURE_2D, 0, GL_RGBA, GL_UNSIGNED_SHORT_5_5_5_1, pixels);
        glBindTexture(GL_TEXTURE_2D, oldTexture);
        PCSX::Slice slice;
        slice.acquire(pixels, texSize);
        client->write(std::move(slice));

        return true;
    }

    PCSX::EventBus::Listener m_listener;
    unsigned int m_VRAMTexture;

  public:
    VramExecutor() : m_listener(PCSX::g_system->m_eventBus) {
        m_listener.listen<PCSX::Events::CreatedVRAMTexture>([this](const auto& event) { m_VRAMTexture = event.id; });
    }
};

}  // namespace

PCSX::WebServer::WebServer() : m_listener(g_system->m_eventBus) {
    m_executors.push_back(new VramExecutor());
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
    m_server->close();
}

void PCSX::WebServer::startServer(int port) {
    assert(m_serverStatus == SERVER_STOPPED);
    m_server = g_emulator->m_loop->resource<uvw::TCPHandle>();
    m_server->on<uvw::ListenEvent>([this](const uvw::ListenEvent&, uvw::TCPHandle& srv) { onNewConnection(); });
    m_server->on<uvw::CloseEvent>(
        [this](const uvw::CloseEvent&, uvw::TCPHandle& srv) { m_serverStatus = SERVER_STOPPED; });
    m_server->bind("0.0.0.0", port);
    m_server->listen();

    m_serverStatus = SERVER_STARTED;
}

void PCSX::WebServer::onNewConnection() {
    WebClient* client = new WebClient(this, m_server);
    m_clients.push_back(client);
    client->accept(m_server);
}

struct PCSX::WebClient::WebClientImpl {
    struct WriteRequest : public Intrusive::List<WriteRequest>::Node {
        WriteRequest() {}
        WriteRequest(Slice&& slice) : m_slice(std::move(slice)) {}
        void enqueue(WebClientImpl* client) {
            client->m_requests.push_back(this);
            client->m_tcp->write(static_cast<char*>(const_cast<void*>(m_slice.data())), m_slice.size());
        }
        void gotWriteEvent() { delete this; }
        uv_write_t m_req;
        Slice m_slice;
    };
    Intrusive::List<WriteRequest> m_requests;

    WebClientImpl(WebServer* server, WebClient* parent, std::shared_ptr<uvw::TCPHandle> srv)
        : m_server(server), m_tcp(srv->loop().resource<uvw::TCPHandle>()), m_parent(parent) {
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
        m_tcp->on<uvw::CloseEvent>([this](const uvw::CloseEvent&, uvw::TCPHandle&) { delete m_parent; });
        m_tcp->on<uvw::EndEvent>([this](const uvw::EndEvent&, uvw::TCPHandle&) { onEOF(); });
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
        copyField(m_requestData.urlData.schema, UF_SCHEMA);
        copyField(m_requestData.urlData.host, UF_HOST);
        copyField(m_requestData.urlData.port, UF_PORT);
        copyField(m_requestData.urlData.path, UF_PATH);
        copyField(m_requestData.urlData.query, UF_QUERY);
        copyField(m_requestData.urlData.fragment, UF_FRAGMENT);
        copyField(m_requestData.urlData.userInfo, UF_USERINFO);
        return findExecutor() ? 0 : 1;
    }
    int onStatus(const Slice& slice) { return 0; }
    int onHeaderField(const Slice& slice) {
        m_currentHeader = slice.asString();
        return 0;
    }
    int onHeaderValue(const Slice& slice) {
        m_requestData.headers.insert(std::pair(m_currentHeader, slice.asString()));
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
        if (m_status != OPEN) return;
        Slice slice;
        slice.borrow(event.data.get(), event.length);

        processData(slice);
    }
    void processData(const Slice& slice) {
        const char* ptr = reinterpret_cast<const char*>(slice.data());
        auto size = slice.size();

        auto parsed = http_parser_execute(&m_httpParser, &m_httpParserSettings, ptr, size);
        if (m_status != OPEN) return;
        if (parsed != size) close();
        if (m_httpParser.upgrade) {
            onUpgrade();
        }
    }

    template <size_t L>
    void write(const char (&str)[L]) {
        static_assert((L - 1) <= std::numeric_limits<uint32_t>::max());
        Slice slice;
        slice.borrow(str, L - 1);
        write(std::move(slice));
    }

    void write(Slice&& slice) {
        auto* req = new WriteRequest(std::move(slice));
        req->enqueue(this);
    }

    void write(std::string&& str) {
        Slice slice(std::move(str));
        write(std::move(slice));
    }

    void write(const std::string& str) {
        Slice slice(str);
        write(std::move(slice));
    }

    void send404() {
        write("HTTP/1.1 404 Not Found\r\n\r\nURL Not found\r\n");
        close();
    }

    bool findExecutor() {
        auto& list = m_server->m_executors;
        for (m_currentExecutor = list.begin(); m_currentExecutor != list.end(); m_currentExecutor++) {
            if (m_currentExecutor->match(m_parent, m_requestData.urlData)) return true;
        }
        send404();
        return false;
    }
    int executeRequest() {
        m_requestData.method = static_cast<RequestData::Method>(m_httpParser.method);
        m_currentExecutor->execute(m_parent, m_requestData);
        close();
        return 0;
    }

    WebServer* m_server;
    std::shared_ptr<uvw::TCPHandle> m_tcp;
    enum { CLOSED, OPEN, CLOSING } m_status = CLOSED;
    http_parser_settings m_httpParserSettings;
    http_parser m_httpParser;
    Intrusive::List<WebExecutor>::iterator m_currentExecutor;
    WebClient* m_parent;

    std::string m_currentHeader;
    RequestData m_requestData;
};

PCSX::WebClient::WebClient(WebServer* server, std::shared_ptr<uvw::TCPHandle> srv)
    : m_impl(std::make_unique<WebClientImpl>(server, this, srv)) {}
void PCSX::WebClient::close() { m_impl->close(); }
void PCSX::WebClient::accept(std::shared_ptr<uvw::TCPHandle> srv) { m_impl->accept(srv); }
void PCSX::WebClient::write(Slice&& slice) { m_impl->write(std::move(slice)); }
void PCSX::WebClient::write(std::string&& str) { m_impl->write(std::move(str)); }
void PCSX::WebClient::write(const std::string& str) { m_impl->write(str); }
