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
#include "support/hashtable.h"

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
        if (g_emulator->settings.get<Emulator::SettingWebServer>() && (m_serverStatus != SERVER_STARTED)) {
            startServer(&g_emulator->m_loop, g_emulator->settings.get<Emulator::SettingWebServerPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto& event) {
        if (m_serverStatus == SERVER_STARTED) stopServer();
    });
}

void PCSX::WebServer::stopServer() {
    assert(m_serverStatus == SERVER_STARTED);
    m_serverStatus = SERVER_STOPPING;
    for (auto& client : m_clients) client.close();
    uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
}

void PCSX::WebServer::startServer(uv_loop_t* loop, int port) {
    assert(m_serverStatus == SERVER_STOPPED);
    m_loop = loop;
    uv_tcp_init(loop, &m_server);
    m_server.data = this;

    struct sockaddr_in bindAddr;
    int result = uv_ip4_addr("0.0.0.0", port, &bindAddr);
    if (result != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
        return;
    }
    result = uv_tcp_bind(&m_server, reinterpret_cast<const sockaddr*>(&bindAddr), 0);
    if (result != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
        return;
    }
    result = uv_listen((uv_stream_t*)&m_server, 16, onNewConnectionTrampoline);
    if (result != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(&m_server), closeCB);
        return;
    }
    m_serverStatus = SERVER_STARTED;
}

void PCSX::WebServer::closeCB(uv_handle_t* handle) {
    WebServer* self = static_cast<WebServer*>(handle->data);
    self->m_serverStatus = SERVER_STOPPED;
}

void PCSX::WebServer::onNewConnectionTrampoline(uv_stream_t* handle, int status) {
    WebServer* self = static_cast<WebServer*>(handle->data);
    self->onNewConnection(status);
}

void PCSX::WebServer::onNewConnection(int status) {
    if (status < 0) return;
    WebClient* client = new WebClient(this);
    if (client->accept(&m_server)) {
        m_clients.push_back(client);
    } else {
        delete client;
    }
}

struct PCSX::WebClient::WebClientImpl {
    struct WriteRequest : public Intrusive::HashTable<uintptr_t, WriteRequest>::Node {
        WriteRequest() {}
        WriteRequest(Slice&& slice) : m_slice(std::move(slice)) {}
        void enqueue(WebClientImpl* client) {
            if (client->m_closeScheduled) {
                delete this;
                return;
            }
            m_buf.base = static_cast<char*>(const_cast<void*>(m_slice.data()));
            m_buf.len = m_slice.size();
            client->m_requests.insert(reinterpret_cast<uintptr_t>(&m_req), this);
            uv_write(&m_req, reinterpret_cast<uv_stream_t*>(&client->m_tcp), &m_buf, 1, writeCB);
        }
        static void writeCB(uv_write_t* request, int status) {
            WebClientImpl* client = static_cast<WebClientImpl*>(request->handle->data);
            auto self = client->m_requests.find(reinterpret_cast<uintptr_t>(request));
            delete &*self;
            if ((status != 0) || (client->m_closeScheduled && (client->m_requests.size() == 0))) client->close();
        }
        uv_buf_t m_buf;
        uv_write_t m_req;
        Slice m_slice;
    };
    Intrusive::HashTable<uintptr_t, WriteRequest> m_requests;

    WebClientImpl(WebServer* server, WebClient* parent) : m_server(server), m_parent(parent) {
        uv_tcp_init(server->m_loop, &m_tcp);
        m_tcp.data = this;
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
        if (m_status != OPEN) return;
        m_status = CLOSING;
        uv_close(reinterpret_cast<uv_handle_t*>(&m_tcp), closeCB);
    }
    bool accept(uv_tcp_t* srv) {
        assert(m_status == CLOSED);
        if (uv_accept(reinterpret_cast<uv_stream_t*>(srv), reinterpret_cast<uv_stream_t*>(&m_tcp)) == 0) {
            uv_read_start(reinterpret_cast<uv_stream_t*>(&m_tcp), allocTrampoline, readTrampoline);
            m_status = OPEN;
        }
        return m_status == OPEN;
    }

    void onEOF() {
        http_parser_execute(&m_httpParser, &m_httpParserSettings, nullptr, 0);
        if (m_httpParser.upgrade) {
            onUpgrade();
        }
        scheduleClose();
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
    static void allocTrampoline(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf) {
        WebClientImpl* client = static_cast<WebClientImpl*>(handle->data);
        client->alloc(suggestedSize, buf);
    }
    void alloc(size_t suggestedSize, uv_buf_t* buf) {
        assert(!m_allocated);
        m_allocated = true;
        buf->base = m_buffer;
        buf->len = sizeof(m_buffer);
    }
    static void readTrampoline(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
        WebClientImpl* client = static_cast<WebClientImpl*>(stream->data);
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
    static void closeCB(uv_handle_t* handle) {
        WebClientImpl* client = static_cast<WebClientImpl*>(handle->data);
        delete client->m_parent;
    }
    void processData(const Slice& slice) {
        const char* ptr = reinterpret_cast<const char*>(slice.data());
        auto size = slice.size();

        auto parsed = http_parser_execute(&m_httpParser, &m_httpParserSettings, ptr, size);
        if (m_status != OPEN) return;
        if (parsed != size) send400();
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

    void send400() {
        write("HTTP/1.1 400 Bad Request\r\n\r\nThis request failed to parse properly.\r\n");
        scheduleClose();
    }

    void send404() {
        write("HTTP/1.1 404 Not Found\r\n\r\nURL Not found.\r\n");
        scheduleClose();
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
        scheduleClose();
        return 0;
    }
    void scheduleClose() {
        if (m_requests.size() == 0) {
            close();
        } else {
            m_closeScheduled = true;
        }
    }

    WebServer* m_server;
    uv_tcp_t m_tcp;
    static constexpr size_t BUFFER_SIZE = 256;
    char m_buffer[BUFFER_SIZE];
    bool m_allocated = false;
    enum { CLOSED, OPEN, CLOSING } m_status = CLOSED;
    http_parser_settings m_httpParserSettings;
    http_parser m_httpParser;
    Intrusive::List<WebExecutor>::iterator m_currentExecutor;
    WebClient* m_parent;

    std::string m_currentHeader;
    RequestData m_requestData;

    bool m_closeScheduled = false;
};

PCSX::WebClient::WebClient(WebServer* server) : m_impl(std::make_unique<WebClientImpl>(server, this)) {}
void PCSX::WebClient::close() { m_impl->close(); }
bool PCSX::WebClient::accept(uv_tcp_t* srv) { return m_impl->accept(srv); }
void PCSX::WebClient::write(Slice&& slice) { m_impl->write(std::move(slice)); }
void PCSX::WebClient::write(std::string&& str) { m_impl->write(std::move(str)); }
void PCSX::WebClient::write(const std::string& str) { m_impl->write(str); }
