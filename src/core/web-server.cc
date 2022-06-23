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

#include <charconv>
#include <map>
#include <memory>
#include <string>

#include "GL/gl3w.h"
#include "core/gpu.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "http-parser/http_parser.h"
#include "multipart-parser-c/multipart_parser.h"
#include "support/file.h"
#include "support/hashtable.h"
#include "support/strings-helpers.h"

namespace {

class VramExecutor : public PCSX::WebExecutor {
    virtual bool match(PCSX::WebClient* client, const PCSX::UrlData& urldata) final {
        return urldata.path == "/api/v1/gpu/vram/raw";
    }
    virtual bool execute(PCSX::WebClient* client, PCSX::RequestData& request) final {
        if (request.method == PCSX::RequestData::Method::HTTP_HTTP_GET) {
            client->write(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1048576\r\n\r\n");
            static constexpr uint32_t texSize = 1024 * 512 * sizeof(uint16_t);
            uint16_t* pixels = (uint16_t*)malloc(texSize);
            int oldTexture;
            glFlush();
            glGetIntegerv(GL_TEXTURE_BINDING_2D, &oldTexture);
            glBindTexture(GL_TEXTURE_2D, m_VRAMTexture);
            glGetTexImage(GL_TEXTURE_2D, 0, GL_RGBA, GL_UNSIGNED_SHORT_5_5_5_1, pixels);
            glBindTexture(GL_TEXTURE_2D, oldTexture);
            PCSX::Slice slice;
            slice.acquire(pixels, texSize);
            client->write(std::move(slice));

            return true;
        } else if (request.method == PCSX::RequestData::Method::HTTP_POST) {
            auto vars = parseQuery(request.urlData.query);
            auto ix = vars.find("x");
            auto iy = vars.find("y");
            auto iwidth = vars.find("width");
            auto iheight = vars.find("height");
            if ((ix == vars.end()) || (iy == vars.end()) || (iwidth == vars.end()) || (iheight == vars.end())) {
                client->write("HTTP/1.1 400 Bad Request\r\n\r\n");
                return true;
            }
            auto x = std::stoi(ix->second);
            auto y = std::stoi(iy->second);
            auto width = std::stoi(iwidth->second);
            auto height = std::stoi(iheight->second);
            if ((x < 0) || (y < 0) || (width < 0) || (height < 0)) {
                client->write("HTTP/1.1 400 Bad Request\r\n\r\n");
                return true;
            }
            if ((x > 1024) || (y > 512) || ((x + width) > 1024) || ((y + height) > 512)) {
                client->write("HTTP/1.1 400 Bad Request\r\n\r\n");
                return true;
            }
            auto size = width * height * sizeof(uint16_t);
            if (size != request.body.size()) {
                client->write("HTTP/1.1 400 Bad Request\r\n\r\n");
                return true;
            }

            PCSX::g_emulator->m_gpu->partialUpdateVRAM(x, y, width, height, request.body.data<uint16_t>());
            client->write("HTTP/1.1 200 OK\r\n\r\n");
            return true;
        }
        return false;
    }

    PCSX::EventBus::Listener m_listener;
    unsigned int m_VRAMTexture;

  public:
    VramExecutor() : m_listener(PCSX::g_system->m_eventBus) {
        m_listener.listen<PCSX::Events::CreatedVRAMTexture>([this](const auto& event) { m_VRAMTexture = event.id; });
    }
    virtual ~VramExecutor() = default;
};

class RamExecutor : public PCSX::WebExecutor {
    virtual bool match(PCSX::WebClient* client, const PCSX::UrlData& urldata) final {
        return urldata.path == "/api/v1/cpu/ram/raw";
    }
    virtual bool execute(PCSX::WebClient* client, PCSX::RequestData& request) final {
        const auto& ram8M = PCSX::g_emulator->settings.get<PCSX::Emulator::Setting8MB>().value;
        if (request.method == PCSX::RequestData::Method::HTTP_HTTP_GET) {
            if (ram8M) {
                client->write(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 8388608\r\n\r\n");
            } else {
                client->write(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 2097152\r\n\r\n");
            }
            uint32_t size = 1024 * 1024 * (ram8M ? 8 : 2);
            uint8_t* data = (uint8_t*)malloc(size);
            memcpy(data, PCSX::g_emulator->m_mem->m_psxM, size);
            PCSX::Slice slice;
            slice.acquire(data, size);
            client->write(std::move(slice));
            return true;
        } else if (request.method == PCSX::RequestData::Method::HTTP_POST) {
            const auto ramSize = (ram8M ? 8 : 2) * 1024 * 1024;
            auto vars = parseQuery(request.urlData.query);
            auto ioffset = vars.find("offset");
            auto isize = vars.find("size");
            if ((ioffset == vars.end()) || (isize == vars.end())) {
                client->write("HTTP/1.1 400 Bad Request\r\n\r\n");
                return true;
            }
            auto offset = std::stoul(ioffset->second);
            auto size = std::stoul(isize->second);
            if ((offset >= ramSize) || (size > ramSize) || ((offset + size) > ramSize)) {
                client->write("HTTP/1.1 400 Bad Request\r\n\r\n");
                return true;
            }
            if (size != request.body.size()) {
                client->write("HTTP/1.1 400 Bad Request\r\n\r\n");
                return true;
            }

            memcpy(PCSX::g_emulator->m_mem->m_psxM + offset, request.body.data<uint8_t>(), size);
            client->write("HTTP/1.1 200 OK\r\n\r\n");
            return true;
        }
        return false;
    }

  public:
    RamExecutor() = default;
    virtual ~RamExecutor() = default;
};

class AssemblyExecutor : public PCSX::WebExecutor {
    virtual bool match(PCSX::WebClient* client, const PCSX::UrlData& urldata) final {
        return urldata.path == "/api/v1/assembly/symbols";
    }
    virtual bool execute(PCSX::WebClient* client, PCSX::RequestData& request) final {
        auto& cpu = PCSX::g_emulator->m_cpu;
        auto& body = request.body;
        PCSX::IO<PCSX::File> file = new PCSX::BufferFile(std::move(body));
        while (file && !file->failed() && !file->eof()) {
            auto line = file->gets();
            auto tokens = PCSX::StringsHelpers::split(std::string_view(line), " ");
            if (tokens.size() != 2) {
                continue;
            }
            auto addressStr = tokens[0];
            auto name = tokens[1];
            uint32_t address;
            auto result = std::from_chars(addressStr.data(), addressStr.data() + addressStr.size(), address, 16);
            if (result.ec == std::errc::invalid_argument) continue;

            cpu->m_symbols[address] = name;
        }
        client->write("HTTP/1.1 200 OK\r\n\r\n");
        return true;
    }

  public:
    AssemblyExecutor() = default;
    virtual ~AssemblyExecutor() = default;
};

}  // namespace

std::multimap<std::string, std::string> PCSX::WebExecutor::parseQuery(const std::string& query) {
    std::multimap<std::string, std::string> ret;
    auto fragments = StringsHelpers::split(std::string_view(query), "&");
    for (auto& f : fragments) {
        auto parts = StringsHelpers::split(f, "=", true);
        if (parts.size() == 2) {
            ret.emplace(percentDecode(parts[0]), percentDecode(parts[1]));
        }
    }
    return ret;
}

std::string PCSX::WebExecutor::percentDecode(std::string_view str) {
    std::string ret;
    auto len = str.length();
    for (decltype(len) i = 0; i < len; i++) {
        auto c = str[i];
        switch (c) {
            case '%': {
                if ((len - i) < 3) return ret;

                auto hex = str.substr(i + 1, 2);
                uint8_t result = 0;

                auto [ptr, ec]{std::from_chars(hex.data(), hex.data() + hex.size(), result, 16)};

                if (ec != std::errc()) return ret;
                i += 2;
                break;
            }
            case '+': {
                ret += ' ';
                break;
            }
            default: {
                ret += c;
                break;
            }
        }
    }
    return ret;
}

PCSX::WebServer::WebServer() : m_listener(g_system->m_eventBus) {
    m_executors.push_back(new VramExecutor());
    m_executors.push_back(new RamExecutor());
    m_executors.push_back(new AssemblyExecutor());
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) {
        auto& debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();
        if (debugSettings.get<Emulator::DebugSettings::WebServer>() && (m_serverStatus != SERVER_STARTED)) {
            startServer(g_system->getLoop(), debugSettings.get<Emulator::DebugSettings::WebServerPort>());
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
    result = uv_listen((uv_stream_t*)&m_server, 16, [](uv_stream_t* handle, int status) {
        WebServer* self = static_cast<WebServer*>(handle->data);
        self->onNewConnection(status);
    });
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
        m_httpParserSettings.on_message_begin = [](http_parser* parser) {
            return static_cast<WebClientImpl*>(parser->data)->onMessageBegin();
        };
        m_httpParserSettings.on_url = [](http_parser* parser, const char* data, size_t size) {
            Slice slice;
            slice.borrow(data, size);
            return static_cast<WebClientImpl*>(parser->data)->onUrl(slice);
        };
        m_httpParserSettings.on_status = [](http_parser* parser, const char* data, size_t size) {
            Slice slice;
            slice.borrow(data, size);
            return static_cast<WebClientImpl*>(parser->data)->onStatus(slice);
        };
        m_httpParserSettings.on_header_field = [](http_parser* parser, const char* data, size_t size) {
            Slice slice;
            slice.borrow(data, size);
            return static_cast<WebClientImpl*>(parser->data)->onHeaderField(slice);
        };
        m_httpParserSettings.on_header_value = [](http_parser* parser, const char* data, size_t size) {
            Slice slice;
            slice.borrow(data, size);
            return static_cast<WebClientImpl*>(parser->data)->onHeaderValue(slice);
        };
        m_httpParserSettings.on_headers_complete = [](http_parser* parser) {
            return static_cast<WebClientImpl*>(parser->data)->onHeadersComplete();
        };
        m_httpParserSettings.on_body = [](http_parser* parser, const char* data, size_t size) {
            Slice slice;
            slice.borrow(data, size);
            return static_cast<WebClientImpl*>(parser->data)->onBody(slice);
        };
        m_httpParserSettings.on_message_complete = [](http_parser* parser) {
            return static_cast<WebClientImpl*>(parser->data)->onMessageComplete();
        };
        m_httpParserSettings.on_chunk_header = [](http_parser* parser) {
            return static_cast<WebClientImpl*>(parser->data)->onChunkHeader();
        };
        m_httpParserSettings.on_chunk_complete = [](http_parser* parser) {
            return static_cast<WebClientImpl*>(parser->data)->onChunkComplete();
        };
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
            uv_read_start(
                reinterpret_cast<uv_stream_t*>(&m_tcp),
                [](uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf) {
                    WebClientImpl* client = static_cast<WebClientImpl*>(handle->data);
                    client->alloc(suggestedSize, buf);
                },
                [](uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
                    WebClientImpl* client = static_cast<WebClientImpl*>(stream->data);
                    client->read(nread, buf);
                });
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
    void headerComplete() {
        m_requestData.headers.insert(std::pair(m_currentHeader, m_currentValue));
        m_currentHeader.clear();
        m_currentValue.clear();
    }
    int onHeaderField(const Slice& slice) {
        if (m_headerState == PARSING_VALUE) {
            headerComplete();
            m_headerState = PARSING_HEADER;
        }
        m_currentHeader += slice.asString();
        return 0;
    }
    int onHeaderValue(const Slice& slice) {
        m_headerState = PARSING_VALUE;
        m_currentValue += slice.asString();
        return 0;
    }
    void formHeaderComplete() {
        m_requestData.form.insert(std::pair(m_currentFormHeader, m_currentFormValue));
        m_currentFormHeader.clear();
        m_currentFormValue.clear();
    }
    int onFormHeaderField(const Slice& slice) {
        if (m_formHeaderState == PARSING_VALUE) {
            formHeaderComplete();
            m_formHeaderState = PARSING_HEADER;
        }
        m_currentFormHeader += slice.asString();
        return 0;
    }
    int onFormHeaderValue(const Slice& slice) {
        m_formHeaderState = PARSING_VALUE;
        m_currentFormValue += slice.asString();
        return 0;
    }
    int onHeadersComplete() {
        headerComplete();
        auto& ct = m_requestData.headers;
        auto it = ct.find("Content-Type");
        if (it != ct.end()) {
            auto& contentType = it->second;
            if (contentType.starts_with("multipart/form-data")) {
                auto pos = contentType.find("boundary=");
                if (pos != std::string::npos) {
                    m_multipartBoundary = "--" + contentType.substr(pos + 9);
                    m_multipart = true;
                    memset(&m_multipartParserCallbacks, 0, sizeof(multipart_parser_settings));
                    m_multipartParserCallbacks.on_header_field = [](multipart_parser* p, const char* at,
                                                                    size_t length) {
                        Slice slice;
                        slice.borrow(at, length);
                        return static_cast<WebClientImpl*>(multipart_parser_get_data(p))->onFormHeaderField(slice);
                    };
                    m_multipartParserCallbacks.on_header_value = [](multipart_parser* p, const char* at,
                                                                    size_t length) {
                        Slice slice;
                        slice.borrow(at, length);
                        return static_cast<WebClientImpl*>(multipart_parser_get_data(p))->onFormHeaderValue(slice);
                    };
                    m_multipartParserCallbacks.on_headers_complete = [](multipart_parser* p) {
                        return static_cast<WebClientImpl*>(multipart_parser_get_data(p))->onFormHeadersComplete();
                    };
                    m_multipartParserCallbacks.on_part_data = [](multipart_parser* p, const char* at, size_t length) {
                        Slice slice;
                        slice.borrow(at, length);
                        return static_cast<WebClientImpl*>(multipart_parser_get_data(p))->onFormData(slice);
                    };
                    m_multipartParser = multipart_parser_init(m_multipartBoundary.c_str(), &m_multipartParserCallbacks);
                    multipart_parser_set_data(m_multipartParser, this);
                }
            }
        }
        return 0;
    }

    int onFormHeadersComplete() {
        formHeaderComplete();
        return 0;
    }

    int onFormData(const Slice& slice) {
        m_requestData.body.concatenate(slice);
        return 0;
    }

    int onBody(const Slice& slice) {
        if (m_multipart) {
            multipart_parser_execute(m_multipartParser, slice.data<char>(), slice.size());
        } else {
            m_requestData.body.concatenate(slice);
        }
        return 0;
    }
    int onMessageComplete() {
        if (m_multipart) {
            multipart_parser_free(m_multipartParser);
        }
        executeRequest();
        return 0;
    }
    int onChunkHeader() { return 0; }
    int onChunkComplete() { return 0; }
    void alloc(size_t suggestedSize, uv_buf_t* buf) {
        assert(!m_allocated);
        m_allocated = true;
        buf->base = m_buffer;
        buf->len = sizeof(m_buffer);
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
    std::string m_currentValue;
    std::string m_currentFormHeader;
    std::string m_currentFormValue;
    enum HeaderState {
        PARSING_HEADER,
        PARSING_VALUE,
    };
    HeaderState m_headerState = PARSING_HEADER;
    HeaderState m_formHeaderState = PARSING_HEADER;
    RequestData m_requestData;
    bool m_multipart = false;
    std::string m_multipartBoundary;
    multipart_parser* m_multipartParser;
    multipart_parser_settings m_multipartParserCallbacks;

    bool m_closeScheduled = false;
};

PCSX::WebClient::WebClient(WebServer* server) : m_impl(std::make_unique<WebClientImpl>(server, this)) {}
void PCSX::WebClient::close() { m_impl->close(); }
bool PCSX::WebClient::accept(uv_tcp_t* srv) { return m_impl->accept(srv); }
void PCSX::WebClient::write(Slice&& slice) { m_impl->write(std::move(slice)); }
void PCSX::WebClient::write(std::string&& str) { m_impl->write(std::move(str)); }
void PCSX::WebClient::write(const std::string& str) { m_impl->write(str); }
