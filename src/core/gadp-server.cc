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

#include "core/gadp-server.h"

#include <assert.h>

#include "core/debug.h"
#include "core/misc.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "support/protobuf.h"
#include "uvw.hpp"

enum class ErrorCode {
    EC_UNKNOWN = 0,
    EC_BAD_REQUEST = 1,
    EC_NO_VERSION = 2,
    EC_NO_OBJECT = 3,
    EC_NO_INTERFACE = 4,
    EC_BAD_ARGUMENT = 5,
    EC_BAD_ADDRESS = 6,
    EC_NOT_SUPPORTED = 7,
    EC_MEMORY_ACCESS = 8,
    EC_REGISTER_ACCESS = 9,
    EC_USER_ERROR = 10,
    EC_MODEL_ACCESS = 11,
};

enum class StepKind {
    SK_INTO = 0,
    SK_ADVANCE = 1,
    SK_FINISH = 2,
    SK_LINE = 3,
    SK_OVER = 4,
    SK_OVER_LINE = 5,
    SK_SKIP = 6,
    SK_RETURN = 7,
    SK_UNTIL = 8,
};

enum class AttachKind {
    AK_BY_OBJECT_REF = 0,
    AK_BY_ID = 1,
};

enum class ExecutionState {
    ES_INACTIVE = 0,
    ES_ACTIVE = 1,
    ES_STOPPED = 2,
    ES_RUNNING = 3,
    ES_TERMINATED = 4,
};

enum class PrimitiveKind {
    PK_UNDEFINED = 0,
    PK_VOID = 1,
    PK_UINT = 2,
    PK_SINT = 3,
    PK_FLOAT = 4,
    PK_COMPLEX = 5,
};

enum class UpdateMode {
    UM_UNSOLICITED = 0,
    UM_SOLICITED = 1,
    UM_FIXED = 2,
};

enum class ValueType {
    VT_VOID = 0,
    VT_BOOL = 1,
    VT_INT = 2,
    VT_LONG = 3,
    VT_FLOAT = 4,
    VT_DOUBLE = 5,
    VT_BYTES = 6,
    VT_STRING = 7,
    VT_STRING_LIST = 8,
    VT_ADDRESS = 9,
    VT_RANGE = 10,
    VT_BREAK_KIND_SET = 11,
    VT_EXECUTION_STATE = 12,
    VT_STEP_KIND_SET = 13,
    VT_PRIMITIVE_KIND = 14,
    VT_DATA_TYPE = 15,
    VT_UPDATE_MODE = 16,
    VT_PATH = 17,
    VT_PATH_LIST = 18,
    VT_TYPE = 19,
    VT_ATTACH_KIND_SET = 20,
};

enum class TargetEventType {
    TET_STOPPED = 0,
    TET_RUNNING = 1,
    TET_PROCESS_CREATED = 2,
    TET_PROCESS_EXITED = 3,
    TET_THREAD_CREATED = 4,
    TET_THREAD_EXITED = 5,
    TET_MODULE_LOADED = 6,
    TET_MODULE_UNLOADED = 7,
    TET_BREAKPOINT_HIT = 8,
    TET_STEP_COMPLETED = 9,
    TET_EXCEPTION = 10,
    TET_SIGNAL = 11,
};

PCSX::GadpServer::GadpServer() : m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) {
        if (g_emulator->settings.get<Emulator::SettingGadpServer>()) {
            startServer(g_emulator->settings.get<Emulator::SettingGadpServerPort>());
        }
    });
    m_listener.listen<Events::Quitting>([this](const auto& event) {
        if (m_serverStatus == SERVER_STARTED) stopServer();
    });
}

void PCSX::GadpServer::stopServer() {
    assert(m_serverStatus == SERVER_STARTED);
    for (auto& client : m_clients) client.close();
    m_server->close();
}

void PCSX::GadpServer::startServer(int port) {
    assert(m_serverStatus == SERVER_STOPPED);
    m_server = g_emulator->m_loop->resource<uvw::TCPHandle>();
    m_server->on<uvw::ListenEvent>([this](const uvw::ListenEvent&, uvw::TCPHandle& srv) { onNewConnection(); });
    m_server->on<uvw::CloseEvent>(
        [this](const uvw::CloseEvent&, uvw::TCPHandle& srv) { m_serverStatus = SERVER_STOPPED; });
    m_server->on<uvw::ErrorEvent>(
        [this](const uvw::ErrorEvent& event, uvw::TCPHandle& srv) { m_gotError = event.what(); });
    m_gotError = "";
    m_server->bind("0.0.0.0", port);
    if (!m_gotError.empty()) {
        g_system->printf("Error while trying to bind to port %i: %s\n", port, m_gotError.c_str());
        m_server->close();
        return;
    }
    m_server->listen();
    if (!m_gotError.empty()) {
        g_system->printf("Error while trying to listen to port %i: %s\n", port, m_gotError.c_str());
        m_server->close();
        return;
    }

    m_serverStatus = SERVER_STARTED;
}

void PCSX::GadpServer::onNewConnection() {
    GadpClient* client = new GadpClient(m_server);
    m_clients.push_back(client);
    client->accept(m_server);
}

PCSX::GadpClient::GadpClient(std::shared_ptr<uvw::TCPHandle> srv)
    : m_tcp(srv->loop().resource<uvw::TCPHandle>()), m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::ExecutionFlow::Pause>([this](const auto& event) {});
    m_listener.listen<Events::ExecutionFlow::ShellReached>([this](const auto& event) {});
}

void PCSX::GadpClient::processData(const Slice& slice) {
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(slice.data());
    auto size = slice.size();
    int v = 0;

    while (size) {
        switch (m_state) {
            case WAIT_FOR_LEN:
                m_lenBuffer[m_length++] = *ptr++;
                size--;
                if (m_length == 4) {
                    m_length = m_lenBuffer[0] | (m_lenBuffer[1] << 8) | (m_lenBuffer[2] << 16) | (m_lenBuffer[3] << 24);
                    m_protoBuffer.clear();
                    if (m_length != 0) {
                        m_state = READING_DATA;
                    } else {
                        // process empty proto
                    }
                }
                break;
            case READING_DATA: {
                auto copySize = std::min(size, m_length);
                m_protoBuffer += std::string((const char*)ptr, copySize);
                ptr += copySize;
                size -= copySize;
                m_length -= copySize;

                if (m_length == 0) {
                    m_state = WAIT_FOR_LEN;
                    // process proto
                }
            }
        }
    }
}
