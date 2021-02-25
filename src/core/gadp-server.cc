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

enum class BreakKind {
    BK_READ = 0,
    BK_WRITE = 1,
    BK_EXECUTE = 2,
    BK_SOFTWARE = 3,
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
    EV_STOPPED = 0,
    EV_RUNNING = 1,
    EV_PROCESS_CREATED = 2,
    EV_PROCESS_EXITED = 3,
    EV_THREAD_CREATED = 4,
    EV_THREAD_EXITED = 5,
    EV_MODULE_LOADED = 6,
    EV_MODULE_UNLOADED = 7,
    EV_BREAKPOINT_HIT = 8,
    EV_STEP_COMPLETED = 9,
    EV_EXCEPTION = 10,
    EV_SIGNAL = 11,
};

namespace PCSX {

namespace {

typedef Protobuf::Message<TYPESTRING("ErrorRequest")> ErrorRequest;

typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("code"), 1> ErrorReplyCode;
typedef Protobuf::Field<Protobuf::String, TYPESTRING("message"), 2> ErrorReplyMessage;
typedef Protobuf::Message<TYPESTRING("ErrorReply"), ErrorReplyCode, ErrorReplyMessage> ErrorReply;

typedef Protobuf::RepeatedFieldVariable<Protobuf::String, TYPESTRING("version"), 1> ConnectRequestVersion;
typedef Protobuf::Message<TYPESTRING("ConnectRequest"), ConnectRequestVersion> ConnectRequest;

typedef Protobuf::Field<Protobuf::String, TYPESTRING("version"), 1> ConnectReplyVersion;
typedef Protobuf::Field<Protobuf::String, TYPESTRING("schema_context"), 2> ConnectReplySchemaContext;
typedef Protobuf::Field<Protobuf::String, TYPESTRING("root_schema"), 3> ConnectReplyRootSchema;
typedef Protobuf::Message<TYPESTRING("ConnectReply"), ConnectReplyVersion, ConnectReplySchemaContext,
                          ConnectReplyRootSchema>
    ConnectReply;

typedef Protobuf::Field<Protobuf::String, TYPESTRING("content"), 1> PingContent;
typedef Protobuf::Message<TYPESTRING("PingRequest"), PingContent> PingRequest;
typedef Protobuf::Message<TYPESTRING("PingReply"), PingContent> PingReply;

typedef Protobuf::Field<Protobuf::String, TYPESTRING("space"), 1> AddressSpace;
typedef Protobuf::Field<Protobuf::UInt64, TYPESTRING("offset"), 2> AddressOffset;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("extend"), 3> AddressExtend;
typedef Protobuf::Message<TYPESTRING("Address"), AddressSpace, AddressOffset> Address;
typedef Protobuf::Message<TYPESTRING("AddressRange"), AddressSpace, AddressOffset, AddressExtend> AddressRange;

typedef Protobuf::RepeatedFieldVariable<Protobuf::String, TYPESTRING("e"), 1> PathElement;
typedef Protobuf::Message<TYPESTRING("Path"), PathElement> Path;
typedef Protobuf::RepeatedFieldVariable<Path, TYPESTRING("path"), 1> PathListPath;
typedef Protobuf::Message<TYPESTRING("path"), PathListPath> PathList;

typedef Protobuf::RepeatedFieldVariable<Protobuf::Int32, TYPESTRING("k"), 1> KindSet;
typedef Protobuf::Message<TYPESTRING("BreakKindsSet"), KindSet> BreakKindsSet;
typedef Protobuf::Message<TYPESTRING("StepKindsSet"), KindSet> StepKindsSet;

typedef Protobuf::RepeatedFieldVariable<Protobuf::String, TYPESTRING("s"), 1> StringListField;
typedef Protobuf::Message<TYPESTRING("StringList"), StringListField> StringList;

typedef Protobuf::Message<TYPESTRING("AttachKindSet"), KindSet> AttachKindSet;

typedef Protobuf::Message<TYPESTRING("DataType")> DataType;

typedef Protobuf::Field<Protobuf::Bool, TYPESTRING("bool_value"), 1> BoolValue;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("int_value"), 2> IntValue;
typedef Protobuf::Field<Protobuf::Int64, TYPESTRING("long_value"), 3> LongValue;
typedef Protobuf::Field<Protobuf::Float, TYPESTRING("float_value"), 4> FloatValue;
typedef Protobuf::Field<Protobuf::Double, TYPESTRING("double_value"), 5> DoubleValue;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("bytes_value"), 6> BytesValue;
typedef Protobuf::Field<Protobuf::String, TYPESTRING("string_value"), 7> StringValue;
typedef Protobuf::MessageField<StringList, TYPESTRING("string_list_value"), 8> StringListValue;
typedef Protobuf::MessageField<Address, TYPESTRING("address_value"), 9> AddressValue;
typedef Protobuf::MessageField<AddressRange, TYPESTRING("range_value"), 10> RangeValue;
typedef Protobuf::MessageField<BreakKindsSet, TYPESTRING("break_kinds_value"), 11> BreakKindsValue;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("exec_state_value"), 12> ExecStateValue;
typedef Protobuf::MessageField<StepKindsSet, TYPESTRING("step_kinds_value"), 13> StepKindsValue;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("primitive_kind_value"), 14> PrimitiveKindValue;
typedef Protobuf::MessageField<DataType, TYPESTRING("data_type_value"), 15> DataTypeValue;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("update_mode_value"), 16> UpdateModeValue;
typedef Protobuf::MessageField<Path, TYPESTRING("path_value"), 17> PathValue;
typedef Protobuf::MessageField<PathList, TYPESTRING("path_list_value"), 18> PathListValue;

}  // namespace

}  // namespace PCSX

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
