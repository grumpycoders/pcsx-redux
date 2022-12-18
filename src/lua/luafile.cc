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

#include "lua/luafile.h"

#include "core/system.h"
#include "lua/luawrapper.h"
#include "support/uvfile.h"
#include "support/zfile.h"

namespace {

using LuaFile = PCSX::LuaFFI::LuaFile;
using LuaServer = PCSX::LuaFFI::LuaServer;

enum FileOps {
    READ,
    TRUNCATE,
    CREATE,
    READWRITE,
    DOWNLOAD_URL,
};

void deleteFile(LuaFile* wrapper) { delete wrapper; }

LuaFile* openFile(const char* filename, FileOps type) {
    switch (type) {
        case READ:
            return new LuaFile(new PCSX::UvFile(filename));
        case TRUNCATE:
            return new LuaFile(new PCSX::UvFile(filename, PCSX::FileOps::TRUNCATE));
        case CREATE:
            return new LuaFile(new PCSX::UvFile(filename, PCSX::FileOps::CREATE));
        case READWRITE:
            return new LuaFile(new PCSX::UvFile(filename, PCSX::FileOps::READWRITE));
        case DOWNLOAD_URL:
            return new LuaFile(new PCSX::UvFile(filename, PCSX::UvFile::DOWNLOAD_URL));
    }

    return nullptr;
}

LuaFile* openFileWithCallback(const char* url, void (*callback)()) {
    return new LuaFile(new PCSX::UvFile(
        url, [callback]() { callback(); }, PCSX::g_system->getLoop(), PCSX::UvFile::DOWNLOAD_URL));
}

LuaFile* bufferFileReadOnly(void* data, uint64_t size) { return new LuaFile(new PCSX::BufferFile(data, size)); }
LuaFile* bufferFile(void* data, uint64_t size) {
    return new LuaFile(new PCSX::BufferFile(data, size, PCSX::FileOps::READWRITE));
}
LuaFile* bufferFileAcquire(void* data, uint64_t size) {
    return new LuaFile(new PCSX::BufferFile(data, size, PCSX::BufferFile::ACQUIRE));
}
LuaFile* bufferFileEmpty() { return new LuaFile(new PCSX::BufferFile(PCSX::FileOps::READWRITE)); }
LuaFile* subFile(LuaFile* wrapper, uint64_t start, int64_t size) {
    return new LuaFile(new PCSX::SubFile(wrapper->file, start, size));
}
LuaFile* uvFifo(const char* address, int port) { return new LuaFile(new PCSX::UvFifo(address, port)); }

LuaServer* uvFifoListener() {return new LuaServer(new PCSX::UvFifoListener());}

void startListener(LuaServer* server, unsigned port, void (*cb)(LuaFile* fifo)) { server->m_listener->start(port, PCSX::g_system->getLoop(), &server->m_async, [cb, server](PCSX::UvFifo* fifo) {
        if (fifo) {
            cb(new LuaFile(fifo));
            server->m_status = LuaServer::Status::STARTED;
        } else {
            server->m_async.data = server;
            uv_close(reinterpret_cast<uv_handle_t*>(&server->m_async), [](uv_handle_t* handle) {});
            if (!server->m_listener->isListening())
                server->m_status = LuaServer::Status::STOPPED;
        }
    });
}

void stopListener(LuaServer* server) {
    if (server->m_status == LuaServer::Status::STOPPED) return;

    server->m_status = LuaServer::Status::STOPPING;
    if (server->m_listener->isListening())
        server->m_listener->stop();

    if (!server->m_listener->isListening())
        server->m_status = LuaServer::Status::STOPPED;
}

void deleteListener(LuaServer* server) {
    if (server->m_status == LuaServer::Status::STARTED) {
        server->m_async.data = server;
        uv_close(reinterpret_cast<uv_handle_t*>(&server->m_async), [](uv_handle_t* handle) {
            auto tcp = reinterpret_cast<uv_tcp_t *>(handle);
            LuaServer* server = reinterpret_cast<LuaServer*>(handle->data);
            server->m_status = LuaServer::Status::STOPPED;

            delete tcp;
            delete server;
        });
    }
}

void closeFile(LuaFile* wrapper) { wrapper->file->close(); }

uint64_t readFileRawPtr(LuaFile* wrapper, void* dst, uint64_t size) { return wrapper->file->read(dst, size); }
uint64_t readFileBuffer(LuaFile* wrapper, void* buffer) {
    uint32_t* pSize = reinterpret_cast<uint32_t*>(buffer);
    uint8_t* data = reinterpret_cast<uint8_t*>(pSize + 1);
    return *pSize = wrapper->file->read(data, *pSize);
}

uint64_t writeFileRawPtr(LuaFile* wrapper, const uint8_t* data, uint64_t size) {
    return wrapper->file->write(data, size);
}
uint64_t writeFileBuffer(LuaFile* wrapper, const void* buffer) {
    const uint32_t* pSize = reinterpret_cast<const uint32_t*>(buffer);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(pSize + 1);
    return wrapper->file->write(data, *pSize);
}

void writeFileMoveSlice(LuaFile* wrapper, PCSX::Slice* slice) { wrapper->file->write(std::move(*slice)); }

int64_t rSeek(LuaFile* wrapper, int64_t pos, PCSX::LuaFFI::SeekWheel wheel) {
    return wrapper->file->rSeek(pos, PCSX::LuaFFI::wheelConv(wheel));
}
int64_t rTell(LuaFile* wrapper) { return wrapper->file->rTell(); }
int64_t wSeek(LuaFile* wrapper, int64_t pos, PCSX::LuaFFI::SeekWheel wheel) {
    return wrapper->file->wSeek(pos, PCSX::LuaFFI::wheelConv(wheel));
}
int64_t wTell(LuaFile* wrapper) { return wrapper->file->wTell(); }

uint64_t getFileSize(LuaFile* wrapper) { return wrapper->file->size(); }

uint64_t readFileAtRawPtr(LuaFile* wrapper, void* dst, uint64_t size, uint64_t pos) {
    return wrapper->file->readAt(dst, size, pos);
}
uint64_t readFileAtBuffer(LuaFile* wrapper, void* buffer, uint64_t pos) {
    uint32_t* pSize = reinterpret_cast<uint32_t*>(buffer);
    uint8_t* data = reinterpret_cast<uint8_t*>(pSize + 1);
    return *pSize = wrapper->file->readAt(data, *pSize, pos);
}

uint64_t writeFileAtRawPtr(LuaFile* wrapper, const uint8_t* data, uint64_t size, uint64_t pos) {
    return wrapper->file->writeAt(data, size, pos);
}
uint64_t writeFileAtBuffer(LuaFile* wrapper, const void* buffer, uint64_t pos) {
    const uint32_t* pSize = reinterpret_cast<const uint32_t*>(buffer);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(pSize + 1);
    return wrapper->file->writeAt(data, *pSize, pos);
}

void writeFileAtMoveSlice(LuaFile* wrapper, PCSX::Slice* slice, uint64_t pos) {
    wrapper->file->writeAt(std::move(*slice), pos);
}

bool isFileSeekable(LuaFile* wrapper) { return wrapper->file->seekable(); }
bool isFileWritable(LuaFile* wrapper) { return wrapper->file->writable(); }
bool isFileEOF(LuaFile* wrapper) { return wrapper->file->eof(); }
bool isFileFailed(LuaFile* wrapper) { return wrapper->file->failed(); }
bool isFileCacheable(LuaFile* wrapper) { return wrapper->file.isA<PCSX::UvFile>(); }
bool isFileCaching(LuaFile* wrapper) {
    PCSX::IO<PCSX::UvFile> file = wrapper->file.asA<PCSX::UvFile>();
    if (file) return file->caching();
    return false;
}
float fileCacheProgress(LuaFile* wrapper) {
    PCSX::IO<PCSX::UvFile> file = wrapper->file.asA<PCSX::UvFile>();
    if (file) return file->cacheProgress();
    return 0.0f;
}
void startFileCaching(LuaFile* wrapper) {
    PCSX::IO<PCSX::UvFile> file = wrapper->file.asA<PCSX::UvFile>();
    if (file) file->startCaching();
}
bool startFileCachingWithCallback(LuaFile* wrapper, void (*callback)()) {
    PCSX::IO<PCSX::UvFile> file = wrapper->file.asA<PCSX::UvFile>();
    if (file) {
        file->startCaching([callback]() { callback(); }, PCSX::g_system->getLoop());
        return true;
    } else {
        return false;
    }
}

LuaFile* dupFile(LuaFile* wrapper) { return new LuaFile(wrapper->file->dup()); }

LuaFile* zReader(LuaFile* wrapper, int64_t size, bool raw) {
    return new LuaFile(raw ? new PCSX::ZReader(wrapper->file, size, PCSX::ZReader::RAW)
                           : new PCSX::ZReader(wrapper->file, size));
}

uint64_t getSliceSize(PCSX::Slice* slice) { return slice->size(); }

const void* getSliceData(PCSX::Slice* slice) { return slice->data(); }

void destroySlice(PCSX::Slice* slice) { delete slice; }

}  // namespace

template <typename T, size_t S>
static void registerSymbol(PCSX::Lua L, const char (&name)[S], const T ptr) {
    L.push<S>(name);
    L.push((void*)ptr);
    L.settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

static void registerAllSymbols(PCSX::Lua L) {
    L.getfieldtable("_CLIBS", LUA_REGISTRYINDEX);
    L.push("SUPPORT_FILE");
    L.newtable();

    REGISTER(L, deleteFile);

    REGISTER(L, openFile);
    REGISTER(L, openFileWithCallback);
    REGISTER(L, bufferFileReadOnly);
    REGISTER(L, bufferFile);
    REGISTER(L, bufferFileAcquire);
    REGISTER(L, bufferFileEmpty);
    REGISTER(L, subFile);
    REGISTER(L, uvFifo);
    REGISTER(L, uvFifoListener);
    REGISTER(L, stopListener);
    REGISTER(L, startListener);
    REGISTER(L, deleteListener);

    REGISTER(L, closeFile);

    REGISTER(L, readFileRawPtr);
    REGISTER(L, readFileBuffer);
    REGISTER(L, writeFileRawPtr);
    REGISTER(L, writeFileBuffer);
    REGISTER(L, writeFileMoveSlice);

    REGISTER(L, rSeek);
    REGISTER(L, rTell);
    REGISTER(L, wSeek);
    REGISTER(L, wTell);

    REGISTER(L, getFileSize);

    REGISTER(L, readFileAtRawPtr);
    REGISTER(L, readFileAtBuffer);

    REGISTER(L, writeFileAtRawPtr);
    REGISTER(L, writeFileAtBuffer);
    REGISTER(L, writeFileAtMoveSlice);

    REGISTER(L, isFileSeekable);
    REGISTER(L, isFileWritable);
    REGISTER(L, isFileEOF);
    REGISTER(L, isFileFailed);
    REGISTER(L, isFileCacheable);
    REGISTER(L, isFileCaching);
    REGISTER(L, fileCacheProgress);
    REGISTER(L, startFileCaching);
    REGISTER(L, startFileCachingWithCallback);

    REGISTER(L, dupFile);

    REGISTER(L, zReader);

    REGISTER(L, getSliceSize);
    REGISTER(L, getSliceData);
    REGISTER(L, destroySlice);

    L.settable();
    L.pop();
}

void PCSX::LuaFFI::open_file(Lua L) {
    static int lualoader = 1;
    static const char* fileFFI = (
#include "lua/fileffi.lua"
    );
    registerAllSymbols(L);
    L.load(fileFFI, "internal:lua/fileffi.lua");
}
