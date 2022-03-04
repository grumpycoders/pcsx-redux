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

#include <uv.h>

#include <atomic>
#include <future>
#include <string>
#include <thread>
#include <variant>

#include "concurrentqueue/concurrentqueue.h"
#include "support/file.h"

namespace PCSX {

class UvFile : public File {
  public:
    static void startThread();
    static void stopThread();

    virtual void close() final override;
    virtual ssize_t rSeek(ssize_t pos, int wheel) final override;
    virtual ssize_t rTell() final override { return m_ptrR; }
    virtual ssize_t wSeek(ssize_t pos, int wheel) final override;
    virtual ssize_t wTell() final override { return m_ptrW; }
    virtual size_t size() final override { return m_size; }
    virtual ssize_t read(void* dest, size_t size) final override;
    virtual ssize_t write(const void* dest, size_t size) final override;
    virtual bool eof() final override;
    virtual std::filesystem::path filename() final override { return m_filename; }
    virtual File* dup() final override {
        return writable() ? new UvFile(m_filename, FileOps::READWRITE) : new UvFile(m_filename);
    }

    // Open the file in read-only mode.
    UvFile(const std::filesystem::path& filename) : UvFile(filename.u8string()) {}
    // Open the file in write-only mode, creating it if needed, and truncate it otherwise.
    UvFile(const std::filesystem::path& filename, FileOps::Truncate) : UvFile(filename.u8string(), FileOps::TRUNCATE) {}
    // Open the file in write-only mode, creating it if needed, but won't truncate.
    UvFile(const std::filesystem::path& filename, FileOps::Create) : UvFile(filename.u8string(), FileOps::CREATE) {}
    // Open the existing file in read-write mode. Must exist.
    UvFile(const std::filesystem::path& filename, FileOps::ReadWrite)
        : UvFile(filename.u8string(), FileOps::READWRITE) {}
#if defined(__cpp_lib_char8_t)
    UvFile(const std::u8string& filename) : UvFile(reinterpret_cast<const char*>(filename.c_str())) {}
    UvFile(const std::u8string& filename, FileOps::Truncate)
        : UvFile(reinterpret_cast<const char*>(filename.c_str()), FileOps::TRUNCATE) {}
    UvFile(const std::u8string& filename, FileOps::Create)
        : UvFile(reinterpret_cast<const char*>(filename.c_str()), FileOps::CREATE) {}
    UvFile(const std::u8string& filename, FileOps::ReadWrite)
        : UvFile(reinterpret_cast<const char*>(filename.c_str()), FileOps::READWRITE) {}
#endif
    UvFile(const std::string& filename) : UvFile(filename.c_str()) {}
    UvFile(const std::string& filename, FileOps::Truncate) : UvFile(filename.c_str(), FileOps::TRUNCATE) {}
    UvFile(const std::string& filename, FileOps::Create) : UvFile(filename.c_str(), FileOps::CREATE) {}
    UvFile(const std::string& filename, FileOps::ReadWrite) : UvFile(filename.c_str(), FileOps::READWRITE) {}
    UvFile(const char* filename);
    UvFile(const char* filename, FileOps::Truncate);
    UvFile(const char* filename, FileOps::Create);
    UvFile(const char* filename, FileOps::ReadWrite);

  private:
    const std::filesystem::path m_filename;
    size_t m_ptrR = 0;
    size_t m_ptrW = 0;
    size_t m_size = 0;
    uint8_t* m_cache = nullptr;
    uv_file m_handle = uv_file();

    static std::pair<uv_file, size_t> openwrapper(const char* filename, int flags);

    std::atomic<float> m_cacheProgress = 0.0;

    // This isn't really safe, but it's not meant to.
    static bool s_threadRunning;
    static std::thread s_uvThread;
    static uv_async_t s_kicker;

    struct StopRequest {
        StopRequest() {}
        StopRequest(const StopRequest&) = delete;
        StopRequest(StopRequest&&) = default;
        StopRequest& operator=(const StopRequest&) = delete;
        StopRequest& operator=(StopRequest&&) = default;
        std::promise<void> barrier;
    };
    struct OpenRequest {
        OpenRequest() {}
        OpenRequest(const OpenRequest&) = delete;
        OpenRequest(OpenRequest&&) = default;
        OpenRequest& operator=(const OpenRequest&) = delete;
        OpenRequest& operator=(OpenRequest&&) = default;
        std::string fname;
        int flags;
        std::promise<std::pair<uv_file, size_t>> ret;
    };
    struct CloseRequest {
        CloseRequest() {}
        CloseRequest(const CloseRequest&) = delete;
        CloseRequest(CloseRequest&&) = default;
        CloseRequest& operator=(const CloseRequest&) = delete;
        CloseRequest& operator=(CloseRequest&&) = default;
        uv_file file;
    };
    struct ReadRequest {
        ReadRequest() {}
        ReadRequest(const ReadRequest&) = delete;
        ReadRequest(ReadRequest&&) = default;
        ReadRequest& operator=(const ReadRequest&) = delete;
        ReadRequest& operator=(ReadRequest&&) = default;
        uv_file file;
        void* dest;
        size_t size;
        size_t offset;
        std::promise<size_t> ret;
    };
    struct CacheRequest {
        CacheRequest() {}
        CacheRequest(const CacheRequest&) = delete;
        CacheRequest(CacheRequest&&) = default;
        CacheRequest& operator=(const CacheRequest&) = delete;
        CacheRequest& operator=(CacheRequest&&) = default;
    };
    struct WriteRequest {
        WriteRequest() {}
        WriteRequest(const WriteRequest&) = delete;
        WriteRequest(WriteRequest&&) = default;
        WriteRequest& operator=(const WriteRequest&) = delete;
        WriteRequest& operator=(WriteRequest&&) = default;
    };
    typedef std::variant<StopRequest, OpenRequest, CloseRequest, ReadRequest, WriteRequest> UvRequest;
    static moodycamel::ConcurrentQueue<UvRequest> s_queue;

    struct OpenInfo {
        OpenInfo(decltype(OpenRequest::ret)&& ret_) : ret(std::move(ret_)) {}
        uv_fs_t req;
        uv_file file;
        decltype(OpenRequest::ret) ret;
    };
    struct ReadInfo {
        ReadInfo(decltype(ReadRequest::ret)&& ret_) : ret(std::move(ret_)) {}
        uv_fs_t req;
        uv_buf_t buf;
        decltype(ReadRequest::ret) ret;
    };
};

}  // namespace PCSX
