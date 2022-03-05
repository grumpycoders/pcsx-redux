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
#include <functional>
#include <future>
#include <string>
#include <thread>

#include "concurrentqueue/concurrentqueue.h"
#include "support/file.h"
#include "support/list.h"

namespace PCSX {

class UvFile;
typedef Intrusive::List<UvFile> UvFilesListType;

class UvFile : public File, public UvFilesListType::Node {
  public:
    struct UvFileThread {
        UvFileThread() { PCSX::UvFile::startThread(); }
        ~UvFileThread() { PCSX::UvFile::stopThread(); }
    };

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
    virtual bool failed() final override { return m_handle < 0; }
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

    void startCaching();
    bool cached() { return m_cache; }
    float cacheProgress() { return m_cacheProgress.load(std::memory_order_relaxed); }
    void waitCache() { m_cacheBarrier.get_future().get(); }

    static void iterateOverAllFiles(std::function<void(UvFile*)> walker) {
        for (auto& f : s_allFiles) walker(&f);
    }

  private:
    const std::filesystem::path m_filename;
    size_t m_ptrR = 0;
    size_t m_ptrW = 0;
    size_t m_size = 0;
    uint8_t* m_cache = nullptr;
    uv_file m_handle = -1;  // ugh
    uv_buf_t m_cacheBuf;
    uv_fs_t m_cacheReq;

    void readCacheChunk(uv_loop_t* loop);
    void readCacheChunkResult();

    void openwrapper(const char* filename, int flags);

    std::atomic<float> m_cacheProgress = 0.0;
    std::promise<void> m_cacheBarrier;
    size_t m_cachePtr = 0;

    // This isn't really safe, but it's not meant to.
    static bool s_threadRunning;
    static std::thread s_uvThread;
    static uv_async_t s_kicker;

    typedef std::function<void(uv_loop_t*)> UvRequest;
    static moodycamel::ConcurrentQueue<UvRequest> s_queue;

    static void request(UvRequest&& req) {
        s_queue.enqueue(std::move(req));
        uv_async_send(&s_kicker);
    }

    static UvFilesListType s_allFiles;
};

}  // namespace PCSX
