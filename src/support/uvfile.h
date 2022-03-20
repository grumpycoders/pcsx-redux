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

#include <curl/curl.h>
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
    enum DownloadUrl { DOWNLOAD_URL };
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
    virtual void write(Slice&& slice) final override;
    virtual ssize_t readAt(void* dest, size_t size, size_t ptr) final override;
    virtual ssize_t writeAt(const void* src, size_t size, size_t ptr) final override;
    virtual void writeAt(Slice&& slice, size_t ptr) final override;
    virtual bool failed() final override { return m_failed; }
    virtual bool eof() final override;
    virtual std::filesystem::path filename() final override { return m_filename; }
    virtual File* dup() final override {
        return m_download   ? new UvFile(m_filename.string(), DOWNLOAD_URL)
               : writable() ? new UvFile(m_filename, FileOps::READWRITE)
                            : new UvFile(m_filename);
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
    // Download a URL
    UvFile(const std::string_view& url, DownloadUrl) : UvFile(url, nullptr, nullptr, DOWNLOAD_URL) {}
    UvFile(const std::string_view& url, std::function<void(UvFile*)>&& completed, uv_loop_t* other, DownloadUrl);
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

    void startCaching() { startCaching(nullptr, nullptr); }
    void startCaching(std::function<void(UvFile*)>&& completed, uv_loop_t* loop);
    bool caching() { return m_cache; }
    float cacheProgress() { return m_cacheProgress.load(std::memory_order_relaxed); }
    void waitCache() { m_cacheBarrier.get_future().get(); }

    static void iterateOverAllFiles(std::function<void(UvFile*)> walker) {
        for (auto& f : s_allFiles) walker(&f);
    }

    static float getReadRate() {
        return 1000.0f * float(s_dataReadLastTick.load(std::memory_order_relaxed)) / float(c_tick);
    }
    static float getWriteRate() {
        return 1000.0f * float(s_dataWrittenLastTick.load(std::memory_order_relaxed)) / float(c_tick);
    }
    static float getDownloadRate() {
        return 1000.0f * float(s_dataDownloadLastTick.load(std::memory_order_relaxed)) / float(c_tick);
    }

  private:
    bool m_failed = true;
    bool m_download = false;
    std::atomic<bool> m_cancelDownload = false;
    std::function<void(UvFile*)> m_cachingDoneCB = nullptr;
    uv_async_t m_cbAsync;
    const std::filesystem::path m_filename;
    size_t m_ptrR = 0;
    size_t m_ptrW = 0;
    size_t m_size = 0;
    uint8_t* m_cache = nullptr;
    uv_file m_handle = -1;  // ugh
    CURL* m_curlHandle = nullptr;
    uv_buf_t m_cacheBuf;
    uv_fs_t m_cacheReq;

    static uv_loop_t s_uvLoop;
    static uv_timer_t s_curlTimeout;
    static CURLM* s_curlMulti;

    void readCacheChunk(uv_loop_t* loop);
    void readCacheChunkResult();
    static void processCurlMultiInfo();
    void downloadDone(CURLMsg* message);
    static int curlSocketFunction(CURL* easy, curl_socket_t s, int action, void* userp, void* socketp);
    static int curlTimerFunction(CURLM* multi, long timeout_ms, void* userp);
    static size_t curlWriteFunctionTrampoline(char* ptr, size_t size, size_t nmemb, void* userdata);
    size_t curlWriteFunction(char* ptr, size_t size);
    static int curlXferInfoFunctionTrampoline(void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
                                              curl_off_t ulnow);
    int curlXferInfoFunction(curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);

    void openwrapper(const char* filename, int flags);

    void cacheCallbackSetup(std::function<void(UvFile*)>&& callbackDone, uv_loop_t* otherLoop);

    std::atomic<float> m_cacheProgress = 0.0;
    std::promise<void> m_cacheBarrier;
    size_t m_cachePtr = 0;

    // This isn't really safe, but it's not meant to.
    static bool s_threadRunning;
    static std::thread s_uvThread;
    static uv_async_t s_kicker;
    static uv_timer_t s_timer;
    static size_t s_dataReadTotal;
    static size_t s_dataWrittenTotal;
    static size_t s_dataDownloadTotal;
    static size_t s_dataReadSinceLastTick;
    static size_t s_dataWrittenSinceLastTick;
    static size_t s_dataDownloadSinceLastTick;
    static std::atomic<size_t> s_dataReadLastTick;
    static std::atomic<size_t> s_dataWrittenLastTick;
    static std::atomic<size_t> s_dataDownloadLastTick;
    static constexpr uint64_t c_tick = 500;

    typedef std::function<void(uv_loop_t*)> UvRequest;
    static moodycamel::ConcurrentQueue<UvRequest> s_queue;

    static void request(UvRequest&& req) {
        s_queue.enqueue(std::move(req));
        uv_async_send(&s_kicker);
    }

    static UvFilesListType s_allFiles;
};

}  // namespace PCSX
