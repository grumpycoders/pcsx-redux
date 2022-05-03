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

#include "support/uvfile.h"

#include <curl/curl.h>

#include <exception>

struct CurlContext {
    CurlContext(curl_socket_t sockfd, uv_loop_t *loop) : sockfd(sockfd) {
        uv_poll_init_socket(loop, &poll_handle, sockfd);
        poll_handle.data = this;
    }
    void close() {
        uv_close(reinterpret_cast<uv_handle_t *>(&poll_handle), [](uv_handle_t *handle) -> void {
            CurlContext *context = reinterpret_cast<CurlContext *>(handle->data);
            delete context;
        });
    }
    uv_poll_t poll_handle;
    curl_socket_t sockfd;
};

std::thread PCSX::UvThreadOp::s_uvThread;
bool PCSX::UvThreadOp::s_threadRunning = false;
uv_async_t PCSX::UvThreadOp::s_kicker;
uv_timer_t PCSX::UvThreadOp::s_timer;
size_t PCSX::UvThreadOp::s_dataReadTotal;
size_t PCSX::UvThreadOp::s_dataWrittenTotal;
size_t PCSX::UvThreadOp::s_dataDownloadTotal;
size_t PCSX::UvThreadOp::s_dataReadSinceLastTick;
size_t PCSX::UvThreadOp::s_dataWrittenSinceLastTick;
size_t PCSX::UvThreadOp::s_dataDownloadSinceLastTick;
std::atomic<size_t> PCSX::UvThreadOp::s_dataReadLastTick;
std::atomic<size_t> PCSX::UvThreadOp::s_dataWrittenLastTick;
std::atomic<size_t> PCSX::UvThreadOp::s_dataDownloadLastTick;
ConcurrentQueue<PCSX::UvThreadOp::UvRequest> PCSX::UvThreadOp::s_queue;
PCSX::UvThreadOpListType PCSX::UvThreadOp::s_allOps;
uv_loop_t PCSX::UvThreadOp::s_uvLoop;
uv_timer_t PCSX::UvThreadOp::s_curlTimeout;
CURLM *PCSX::UvThreadOp::s_curlMulti = nullptr;

void PCSX::UvThreadOp::startThread() {
    if (s_threadRunning) throw std::runtime_error("UV thread already running");
    std::promise<void> barrier;
    auto f = barrier.get_future();
    s_threadRunning = true;
    s_uvThread = std::thread([barrier = std::move(barrier)]() mutable -> void {
        if (curl_global_init(CURL_GLOBAL_ALL)) {
            throw std::runtime_error("Failed to initialize libcurl");
        }
        uv_loop_init(&s_uvLoop);
        uv_timer_init(&s_uvLoop, &s_curlTimeout);
        s_curlMulti = curl_multi_init();
        curl_multi_setopt(s_curlMulti, CURLMOPT_SOCKETFUNCTION, curlSocketFunction);
        curl_multi_setopt(s_curlMulti, CURLMOPT_TIMERFUNCTION, curlTimerFunction);
        s_dataReadTotal = 0;
        s_dataWrittenTotal = 0;
        s_dataDownloadTotal = 0;
        s_dataReadSinceLastTick = 0;
        s_dataWrittenSinceLastTick = 0;
        s_dataDownloadSinceLastTick = 0;
        s_dataReadLastTick = 0;
        s_dataWrittenLastTick = 0;
        s_dataDownloadLastTick = 0;
        uv_async_init(&s_uvLoop, &s_kicker, [](uv_async_t *async) {
            UvRequest req;
            while (s_queue.Dequeue(req)) {
                req(async->loop);
            }
        });
        uv_timer_init(&s_uvLoop, &s_timer);
        uv_timer_start(
            &s_timer,
            [](uv_timer_t *timer) {
                s_dataReadLastTick.store(s_dataReadTotal - s_dataReadSinceLastTick, std::memory_order_relaxed);
                s_dataWrittenLastTick.store(s_dataWrittenTotal - s_dataWrittenSinceLastTick, std::memory_order_relaxed);
                s_dataDownloadLastTick.store(s_dataDownloadTotal - s_dataDownloadSinceLastTick,
                                             std::memory_order_relaxed);
                s_dataReadSinceLastTick = s_dataReadTotal;
                s_dataWrittenSinceLastTick = s_dataWrittenTotal;
                s_dataDownloadSinceLastTick = s_dataDownloadTotal;
            },
            c_tick, c_tick);
        barrier.set_value();
        uv_run(&s_uvLoop, UV_RUN_DEFAULT);
        uv_loop_close(&s_uvLoop);
    });
    f.wait();
}

int PCSX::UvThreadOp::curlSocketFunction(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp) {
    CurlContext *curlContext = reinterpret_cast<CurlContext *>(socketp);
    int events = 0;

    switch (action) {
        case CURL_POLL_IN:
        case CURL_POLL_OUT:
        case CURL_POLL_INOUT:
            if (!curlContext) curlContext = new CurlContext(s, &s_uvLoop);

            curl_multi_assign(s_curlMulti, s, (void *)curlContext);

            if (action != CURL_POLL_IN) events |= UV_WRITABLE;
            if (action != CURL_POLL_OUT) events |= UV_READABLE;

            uv_poll_start(&curlContext->poll_handle, events, [](uv_poll_t *req, int status, int events) -> void {
                int running_handles;
                int flags = 0;
                CurlContext *context;

                if (events & UV_READABLE) flags |= CURL_CSELECT_IN;
                if (events & UV_WRITABLE) flags |= CURL_CSELECT_OUT;

                context = reinterpret_cast<CurlContext *>(req->data);

                curl_multi_socket_action(s_curlMulti, context->sockfd, flags, &running_handles);

                processCurlMultiInfo();
            });
            break;
        case CURL_POLL_REMOVE:
            if (socketp) {
                uv_poll_stop(&curlContext->poll_handle);
                curlContext->close();
                curl_multi_assign(s_curlMulti, s, NULL);
            }
            break;
        default:
            throw std::runtime_error("Shouldn't happen - corrupted curl state");
    }

    return 0;
}

int PCSX::UvThreadOp::curlTimerFunction(CURLM *multi, long timeout_ms, void *userp) {
    if (timeout_ms < 0) {
        uv_timer_stop(&s_curlTimeout);
    } else {
        if (timeout_ms == 0)
            timeout_ms = 1; /* 0 means directly call socket_action, but we will do it
                               in a bit */
        uv_timer_start(
            &s_curlTimeout,
            [](uv_timer_t *req) -> void {
                int running_handles;
                curl_multi_socket_action(s_curlMulti, CURL_SOCKET_TIMEOUT, 0, &running_handles);
                processCurlMultiInfo();
            },
            timeout_ms, 0);
    }
    return 0;
}

void PCSX::UvThreadOp::stopThread() {
    if (!s_threadRunning) throw std::runtime_error("UV thread isn't running");
    request([](auto loop) {
        uv_close(reinterpret_cast<uv_handle_t *>(&s_kicker), [](auto handle) {});
        uv_close(reinterpret_cast<uv_handle_t *>(&s_timer), [](auto handle) {});
    });
    s_uvThread.join();
    s_threadRunning = false;
}

void PCSX::UvFile::close() {
    if (m_download && (m_cacheProgress.load(std::memory_order_acquire) != 1.0)) {
        m_cancelDownload.store(true, std::memory_order_release);
        m_cacheBarrier.get_future().wait();
    } else if (m_cache && (m_cacheProgress.load(std::memory_order_acquire) != 1.0)) {
        request([this](auto loop) { m_cachePtr = m_size; });
        m_cacheBarrier.get_future().wait();
    }
    free(m_cache);
    m_cache = nullptr;
    if (m_handle < 0) return;
    request([handle = m_handle](auto loop) {
        auto req = new uv_fs_t();
        uv_fs_close(loop, req, handle, [](uv_fs_t *req) {
            uv_fs_req_cleanup(req);
            delete req;
        });
    });
}

void PCSX::UvFile::openwrapper(const char *filename, int flags) {
    s_allOps.push_back(this);
    struct Info {
        std::promise<uv_file> handle;
        std::promise<size_t> size;
        uv_fs_t req;
    };
    Info info;
    info.req.data = &info;
    size_t size = 0;
    uv_file handle = -1;  // why isn't there any good "failed" value in libuv?
    request([&info, filename, flags](auto loop) {
        int ret = uv_fs_open(loop, &info.req, filename, flags, 0644, [](uv_fs_t *req) {
            auto info = reinterpret_cast<Info *>(req->data);
            auto loop = req->loop;
            auto handle = req->result;
            uv_fs_req_cleanup(req);
            info->handle.set_value(handle);
            if (handle < 0) return;
            req->data = info;
            int ret = uv_fs_fstat(loop, req, handle, [](uv_fs_t *req) {
                auto info = reinterpret_cast<Info *>(req->data);
                auto size = req->statbuf.st_size;
                uv_fs_req_cleanup(req);
                info->size.set_value(size);
            });
            if (ret != 0) {
                info->size.set_exception(std::make_exception_ptr(std::runtime_error("uv_fs_fstat failed")));
            }
        });
        if (ret != 0) {
            info.handle.set_exception(std::make_exception_ptr(std::runtime_error("uv_fs_open failed")));
        }
    });
    try {
        handle = info.handle.get_future().get();
        if (handle >= 0) size = info.size.get_future().get();
    } catch (...) {
    }
    m_handle = handle;
    m_size = size;
    if (handle >= 0) m_failed = false;
}

PCSX::UvFile::UvFile(const char *filename) : File(RO_SEEKABLE), m_filename(filename) {
    openwrapper(filename, UV_FS_O_RDONLY);
}
PCSX::UvFile::UvFile(const char *filename, FileOps::Create) : File(RW_SEEKABLE), m_filename(filename) {
    openwrapper(filename, UV_FS_O_RDWR | UV_FS_O_CREAT);
}
PCSX::UvFile::UvFile(const char *filename, FileOps::Truncate) : File(RW_SEEKABLE), m_filename(filename) {
    openwrapper(filename, UV_FS_O_RDWR | UV_FS_O_CREAT | UV_FS_O_TRUNC);
}
PCSX::UvFile::UvFile(const char *filename, FileOps::ReadWrite) : File(RW_SEEKABLE), m_filename(filename) {
    openwrapper(filename, UV_FS_O_RDWR);
}

PCSX::UvFile::UvFile(const std::string_view &url, std::function<void()> &&callbackDone, uv_loop_t *otherLoop,
                     DownloadUrl)
    : File(RO_SEEKABLE), m_filename(url), m_download(true), m_failed(false) {
    s_allOps.push_back(this);
    std::string urlCopy(url);
    cacheCallbackSetup(std::move(callbackDone), otherLoop);
    request([url = std::move(urlCopy), this](auto loop) {
        m_curlHandle = curl_easy_init();
        curl_easy_setopt(m_curlHandle, CURLOPT_URL, url.data());
        curl_easy_setopt(m_curlHandle, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(m_curlHandle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(m_curlHandle, CURLOPT_FAILONERROR, 1L);
        curl_easy_setopt(m_curlHandle, CURLOPT_PRIVATE, dynamic_cast<UvThreadOp *>(this));
        curl_easy_setopt(m_curlHandle, CURLOPT_WRITEDATA, this);
        curl_easy_setopt(m_curlHandle, CURLOPT_XFERINFODATA, this);
        curl_easy_setopt(m_curlHandle, CURLOPT_WRITEFUNCTION, curlWriteFunctionTrampoline);
        curl_easy_setopt(m_curlHandle, CURLOPT_XFERINFOFUNCTION, curlXferInfoFunctionTrampoline);
        curl_multi_add_handle(s_curlMulti, m_curlHandle);
    });
}

size_t PCSX::UvFile::curlWriteFunctionTrampoline(char *ptr, size_t size, size_t nmemb, void *userdata) {
    UvFile *file = reinterpret_cast<UvFile *>(userdata);
    return file->curlWriteFunction(ptr, size * nmemb);
}

int PCSX::UvFile::curlXferInfoFunctionTrampoline(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                                                 curl_off_t ultotal, curl_off_t ulnow) {
    UvFile *file = reinterpret_cast<UvFile *>(clientp);
    return file->curlXferInfoFunction(dltotal, dlnow, ultotal, ulnow);
}

size_t PCSX::UvFile::curlWriteFunction(char *ptr, size_t size) {
    s_dataDownloadTotal += size;
    if (size == 0) return 0;
    if (m_cancelDownload.load(std::memory_order_acquire)) {
        m_failed = true;
        return 0;
    }
    size_t endPtr = m_cachePtr + size;
    if (endPtr > m_size) {
        m_cache = reinterpret_cast<uint8_t *>(realloc(m_cache, endPtr));
        m_size = endPtr;
    }
    memcpy(m_cache + m_cachePtr, ptr, size);
    m_cachePtr = endPtr;
    float progress = float(m_cachePtr) / float(m_size);
    m_cacheProgress.store(std::min(progress, 0.99f));
    return size;
}

int PCSX::UvFile::curlXferInfoFunction(curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    if (m_cancelDownload.load(std::memory_order_acquire)) {
        m_failed = true;
        return -1;
    }
    if (dltotal == 0) return 0;
    if (dltotal > m_size) {
        m_cache = reinterpret_cast<uint8_t *>(realloc(m_cache, dltotal));
        m_size = dltotal;
    }
    float progress = float(dlnow) / float(dltotal);
    m_cacheProgress.store(std::min(progress, 0.99f));
    return 0;
}

void PCSX::UvThreadOp::processCurlMultiInfo() {
    CURLMsg *message;
    int pending;

    while ((message = curl_multi_info_read(s_curlMulti, &pending))) {
        switch (message->msg) {
            case CURLMSG_DONE: {
                CURL *easy_handle = message->easy_handle;
                UvThreadOp *self;

                curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, &self);
                self->downloadDone(message);
                break;
            }
        }
    }
}

void PCSX::UvFile::downloadDone(CURLMsg *message) {
    if (message->data.result != CURLE_OK) m_failed = true;
    curl_multi_remove_handle(s_curlMulti, m_curlHandle);
    curl_easy_cleanup(m_curlHandle);
    m_curlHandle = nullptr;
    m_cacheProgress.store(1.0f, std::memory_order_release);
    if (m_cachingDoneCB) {
        uv_async_send(m_cbAsync);
    }
    m_cacheBarrier.set_value();
}

ssize_t PCSX::UvFile::rSeek(ssize_t pos, int wheel) {
    switch (wheel) {
        case SEEK_SET:
            m_ptrR = pos;
            break;
        case SEEK_END:
            m_ptrR = m_size - pos;
            break;
        case SEEK_CUR:
            m_ptrR += pos;
            break;
    }
    m_ptrR = std::max(std::min(m_ptrR, m_size), size_t(0));
    return m_ptrR;
}

ssize_t PCSX::UvFile::wSeek(ssize_t pos, int wheel) {
    switch (wheel) {
        case SEEK_SET:
            m_ptrW = pos;
            break;
        case SEEK_END:
            m_ptrW = m_size - pos;
            break;
        case SEEK_CUR:
            m_ptrW += pos;
            break;
    }
    m_ptrW = std::max(m_ptrW, size_t(0));
    return m_ptrW;
}

ssize_t PCSX::UvFile::read(void *dest, size_t size) {
    size = std::min(m_size - m_ptrR, size);
    if (size == 0) return -1;

    float progress = m_cacheProgress.load(std::memory_order_relaxed);

    if (progress != 1.0f) {
        if (m_download) {
            m_cacheBarrier.get_future().wait();
            progress = 1.0f;
        }
    }

    if (progress == 1.0f) {
        memcpy(dest, m_cache + m_ptrR, size);
        m_ptrR += size;
        return size;
    }
    struct Info {
        std::promise<ssize_t> res;
        uv_buf_t buf;
        uv_fs_t req;
    };
    Info info;
    info.req.data = &info;
    info.buf.base = reinterpret_cast<decltype(info.buf.base)>(dest);
    info.buf.len = size;
    request([&info, handle = m_handle, offset = m_ptrR](auto loop) {
        int ret = uv_fs_read(loop, &info.req, handle, &info.buf, 1, offset, [](uv_fs_t *req) {
            auto info = reinterpret_cast<Info *>(req->data);
            ssize_t ret = req->result;
            uv_fs_req_cleanup(req);
            info->res.set_value(ret);
            if (ret >= 0) s_dataReadTotal += ret;
        });
        if (ret != 0) {
            info.res.set_exception(std::make_exception_ptr(std::runtime_error("uv_fs_read failed")));
        }
    });
    size = -1;
    try {
        size = info.res.get_future().get();
    } catch (...) {
    }
    if (size > 0) m_ptrR += size;
    return size;
}

ssize_t PCSX::UvFile::write(const void *src, size_t size) {
    if (!writable()) return -1;
    if (m_cache) {
        while (m_cacheProgress.load(std::memory_order_relaxed) != 1.0)
            ;
        size_t newSize = m_ptrW + size;
        if (newSize > m_size) {
            m_cache = reinterpret_cast<uint8_t *>(realloc(m_cache, newSize));
            if (m_cache == nullptr) throw std::runtime_error("Out of memory");
            m_size = newSize;
        }

        memcpy(m_cache + m_ptrW, src, size);
    }
    struct Info {
        uv_buf_t buf;
        uv_fs_t req;
        Slice slice;
    };
    auto info = new Info();
    info->req.data = info;
    info->slice.copy(src, size);
    info->buf.base = reinterpret_cast<decltype(info->buf.base)>(const_cast<void *>(info->slice.data()));
    info->buf.len = size;
    request([info, handle = m_handle, offset = m_ptrW](auto loop) {
        uv_fs_write(loop, &info->req, handle, &info->buf, 1, offset, [](uv_fs_t *req) {
            ssize_t ret = req->result;
            if (ret >= 0) s_dataWrittenTotal += ret;
            auto info = reinterpret_cast<Info *>(req->data);
            uv_fs_req_cleanup(req);
            delete info;
        });
    });
    m_ptrW += size;
    return size;
}

void PCSX::UvFile::write(Slice &&slice) {
    if (!writable()) return;
    if (m_cache) {
        while (m_cacheProgress.load(std::memory_order_relaxed) != 1.0)
            ;
        size_t newSize = m_ptrW + slice.size();
        if (newSize > m_size) {
            m_cache = reinterpret_cast<uint8_t *>(realloc(m_cache, newSize));
            if (m_cache == nullptr) throw std::runtime_error("Out of memory");
            m_size = newSize;
        }

        memcpy(m_cache + m_ptrW, slice.data(), slice.size());
    }
    struct Info {
        uv_buf_t buf;
        uv_fs_t req;
        Slice slice;
    };
    auto size = slice.size();
    auto info = new Info();
    info->req.data = info;
    info->buf.len = size;
    info->slice = std::move(slice);
    request([info, handle = m_handle, offset = m_ptrW](auto loop) {
        info->buf.base = reinterpret_cast<decltype(info->buf.base)>(const_cast<void *>(info->slice.data()));
        uv_fs_write(loop, &info->req, handle, &info->buf, 1, offset, [](uv_fs_t *req) {
            ssize_t ret = req->result;
            if (ret >= 0) s_dataWrittenTotal += ret;
            auto info = reinterpret_cast<Info *>(req->data);
            uv_fs_req_cleanup(req);
            delete info;
        });
    });
    m_ptrW += size;
}

ssize_t PCSX::UvFile::readAt(void *dest, size_t size, size_t ptr) {
    size = std::min(m_size - ptr, size);
    if (size == 0) return -1;
    float progress = m_cacheProgress.load(std::memory_order_acquire);

    if (progress != 1.0f) {
        if (m_download) {
            m_cacheBarrier.get_future().wait();
            progress = 1.0f;
        }
    }

    if (progress == 1.0f) {
        memcpy(dest, m_cache + ptr, size);
        return size;
    }
    struct Info {
        std::promise<ssize_t> res;
        uv_buf_t buf;
        uv_fs_t req;
    };
    Info info;
    info.req.data = &info;
    info.buf.base = reinterpret_cast<decltype(info.buf.base)>(dest);
    info.buf.len = size;
    request([&info, handle = m_handle, offset = ptr](auto loop) {
        int ret = uv_fs_read(loop, &info.req, handle, &info.buf, 1, offset, [](uv_fs_t *req) {
            auto info = reinterpret_cast<Info *>(req->data);
            ssize_t ret = req->result;
            uv_fs_req_cleanup(req);
            info->res.set_value(ret);
            if (ret >= 0) s_dataReadTotal += ret;
        });
        if (ret != 0) {
            info.res.set_exception(std::make_exception_ptr(std::runtime_error("uv_fs_read failed")));
        }
    });
    size = -1;
    try {
        size = info.res.get_future().get();
    } catch (...) {
    }
    return size;
}

ssize_t PCSX::UvFile::writeAt(const void *src, size_t size, size_t ptr) {
    if (!writable()) return -1;
    if (m_cache) {
        while (m_cacheProgress.load(std::memory_order_acquire) != 1.0)
            ;
        size_t newSize = ptr + size;
        if (newSize > m_size) {
            m_cache = reinterpret_cast<uint8_t *>(realloc(m_cache, newSize));
            if (m_cache == nullptr) throw std::runtime_error("Out of memory");
            m_size = newSize;
        }

        memcpy(m_cache + ptr, src, size);
    }
    struct Info {
        uv_buf_t buf;
        uv_fs_t req;
        Slice slice;
    };
    auto info = new Info();
    info->req.data = info;
    info->slice.copy(src, size);
    info->buf.base = reinterpret_cast<decltype(info->buf.base)>(const_cast<void *>(info->slice.data()));
    info->buf.len = size;
    request([info, handle = m_handle, offset = ptr](auto loop) {
        uv_fs_write(loop, &info->req, handle, &info->buf, 1, offset, [](uv_fs_t *req) {
            ssize_t ret = req->result;
            if (ret >= 0) s_dataWrittenTotal += ret;
            auto info = reinterpret_cast<Info *>(req->data);
            uv_fs_req_cleanup(req);
            delete info;
        });
    });
    return size;
}

void PCSX::UvFile::writeAt(Slice &&slice, size_t ptr) {
    if (!writable()) return;
    if (m_cache) {
        while (m_cacheProgress.load(std::memory_order_acquire) != 1.0)
            ;
        size_t newSize = ptr + slice.size();
        if (newSize > m_size) {
            m_cache = reinterpret_cast<uint8_t *>(realloc(m_cache, newSize));
            if (m_cache == nullptr) throw std::runtime_error("Out of memory");
            m_size = newSize;
        }

        memcpy(m_cache + ptr, slice.data(), slice.size());
    }
    struct Info {
        uv_buf_t buf;
        uv_fs_t req;
        Slice slice;
    };
    auto size = slice.size();
    auto info = new Info();
    info->req.data = info;
    info->buf.len = size;
    info->slice = std::move(slice);
    request([info, handle = m_handle, offset = ptr](auto loop) {
        info->buf.base = reinterpret_cast<decltype(info->buf.base)>(const_cast<void *>(info->slice.data()));
        uv_fs_write(loop, &info->req, handle, &info->buf, 1, offset, [](uv_fs_t *req) {
            ssize_t ret = req->result;
            if (ret >= 0) s_dataWrittenTotal += ret;
            auto info = reinterpret_cast<Info *>(req->data);
            uv_fs_req_cleanup(req);
            delete info;
        });
    });
}

bool PCSX::UvFile::eof() { return m_size == m_ptrR; }

void PCSX::UvFile::readCacheChunk(uv_loop_t *loop) {
    if (m_cachePtr >= m_size) {
        m_cacheProgress.store(1.0f, std::memory_order_release);
        if (m_cachingDoneCB) {
            uv_async_send(m_cbAsync);
        }
        m_cacheBarrier.set_value();
        return;
    }
    ssize_t delta = m_size - m_cachePtr;
    m_cacheReq.data = this;
    m_cacheBuf.base = reinterpret_cast<decltype(m_cacheBuf.base)>(m_cache + m_cachePtr);
    m_cacheBuf.len = std::min(delta, ssize_t(64 * 1024));

    int ret = uv_fs_read(loop, &m_cacheReq, m_handle, &m_cacheBuf, 1, m_cachePtr, [](uv_fs_t *req) {
        auto file = reinterpret_cast<UvFile *>(req->data);
        file->readCacheChunkResult();
    });
    if (ret != 0) throw std::runtime_error("uv_fs_read failed while caching");
}

void PCSX::UvFile::readCacheChunkResult() {
    auto loop = m_cacheReq.loop;
    auto res = m_cacheReq.result;

    uv_fs_req_cleanup(&m_cacheReq);

    if (res < 0) throw std::runtime_error("uv_fs_read failed while caching");

    s_dataReadTotal += res;

    m_cachePtr += res;
    if (m_cachePtr < m_size) {
        m_cacheProgress.store(float(m_cachePtr) / float(m_size), std::memory_order_release);
    }
    readCacheChunk(loop);
}

void PCSX::UvFile::startCaching(std::function<void()> &&completed, uv_loop_t *loop) {
    if (m_cache || m_download) throw std::runtime_error("File is already cached");
    cacheCallbackSetup(std::move(completed), loop);
    if (failed()) return;
    m_cache = reinterpret_cast<uint8_t *>(malloc(m_size));
    request([this](auto loop) { readCacheChunk(loop); });
}

void PCSX::UvFile::cacheCallbackSetup(std::function<void()> &&callbackDone, uv_loop_t *otherLoop) {
    if (otherLoop && callbackDone) {
        m_cachingDoneCB = std::move(callbackDone);
        m_cbAsync = new uv_async_t();
        uv_async_init(otherLoop, m_cbAsync, [](uv_async_t *handle) -> void {
            UvFile *self = reinterpret_cast<UvFile *>(handle->data);
            uv_close(reinterpret_cast<uv_handle_t *>(handle), [](uv_handle_t *handle_) {
                uv_async_t *handle = reinterpret_cast<uv_async_t *>(handle_);
                delete handle;
            });
            self->m_cachingDoneCB();
        });
        m_cbAsync->data = this;
        if (failed()) uv_async_send(m_cbAsync);
    }
}

PCSX::UvFifo::UvFifo(uv_tcp_t *tcp) : File(File::FileType::RW_STREAM) {
    tcp->data = this;
    m_tcp = tcp;
    uv_read_start(
        reinterpret_cast<uv_stream_t *>(m_tcp),
        [](uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
            UvFifo *fifo = reinterpret_cast<UvFifo *>(handle->data);
            assert(!fifo->m_buffer);
            void *b = fifo->m_buffer = malloc(fifo->c_chunkSize);
            buf->base = reinterpret_cast<char *>(b);
            buf->len = fifo->c_chunkSize;
        },
        [](uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
            UvFifo *fifo = reinterpret_cast<UvFifo *>(client->data);
            if (nread <= 0) {
                free(fifo->m_buffer);
                fifo->m_closed = true;
                return;
            }
            assert(fifo->m_buffer);
            void *b = realloc(fifo->m_buffer, nread);
            fifo->m_buffer = nullptr;
            Slice slice;
            slice.acquire(b, nread);
            fifo->m_queue.Enqueue(std::move(slice));
            fifo->m_size.fetch_add(nread);
        });
}

void PCSX::UvFifo::close() {
    m_closed.store(true);
    request([tcp = m_tcp](uv_loop_t *loop) {
        if (!tcp) return;
        uv_close(reinterpret_cast<uv_handle_t *>(tcp), [](uv_handle_t *handle) {
            auto tcp = reinterpret_cast<uv_tcp_t *>(handle);
            delete tcp;
        });
    });
}

ssize_t PCSX::UvFifo::read(void *dest_, size_t size) {
    uint8_t *dest = static_cast<uint8_t *>(dest_);
    ssize_t ret = 0;

    while (size) {
        if (m_slice.size() == m_currentPtr) {
            m_currentPtr = 0;
            m_slice.reset();
            if (m_size.load() == 0) {
                return ret == 0 ? -1 : ret;
            }
            while (!m_queue.Dequeue(m_slice))
                ;
        }
        auto toRead = std::min(size, static_cast<size_t>(m_slice.size()) - m_currentPtr);
        memcpy(dest, m_slice.data<uint8_t>() + m_currentPtr, toRead);
        dest += toRead;
        m_currentPtr += toRead;
        size -= toRead;
        ret += toRead;
        m_size.fetch_sub(toRead);
    }

    return ret;
}

ssize_t PCSX::UvFifo::write(const void *src, size_t size) {
    struct Info {
        uv_buf_t buf;
        uv_write_t req;
        Slice slice;
    };
    auto info = new Info();
    info->req.data = info;
    info->slice.copy(src, size);
    info->buf.base = reinterpret_cast<decltype(info->buf.base)>(const_cast<void *>(info->slice.data()));
    info->buf.len = size;
    request([info, tcp = m_tcp](auto loop) {
        info->buf.base = reinterpret_cast<decltype(info->buf.base)>(const_cast<void *>(info->slice.data()));
        uv_write(&info->req, reinterpret_cast<uv_stream_t *>(tcp), &info->buf, 1, [](uv_write_t *req, int status) {
            auto info = reinterpret_cast<Info *>(req->data);
            delete info;
        });
    });
    return size;
}

void PCSX::UvFifo::write(Slice &&slice) {
    struct Info {
        uv_buf_t buf;
        uv_write_t req;
        Slice slice;
    };
    auto size = slice.size();
    auto info = new Info();
    info->req.data = info;
    info->buf.len = size;
    info->slice = std::move(slice);
    request([info, tcp = m_tcp](auto loop) {
        info->buf.base = reinterpret_cast<decltype(info->buf.base)>(const_cast<void *>(info->slice.data()));
        uv_write(&info->req, reinterpret_cast<uv_stream_t *>(tcp), &info->buf, 1, [](uv_write_t *req, int status) {
            auto info = reinterpret_cast<Info *>(req->data);
            delete info;
        });
    });
}

void PCSX::UvFifoListener::start(unsigned port, uv_loop_t *loop, uv_async_t *async,
                                 std::function<void(UvFifo *)> &&cb) {
    m_cb = std::move(cb);
    async->data = this;
    m_async = async;
    uv_async_init(loop, async, [](uv_async_t *async) {
        UvFifoListener *self = reinterpret_cast<UvFifoListener *>(async->data);
        UvFifo *fifo = nullptr;
        while (self->m_pending.Dequeue(fifo)) {
            self->m_cb(fifo);
        }
    });
    request([this, port](auto loop) {
        uv_tcp_init(loop, &m_server);
        m_server.data = this;

        struct sockaddr_in bindAddr;
        int result = uv_ip4_addr("0.0.0.0", port, &bindAddr);
        if (result != 0) {
            uv_close(reinterpret_cast<uv_handle_t *>(&m_server), [](uv_handle_t *handle) {});
            return;
        }
        result = uv_tcp_bind(&m_server, reinterpret_cast<const sockaddr *>(&bindAddr), 0);
        if (result != 0) {
            uv_close(reinterpret_cast<uv_handle_t *>(&m_server), [](uv_handle_t *handle) {});
            return;
        }
        result = uv_listen((uv_stream_t *)&m_server, 16, [](uv_stream_t *server, int status) {
            if (status < 0) return;
            UvFifoListener *listener = reinterpret_cast<UvFifoListener *>(server->data);
            uv_tcp_t *tcp = new uv_tcp_t();
            auto loop = server->loop;
            uv_tcp_init(loop, tcp);
            if (uv_accept(reinterpret_cast<uv_stream_t *>(server), reinterpret_cast<uv_stream_t *>(tcp)) == 0) {
                UvFifo *fifo = new UvFifo(tcp);
                listener->m_pending.Enqueue(fifo);
                uv_async_send(listener->m_async);
            } else {
                uv_close(reinterpret_cast<uv_handle_t *>(tcp),
                         [](uv_handle_t *handle) { delete reinterpret_cast<uv_tcp_t *>(handle); });
            }
        });
        if (result != 0) {
            uv_close(reinterpret_cast<uv_handle_t *>(&m_server), [](uv_handle_t *handle) {});
            return;
        }
    });
}

void PCSX::UvFifoListener::stop() {
    request([this](auto loop) {
        uv_close(reinterpret_cast<uv_handle_t *>(&m_server), [](uv_handle_t *handle) {
            UvFifoListener *listener = reinterpret_cast<UvFifoListener *>(handle->data);
            listener->m_pending.Enqueue(nullptr);
            uv_async_send(listener->m_async);
        });
    });
}
