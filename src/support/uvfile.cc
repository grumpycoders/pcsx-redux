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

#include <exception>

std::thread PCSX::UvFile::s_uvThread;
bool PCSX::UvFile::s_threadRunning = false;
uv_async_t PCSX::UvFile::s_kicker;
moodycamel::ConcurrentQueue<PCSX::UvFile::UvRequest> PCSX::UvFile::s_queue;
PCSX::UvFilesListType PCSX::UvFile::s_allFiles;

void PCSX::UvFile::startThread() {
    if (s_threadRunning) throw std::runtime_error("UV thread already running");
    std::promise<void> barrier;
    auto f = barrier.get_future();
    s_threadRunning = true;
    s_uvThread = std::thread([barrier = std::move(barrier)]() mutable {
        uv_loop_t loop;
        uv_loop_init(&loop);
        uv_async_init(&loop, &s_kicker, [](uv_async_t *async) {
            UvRequest req;
            while (s_queue.try_dequeue(req)) {
                req(async->loop);
            }
        });
        barrier.set_value();
        uv_run(&loop, UV_RUN_DEFAULT);
    });
    f.wait();
}

void PCSX::UvFile::stopThread() {
    if (!s_threadRunning) throw std::runtime_error("UV thread isn't running");
    request([](auto loop) { uv_close(reinterpret_cast<uv_handle_t *>(&s_kicker), [](auto handle) {}); });
    s_uvThread.join();
    s_threadRunning = false;
}

void PCSX::UvFile::close() {
    if (m_cache && (m_cacheProgress.load(std::memory_order_relaxed) != 1.0)) {
        request([this](auto loop) { m_cachePtr = m_size; });
        m_cacheBarrier.get_future().wait();
    }
    free(m_cache);
    m_cache = nullptr;
    request([handle = m_handle](auto loop) {
        auto req = new uv_fs_t();
        uv_fs_close(loop, req, handle, [](uv_fs_t *req) {
            uv_fs_req_cleanup(req);
            delete req;
        });
    });
}

void PCSX::UvFile::openwrapper(const char *filename, int flags) {
    s_allFiles.push_back(this);
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
    if (m_cacheProgress.load(std::memory_order_relaxed) == 1.0) {
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
    };
    auto info = new Info();
    info->req.data = info;
    info->buf.base = reinterpret_cast<decltype(info->buf.base)>(malloc(size));
    memcpy(info->buf.base, src, size);
    info->buf.len = size;
    request([info, handle = m_handle, offset = m_ptrR](auto loop) {
        uv_fs_write(loop, &info->req, handle, &info->buf, 1, offset, [](uv_fs_t *req) {
            auto info = reinterpret_cast<Info *>(req->data);
            uv_fs_req_cleanup(req);
            free(info->buf.base);
            delete info;
        });
    });
    m_ptrW += size;
    return size;
}

bool PCSX::UvFile::eof() { return m_size == m_ptrR; }

void PCSX::UvFile::readCacheChunk(uv_loop_t *loop) {
    if (m_cachePtr >= m_size) {
        m_cacheProgress.store(1.0f);
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

    m_cachePtr += res;
    if (m_cachePtr < m_size) {
        m_cacheProgress.store(float(m_cachePtr) / float(m_size));
    }
    readCacheChunk(loop);
}

void PCSX::UvFile::startCaching() {
    if (m_cache) throw std::runtime_error("File is already cached");
    if (failed()) return;
    m_cache = reinterpret_cast<uint8_t *>(malloc(m_size));
    request([this](auto loop) { readCacheChunk(loop); });
}
