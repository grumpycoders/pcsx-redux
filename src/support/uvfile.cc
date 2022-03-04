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

void PCSX::UvFile::startThread() {
    if (s_threadRunning) throw std::runtime_error("UV thread already running");
    s_threadRunning = true;
    s_uvThread = std::thread([]() -> void {
        uv_loop_t loop;
        uv_loop_init(&loop);
        uv_async_init(&loop, &s_kicker, [](uv_async_t *async) {
            UvRequest req;
            while (s_queue.try_dequeue(req)) {
                std::visit(
                    [async](auto &req) -> void {
                        using T = std::decay<decltype(req)>::type;
                        if constexpr (std::is_same<T, StopRequest>::value) {
                            uv_unref(reinterpret_cast<uv_handle_t *>(async));
                            req.barrier.set_value();
                        } else if constexpr (std::is_same<T, OpenRequest>::value) {
                            auto *info = new OpenInfo(std::move(req.ret));
                            info->req.data = info;
                            uv_fs_open(async->loop, &info->req, req.fname.c_str(), req.flags, 0644, [](uv_fs_t *req) {
                                OpenInfo *info = reinterpret_cast<OpenInfo *>(req->data);
                                uv_file file = req->result;
                                if (file < 0) {
                                    info->ret.set_value({file, 0});
                                    uv_fs_req_cleanup(req);
                                    delete info;
                                    return;
                                }
                                info->file = file;
                                auto loop = req->loop;
                                uv_fs_req_cleanup(req);
                                req->data = info;
                                uv_fs_fstat(loop, req, info->file, [](uv_fs_t *req) {
                                    OpenInfo *info = reinterpret_cast<OpenInfo *>(req->data);
                                    info->ret.set_value({info->file, req->statbuf.st_size});
                                    uv_fs_req_cleanup(req);
                                    delete info;
                                });
                            });
                        } else if constexpr (std::is_same<T, CloseRequest>::value) {
                            auto *info = new uv_fs_t();
                            uv_fs_close(async->loop, info, req.file, [](uv_fs_t *req) {
                                uv_fs_req_cleanup(req);
                                delete req;
                            });
                        } else if constexpr (std::is_same<T, ReadRequest>::value) {
                            auto *info = new ReadInfo(std::move(req.ret));
                            info->buf.base = reinterpret_cast<decltype(info->buf.base)>(req.dest);
                            info->buf.len = req.size;
                            uv_fs_read(async->loop, &info->req, req.file, &info->buf, 1, req.offset, [](uv_fs_t *req) {
                                ReadInfo *info = reinterpret_cast<ReadInfo *>(req->data);
                                info->ret.set_value(req->result);
                                uv_fs_req_cleanup(req);
                                delete info;
                            });
                        } else if constexpr (std::is_same<T, CacheRequest>::value) {
                        } else if constexpr (std::is_same<T, WriteRequest>::value) {
                        }
                    },
                    req);
            }
        });
        uv_run(&loop, UV_RUN_DEFAULT);
    });
}

void PCSX::UvFile::stopThread() {
    if (!s_threadRunning) throw std::runtime_error("UV thread isn't running");
    StopRequest req;
    auto res = req.barrier.get_future();
    s_queue.enqueue(std::move(req));
    res.wait();
    s_uvThread.join();
}

void PCSX::UvFile::close() {
    free(m_cache);
    CloseRequest req;
    req.file = m_handle;
    s_queue.enqueue(std::move(req));
}

std::pair<uv_file, size_t> PCSX::UvFile::openwrapper(const char *filename, int flags) {
    OpenRequest req;
    req.flags = flags;
    req.fname = filename;
    auto ret = req.ret.get_future();
    s_queue.enqueue(std::move(req));
    return ret.get();
}

PCSX::UvFile::UvFile(const char *filename) : File(RO_SEEKABLE), m_filename(filename) {
    auto ret = openwrapper(filename, UV_FS_O_RDONLY);
    m_handle = ret.first;
    m_size = ret.second;
}
PCSX::UvFile::UvFile(const char *filename, FileOps::Create) : File(RW_SEEKABLE), m_filename(filename) {
    auto ret = openwrapper(filename, UV_FS_O_RDWR | UV_FS_O_CREAT);
    m_handle = ret.first;
    m_size = ret.second;
}
PCSX::UvFile::UvFile(const char *filename, FileOps::Truncate) : File(RW_SEEKABLE), m_filename(filename) {
    auto ret = openwrapper(filename, UV_FS_O_RDWR | UV_FS_O_CREAT | UV_FS_O_TRUNC);
    m_handle = ret.first;
    m_size = ret.second;
}
PCSX::UvFile::UvFile(const char *filename, FileOps::ReadWrite) : File(RW_SEEKABLE), m_filename(filename) {
    auto ret = openwrapper(filename, UV_FS_O_RDWR);
    m_handle = ret.first;
    m_size = ret.second;
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
    ReadRequest req;
    auto ret = req.ret.get_future();
    req.dest = dest;
    req.file = m_handle;
    req.offset = m_ptrR;
    req.size = size;
    s_queue.enqueue(std::move(req));
    size = ret.get();
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
    // schedule write
    m_ptrW += size;
    return size;
}

bool PCSX::UvFile::eof() { return m_size == m_ptrR; }
