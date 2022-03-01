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

void PCSX::UvFile::close() { free(m_cache); }

PCSX::UvFile::UvFile(const char *filename)
    : File(RO_SEEKABLE), m_filename(filename) { /*m_handle = fopen(filename, "rb");*/
}
PCSX::UvFile::UvFile(const char *filename, FileOps::Create) : File(RW_SEEKABLE), m_filename(filename) {
    /*m_handle = fopen(filename, "ab+");*/
}
PCSX::UvFile::UvFile(const char *filename, FileOps::Truncate) : File(RW_SEEKABLE), m_filename(filename) {
    /*m_handle = fopen(filename, "wb+");*/
}
PCSX::UvFile::UvFile(const char *filename, FileOps::ReadWrite) : File(RW_SEEKABLE), m_filename(filename) {
    /*m_handle = fopen(filename, "rb+");*/
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
    // schedule read
    // wait
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
