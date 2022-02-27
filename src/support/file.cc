/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "support/file.h"

#include <algorithm>

#include "support/windowswrapper.h"

uint8_t PCSX::BufferFile::m_internalBuffer = 0;

PCSX::BufferFile::BufferFile(void *data, size_t size) : File(false) {
    m_data = reinterpret_cast<uint8_t *>(data);
    m_size = size;
}

PCSX::BufferFile::BufferFile(void *data, size_t size, FileOps::ReadWrite) : File(true) {
    m_data = reinterpret_cast<uint8_t *>(malloc(size));
    if (m_data == nullptr) throw std::runtime_error("Out of memory");
    memcpy(m_data, data, size);
    m_size = m_allocSize = size;
    m_owned = true;
}

PCSX::BufferFile::BufferFile(void *data, size_t size, Acquire) : File(true) {
    m_data = reinterpret_cast<uint8_t *>(data);
    m_size = m_allocSize = size;
    m_owned = true;
}

PCSX::BufferFile::BufferFile() : File(false) {
    m_data = &m_internalBuffer;
    m_size = 1;
}

PCSX::BufferFile::BufferFile(FileOps::ReadWrite) : File(true) {
    m_data = nullptr;
    m_owned = true;
}

void PCSX::BufferFile::close() {
    if (m_owned) free(m_data);
    m_owned = true;
    m_data = nullptr;
    m_size = 0;
    m_ptrR = 0;
    m_ptrW = 0;
}

ssize_t PCSX::BufferFile::rSeek(ssize_t pos, int wheel) {
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

ssize_t PCSX::BufferFile::wSeek(ssize_t pos, int wheel) {
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

ssize_t PCSX::BufferFile::read(void *dest, size_t size) {
    size = std::min(m_size - m_ptrR, size);
    if (size == 0) return -1;
    memcpy(dest, m_data + m_ptrR, size);
    m_ptrR += size;
    return size;
}

ssize_t PCSX::BufferFile::write(const void *src, size_t size) {
    if (!m_writable) return -1;
    size_t newSize = m_ptrW + size;
    if (newSize > m_size) {
        m_size = newSize;
    }
    if (newSize > m_allocSize) {
        static_assert((sizeof(newSize) == 4) || (sizeof(newSize) == 8));
        newSize--;
        newSize |= newSize >> 1;
        newSize |= newSize >> 2;
        newSize |= newSize >> 4;
        newSize |= newSize >> 8;
        newSize |= newSize >> 16;
        if (sizeof(newSize) == 8) newSize |= newSize >> 32;
        newSize++;
        // TODO: maybe cap the power-of-two increase..?
        m_data = reinterpret_cast<uint8_t *>(realloc(m_data, newSize));
        if (m_data == nullptr) throw std::runtime_error("Out of memory");
        m_allocSize = newSize;
    }

    memcpy(m_data + m_ptrW, src, size);
    m_ptrW += size;
    return size;
}

bool PCSX::BufferFile::eof() { return m_size == m_ptrR; }

PCSX::File *PCSX::BufferFile::dup() {
    if (!m_owned) {
        return new BufferFile(m_data, m_size);
    } else {
        return new BufferFile(m_data, m_size, FileOps::READWRITE);
    }
}

void PCSX::PosixFile::close() {
    if (m_handle) {
        fclose(m_handle);
        m_handle = nullptr;
    }
}

#if defined(_WIN32) && defined(UNICODE)
static FILE *openwrapper(const char *filename, const wchar_t *mode) {
    int needed = MultiByteToWideChar(CP_UTF8, 0, filename, -1, NULL, 0);
    if (needed <= 0) return nullptr;
    LPWSTR str = (LPWSTR)_malloca(needed * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, filename, -1, str, needed * sizeof(wchar_t));
    FILE *ret = _wfopen(str, mode);
    _freea(str);
    return ret;
}

PCSX::PosixFile::PosixFile(const char *filename) : File(false), m_filename(filename) {
    m_handle = openwrapper(filename, L"rb");
}

PCSX::PosixFile::PosixFile(const char *filename, FileOps::Create) : File(true), m_filename(filename) {
    m_handle = openwrapper(filename, L"ab+");
}

PCSX::PosixFile::PosixFile(const char *filename, FileOps::Truncate) : File(true), m_filename(filename) {
    m_handle = openwrapper(filename, L"wb+");
}

PCSX::PosixFile::PosixFile(const char *filename, FileOps::ReadWrite) : File(true), m_filename(filename) {
    m_handle = openwrapper(filename, L"rb+");
}
#else  // !Windows || !UNICODE
PCSX::PosixFile::PosixFile(const char *filename) : File(false), m_filename(filename) {
    m_handle = fopen(filename, "rb");
}
PCSX::PosixFile::PosixFile(const char *filename, FileOps::Create) : File(true), m_filename(filename) {
    m_handle = fopen(filename, "ab+");
}
PCSX::PosixFile::PosixFile(const char *filename, FileOps::Truncate) : File(true), m_filename(filename) {
    m_handle = fopen(filename, "wb+");
}
PCSX::PosixFile::PosixFile(const char *filename, FileOps::ReadWrite) : File(true), m_filename(filename) {
    m_handle = fopen(filename, "rb+");
}
#endif

ssize_t PCSX::PosixFile::rSeek(ssize_t pos, int wheel) {
    if (failed()) throw std::runtime_error("Invalid file");
    ssize_t ret = 0;
    switch (wheel) {
        case SEEK_SET:
        case SEEK_END:
            ret = fseek(m_handle, pos, wheel);
            break;
        case SEEK_CUR:
            ret = fseek(m_handle, pos + m_ptrR, SEEK_SET);
            break;
    }
    if (ret < 0) throw std::runtime_error("Error seeking file...");
    m_ptrR = ftell(m_handle);
    return m_ptrR;
}

ssize_t PCSX::PosixFile::wSeek(ssize_t pos, int wheel) {
    if (failed()) throw std::runtime_error("Invalid file");
    ssize_t ret = 0;
    switch (wheel) {
        case SEEK_SET:
        case SEEK_END:
            ret = fseek(m_handle, pos, wheel);
            break;
        case SEEK_CUR:
            ret = fseek(m_handle, pos + m_ptrW, SEEK_SET);
            break;
    }
    if (ret < 0) throw std::runtime_error("Error seeking file...");
    m_ptrW = ftell(m_handle);
    return m_ptrW;
}

size_t PCSX::PosixFile::size() {
    if (failed()) throw std::runtime_error("Invalid file");
    ssize_t ret = fseek(m_handle, 0, SEEK_SET);
    if (ret < 0) throw std::runtime_error("Can't seek file...");
    return ftell(m_handle);
}

ssize_t PCSX::PosixFile::read(void *dest, size_t size) {
    if (failed()) throw std::runtime_error("Invalid file");
    if (feof(m_handle)) return -1;
    ssize_t ret = fseek(m_handle, m_ptrR, SEEK_SET);
    if (ret < 0) throw std::runtime_error("Error seeking file...");
    ret = fread(dest, 1, size, m_handle);
    if (ret < 0) throw std::runtime_error("Error reading file...");
    m_ptrR += ret;
    return ret;
}

ssize_t PCSX::PosixFile::write(const void *src, size_t size) {
    if (failed()) throw std::runtime_error("Invalid file");
    ssize_t ret = fseek(m_handle, m_ptrW, SEEK_SET);
    if (ret < 0) throw std::runtime_error("Error seeking file...");
    ret = fwrite(src, 1, size, m_handle);
    if (ret < 0) throw std::runtime_error("Error writing file...");
    m_ptrW += ret;
    return ret;
}

ssize_t PCSX::SubFile::rSeek(ssize_t pos, int wheel) {
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

ssize_t PCSX::SubFile::read(void *dest, size_t size) {
    ssize_t ret = readAt(dest, size, m_ptrR);
    if (ret < 0) return ret;
    m_ptrR += ret;
    if ((m_ptrR < 0) || (m_ptrR > m_size)) {
        throw std::runtime_error("SubFile pointer got out of bound - shouldn't happen");
    }
    return ret;
}

ssize_t PCSX::SubFile::readAt(void *dest, size_t size, size_t ptr) {
    ssize_t excess = size + ptr - m_size;
    if (excess > 0) size -= excess;
    return m_file->readAt(dest, size, ptr + m_start);
}
