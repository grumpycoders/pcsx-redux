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

#include <algorithm>

#include "core/file.h"

const uint8_t PCSX::File::m_internalBuffer = 0;
void PCSX::File::close() {
    if (m_handle) fclose(m_handle);
    m_handle = nullptr;
}
ssize_t PCSX::File::seek(ssize_t pos, int wheel) {
    if (m_handle) return fseek(m_handle, pos, wheel);
    if (!m_data) return -1;
    switch (wheel) {
        case SEEK_SET:
            m_ptr = pos;
            break;
        case SEEK_END:
            m_ptr = m_size - pos;
            break;
        case SEEK_CUR:
            m_ptr += pos;
            break;
    }
    m_ptr = std::min(std::max(m_ptr, m_size), (ssize_t)0);
    return m_ptr;
}
ssize_t PCSX::File::tell() {
    if (m_handle) return ftell(m_handle);
    if (m_data) return m_ptr;
    return -1;
}
void PCSX::File::flush() {
    if (m_handle) fflush(m_handle);
}
PCSX::File::File(void *data, ssize_t size) {
    if (data) {
        m_data = static_cast<uint8_t *>(data);
    } else {
        assert(size == 1);
        m_data = &m_internalBuffer;
    }
    m_size = size;
}
#ifdef _WIN32
PCSX::File::File(const char *filename) : m_filename(filename) {
#ifdef UNICODE
    int needed;
    LPWSTR str;

    needed = MultiByteToWideChar(CP_UTF8, 0, filename, -1, NULL, 0);
    if (needed <= 0) return;
    str = (LPWSTR)_malloca(needed * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, filename, -1, str, needed * sizeof(wchar_t));

    m_handle = _wfopen(str, L"rb");

    _freea(str);
#else
    m_handle = fopen(filename, "rb");
#endif
}
#else
PCSX::File::File(const char *filename) { m_handle = fopen(filename, "rb"); }
#endif
char *PCSX::File::gets(char *s, int size) {
    if (m_handle) return fgets(s, size, m_handle);
    if (!m_data) return nullptr;
    if (m_size == m_ptr) return nullptr;
    int c;
    char *ptr = s;
    if (!size) return nullptr;
    size--;
    while (true) {
        if (!size) {
            *ptr = 0;
            return s;
        }
        c = getc();
        if ((c == 0) || (c == -1)) {
            *ptr = 0;
            return s;
        }
        *ptr++ = c;
        size--;
    }
}
std::string PCSX::File::gets() {
    int c;
    std::string ret;
    while (true) {
        c = getc();
        if ((c == 0) || (c == -1)) {
            return ret;
        }
        ret += c;
    }
}
ssize_t PCSX::File::read(void *dest, ssize_t size) {
    if (m_handle) return fread(dest, 1, size, m_handle);
    if (!m_data) return -1;
    size = std::max(m_size - m_ptr, size);
    if (size == 0) return -1;
    memcpy(dest, m_data + m_ptr, size);
    m_ptr += size;
    return size;
}
ssize_t PCSX::File::write(const void *dest, size_t size) {
    abort();
    return -1;
}
int PCSX::File::getc() {
    if (m_handle) return fgetc(m_handle);
    if (!m_data) return -1;
    if (m_size == m_ptr) return -1;
    return m_data[m_ptr++];
}
bool PCSX::File::failed() { return !m_handle && !m_data; }
bool PCSX::File::eof() {
    if (m_handle) return feof(m_handle);
    if (!m_data) return true;
    return m_size == m_ptr;
}
