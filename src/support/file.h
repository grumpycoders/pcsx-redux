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

#pragma once

#include <stdint.h>
#include <stdio.h>

#include <filesystem>

#include "core/psxemulator.h"
#include "support/slice.h"

namespace PCSX {

class File {
  public:
    void close();
    ssize_t seek(ssize_t pos, int wheel);
    ssize_t tell();
    void flush();
    enum Create { CREATE };
    File(void* data, ssize_t size);
    File(const std::filesystem::path& filename) : File(filename.u8string()) {}
    File(const std::filesystem::path& filename, Create) : File(filename.u8string(), CREATE) {}
#if defined(__cpp_lib_char8_t)
    File(const std::u8string& filename) : File(reinterpret_cast<const char*>(filename.c_str())) {}
    File(const std::u8string& filename, Create) : File(reinterpret_cast<const char*>(filename.c_str()), CREATE) {}
#endif
    File(const std::string& filename) : File(filename.c_str()) {}
    File(const std::string& filename, Create) : File(filename.c_str(), CREATE) {}
    File(const char* filename);
    File(const char* filename, Create);
    ~File() { close(); }
    File* dup() { return new File(m_filename); }
    char* gets(char* s, int size);
    std::string gets();
    template <class T>
    T read() {
        T ret = 0;
        for (int i = 0; i < sizeof(T); i++) {
            T b = byte();
            ret |= (b << (i * 8));
        }
        return ret;
    }
    uint8_t byte() {
        uint8_t r;
        read(&r, 1);
        return r;
    }
    std::string readString(size_t size) {
        std::string r;
        r.reserve(size);
        for (size_t i = 0; i < size; i++) {
            r += (char)byte();
        }
        return r;
    }
    ssize_t read(void* dest, ssize_t size);
    ssize_t write(const void* dest, size_t size);
    Slice read(ssize_t size) {
        void* data = malloc(size);
        read(data, size);
        Slice slice;
        slice.acquire(data, size);
        return slice;
    }
    int getc();
    bool failed();
    bool eof();
    std::filesystem::path filename() { return m_filename; }

  private:
    const std::filesystem::path m_filename;
    static const uint8_t m_internalBuffer;
    FILE* m_handle = NULL;
    ssize_t m_ptr = 0;
    ssize_t m_size = 0;
    const uint8_t* m_data = NULL;
};

}  // namespace PCSX
