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

#include <zlib.h>

#include "support/file.h"

namespace PCSX {

class ZReader : public File {
  public:
    enum Raw { RAW };
    ZReader(IO<File> file) : ZReader(INTERNAL, file, -1, false) {}
    ZReader(IO<File> file, Raw) : ZReader(INTERNAL, file, -1, true) {}
    ZReader(IO<File> file, ssize_t size) : ZReader(INTERNAL, file, size, false) {}
    ZReader(IO<File> file, ssize_t size, Raw) : ZReader(INTERNAL, file, size, true) {}
    virtual ssize_t rSeek(ssize_t pos, int wheel) final override;
    virtual ssize_t rTell() final override { return m_filePtr; }
    virtual ssize_t read(void* dest, size_t size) final override;
    virtual size_t size() final override {
        if (m_size >= 0) return m_size;
        throw std::runtime_error("Unable to determine file size");
    }
    virtual bool eof() final override { return m_hitEOF; }
    virtual File* dup() final override { return new ZReader(INTERNAL, m_file, m_size, m_raw); };
    virtual bool failed() final override { return m_file->failed(); }

  private:
    virtual void closeInternal() final override { inflateEnd(&m_zstream); }
    enum Internal { INTERNAL };
    ZReader(Internal, IO<File> file, ssize_t size, bool raw)
        : File(RO_SEEKABLE), m_file(file), m_size(size), m_raw(raw) {
        auto z = &m_zstream;
        z->zalloc = Z_NULL;
        z->zfree = Z_NULL;
        z->opaque = Z_NULL;
        z->avail_in = 0;
        int wbits = MAX_WBITS;
        if (raw) {
            wbits = -wbits;
        } else {
            wbits += 32;
        }
        auto res = inflateInit2(z, wbits);
        if (res != Z_OK) throw std::runtime_error("inflateInit2 didn't work");
    }
    IO<File> m_file;
    z_stream m_zstream;
    ssize_t m_filePtr = 0;
    ssize_t m_size = 0;
    bool m_hitEOF = false;
    bool m_raw = false;
    uint8_t m_inBuffer[1024];
};

class ZWriter : public File {
  public:
    enum Raw { RAW };
    enum GZip { GZIP };
    ZWriter(IO<File> file) : ZWriter(INTERNAL, file, false, false) {}
    ZWriter(IO<File> file, Raw) : ZWriter(INTERNAL, file, true, false) {}
    ZWriter(IO<File> file, GZip) : ZWriter(INTERNAL, file, false, true) {}
    virtual ssize_t write(const void* dest, size_t size) final override;
    virtual bool failed() final override { return m_file->failed(); }

  private:
    virtual void closeInternal() final override;
    static constexpr size_t c_chunkSize = 65536;
    enum Internal { INTERNAL };
    ZWriter(Internal, IO<File> file, bool raw, bool gzip) : File(RW_STREAM), m_file(file) {
        auto z = &m_zstream;
        z->zalloc = Z_NULL;
        z->zfree = Z_NULL;
        z->opaque = Z_NULL;
        z->avail_in = 0;
        int wbits = MAX_WBITS;
        if (raw) wbits = -wbits;
        if (gzip) wbits += 16;
        auto res = deflateInit2(z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, wbits, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
        if (res != Z_OK) throw std::runtime_error("deflateInit2 didn't work");
    }
    IO<File> m_file;
    z_stream m_zstream;
};

}  // namespace PCSX
