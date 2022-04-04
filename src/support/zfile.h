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
    virtual void close() final override { inflateEnd(&m_infstream); }
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
    enum Internal { INTERNAL };
    ZReader(Internal, IO<File> file, ssize_t size, bool raw) : File(RO_SEEKABLE), m_file(file), m_size(size), m_raw(raw) {
        m_infstream.zalloc = Z_NULL;
        m_infstream.zfree = Z_NULL;
        m_infstream.opaque = Z_NULL;
        m_infstream.avail_in = 0;
        auto res = inflateInit2(&m_infstream, raw ? -MAX_WBITS : MAX_WBITS);
        if (res != Z_OK) throw std::runtime_error("inflateInit didn't work");
    }
    IO<File> m_file;
    z_stream m_infstream;
    ssize_t m_filePtr = 0;
    ssize_t m_size = 0;
    bool m_hitEOF = false;
    bool m_raw = false;
    uint8_t m_inBuffer[1024];
};

}  // namespace PCSX
