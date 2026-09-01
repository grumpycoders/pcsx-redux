/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

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
