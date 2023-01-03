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

#include "support/zfile.h"

ssize_t PCSX::ZReader::rSeek(ssize_t pos, int wheel) {
    switch (wheel) {
        case SEEK_SET:
            m_filePtr = pos;
            break;
        case SEEK_END:
            if (m_size < 0) {
                throw std::runtime_error("Unable to seek from end without knowing full size");
            }
            m_filePtr = m_size + pos;
            break;
        case SEEK_CUR:
            m_filePtr += pos;
            break;
    }
    return m_filePtr;
}

ssize_t PCSX::ZReader::read(void *dest_, size_t size) {
    uint8_t *dest = reinterpret_cast<uint8_t *>(dest_);

    ssize_t dumpDelta = m_filePtr - m_zstream.total_out;
    if (dumpDelta < 0) {
        dumpDelta = m_filePtr;
        m_filePtr = 0;
        m_hitEOF = false;
        inflateEnd(&m_zstream);
        m_zstream.avail_in = sizeof(m_inBuffer);
        m_zstream.next_in = m_inBuffer;
        inflateInit2(&m_zstream, m_raw ? -MAX_WBITS : MAX_WBITS);
    }
    if (m_hitEOF) return -1;
    auto decompSome = [this](void *dest, ssize_t size) -> ssize_t {
        m_zstream.avail_out = size;
        m_zstream.next_out = reinterpret_cast<decltype(m_zstream.next_out)>(dest);
        if (!m_zstream.avail_in) {
            ssize_t block = m_file->readAt(m_inBuffer, sizeof(m_inBuffer), m_zstream.total_in);
            if (block < 0) return block;
            m_zstream.avail_in = block;
            m_zstream.next_in = m_inBuffer;
        }
        auto res = inflate(&m_zstream, Z_FINISH);
        if ((res < 0) && (res != Z_BUF_ERROR)) {
            return -1;
        }
        ssize_t delta = size - m_zstream.avail_out;
        m_filePtr += delta;
        if (res == Z_STREAM_END) m_hitEOF = true;
        return delta;
    };
    ssize_t ret = 0;
    while (dumpDelta) {
        uint8_t dummy[256];
        ssize_t toDump = std::min(ssize_t(sizeof(dummy)), dumpDelta);
        ssize_t p = decompSome(dummy, toDump);
        if (p < 0) return p;
        dumpDelta -= p;
        if (m_hitEOF || !p) break;
    }
    while (size) {
        if (m_hitEOF) break;
        ssize_t p = decompSome(dest, size);
        if (p < 0) return p;
        if (!p) break;
        size -= p;
        ret += p;
        dest += p;
    }

    return ret;
}

ssize_t PCSX::ZWriter::write(const void *dest, size_t size) {
    m_zstream.avail_in = size;
    m_zstream.next_in = static_cast<Bytef *>(const_cast<void *>(dest));

    while (m_zstream.avail_in) {
        void *data = malloc(c_chunkSize);
        m_zstream.avail_out = c_chunkSize;
        m_zstream.next_out = static_cast<Bytef *>(data);
        deflate(&m_zstream, Z_NO_FLUSH);
        Slice out;
        out.acquire(data, c_chunkSize - m_zstream.avail_out);
        m_file->write(std::move(out));
    }

    return size;
}

void PCSX::ZWriter::closeInternal() {
    int r = Z_OK;
    while (r != Z_STREAM_END) {
        void *data = malloc(c_chunkSize);
        m_zstream.avail_out = c_chunkSize;
        m_zstream.next_out = static_cast<Bytef *>(data);
        r = deflate(&m_zstream, Z_FINISH);
        Slice out;
        out.acquire(data, c_chunkSize - m_zstream.avail_out);
        m_file->write(std::move(out));
    }
    deflateEnd(&m_zstream);
}
