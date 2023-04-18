/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include "support/mem4g.h"

ssize_t PCSX::Mem4G::rSeek(ssize_t pos, int wheel) {
    switch (wheel) {
        case SEEK_SET:
            m_ptrR = pos;
            break;
        case SEEK_END:
            m_ptrR = c_size - pos;
            break;
        case SEEK_CUR:
            m_ptrR += pos;
            break;
    }
    m_ptrR = std::max(std::min(m_ptrR, c_size), size_t(0));
    return m_ptrR;
}

ssize_t PCSX::Mem4G::wSeek(ssize_t pos, int wheel) {
    switch (wheel) {
        case SEEK_SET:
            m_ptrW = pos;
            break;
        case SEEK_END:
            m_ptrW = c_size - pos;
            break;
        case SEEK_CUR:
            m_ptrW += pos;
            break;
    }
    m_ptrW = std::max(std::min(m_ptrW, c_size), size_t(0));
    return m_ptrW;
}

ssize_t PCSX::Mem4G::readAt(void* dest, size_t size, size_t ptr) {
    if (ptr >= c_size) return 0;
    size_t ret = size = cappedSize(size, ptr);
    while (size) {
        auto blockSize = std::min(size, c_blockSize - (ptr % c_blockSize));
        readBlock(dest, blockSize, ptr);
        size -= blockSize;
        ptr += blockSize;
        dest = (char*)dest + blockSize;
    }
    return ret;
}

ssize_t PCSX::Mem4G::writeAt(const void* src, size_t size, size_t ptr) {
    if (ptr >= c_size) return 0;
    size_t ret = size = cappedSize(size, ptr);
    m_lowestAddress = std::min<uint32_t>(m_lowestAddress, ptr);
    m_highestAddress = std::max<uint32_t>(m_highestAddress, ptr + size);
    while (size) {
        auto blockSize = std::min(size, c_blockSize - (ptr % c_blockSize));
        writeBlock(src, blockSize, ptr);
        size -= blockSize;
        ptr += blockSize;
        src = (char*)src + blockSize;
    }
    return ret;
}

void PCSX::Mem4G::closeInternal() { m_blocks.destroyAll(); }

void PCSX::Mem4G::readBlock(void* dest, size_t size, size_t ptr) {
    auto block = m_blocks.find(ptr / c_blockSize);
    if (block == m_blocks.end()) {
        memset(dest, 0, size);
        return;
    }
    auto offset = ptr % c_blockSize;
    auto toCopy = std::min(size, c_blockSize - offset);
    memcpy(dest, block->data + offset, toCopy);
}

void PCSX::Mem4G::writeBlock(const void* src, size_t size, size_t ptr) {
    auto block = m_blocks.find(ptr / c_blockSize);
    if (block == m_blocks.end()) {
        block = m_blocks.insert(ptr / c_blockSize, new Block());
    }
    auto offset = ptr % c_blockSize;
    auto toCopy = std::min(size, c_blockSize - offset);
    memcpy(block->data + offset, src, toCopy);
}
