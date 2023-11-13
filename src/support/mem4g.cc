/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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
