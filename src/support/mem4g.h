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

#pragma once

#include "support/file.h"
#include "support/hashtable.h"

namespace PCSX {

class Mem4G : public File {
  public:
    Mem4G() : File(File::FileType::RW_SEEKABLE) {}
    virtual ~Mem4G() { m_blocks.destroyAll(); }
    ssize_t rSeek(ssize_t pos, int wheel) final override;
    ssize_t rTell() final override { return m_ptrR; }
    ssize_t wSeek(ssize_t pos, int wheel) final override;
    ssize_t wTell() final override { return m_ptrW; }
    size_t size() final override { return c_size; }
    ssize_t read(void* dest, size_t size) final override {
        auto ret = readAt(dest, size, m_ptrR);
        m_ptrR += ret;
        return ret;
    }
    ssize_t write(const void* dest, size_t size) final override {
        auto ret = writeAt(dest, size, m_ptrW);
        m_ptrW += ret;
        return ret;
    }
    ssize_t readAt(void* dest, size_t size, size_t ptr) final override;
    ssize_t writeAt(const void* src, size_t size, size_t ptr) final override;

    uint32_t lowestAddress() const { return m_lowestAddress; }
    uint32_t highestAddress() const { return m_highestAddress; }

    uint32_t actualSize() const { return isEmpty() ? 0 : m_highestAddress - m_lowestAddress; }

    bool isEmpty() const { return m_lowestAddress == 0xffffffff; }

  private:
    constexpr static size_t c_size = 0x100000000ULL;
    constexpr static size_t c_blockSize = 64 * 1024;
    void closeInternal() final override;
    size_t m_ptrR = 0;
    size_t m_ptrW = 0;
    uint32_t m_lowestAddress = 0xffffffff;
    uint32_t m_highestAddress = 0;

    struct Block;
    typedef PCSX::Intrusive::HashTable<uint32_t, Block> Blocks;
    struct Block : public Blocks::Node {
        Block() { memset(data, 0, c_blockSize); }
        uint8_t data[c_blockSize];
    };
    Blocks m_blocks;
    size_t cappedSize(size_t size, size_t ptr) const { return std::min(size, c_size - ptr); }

    void readBlock(void* dest, size_t size, size_t ptr);
    void writeBlock(const void* src, size_t size, size_t ptr);
};

}  // namespace PCSX
