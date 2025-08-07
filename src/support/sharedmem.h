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

#include <stdint.h>

#include <string>

namespace PCSX {

class SharedMem {
  public:
    SharedMem() {}
    ~SharedMem();

    /**
     * Returns true if:
     *  - the memory was sucessfully shared with the given ID, or
     *  - no ID was given and a raw alloc was performed
     * Returns false if:
     *  - the memory failed to successfully share and defaulted to a raw alloc
     */
    bool init(const char* id, size_t size, bool initToZero);

    uint8_t* getPtr() { return m_mem; }
    size_t getSize() { return m_size; }

    const std::string& getSharedName() { return m_sharedName; }

  private:
    std::string getSharedName(const char* id, uint32_t pid);

  private:
    uint8_t* m_mem = nullptr;
    size_t m_size = 0;

    void* m_fileHandle = nullptr;
    std::string m_sharedName;
    int m_fd = -1;
};

}  // namespace PCSX
