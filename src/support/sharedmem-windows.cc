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
#if defined(_WIN32) || defined(_WIN64)

#include "support/sharedmem.h"
#include "support/windowswrapper.h"

#include <assert.h>

bool PCSX::SharedMem::init(const char* id, size_t size, bool initToZero) {
    assert(m_mem == nullptr);
    bool doRawAlloc = true;
    m_size = size;
    // Try to create a shared memory mapping, if an id is provided
    if (id != nullptr) {
        // Build the full name to share as
        std::string fullname = getSharedName(id, static_cast<uint32_t>(GetCurrentProcessId()));
        // Create the memory mapping handle
        m_fileHandle = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
            static_cast<uint32_t>(size >> 32), static_cast<uint32_t>(size), fullname.c_str());
        if (m_fileHandle != INVALID_HANDLE_VALUE) {
            // Create a view of the memory mapping at 0 offset
            void* basePointer = MapViewOfFileEx(m_fileHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size, nullptr);
            // Validate success and assign the view to m_mem
            if (basePointer != nullptr) {
                doRawAlloc = false;
                m_mem = static_cast<uint8_t *>(basePointer);
                // Initialise memory to zero, if requested
                if (initToZero) {
                    memset(m_mem, 0, size);
                }
            } else {
                CloseHandle(m_fileHandle);
                m_fileHandle = nullptr;
            }
        } else {
            m_fileHandle = nullptr;
        }
    }
    // Alloc memory directly if we opted out or had problems creating the memory map
    if (doRawAlloc) {
        // calloc will automatically init memory to zero
        m_mem = (uint8_t *)calloc(size, 1);
    }
    // Return false if we had to fall back to a raw alloc
    return !(doRawAlloc && id != nullptr);
}

PCSX::SharedMem::~SharedMem() {
    if (m_fileHandle != nullptr) {
        UnmapViewOfFile(m_mem);
        m_mem = nullptr;
        CloseHandle(m_fileHandle);
        m_fileHandle = nullptr;
    } else {
        free(m_mem);
    }
}

#endif
