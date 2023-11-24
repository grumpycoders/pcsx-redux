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
#include "core/system.h"

#include <assert.h>

void PCSX::SharedMem::init(const char* name, size_t size) {
    assert(m_mem == nullptr);
    bool doRawAlloc = true;
    // Try to create a shared memory mapping, if a name is provided
    if (name != nullptr) {
        // Create the memory mapping handle
        m_fileHandle = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
            static_cast<uint32_t>(size >> 32), static_cast<uint32_t>(size), name);
        if (m_fileHandle != INVALID_HANDLE_VALUE) {
            // Create a view of the memory mapping at 0 offset
            void* basePointer = MapViewOfFileEx(m_fileHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size, nullptr);
            // Validate success and assign the view to m_mem
            if (basePointer != nullptr) {
                doRawAlloc = false;
                m_mem = static_cast<uint8_t *>(basePointer);
            } else {
                CloseHandle(m_fileHandle);
                m_fileHandle = nullptr;
                g_system->message("MapViewOfFileEx failed, falling back to memory alloc, last error: %d, size: %zu\n",
                    (int)GetLastError(), m_size);
            }
        } else {
            m_fileHandle = nullptr;
            g_system->message("CreateFileMappingA failed, falling back to memory alloc, last error: %d, size: %zu\n",
                (int)GetLastError(), m_size);
        }
    }
    
    m_size = size;
    // Alloc memory directly if we opted out or had problems creating the memory map
    if (doRawAlloc) {
        m_mem = (uint8_t *)calloc(size, 1);
    }
}

PCSX::SharedMem::~SharedMem() {
    if (m_fileHandle != nullptr) {
        bool success = static_cast<bool>(UnmapViewOfFile(m_mem));
        if (!success) {
            g_system->printf("Failed to unmap view of allocated memory (size: %zu).\n", m_size);
        }
        m_mem = nullptr;
        CloseHandle(m_fileHandle);
        m_fileHandle = nullptr;
    } else {
        free(m_mem);
    }
}

#endif
