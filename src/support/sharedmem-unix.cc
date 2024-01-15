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

#if !defined(_WIN32) && !defined(_WIN64)

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "support/sharedmem.h"

bool PCSX::SharedMem::init(const char* id, size_t size, bool initToZero) {
    assert(m_mem == nullptr);
    bool doRawAlloc = true;
    m_size = size;
    // Try to create a shared memory mapping, if an ID is provided
    if (id != nullptr) {
        // Build the full name to share as
        m_sharedName = getSharedName(id, static_cast<uint32_t>(getpid()));
        // Try to create a shared memory mapping, if a name is provided
        m_fd = shm_open(m_sharedName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (m_fd >= 0) {
            // fd is ready, reserve the memory we need
            int result = ftruncate(m_fd, static_cast<off_t>(size));
            if (result < 0) {
                shm_unlink(m_sharedName.c_str());
                close(m_fd);
                m_fd = -1;
            } else {
                // ftruncate completed, now map the memory at 0 offset
                void* basePointer = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, 0);
                // Validate success and assign the view to m_mem
                if (basePointer != MAP_FAILED) {
                    doRawAlloc = false;
                    m_mem = static_cast<uint8_t*>(basePointer);
                    // Initialise memory to zero, if requested
                    if (initToZero) {
                        memset(m_mem, 0, size);
                    }
                } else {
                    shm_unlink(m_sharedName.c_str());
                    close(m_fd);
                    m_fd = -1;
                }
            }
        }
    }
    // Alloc memory directly if we opted out or had problems creating the memory map
    if (doRawAlloc) {
        // calloc will automatically init memory to zero
        m_mem = (uint8_t*)calloc(size, 1);
    }

    // Return false if we had to fall back to a raw alloc
    return !(doRawAlloc && id != nullptr);
}

PCSX::SharedMem::~SharedMem() {
    if (m_fd == -1) {
        free(m_mem);
    } else {
        munmap(m_mem, m_size);
        shm_unlink(m_sharedName.c_str());
        close(m_fd);
    }
}

#endif
