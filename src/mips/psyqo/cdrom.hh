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

#include <EASTL/functional.h>
#include <stdint.h>

#include "psyqo/task.hh"

namespace psyqo {

/**
 * @brief The base CDRom class.
 *
 * @details The CDRom system is meant to be swappable between multiple
 * implementations, so the base class is a pure abstraction. This allows
 * the ISO9660 parser to be used with any CDRom implementation.
 */

class CDRom {
  public:
    virtual ~CDRom() {}
    /**
     * @brief An asynchronous read request.
     *
     * @details This struct serves as a persistent storage for an asynchronous read
     * request. Its purpose is to be embedded outside of the device class, so it can
     * keep track of the current state of the request.
     */
    struct ReadRequest {
        uint32_t LBA = 0;
        uint32_t count = 0;
        void *buffer = nullptr;
    };

    /**
     * @brief Read a sector from the CDRom.
     *
     * @details The function will make reasonable attempts at reading the
     * disk, but it is not guaranteed to succeed. Failures may be caused
     * by the disk being faulty, the lid being opened, or no valid disk
     * being present. Only one operation can be in progress at a time.
     *
     * @param sector The sector to read.
     * @param buffer The buffer to read into.
     * @param size The size of the buffer.
     * @param callback The callback to call when the read is done. It will be called
     * from the main thread when possible. Its one argument is a boolean indicating
     * whether the read was successful.
     */
    virtual void readSectors(uint32_t sector, uint32_t count, void *buffer, eastl::function<void(bool)> &&callback) = 0;

    /**
     * @brief Schedule a read operation.
     *
     * @details This is a convenience function that will schedule a read operation
     * and return a task that can be waited on.
     *
     * @param sector The sector to read.
     * @param buffer The buffer to read into.
     * @param size The size of the buffer.
     * @return A task that can be queued into a `TaskQueue`
     */
    TaskQueue::Task scheduleReadSectors(uint32_t sector, uint32_t count, void *buffer);

    /**
     * @brief Schedule a read operation.
     *
     * @details This is a convenience function that will schedule a read operation
     * and return a task that can be waited on. The difference with `scheduleReadSectors`
     * is that this method will read its arguments right before the operation is
     * processed, so the request data can be filled in at the last moment.
     *
     * @param[in] request The request to schedule.
     * @return A task that can be queued into a `TaskQueue`
     */
    TaskQueue::Task scheduleReadRequest(ReadRequest *request);

  private:
    ReadRequest m_readRequest;
};

}  // namespace psyqo
