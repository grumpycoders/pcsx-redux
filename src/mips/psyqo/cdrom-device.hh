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

#include "psyqo/cdrom.hh"

namespace psyqo {

/**
 * @brief A specialization of the CDRom interface.
 *
 * @details This class is a specialization of the CDRom interface, which
 * provides a way to read from the physical CDRom drive of the console.
 *
 */
class CDRomDevice final : public CDRom {
  public:
    virtual ~CDRomDevice();

    /**
     * @brief Prepares the CDRom subsystem.
     *
     * @details This method prepares the kernel and the system for the
     * CDRom subsystem. It should be called once from the application's
     * `prepare` method.
     *
     */
    void prepare();

    /**
     * @brief Resets the CDRom controller.
     *
     * @details This method will reset the CDRom controller. It technically
     * does not need to be called, but it is a good idea to call it when
     * the application starts, in order to ensure that the controller
     * is in a known state.
     *
     */
    void reset(eastl::function<void(bool)> &&callback);
    TaskQueue::Task scheduleReset();

    void readSectors(uint32_t sector, uint32_t count, void *buffer, eastl::function<void(bool)> &&callback) override;
    TaskQueue::Task scheduleReadSectors(uint32_t sector, uint32_t count, void *buffer) override;

  private:
    void irq();

    void dataReady();
    void complete();
    void acknowledge();
    void end();
    void discError();

    eastl::function<void(bool)> m_callback;
    uint32_t m_event = 0;
    uint32_t m_count = 0;
    uint8_t *m_ptr = nullptr;
    enum {
        NONE,
        RESET,
        SETLOC,
        SETMODE,
        READ,
        PAUSE,
    } m_action = NONE;
};

}  // namespace psyqo
