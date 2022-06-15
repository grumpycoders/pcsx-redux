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

#include "psyqo/gpu.hh"

#include <EASTL/atomic.h>

#include "common/hardware/gpu.h"
#include "common/hardware/irq.h"
#include "common/hardware/pcsxhw.h"
#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/kernel.hh"

void psyqo::GPU::initialize(const psyqo::GPU::Configuration& config) {
    GPU_STATUS = 0;
    setDisplayMode(&config.config);
    setHorizontalRange(0, 0xa00);
    setVerticalRange(16, 255);

    if (config.config.videoInterlace == VI_ON) {
        m_interlaced = true;
        m_height = 480;
    } else {
        m_interlaced = false;
        m_height = 240;
    }

    if (config.config.hResolutionExtended == HRE_NORMAL) {
        switch (config.config.hResolution) {
            case HR_256:
                m_width = 256;
                break;
            case HR_320:
                m_width = 320;
                break;
            case HR_512:
                m_width = 512;
                break;
            case HR_640:
                m_width = 640;
                break;
        }
    } else {
        m_width = 368;
    }

    uint32_t event = Kernel::openEvent(0xf2000003, 2, EVENT_MODE_CALLBACK, [this]() { m_frameCount++; });
    syscall_enableEvent(event);
    syscall_enableTimerIRQ(3);
    syscall_setTimerAutoAck(3, 1);
    struct FastFill ff = {
        .c = {{0, 0, 0}},
        .x = int16_t(0),
        .y = int16_t(0),
        .w = int16_t(1024),
        .h = int16_t(512),
    };
    fastFill(&ff);
    enableDisplay();
}

void psyqo::GPU::flip() {
    while (m_previousFrameCount == m_frameCount) {
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
    }

    m_previousFrameCount = m_frameCount;
    if (m_interlaced) return;
    auto parity = m_parity;
    parity ^= 1;
    m_parity = parity;
    auto width = m_width;
    auto height = m_height;
    setDisplayArea(0, parity ? 256 : 0);
    setDrawingArea(0, parity ? 256 : 0, width, parity ? (256 + height) : height);
    setDrawingOffset(0, parity ? 0 : height);
}

void psyqo::GPU::clear(Color bg) {
    auto parity = m_parity;
    int16_t width = m_width;
    int16_t height = m_height;
    bool firstBuffer = parity || m_interlaced;
    struct FastFill ff = {
        .c = bg,
        .x = int16_t(0),
        .y = firstBuffer ? int16_t(0) : int16_t(256),
        .w = width,
        .h = height,
    };
    fastFill(&ff);
}
