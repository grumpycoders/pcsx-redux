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
#include <EASTL/functional.h>

#include "common/hardware/dma.h"
#include "common/hardware/gpu.h"
#include "common/hardware/irq.h"
#include "common/hardware/pcsxhw.h"
#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/kernel.hh"

void psyqo::GPU::initialize(const psyqo::GPU::Configuration &config) {
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
    Kernel::enableDma(Kernel::DMA::GPU);
    Kernel::registerDmaEvent(Kernel::DMA::GPU, [this]() {
        sendGPUStatus(0x04000000);
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
        if (m_flushCacheAfterDMA) {
            flushGPUCache();
            m_flushCacheAfterDMA = false;
        }
        if (m_fromISR) {
            m_dmaCallback();
            m_dmaCallback = nullptr;
        } else {
            Kernel::queueCallbackFromISR(eastl::move(m_dmaCallback));
        }
        eastl::atomic_signal_fence(eastl::memory_order_release);
    });
    auto t = DICR;
    t &= 0xffffff;
    t |= 0x040000;
    DICR = t;
}

void psyqo::GPU::flip() {
    do {
        Kernel::Internal::pumpCallbacks();
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
    } while (m_previousFrameCount == m_frameCount);

    m_previousFrameCount = m_frameCount;
    auto parity = m_parity;
    parity ^= 1;
    m_parity = parity;
    bool firstBuffer = !parity || m_interlaced;
    setDisplayArea(0, firstBuffer ? 256 : 0);
    enableScissor();
}

bool psyqo::GPU::disableScissor() {
    bool wasEnabled = m_scissorEnabled;
    m_scissorEnabled = false;
    setDrawingArea(0, 0, 1024, 512);
    setDrawingOffset(0, 0);
    return wasEnabled;
}

bool psyqo::GPU::enableScissor() {
    bool wasEnabled = m_scissorEnabled;
    m_scissorEnabled = true;
    auto parity = m_parity;
    auto width = m_width;
    auto height = m_height;
    bool firstBuffer = !parity || m_interlaced;
    setDrawingArea(0, firstBuffer ? 0 : 256, width, firstBuffer ? height : (256 + height));
    setDrawingOffset(0, firstBuffer ? 0 : 256);
    return wasEnabled;
}

void psyqo::GPU::clear(Color bg) {
    int16_t width = m_width;
    int16_t height = m_height;
    bool firstBuffer = !m_parity || m_interlaced;
    struct FastFill ff = {
        .c = bg,
        .x = int16_t(0),
        .y = firstBuffer ? int16_t(0) : int16_t(256),
        .w = width,
        .h = height,
    };
    fastFill(&ff);
}

void psyqo::GPU::uploadToVRAM(const uint16_t *data, Rect rect, eastl::function<void()> &&callback,
                              DmaCallback dmaCallback) {
    uintptr_t ptr = reinterpret_cast<uintptr_t>(data);
    Kernel::assert(!m_dmaCallback, "Only one GPU DMA transfer at a time is permitted");
    Kernel::assert((ptr & 3) == 0, "Unaligned DMA transfer");
    // TODO: check rectangle bounds
    m_fromISR = dmaCallback == FROM_ISR;
    m_flushCacheAfterDMA = true;
    m_dmaCallback = eastl::move(callback);
    uint32_t coords = rect.pos.y;
    coords <<= 16;
    coords |= rect.pos.x;
    uint32_t size = rect.size.h;
    size <<= 16;
    size |= rect.size.w;

    uint32_t bcr = rect.size.w * rect.size.h;
    Kernel::assert((bcr & 1) == 0, "Odd number of pixels to transfer");
    bcr >>= 1;

    unsigned bs = 1;
    while (((bcr & 1) == 0) && (bs < 16)) {
        bs <<= 1;
        bcr >>= 1;
    }
    Kernel::assert(bcr < 65536, "Transfer too big or block size too small");
    bcr <<= 16;
    bcr |= bs;

    sendGPUData(0xa0000000);
    GPU_DATA = coords;
    GPU_DATA = size;

    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0)
        ;
    DMA_CTRL[DMA_GPU].MADR = ptr;
    DMA_CTRL[DMA_GPU].BCR = bcr;
    eastl::atomic_signal_fence(eastl::memory_order_release);
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
}

void psyqo::GPU::sendFragment(uint32_t *data, unsigned count, eastl::function<void()> &&callback,
                              DmaCallback dmaCallback) {
    uintptr_t ptr = reinterpret_cast<uintptr_t>(data);
    Kernel::assert(!m_dmaCallback, "Only one GPU DMA transfer at a time is permitted");
    Kernel::assert((ptr & 3) == 0, "Unaligned DMA transfer");
    m_fromISR = dmaCallback == FROM_ISR;
    m_dmaCallback = eastl::move(callback);

    uint32_t bcr = count;

    unsigned bs = 1;
    while (((bcr & 1) == 0) && (bs < 16)) {
        bs <<= 1;
        bcr >>= 1;
    }
    Kernel::assert(bcr < 65536, "Transfer too big or block size too small");
    bcr <<= 16;
    bcr |= bs;

    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0)
        ;
    DMA_CTRL[DMA_GPU].MADR = ptr;
    DMA_CTRL[DMA_GPU].BCR = bcr;
    eastl::atomic_signal_fence(eastl::memory_order_release);
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
}
