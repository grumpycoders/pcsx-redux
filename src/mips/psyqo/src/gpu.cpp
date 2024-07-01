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

#include "common/hardware/counters.h"
#include "common/hardware/dma.h"
#include "common/hardware/pcsxhw.h"
#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/hardware/cpu.hh"
#include "psyqo/kernel.hh"

psyqo::GPU::GPU() {}

void psyqo::GPU::waitReady() {
    while ((Hardware::GPU::Ctrl & uint32_t(0x04000000)) == 0) {
        pumpCallbacks();
    }
}

void psyqo::GPU::waitFifo() {
    while ((Hardware::GPU::Ctrl & uint32_t(0x02000000)) == 0) {
        pumpCallbacks();
    }
}

void psyqo::GPU::initialize(const psyqo::GPU::Configuration &config) {
    // Reset
    Hardware::GPU::Ctrl = 0;
    // FIFO polling mode
    Hardware::GPU::Ctrl = 0x04000001;
    // Display Mode
    Hardware::GPU::Ctrl = 0x08000000 | (config.config.hResolution << 0) | (config.config.vResolution << 2) |
                          (config.config.videoMode << 3) | (config.config.colorDepth << 4) |
                          (config.config.videoInterlace << 5) | (config.config.hResolutionExtended << 6);
    // Horizontal Range
    Hardware::GPU::Ctrl = 0x06000000 | 0x260 | (0xc60 << 12);

    // Vertical Range
    if (config.config.videoMode == Configuration::VM_NTSC) {
        Hardware::GPU::Ctrl = 0x07000000 | 16 | (255 << 10);
    } else {
        Hardware::GPU::Ctrl = 0x07046c2b;
    }

    // Display Area
    Hardware::GPU::Ctrl = 0x05000000;

    COUNTERS[1].mode = 0x100;
    COUNTERS[1].value = 0;

    if (config.config.videoInterlace == Configuration::VI_ON) {
        m_interlaced = true;
        m_height = 480;
    } else {
        m_interlaced = false;
        m_height = 240;
    }

    if (config.config.hResolutionExtended == Configuration::HRE_NORMAL) {
        switch (config.config.hResolution) {
            case Configuration::HR_256:
                m_width = 256;
                break;
            case Configuration::HR_320:
                m_width = 320;
                break;
            case Configuration::HR_512:
                m_width = 512;
                break;
            case Configuration::HR_640:
                m_width = 640;
                break;
        }
    } else {
        m_width = 368;
    }

    if (config.config.videoMode == Configuration::VM_NTSC) {
        m_refreshRate = 60;
    } else {
        m_refreshRate = 50;
    }

    // Install VBlank interrupt handler
    uint32_t event = Kernel::openEvent(0xf2000003, 2, EVENT_MODE_CALLBACK, [this]() {
        m_frameCount++;
        eastl::atomic_signal_fence(eastl::memory_order_release);
    });
    syscall_enableEvent(event);
    syscall_enableTimerIRQ(3);
    syscall_setTimerAutoAck(3, 1);
    if (config.clearVRAM) {
        Prim::FastFill ff;
        ff.rect = Rect{0, 0, 1024, 512};
        sendPrimitive(ff);
    }
    // Enable Display
    Hardware::GPU::Ctrl = 0x03000000;
    Kernel::enableDma(Kernel::DMA::GPU);
    Kernel::enableDma(Kernel::DMA::OTC);
    Kernel::registerDmaEvent(Kernel::DMA::GPU, [this]() {
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
        uint32_t mode = (DMA_CTRL[DMA_GPU].CHCR & 0x00000600) >> 9;
        switch (mode) {
            case 1: {  // was a normal DMA
                auto chainNext = m_chainNext;
                if (!chainNext) break;
                // We just processed a block which was too big, so now we need to send the next one
                // Loading the next header
                uint32_t head = *chainNext;
                uint32_t count = head >> 24;
                if (count > (c_chainThreshold / 4)) {
                    // next one still too big
                    m_chainNext = head == 0xff0000 ? nullptr : reinterpret_cast<uint32_t *>(head & 0x7fffff);
                    scheduleNormalDMA(reinterpret_cast<uintptr_t>(chainNext) + 4, count);
                } else {
                    // next one is small enough
                    m_chainNext = nullptr;
                    scheduleChainedDMA(reinterpret_cast<uintptr_t>(chainNext));
                }
                return;
            }
            case 2: {  // was a linked DMA
                uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
                if (madr != 0xff0000) {
                    madr &= 0x7fffff;
                    // Did we get interrupted in the middle of a chain?
                    // It means we linked a node too big for the DMA engine to handle,
                    // so we need to send it manually
                    uint32_t *next = reinterpret_cast<uint32_t *>(madr | 0x80000000);
                    uint32_t head = *next;
                    uint32_t count = head >> 24;
                    head &= 0xffffff;
                    if (head != 0xff0000) {
                        m_chainNext = reinterpret_cast<uint32_t *>(head & 0x7fffff);
                    }
                    scheduleNormalDMA(madr + 4, count);
                    return;
                }
            } break;
        }
        // GPU back in Fifo polling mode, in case we were uploading to VRAM
        Hardware::GPU::Ctrl = 0x04000001;
        if (m_flushCacheAfterDMA) {
            Prim::FlushCache fc;
            sendPrimitive(fc);
            m_flushCacheAfterDMA = false;
        }
        checkOTCAndTriggerCallback();
    });
    Kernel::registerDmaEvent(Kernel::DMA::OTC, [this]() { checkOTCAndTriggerCallback(); });
    // Enable DMA interrupt for GPU
    uint32_t dicr = Hardware::CPU::DICR;
    dicr &= 0xffffff;
    dicr |= 0x440000;
    Hardware::CPU::DICR = dicr;
}

void psyqo::GPU::checkOTCAndTriggerCallback() {
    auto &OTCs = m_OTCs[m_parity ^ 1];
    if (!OTCs.empty()) {
        auto &otc = OTCs.front();
        DMA_CTRL[DMA_GPUOTC].MADR = uint32_t(otc.start);
        DMA_CTRL[DMA_GPUOTC].BCR = otc.count;
        OTCs.pop_front();
        eastl::atomic_signal_fence(eastl::memory_order_release);
        DMA_CTRL[DMA_GPUOTC].CHCR = 0x11000002;
    } else {
        if (m_fromISR) {
            m_dmaCallback();
            m_dmaCallback = nullptr;
        } else {
            Kernel::queueCallbackFromISR(eastl::move(m_dmaCallback));
        }
        eastl::atomic_signal_fence(eastl::memory_order_release);
    }
}

void psyqo::GPU::flip() {
    do {
        pumpCallbacks();
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
    } while ((m_previousFrameCount == m_frameCount) || (m_chainStatus == CHAIN_TRANSFERRING));

    auto parity = m_parity;
    parity ^= 1;
    if (!m_interlaced) {
        bool firstBuffer = !parity;
        // Set Display Area
        if (firstBuffer) {
            Hardware::GPU::Ctrl = 0x05000000 | (256 << 10);
        } else {
            Hardware::GPU::Ctrl = 0x05000000;
        }
    } else if (!pcsx_present()) {
        while (1) {
            uint32_t stat = Hardware::GPU::Ctrl;
            int isDrawingEven = (stat & 0x80000000) == 0;
            int isMaskingEven = (stat & 0x00002000) == 0;
            if (parity && isDrawingEven && !isMaskingEven) break;
            if (!parity && !isDrawingEven && isMaskingEven) break;
            pumpCallbacks();
        }
    }

    m_chainStatus = CHAIN_IDLE;
    m_parity = parity;
    m_previousFrameCount = m_frameCount;
    eastl::atomic_signal_fence(eastl::memory_order_release);

    enableScissor();
    Kernel::Internal::beginFrame();
    if (m_chainHead) {
        m_chainStatus = CHAIN_TRANSFERRING;
        eastl::atomic_signal_fence(eastl::memory_order_release);
        sendChain(
            [this]() {
                m_chainStatus = CHAIN_TRANSFERRED;
                eastl::atomic_signal_fence(eastl::memory_order_release);
            },
            DMA::FROM_ISR);
    }
}

void psyqo::GPU::disableScissor() {
    Prim::Scissor s;
    sendPrimitive(s);
}

void psyqo::GPU::enableScissor() {
    Prim::Scissor s;
    getScissor(s);
    sendPrimitive(s);
}

void psyqo::GPU::getScissor(Prim::Scissor &scissor) {
    auto parity = m_parity;
    int16_t width = m_width;
    int16_t height = m_height;
    bool firstBuffer = !parity || m_interlaced;

    scissor.start = Prim::DrawingAreaStart(Vertex{{.x = 0, .y = firstBuffer ? int16_t(0) : int16_t(256)}});
    scissor.end = Prim::DrawingAreaEnd(Vertex{{.x = width, .y = firstBuffer ? height : int16_t(256 + height)}});
    scissor.offset = Prim::DrawingOffset(Vertex{{.x = int16_t(0), .y = firstBuffer ? int16_t(0) : int16_t(256)}});
}

void psyqo::GPU::getNextScissor(Prim::Scissor &scissor) {
    auto parity = m_parity;
    int16_t width = m_width;
    int16_t height = m_height;
    bool firstBuffer = !parity || m_interlaced;

    scissor.start = Prim::DrawingAreaStart(Vertex{{.x = 0, .y = firstBuffer ? int16_t(256) : int16_t(0)}});
    scissor.end = Prim::DrawingAreaEnd(Vertex{{.x = width, .y = firstBuffer ? int16_t(256 + height) : height}});
    scissor.offset = Prim::DrawingOffset(Vertex{{.x = int16_t(0), .y = firstBuffer ? int16_t(256) : int16_t(0)}});
}

void psyqo::GPU::clear(Color bg) {
    Prim::FastFill ff;
    getClear(ff, bg);
    sendPrimitive(ff);
}

void psyqo::GPU::getClear(Prim::FastFill &ff, Color bg) const {
    int16_t width = m_width;
    int16_t height = m_height;
    bool firstBuffer = !m_parity || m_interlaced;
    ff.setColor(bg);
    ff.rect = Rect{0, firstBuffer ? int16_t(0) : int16_t(256), width, height};
}

void psyqo::GPU::getNextClear(Prim::FastFill &ff, Color bg) const {
    int16_t width = m_width;
    int16_t height = m_height;
    bool firstBuffer = !m_parity || m_interlaced;
    ff.setColor(bg);
    ff.rect = Rect{0, firstBuffer ? int16_t(256) : int16_t(0), width, height};
}

void psyqo::GPU::uploadToVRAM(const uint16_t *data, Rect rect) {
    if (rect.isEmpty()) return;
    bool done = false;
    uploadToVRAM(
        data, rect,
        [&done]() {
            done = true;
            eastl::atomic_signal_fence(eastl::memory_order_release);
        },
        DMA::FROM_ISR);
    while (!done) {
        pumpCallbacks();
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
    }
}

void psyqo::GPU::uploadToVRAM(const uint16_t *data, Rect region, eastl::function<void()> &&callback,
                              DMA::DmaCallback dmaCallback) {
    if (region.isEmpty()) {
        Kernel::assert(dmaCallback == DMA::FROM_MAIN_LOOP, "Empty DMA transfer with ISR callback aren't supported");
        Kernel::queueCallback(eastl::move(callback));
        return;
    }
    uintptr_t ptr = reinterpret_cast<uintptr_t>(data);
    Kernel::assert(!m_dmaCallback, "Only one GPU DMA transfer at a time is permitted");
    Kernel::assert((ptr & 3) == 0, "Unaligned DMA transfer");
    // TODO: check region bounds
    m_fromISR = dmaCallback == DMA::FROM_ISR;
    m_flushCacheAfterDMA = true;
    m_dmaCallback = eastl::move(callback);

    uint32_t bcr = region.size.w * region.size.h;
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

    Prim::VRAMUpload upload;
    upload.region = region;
    sendPrimitive(upload);

    // Activating VRAM DMA upload mode
    Hardware::GPU::Ctrl = 0x04000002;
    while ((Hardware::GPU::Ctrl & uint32_t(0x10000000)) == 0)
        ;
    DMA_CTRL[DMA_GPU].MADR = ptr;
    DMA_CTRL[DMA_GPU].BCR = bcr;
    eastl::atomic_signal_fence(eastl::memory_order_release);
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
}

void psyqo::GPU::sendFragment(const uint32_t *data, size_t count) {
    bool done = false;
    if (count == 0) return;
    sendFragment(
        data, count,
        [&done]() {
            done = true;
            eastl::atomic_signal_fence(eastl::memory_order_release);
        },
        DMA::FROM_ISR);
    while (!done) {
        pumpCallbacks();
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
    }
}

void psyqo::GPU::sendFragment(const uint32_t *data, size_t count, eastl::function<void()> &&callback,
                              DMA::DmaCallback dmaCallback) {
    if (count == 0) {
        Kernel::assert(dmaCallback == DMA::FROM_MAIN_LOOP, "Empty DMA transfer with ISR callback aren't supported");
        Kernel::queueCallback(eastl::move(callback));
        return;
    }
    uintptr_t ptr = reinterpret_cast<uintptr_t>(data);
    Kernel::assert(!m_dmaCallback, "Only one GPU DMA transfer at a time is permitted");
    Kernel::assert((ptr & 3) == 0, "Unaligned DMA transfer");
    m_fromISR = dmaCallback == DMA::FROM_ISR;
    m_dmaCallback = eastl::move(callback);
    scheduleNormalDMA(ptr, count);
}

void psyqo::GPU::scheduleNormalDMA(uintptr_t data, size_t count) {
    uint32_t bcr = count;

    Kernel::assert((DMA_CTRL[DMA_GPU].CHCR & 0x01000000) == 0, "GPU DMA busy");
    unsigned bs = 1;
    while (((bcr & 1) == 0) && (bs < 16)) {
        bs <<= 1;
        bcr >>= 1;
    }
    Kernel::assert(bcr < 65536, "Transfer too big or block size too small");
    bcr <<= 16;
    bcr |= bs;

    while ((Hardware::GPU::Ctrl & uint32_t(0x10000000)) == 0)
        ;
    DMA_CTRL[DMA_GPU].MADR = data;
    DMA_CTRL[DMA_GPU].BCR = bcr;
    eastl::atomic_signal_fence(eastl::memory_order_release);
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
}

void psyqo::GPU::chain(uint32_t *first, uint32_t *last, size_t count) {
    Kernel::assert(count < 256, "Fragment too big to be chained");
    if (!m_chainHead) {
        m_chainHead = first;
    } else {
        uint32_t tailValue = m_chainTailCount | (reinterpret_cast<uintptr_t>(first) & 0xffffff);
        if (count > (c_chainThreshold / 4)) {
            tailValue |= 0x00800000;
        }
        *m_chainTail = tailValue;
    }
    m_chainTail = last;
    m_chainTailCount = count << 24;
}

void psyqo::GPU::sendChain() {
    bool done = false;
    sendChain(
        [&done]() {
            done = true;
            eastl::atomic_signal_fence(eastl::memory_order_release);
        },
        DMA::FROM_ISR);
    while (!done) {
        pumpCallbacks();
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
    }
}

void psyqo::GPU::sendChain(eastl::function<void()> &&callback, DMA::DmaCallback dmaCallback) {
    auto chainHead = m_chainHead;
    uintptr_t ptr = reinterpret_cast<uintptr_t>(chainHead);
    *m_chainTail = m_chainTailCount | 0xff0000;
    Kernel::assert(!m_dmaCallback, "Only one GPU DMA transfer at a time is permitted");
    Kernel::assert((ptr & 3) == 0, "Unaligned DMA transfer");
    m_chainHead = m_chainTail = nullptr;
    m_fromISR = dmaCallback == DMA::FROM_ISR;
    m_dmaCallback = eastl::move(callback);
    uint32_t head = *chainHead;
    uint32_t count = head >> 24;
    head &= 0xffffff;
    if (count > (c_chainThreshold / 4)) {
        m_chainNext = head == 0xff0000 ? nullptr : reinterpret_cast<uint32_t *>(head & 0x7fffff);
        scheduleNormalDMA(ptr + 4, count);
    } else {
        scheduleChainedDMA(ptr);
    }
}

void psyqo::GPU::scheduleChainedDMA(uintptr_t head) {
    Kernel::assert((DMA_CTRL[DMA_GPU].CHCR & 0x01000000) == 0, "GPU DMA busy");
    while ((Hardware::GPU::Ctrl & uint32_t(0x10000000)) == 0)
        ;
    DMA_CTRL[DMA_GPU].MADR = head;
    eastl::atomic_signal_fence(eastl::memory_order_release);
    DMA_CTRL[DMA_GPU].CHCR = 0x01000401;
}

bool psyqo::GPU::isChainIdle() const {
    eastl::atomic_signal_fence(eastl::memory_order_acquire);
    return m_chainStatus == CHAIN_IDLE;
}

bool psyqo::GPU::isChainTransferring() const {
    eastl::atomic_signal_fence(eastl::memory_order_acquire);
    return m_chainStatus == CHAIN_TRANSFERRING;
}

bool psyqo::GPU::isChainTransferred() const {
    eastl::atomic_signal_fence(eastl::memory_order_acquire);
    return m_chainStatus == CHAIN_TRANSFERRED;
}

uintptr_t psyqo::GPU::armTimer(uint32_t deadline, eastl::function<void(uint32_t)> &&callback) {
    m_timers.emplace_back(eastl::move(callback), deadline, 0, 0, false);
    return reinterpret_cast<uintptr_t>(&m_timers.back());
}

uintptr_t psyqo::GPU::armPeriodicTimer(uint32_t interval, eastl::function<void(uint32_t)> &&callback) {
    m_timers.emplace_back(eastl::move(callback), m_currentTime + interval, interval, 0, true);
    return reinterpret_cast<uintptr_t>(&m_timers.back());
}

void psyqo::GPU::changeTimerPeriod(uintptr_t id, uint32_t period, bool reset) {
    for (auto &timer : m_timers) {
        if (reinterpret_cast<uintptr_t>(&timer) != id) continue;
        if (timer.period == period) continue;
        if (!timer.periodic) continue;
        if (reset) {
            timer.deadline = m_currentTime + period;
        } else {
            int32_t diff = period - timer.period;
            timer.deadline += diff;
        }
        timer.period = period;
        return;
    }
}

void psyqo::GPU::pauseTimer(uintptr_t id) {
    for (auto &timer : m_timers) {
        if (reinterpret_cast<uintptr_t>(&timer) != id) continue;
        if (timer.paused) return;
        timer.paused = true;
        timer.pausedRemaining = timer.deadline - m_currentTime;
        return;
    }
}

void psyqo::GPU::resumeTimer(uintptr_t id) {
    for (auto &timer : m_timers) {
        if (reinterpret_cast<uintptr_t>(&timer) != id) continue;
        if (!timer.paused) return;
        timer.paused = false;
        timer.deadline = m_currentTime + timer.pausedRemaining;
        return;
    }
}

void psyqo::GPU::cancelTimer(uintptr_t id) {
    for (auto it = m_timers.begin(); it != m_timers.end(); ++it) {
        if (reinterpret_cast<uintptr_t>(&*it) != id) continue;
        m_timers.erase(it);
        return;
    }
}

void psyqo::GPU::pumpCallbacks() {
    uint32_t lastHSyncCounter = m_lastHSyncCounter;
    uint32_t hsyncCounter = COUNTERS[1].value;
    if (hsyncCounter < lastHSyncCounter) {
        hsyncCounter += 0x10000;
    }
    uint32_t currentTime = m_currentTime = m_currentTime + (hsyncCounter - lastHSyncCounter) * US_PER_HBLANK;
    bool done = false;
    while (!done) {
        done = true;
        for (auto it = m_timers.begin(); it != m_timers.end(); it++) {
            auto &timer = *it;
            if (timer.paused) continue;
            if ((int32_t)(timer.deadline - currentTime) <= 0) {
                if (timer.periodic) {
                    timer.deadline += timer.period;
                }
                timer.callback(currentTime);
                if (!timer.periodic) {
                    m_timers.erase(it);
                }
                done = false;
                break;
            }
        }
    }
    Kernel::Internal::pumpCallbacks();
    m_lastHSyncCounter = hsyncCounter;
}

void psyqo::GPU::scheduleOTC(uint32_t *start, uint32_t count) { m_OTCs[m_parity].emplace_back(start, count); }
