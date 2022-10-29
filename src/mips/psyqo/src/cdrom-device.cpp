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

#include "psyqo/cdrom-device.hh"

#include <EASTL/atomic.h>

#include "common/hardware/cdrom.h"
#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/kernel.hh"
#include "psyqo/msf.hh"

void psyqo::CDRomDevice::prepare() {
    IMASK = IMASK | IRQ_CDROM;
    Kernel::enableDma(Kernel::DMA::CDRom);
    m_event = Kernel::openEvent(EVENT_CDROM, 0x1000, EVENT_MODE_CALLBACK, [this]() { irq(); });
    syscall_setIrqAutoAck(2, 1);
    syscall_enableEvent(m_event);
}

psyqo::CDRomDevice::~CDRomDevice() { Kernel::abort("CDRomDevice can't be destroyed (yet)"); }

void psyqo::CDRomDevice::reset(eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "Only one read allowed at a time");
    Kernel::assert(m_action == NONE, "CDRom state machine is busy");
    m_callback = eastl::move(callback);
    m_action = RESET;
    eastl::atomic_signal_fence(eastl::memory_order_release);
    CDROM_REG0_UC = 1;
    CDROM_REG3_UC = 0x1f;
    CDROM_REG0_UC = 1;
    CDROM_REG2_UC = 0x1f;
    CDROM_REG0_UC = 0;
    CDROM_REG1_UC = CDL_INIT;
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleReset() {
    return TaskQueue::Task([this](auto task) { reset([task](bool success) { task->complete(success); }); });
}

void psyqo::CDRomDevice::readSectors(uint32_t sector, uint32_t count, void *buffer,
                                     eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "Only one action allowed at a time");
    Kernel::assert(m_action == NONE, "CDRom state machine is busy");
    m_callback = eastl::move(callback);
    m_action = SETLOC;
    m_count = count;
    m_ptr = reinterpret_cast<uint8_t *>(buffer);
    eastl::atomic_signal_fence(eastl::memory_order_release);
    MSF msf(sector + 150);
    uint8_t bcd[3];
    msf.toBCD(bcd);
    CDROM_REG0_UC = 0;
    CDROM_REG2_UC = bcd[0];
    CDROM_REG2_UC = bcd[1];
    CDROM_REG2_UC = bcd[2];
    CDROM_REG1_UC = CDL_SETLOC;
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleReadSectors(uint32_t sector, uint32_t count, void *buffer) {
    m_count = count;
    m_ptr = reinterpret_cast<uint8_t *>(buffer);
    return TaskQueue::Task([this, sector](auto task) {
        readSectors(sector, m_count, m_ptr, [task](bool success) { task->complete(success); });
    });
}

void psyqo::CDRomDevice::irq() {
    CDROM_REG0_UC = 1;
    uint8_t irqReason = CDROM_REG3_UC;

    if (irqReason & 7) {
        CDROM_REG0_UC = 1;
        CDROM_REG3_UC = 7;
    }

    if (irqReason & 0x18) {
        CDROM_REG0_UC = 1;
        CDROM_REG3_UC = irqReason & 0x18;
    }

    switch (irqReason & 7) {
        case 1:
            dataReady();
            break;
        case 2:
            complete();
            break;
        case 3:
            acknowledge();
            break;
        case 4:
            end();
            break;
        case 5:
            discError();
            break;
    }
}

void psyqo::CDRomDevice::dataReady() {
    uint8_t status = CDROM_REG1_UC;
    CDROM_REG0_UC = 0;
    CDROM_REG0_UC;
    CDROM_REG3_UC = 0;
    CDROM_REG3_UC;
    CDROM_REG0_UC = 0;
    CDROM_REG3_UC = 0x80;
    SBUS_DEV5_CTRL = 0x20943;
    SBUS_COM_CTRL = 0x132c;
    eastl::atomic_signal_fence(eastl::memory_order_acquire);
    DMA_CTRL[DMA_CDROM].MADR = reinterpret_cast<uintptr_t>(m_ptr);
    DMA_CTRL[DMA_CDROM].BCR = 512 | 0x10000;
    DMA_CTRL[DMA_CDROM].CHCR = 0x11000000;
    m_ptr += 2048;
    if (--m_count == 0) {
        m_action = PAUSE;
        CDROM_REG0 = 0;
        CDROM_REG1 = CDL_PAUSE;
    }
    eastl::atomic_signal_fence(eastl::memory_order_release);
}

void psyqo::CDRomDevice::complete() {
    switch (m_action) {
        case RESET:
        case PAUSE:
            eastl::atomic_signal_fence(eastl::memory_order_acquire);
            Kernel::assert(!!m_callback, "Wrong CDRomDevice state");
            Kernel::queueCallbackFromISR([this]() {
                auto callback = eastl::move(m_callback);
                m_action = NONE;
                callback(true);
            });
            break;
        default:
            Kernel::abort("CDRomDevice::complete() called in wrong state");
            break;
    }
}

void psyqo::CDRomDevice::acknowledge() {
    uint8_t status = CDROM_REG1;
    switch (m_action) {
        case RESET:
            break;
        case SETLOC:
            m_action = SETMODE;
            CDROM_REG0_UC = 0;
            CDROM_REG2_UC = 0x80;
            CDROM_REG1_UC = CDL_SETMODE;
            break;
        case SETMODE:
            m_action = READ;
            CDROM_REG0_UC = 0;
            CDROM_REG1_UC = CDL_READN;
            break;
        case READ:
            break;
        case PAUSE:
            break;
        default:
            Kernel::abort("Not implemented");
            break;
    }
}

void psyqo::CDRomDevice::end() { Kernel::abort("Not implemented"); }

void psyqo::CDRomDevice::discError() {
    eastl::atomic_signal_fence(eastl::memory_order_acquire);
    Kernel::assert(!!m_callback, "Wrong CDRomDevice state");
    Kernel::queueCallbackFromISR([this]() {
        auto callback = eastl::move(m_callback);
        m_action = NONE;
        callback(false);
    });
}
