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

#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/gpu.hh"
#include "psyqo/hardware/cdrom.hh"
#include "psyqo/hardware/cpu.hh"
#include "psyqo/kernel.hh"

void psyqo::CDRomDevice::prepare() {
    Hardware::CPU::IMask.set(Hardware::CPU::IRQ::CDRom);
    Kernel::enableDma(Kernel::DMA::CDRom);
    eastl::function<void()> callback = [this]() {
        Hardware::CPU::IReg.clear(Hardware::CPU::IRQ::CDRom);
        irq();
    };
    if (Kernel::isKernelTakenOver()) {
        Kernel::queueIRQHandler(Kernel::IRQ::CDRom, eastl::move(callback));
    } else {
        m_event = Kernel::openEvent(EVENT_CDROM, 0x1000, EVENT_MODE_CALLBACK, eastl::move(callback));
        syscall_enableEvent(m_event);
    }
    Kernel::queuePsyqoBreakHandler([this](uint32_t code) {
        switch (code) {
            // Pause CDDA playback
            case 1:
            // Stop CDDA playback
            case 2:
                // If no action is in progress, it means we got
                // raced to the end of the track and/or disc, and
                // we should just ignore this.
                if (m_action == nullptr) return true;
                // If we aren't actually playing audio, that's
                // a fatal error.
                if (m_state != 100) return false;
                m_state = 101;
                eastl::atomic_signal_fence(eastl::memory_order_release);
                Hardware::CDRom::Command.send(code == 1 ? Hardware::CDRom::CDL::PAUSE : Hardware::CDRom::CDL::STOP);
                return true;
                // Get playback location
            case 3:
                // We got raced to the end of the track and/or disc, and we can't
                // properly handle this request. Just ignore it and let the caller
                // retry if they want to.
                if (m_action != nullptr) {
                    Kernel::queueCallbackFromISR([callback = eastl::move(m_locationCallback)]() { callback(nullptr); });
                    return true;
                }
                m_pendingGetLocation = true;
                eastl::atomic_signal_fence(eastl::memory_order_release);
                Hardware::CDRom::Command.send(Hardware::CDRom::CDL::GETLOCP);
                return true;
        }
        return false;
    });
}

psyqo::CDRomDevice::~CDRomDevice() { Kernel::abort("CDRomDevice can't be destroyed (yet)"); }

void psyqo::CDRomDevice::switchAction(ActionBase *action) {
    Kernel::assert(m_action == nullptr, "CDRomDevice can only have one action active at a given time");
    m_action = action;
}

void psyqo::CDRomDevice::ActionBase::queueCallbackFromISR(bool success) {
    Kernel::assert(!!m_device->m_callback, "CDRomDevice::queueCallbackFromISR() called with no callback");
    Kernel::queueCallbackFromISR([device = m_device, success]() { device->m_callback(success); });
}

void psyqo::CDRomDevice::irq() {
    Kernel::assert(m_action != nullptr, "CDRomDevice::irq() called with no action - spurious interrupt?");
    uint8_t cause = Hardware::CDRom::Cause;

    if (cause & 7) {
        Hardware::CDRom::Cause = 7;
    }

    if (cause & 0x18) {
        Hardware::CDRom::Cause = 0x18;
    }

    bool callCallback = false;
    Response response;
    while ((Hardware::CDRom::Ctrl.access() & 0x20) && (response.size() < 16)) {
        response.push_back(Hardware::CDRom::Response);
    }

#ifdef DEBUG_CDROM_RESPONSES
    if (m_blocking) {
        ramsyscall_printf("Got CD-Rom response:");
        for (auto byte : response) {
            ramsyscall_printf(" %02x", byte);
        }
        syscall_puts("\n");
    } else {
        Kernel::queueCallbackFromISR([response]() {
            ramsyscall_printf("Got CD-Rom response:");
            for (auto byte : response) {
                ramsyscall_printf(" %02x", byte);
            }
            syscall_puts("\n");
        });
    }
#endif

    switch (cause & 7) {
        case 1:
            callCallback = m_action->dataReady(response);
            break;
        case 2:
            callCallback = m_action->complete(response);
            break;
        case 3:
            callCallback = m_action->acknowledge(response);
            break;
        case 4:
            callCallback = m_action->end(response);
            break;
        case 5: {
            m_success = false;
            callCallback = true;
#ifdef DEBUG_CDROM_ERRORS
            m_callback = [callback = eastl::move(m_callback), name = m_action->name(),
                          response = eastl::move(response)](bool) {
                ramsyscall_printf("Got CD-Rom error during action %s:", name);
                for (auto byte : response) {
                    ramsyscall_printf(" %02x", byte);
                }
                syscall_puts("\n");
                callback(false);
            };
#endif
        } break;
        default:
            Kernel::abort("CDRomDevice::irq() invoked with unknown cause");
            break;
    }

    if (callCallback) {
        Kernel::assert(!!m_callback, "Wrong CDRomDevice state");
        m_action = nullptr;
        if (m_blocking) {
            actionComplete();
        } else {
            eastl::atomic_signal_fence(eastl::memory_order_acquire);
            Kernel::queueCallbackFromISR([this]() { actionComplete(); });
        }
    }
}

psyqo::CDRomDevice::BlockingAction::BlockingAction(CDRomDevice *device, GPU &gpu) : m_device(device), m_gpu(gpu) {
    device->m_blocking = true;
    Hardware::CPU::IMask.clear(Hardware::CPU::IRQ::CDRom);
    Hardware::CPU::flushWriteQueue();
}

psyqo::CDRomDevice::BlockingAction::~BlockingAction() {
    auto device = m_device;
    auto gpu = &m_gpu;
    while (device->m_state != 0) {
        if (Hardware::CPU::IReg.isSet(Hardware::CPU::IRQ::CDRom)) {
            Hardware::CPU::IReg.clear(Hardware::CPU::IRQ::CDRom);
            device->irq();
        }
        gpu->pumpCallbacks();
    }
    device->m_blocking = false;
    Hardware::CPU::IMask.set(Hardware::CPU::IRQ::CDRom);
}

void psyqo::CDRomDevice::actionComplete() {
    auto callback = eastl::move(m_callback);
    m_callback = nullptr;
    auto success = m_success;
    m_success = false;
    m_state = 0;
    callback(success);
}

void psyqo::CDRomDevice::ActionBase::setCallback(eastl::function<void(bool)> &&callback) {
    auto &deviceCallback = m_device->m_callback;
    Kernel::assert(!deviceCallback && m_device->m_state == 0, "Action setup called with pending action");
    m_device->m_callback = eastl::move(callback);
}
void psyqo::CDRomDevice::ActionBase::setSuccess(bool success) { m_device->m_success = success; }
bool psyqo::CDRomDevice::ActionBase::dataReady(const Response &) {
    Kernel::abort("Action::dataReady() not implemented - spurious interrupt?");
}
bool psyqo::CDRomDevice::ActionBase::complete(const Response &) {
    Kernel::abort("Action::complete() not implemented - spurious interrupt?");
}
bool psyqo::CDRomDevice::ActionBase::acknowledge(const Response &) {
    Kernel::abort("Action::acknowledge() not implemented - spurious interrupt?");
}
bool psyqo::CDRomDevice::ActionBase::end(const Response &) {
    Kernel::abort("Action::end() not implemented - spurious interrupt?");
}
