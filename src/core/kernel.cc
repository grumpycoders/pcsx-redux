/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "core/kernel.h"

#include <string>

#include "core/psxmem.h"
#include "fmt/format.h"
#include "magic_enum/include/magic_enum.hpp"

enum class Hw {
    VBLANK = 0x00000001,
    GPU = 0x00000002,
    CDROM = 0x00000003,
    DMA = 0x00000004,
    RTC0 = 0x00000005,
    RTC1 = 0x00000006,
    RTC2 = 0x00000007,
    PADS = 0x00000008,
    SPU = 0x00000009,
    PIO = 0x0000000a,
    SIO = 0x0000000b,
    CARD = 0x00000011,
};

enum class Sw {
    BU = 0x00000001,
};

int PCSX::Kernel::Events::Event::findEvent(IO<File> memory, uint32_t classId, uint16_t spec) {
    uint32_t eventsPtr = memory->readAt<uint32_t>(0x48 * 4);
    uint32_t eventsCount = memory->readAt<uint32_t>(0x49 * 4);
    eventsPtr &= 0x1fffffff;
    eventsPtr >>= 2;
    eventsCount /= 28;

    for (unsigned i = 0; i < eventsCount; i++) {
        memory->rSeek(memory->readAt<uint32_t>(eventsPtr + i * 7 * 4));

        uint32_t evtClassId = memory->read<uint32_t>();
        uint32_t flag = memory->read<uint32_t>();
        uint32_t evtSpec = memory->read<uint32_t>();

        if ((classId == evtClassId) && (spec == evtSpec) && (flag != 0)) return i;
    }

    return -1;
}

void PCSX::Kernel::Events::Event::set(IO<File> memory, int id) {
    uint32_t eventsPtr = memory->readAt<uint32_t>(0x48 * 4);
    eventsPtr &= 0x1fffffff;
    eventsPtr >>= 2;
    id &= 0xffff;

    memory->rSeek(memory->readAt<uint32_t>(eventsPtr + id * 7 * 4));

    m_class = memory->read<uint32_t>();
    m_flag = memory->read<uint32_t>();
    m_spec = memory->read<uint32_t>();
    m_mode = memory->read<uint32_t>();
    m_cb = memory->read<uint32_t>();
}

std::string PCSX::Kernel::Events::Event::resolveClass(uint32_t classId) {
    switch (classId & 0xff000000) {
        case 0xf0000000: {
            auto hw = magic_enum::enum_cast<Hw>(classId & 0x00ffffff);
            if (hw.has_value()) return "Hw::" + std::string{magic_enum::enum_name(hw.value())};
            break;
        }
        case 0xf4000000: {
            auto sw = magic_enum::enum_cast<Sw>(classId & 0x00ffffff);
            if (sw.has_value()) return "Sw::" + std::string{magic_enum::enum_name(sw.value())};
            break;
        }
    }

    return fmt::format("{:08x}", classId);
}

std::string PCSX::Kernel::Events::Event::resolveSpec(uint16_t spec) { return fmt::format("{:04x}", spec); }

std::string PCSX::Kernel::Events::Event::resolveMode(uint16_t mode) {
    switch (mode) {
        case 0x1000:
            return "CB";
        case 0x2000:
            return "IMM";
        default:
            return fmt::format("U{:04x}", mode);
    }
}

std::string PCSX::Kernel::Events::Event::resolveFlag(uint16_t flag) {
    switch (flag) {
        case 0x0000:
            return "FREE";
        case 0x1000:
            return "DISABLED";
        case 0x2000:
            return "ENABLED";
        case 0x4000:
            return "PENDING";
        default:
            return fmt::format("U{:04x}", flag);
    }
}

PCSX::Kernel::Events::Event::Event(IO<File> memory, uint32_t eventId) {
    uint32_t eventsPtr = memory->readAt<uint32_t>(0x48 * 4);
    uint32_t eventsCount = memory->readAt<uint32_t>(0x49 * 4);
    eventsCount /= 28;

    uint32_t segment = eventsPtr & 0xe0000000;
    if ((segment != 0x00000000) && (segment != 0x80000000) && (segment != 0xa0000000))
        return;  // events table not in any known segment

    eventsPtr &= 0x1fffffff;
    if (eventsPtr >= 65536) return;  // events table not in kernel memory

    if ((eventId & 0xffff0000) != 0xf1000000) return;  // not an eventId

    m_id = eventId;
    eventId &= 0x0000ffff;
    if (eventId >= eventsCount) return;  // eventId too high

    m_valid = true;
    set(memory, eventId);
}

PCSX::Kernel::Events::Event::Event(IO<File> memory, uint32_t classId, uint16_t spec) {
    uint32_t eventsPtr = memory->readAt<uint32_t>(0x48 * 4);
    uint32_t segment = eventsPtr & 0xe0000000;
    if ((segment != 0x00000000) && (segment != 0x80000000) && (segment != 0xa0000000))
        return;  // events table not in any known segment

    eventsPtr &= 0x1fffffff;
    if (eventsPtr >= 65536) return;  // events table not in kernel memory

    int id = findEvent(memory, classId, spec);
    if (id < 0) return;

    set(memory, id);
}

std::vector<PCSX::Kernel::Events::Event> PCSX::Kernel::Events::getAllEvents(IO<File> memory) {
    uint32_t eventsPtr = memory->readAt<uint32_t>(0x48 * 4);
    uint32_t eventsCount = memory->readAt<uint32_t>(0x49 * 4);
    eventsPtr &= 0x1fffffff;
    eventsPtr >>= 2;
    eventsCount /= 28;

    std::vector<Event> ret;
    ret.reserve(eventsCount);

    for (uint32_t i = 0; i < eventsCount; i++) {
        Event ev{memory, i | 0xf1000000};
        if (ev.isValid()) ret.push_back(std::move(ev));
    }

    return ret;
}

int PCSX::Kernel::Events::getFirstFreeEvent(IO<File> memory) {
    uint32_t eventsPtr = memory->readAt<uint32_t>(0x48 * 4);
    uint32_t eventsCount = memory->readAt<uint32_t>(0x49 * 4);
    eventsPtr &= 0x1fffffff;
    eventsPtr >>= 2;
    eventsCount /= 28;

    std::vector<Event> ret;
    ret.reserve(eventsCount);

    for (uint32_t i = 0; i < eventsCount; i++) {
        memory->rSeek(memory->readAt<uint32_t>(eventsPtr + i * 7 * 4));

        memory->skip<uint32_t>();
        uint32_t flag = memory->read<uint32_t>();

        flag = SWAP_LE32(flag);

        if (flag == 0) return i;
    }

    return -1;
}
