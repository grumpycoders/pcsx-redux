/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "core/spulogger.h"

#include "core/psxemulator.h"
#include "core/r3000a.h"

void PCSX::SPULogger::logInternal(Kind kind, uint32_t address, uint32_t length, uint32_t value, uint8_t voice) {
    // Allocated on first use rather than at construction, so a session that never turns the
    // logger on never pays for the ring.
    if (m_events.size() != c_capacity) m_events.resize(c_capacity);

    Event ev;
    const auto &regs = g_emulator->m_cpu->m_regs;
    ev.cycle = regs.cycle;
    ev.pc = regs.pc;
    ev.address = address;
    ev.length = length;
    ev.value = value;
    ev.kind = kind;
    ev.voice = voice;

    if (m_count == c_capacity) {
        m_events[m_head] = ev;
        m_head = (m_head + 1) % c_capacity;
    } else {
        m_events[(m_head + m_count) % c_capacity] = ev;
        m_count++;
    }
    m_seen++;
}

void PCSX::SPULogger::clear() {
    m_head = 0;
    m_count = 0;
    m_seen = 0;
    m_clears++;
}

const char *PCSX::SPULogger::kindName(Kind kind) {
    switch (kind) {
        case Kind::DMAWrite:
            return "DMA write";
        case Kind::DMARead:
            return "DMA read";
        case Kind::PIOWrite:
            return "PIO write";
        case Kind::TransferAddr:
            return "Transfer addr";
        case Kind::VoiceStart:
            return "Voice start";
        case Kind::VoiceLoop:
            return "Voice loop";
        case Kind::KeyOn:
            return "Key on";
        case Kind::KeyOff:
            return "Key off";
        case Kind::ReverbAddr:
            return "Reverb addr";
    }
    return "?";
}

bool PCSX::SPULogger::isVoiceScoped(Kind kind) {
    switch (kind) {
        case Kind::VoiceStart:
        case Kind::VoiceLoop:
            return true;
        default:
            return false;
    }
}
