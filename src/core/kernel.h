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

#pragma once

#include <stdint.h>

#include <string>
#include <vector>

namespace PCSX {

namespace Kernel {

namespace Events {

class Event {
  public:
    Event(const uint32_t* psxMemory, uint32_t eventId);
    Event(const uint32_t* psxMemory, uint32_t classId, uint16_t spec);
    Event(const Event&) = default;
    Event(Event&&) = default;
    bool isValid() const { return m_valid; }
    uint32_t getId() const { return m_id; }
    const std::string& getClass() const { return m_class; }
    const std::string& getSpec() const { return m_spec; }
    const std::string& getMode() const { return m_mode; }
    const std::string& getFlag() const { return m_flag; }
    uint32_t getCB() const { return m_cb; }

    static std::string resolveClass(uint32_t classId);
    static std::string resolveSpec(uint16_t spec);
    static std::string resolveMode(uint16_t mode);
    static std::string resolveFlag(uint16_t flag);

  private:
    int findEvent(const uint32_t* psxMemory, uint32_t classId, uint16_t spec);
    void set(const uint32_t* psxMemory, int id);
    bool m_valid = false;
    uint32_t m_id = 0;
    std::string m_class;
    std::string m_spec;
    std::string m_mode;
    std::string m_flag;
    uint32_t m_cb = 0;
};

std::vector<Event> getAllEvents(const uint32_t* psxMemory);
int getFirstFreeEvent(const uint32_t* psxMemory);

}  // namespace Events

}  // namespace Kernel

}  // namespace PCSX
