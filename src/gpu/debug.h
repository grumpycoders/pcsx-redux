/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include <functional>
#include <string>
#include <vector>

#include "core/system.h"

namespace PCSX {

namespace GPU {

namespace Debug {

class Command {
  public:
    ~Command() {}
    virtual std::string title() = 0;
};

}  // namespace Debug

class Debugger {
  public:
    Debugger(bool& show) : m_show(show) {}
    void show();

    void nextFrame() {
        if (m_breakOnFrame) {
            if (m_breakOnNonEmptyFrame) {
                if (!m_currentFrameEvents.empty()) g_system->pause();
            } else {
                g_system->pause();
            }
        }
        m_lastFrameEvents.clear();
        m_currentFrameEvents.swap(m_lastFrameEvents);
    }

    void addEvent(std::function<Debug::Command*()> commandGenerator, bool isInvalidOrEmpty = false) {
        if (!m_frameCapture) return;
        if (isInvalidOrEmpty && !m_captureInvalidAndEmpty) return;
        m_currentFrameEvents.emplace_back(commandGenerator());
    }

  private:
    bool& m_show;
    bool m_frameCapture = false;
    bool m_captureInvalidAndEmpty = false;
    bool m_breakOnFrame = false;
    bool m_breakOnNonEmptyFrame = false;
    std::vector<std::unique_ptr<Debug::Command>> m_currentFrameEvents;
    std::vector<std::unique_ptr<Debug::Command>> m_lastFrameEvents;
};

namespace Debug {
class Invalid : public Command {
  public:
    Invalid(const char* reason) : m_reason(reason) {}
    std::string title() final { return m_reason; }

  private:
    std::string m_reason;
};

class VRAMRead : public Command {
  public:
    VRAMRead(uint32_t to, int size, int16_t x, int16_t y, int16_t width, int16_t height)
        : m_to(to), m_size(size), m_x(x), m_y(y), m_width(width), m_height(height) {}
    std::string title() final;

  private:
    uint32_t m_to;
    int m_size;
    int16_t m_x, m_y, m_width, m_height;
};

class VRAMWrite : public Command {
  public:
    VRAMWrite(uint32_t from, int size, int16_t x, int16_t y, int16_t width, int16_t height)
        : m_from(from), m_size(size), m_x(x), m_y(y), m_width(width), m_height(height) {}
    std::string title() final;

  private:
    uint32_t m_from;
    int m_size;
    int16_t m_x, m_y, m_width, m_height;
};

}  // namespace Debug

}  // namespace GPU

}  // namespace PCSX
