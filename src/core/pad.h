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

#include <stdio.h>

#include "json.hpp"
#include "lua/luawrapper.h"

using json = nlohmann::json;

namespace PCSX {

class GUI;

class Pads {
  public:
    enum class Port { Port1 = 0, Port2 };

    virtual ~Pads() = default;

    virtual void init() = 0;
    virtual void shutdown() = 0;
    // Starts an access to the device at address on port: 1 is the pad plugged into the port, or slot A of a
    // multitap there, and 2 to 4 are multitap slots B to D. Returns false when nothing answers the address,
    // and otherwise sets reply to the first byte the device sends.
    virtual bool startPoll(Port port, uint8_t address, uint8_t& reply) = 0;
    // Whether a multitap is plugged into port, which makes addresses 2 to 4 answer.
    virtual bool hasMultitap(Port port) = 0;
    virtual uint8_t poll(uint8_t value, Port port, uint32_t& padState) = 0;

    virtual json getCfg() = 0;
    virtual void setCfg(const json& j) = 0;
    // Rewrites keyboard bindings saved by the GLFW builds as SDL scancodes.
    // Returns true if the pad's config was migrated.
    static bool migrateKeyboardBindings(json& pad);
    virtual void setDefaults() = 0;
    virtual bool configure(PCSX::GUI* gui) = 0;

    virtual void reset() = 0;

    virtual void setLua(PCSX::Lua L) = 0;

    virtual bool isPadConnected(int pad) = 0;

    bool m_showCfg = false;

    enum {
        PAD_STATE_IDLE = 0,
        PAD_STATE_READ_COMMAND = 1,
        PAD_STATE_READ_DATA = 2,
        PAD_STATE_BAD_COMMAND = 3,
    };

    static Pads* factory();
};

}  // namespace PCSX
