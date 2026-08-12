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

#pragma once

#include "support/network.h"

namespace PCSX {

class GUI;

namespace Widgets {

// The network services used to be a flat run of checkboxes buried in the
// emulation configuration window, with no indication anywhere of whether a
// server was actually listening or a client actually connected. A failed bind
// left the checkbox ticked and said nothing at all.
class Network {
  public:
    Network(bool& show) : m_show(show) {}
    bool draw(GUI* gui, const char* title);

    bool& m_show;

  private:
    // Grey stopped, amber connecting, green up, red failed. Returns the width
    // consumed so the rows line up.
    void drawStatus(const PCSX::Network::Endpoint* endpoint);
    // Shared row furniture: bullet, name, state, and a restart button that is
    // only live when there is something to restart.
    bool drawEndpointHeader(PCSX::Network::Endpoint* endpoint, bool enabled);
};

}  // namespace Widgets

}  // namespace PCSX
