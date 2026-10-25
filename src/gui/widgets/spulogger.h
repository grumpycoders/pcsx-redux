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

#include <stdint.h>

#include <vector>

#include "core/spulogger.h"

namespace PCSX {

namespace Widgets {

class SPULogger {
  public:
    SPULogger(bool &show, bool &enabled) : m_show(show), m_enabled(enabled) {}
    void draw(PCSX::SPULogger *logger, const char *title);

    bool &m_show;
    // Capture state is deliberately independent of window visibility, and persisted: closing
    // the window while a game runs must not silently stop recording.
    bool &m_enabled;

  private:
    bool m_filterEnabled = false;
    // One bit per PCSX::SPULogger::Kind, all set: no filtering until asked.
    uint32_t m_kindMask = 0xffffffff;
    bool m_followTail = true;
    // Indices into the ring that survived the filter, rebuilt each frame and fed to the clipper.
    std::vector<uint32_t> m_visible;
};

}  // namespace Widgets

}  // namespace PCSX
