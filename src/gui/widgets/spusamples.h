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

#include <map>
#include <vector>

#include "core/spulogger.h"

namespace PCSX {

namespace Widgets {

// Sample map of sound RAM, and a waveform view of the selected sample. Start addresses come
// from the SPU logger's key-on entries, which are the only ground truth for where a sample
// begins. Everything else is derived from sound RAM: each sample is walked a block at a time
// until a block carries the loop-end flag, noting the loop-start flag on the way.
class SPUSamples {
  public:
    SPUSamples(bool& show) : m_show(show) {}
    void draw(PCSX::SPULogger* logger, const uint8_t* spuRam, const char* title);

    bool& m_show;

    struct Sample {
        uint32_t start = 0;
        uint32_t end = 0;        // one past the block carrying the loop-end flag
        uint32_t loop = 0;       // last block before the end with the loop-start flag
        bool hasLoop = false;    // a loop-start flag was seen
        bool repeats = false;    // the end block has the repeat flag
        bool truncated = false;  // ran off the end of sound RAM with no end flag
        uint32_t keyOns = 0;
        uint32_t voiceMask = 0;  // voices seen keying it on
    };

    // Walks sound RAM from `start`. A pure function of sound RAM.
    static Sample walk(const uint8_t* spuRam, uint32_t start);
    // Decodes a sample from its start, with the filter history cleared as key-on does.
    static void decode(const uint8_t* spuRam, const Sample& sample, std::vector<float>& out);

  private:
    void rebuild(PCSX::SPULogger* logger, const uint8_t* spuRam);

    std::map<uint32_t, Sample> m_samples;
    uint64_t m_lastSeen = ~uint64_t(0);
    uint64_t m_lastClears = 0;
    bool m_autoRefresh = true;
    bool m_selected = false;
    uint32_t m_selectedStart = 0;
    std::vector<float> m_waveform;
};

}  // namespace Widgets

}  // namespace PCSX
