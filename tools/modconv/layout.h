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

#include <algorithm>
#include <cmath>
#include <string>
#include <string_view>

#include "fmt/format.h"

namespace PCSX {
namespace ModConv {

// How a MOD sample is laid out in SPU memory. Lengths are in bytes of the MOD sample, which are also
// samples, since MOD samples are 8 bits.
//
// One-shot samples skip the first word: ProTracker clears it on load, and uses it as the idle loop once a
// non-looped sample is done playing, so it is silence and not part of the sound. The trailing silent loop
// block plays that role on the SPU.
//
// The SPU can only loop on whole 28-sample blocks, so looped samples are laid out as:
//   [pad zeros][sample start .. loop start][loop body]
// - front zeros are padded so that the loop start lands exactly on a block boundary;
// - the loop body is one loop period rounded to the nearest whole block, so the loop period is off by
//   up to 14 samples, which changes the pitch of the looped part of the sound;
// - anything after the loop end is never heard on a MOD player, so it is dropped.
// The first word is skipped like for one-shot samples, unless the loop starts at word 0, in which case
// it is part of the loop body and has to be kept.
// The loop fields written to the .hit file are the clamped loop, 0 and 1 for one-shot samples. modplayer
// derives skip and pad from them with the same formulas to compute 9xx sample offsets, so they are part
// of the .hit contract.
struct SampleLayout {
    bool hasLoop = false;
    unsigned loopStart = 0;   // bytes
    unsigned loopLength = 0;  // bytes, one MOD loop period
    unsigned skip = 2;
    unsigned pad = 0;
    unsigned body = 0;  // bytes of loop body written out
    bool exact = true;
    unsigned encodedLength = 0;
};

inline SampleLayout computeLayout(unsigned length, unsigned loopStart, unsigned loopLength) {
    SampleLayout l;
    // MOD loop fields are in words. A repeat length of 0 or 1 word means "no loop"; a loop starting
    // at word 0 is a regular loop, usually over the whole sample.
    l.hasLoop = loopLength > 1;
    // Some trackers write loops running past the end of the sample; clamp them to the sample end.
    if (l.hasLoop && (loopStart >= length)) l.hasLoop = false;
    if (l.hasLoop && ((loopStart + loopLength) > length)) {
        loopLength = length - loopStart;
        l.hasLoop = loopLength > 1;
    }
    if (length == 0) return l;
    if (!l.hasLoop) {
        l.encodedLength = ((length - 1) * 2 + 27) / 28 * 16 + 16;
        return l;
    }
    l.loopStart = loopStart * 2;
    l.loopLength = loopLength * 2;
    l.skip = loopStart == 0 ? 0 : 2;
    l.pad = (28 - (l.loopStart - l.skip) % 28) % 28;
    l.body = std::max(28u, (l.loopLength + 14) / 28 * 28);
    l.exact = l.body == l.loopLength;
    l.encodedLength = (l.pad + l.loopStart - l.skip + l.body) / 28 * 16;
    return l;
}

// Pitch change of the looped part of a sample, in cents: a longer loop period plays lower.
inline double loopPitchError(const SampleLayout& l) {
    return 1200.0 * std::log2(double(l.loopLength) / double(l.body));
}

// One line of the conversion warning for a sample whose loop period changed. sampleNumber is 1-based,
// like in trackers.
inline std::string loopWarning(unsigned sampleNumber, std::string_view name, const SampleLayout& l) {
    return fmt::format("  Sample {:2} [{}]: loop {} -> {} samples, {:+.1f} cents\n", sampleNumber, name, l.loopLength,
                       l.body, loopPitchError(l));
}

inline constexpr std::string_view c_loopWarningHeader =
    "Warning: the SPU loops on whole 28-sample blocks, so these loops were rounded, changing their pitch:\n";
inline constexpr std::string_view c_loopWarningFooter =
    "Converting with the XM converter, which comes with the XM player, keeps loops exact.\n";

}  // namespace ModConv
}  // namespace PCSX
