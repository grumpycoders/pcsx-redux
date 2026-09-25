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

#include <limits>

#include "gtest/gtest.h"
#include "spu/sdlaudio.h"

using PCSX::SPU::SDLAudio;

TEST(SPUSpeed, Realtime) {
    EXPECT_EQ(SDLAudio::effectiveSpeed(1, 1), 1);
    EXPECT_EQ(SDLAudio::effectiveSpeed(4, 1), 4);
}

TEST(SPUSpeed, TurboDoublesConfiguredSpeed) {
    EXPECT_EQ(SDLAudio::effectiveSpeed(1, 2), 2);
    EXPECT_EQ(SDLAudio::effectiveSpeed(3, 2), 6);
}

TEST(SPUSpeed, ReturningFromTurboRestoresConfiguredSpeed) {
    EXPECT_EQ(SDLAudio::effectiveSpeed(1, 2), 2);
    EXPECT_EQ(SDLAudio::effectiveSpeed(1, 1), 1);
}

TEST(SPUSpeed, NonPositiveConfiguredIsUnbounded) {
    EXPECT_EQ(SDLAudio::effectiveSpeed(0, 1), SDLAudio::kMaxSpeed);
    EXPECT_EQ(SDLAudio::effectiveSpeed(-5, 2), SDLAudio::kMaxSpeed);
}

TEST(SPUSpeed, ClampsWithoutOverflow) {
    EXPECT_EQ(SDLAudio::effectiveSpeed(SDLAudio::kMaxSpeed, 2), SDLAudio::kMaxSpeed);
    EXPECT_EQ(SDLAudio::effectiveSpeed(SDLAudio::kMaxSpeed - 1, 2), SDLAudio::kMaxSpeed);
    EXPECT_EQ(SDLAudio::effectiveSpeed(std::numeric_limits<int>::max(), 2), SDLAudio::kMaxSpeed);
    EXPECT_EQ(SDLAudio::effectiveSpeed(SDLAudio::kMaxSpeed, std::numeric_limits<int>::max()), SDLAudio::kMaxSpeed);
}

TEST(SPUSpeed, NonPositiveTurboIsIgnored) {
    EXPECT_EQ(SDLAudio::effectiveSpeed(2, 0), 2);
    EXPECT_EQ(SDLAudio::effectiveSpeed(2, -1), 2);
}
