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

// Envelope traces against silicon (SCPH-1001 and SCPH-5501, ENVX polled every ~10us):
// key-on with a linear attack at rate 0 (+0x3800 per sample, peak in three samples),
// decay rate D, sustain level SL, a frozen sustain rate (0x7f) so whatever level the
// decay leaves is held. The decay compares the level against SL only on samples
// where a step lands, so a slow decay always takes its first step.

#include <stdint.h>

#include <vector>

#include "gtest/gtest.h"
#include "spu/adsr.h"

namespace {

using PCSX::SPU::AdsrEnvelope;

constexpr int c_peakSample = 2;  // 0x3800, 0x7000, 0x7fff
constexpr int c_holdSamples = 2000;

void program(AdsrEnvelope &env, int sustainLevel, int decayRate) {
    auto &ex = env.ex();
    ex.get<PCSX::SPU::exAttackModeExp>().value = 0;
    ex.get<PCSX::SPU::exAttackRate>().value = 0;
    ex.get<PCSX::SPU::exDecayRate>().value = decayRate;
    ex.get<PCSX::SPU::exSustainLevel>().value = sustainLevel;
    ex.get<PCSX::SPU::exSustainModeExp>().value = 0;
    ex.get<PCSX::SPU::exSustainIncrease>().value = 0;
    ex.get<PCSX::SPU::exSustainRate>().value = 0x7f;
    ex.get<PCSX::SPU::exReleaseModeExp>().value = 0;
    ex.get<PCSX::SPU::exReleaseRate>().value = 0;
    env.keyOn();
}

// One ENVX value per sample from key-on. When phase is not negative, the step counter
// is set to it on the peak sample, right as the decay takes over.
std::vector<int> trace(int sustainLevel, int decayRate, int phase = -1) {
    AdsrEnvelope env;
    program(env, sustainLevel, decayRate);
    std::vector<int> out;
    bool channelOn = true;
    for (int i = 0; i <= c_peakSample + c_holdSamples; i++) {
        out.push_back(env.step(false, channelOn));
        if (i == c_peakSample && phase >= 0) env.ex().get<PCSX::SPU::exEnvelopeVolF>().value = phase;
    }
    return out;
}

// Run-length view: the distinct successive values.
std::vector<int> changes(const std::vector<int> &t) {
    std::vector<int> out;
    for (int v : t) {
        if (out.empty() || out.back() != v) out.push_back(v);
    }
    return out;
}

int lastChange(const std::vector<int> &t) {
    int last = 0;
    for (int i = 1; i < static_cast<int>(t.size()); i++) {
        if (t[i] != t[i - 1]) last = i;
    }
    return last;
}

}  // namespace

TEST(SPUAdsr, FastDecayToSustain15) {
    const auto t = trace(15, 0);
    EXPECT_EQ(changes(t), (std::vector<int>{0x3800, 0x7000, 0x7fff, 0x3fff}));
    EXPECT_EQ(lastChange(t), c_peakSample + 1);
}

TEST(SPUAdsr, FastDecayToSustain14) {
    const auto t = trace(14, 0);
    EXPECT_EQ(changes(t), (std::vector<int>{0x3800, 0x7000, 0x7fff, 0x3fff}));
    EXPECT_EQ(lastChange(t), c_peakSample + 1);
}

TEST(SPUAdsr, SlowestDecayStepsOnceAtSustain15) {
    // The decay rate 15 counter steps every 16 samples; silicon holds 0x7fff for a
    // varying part of that period, then takes one step and stops at 0x7ff7.
    const auto natural = trace(15, 15);
    EXPECT_EQ(changes(natural), (std::vector<int>{0x3800, 0x7000, 0x7fff, 0x7ff7}));
    EXPECT_LE(lastChange(natural), c_peakSample + 16);
    for (int phase = 0; phase < 16; phase++) {
        const auto t = trace(15, 15, phase);
        EXPECT_EQ(changes(t), (std::vector<int>{0x3800, 0x7000, 0x7fff, 0x7ff7})) << "phase " << phase;
        EXPECT_EQ(lastChange(t), c_peakSample + 16 - phase) << "phase " << phase;
    }
}

TEST(SPUAdsr, MidDecaySettlesAtSustain14) {
    // Silicon ENVX sequence, one step per sample, settling ~0.75ms after the peak.
    const std::vector<int> silicon = {0x3800, 0x7000, 0x7fff, 0x7fbf, 0x7f7f, 0x7f3f, 0x7eff, 0x7ebf, 0x7e7f,
                                      0x7e3f, 0x7dff, 0x7dc0, 0x7d81, 0x7d42, 0x7d03, 0x7cc4, 0x7c85, 0x7c46,
                                      0x7c07, 0x7bc8, 0x7b8a, 0x7b4c, 0x7b0e, 0x7ad0, 0x7a92, 0x7a54, 0x7a16,
                                      0x79d8, 0x799b, 0x795e, 0x7921, 0x78e4, 0x78a7, 0x786a, 0x782d, 0x77f0};
    const auto t = trace(14, 8);
    EXPECT_EQ(changes(t), silicon);
    EXPECT_EQ(lastChange(t), c_peakSample + 33);
}

TEST(SPUAdsr, MidDecayStepsOnceAtSustain15) {
    const auto t = trace(15, 8);
    EXPECT_EQ(changes(t), (std::vector<int>{0x3800, 0x7000, 0x7fff, 0x7fbf}));
    EXPECT_EQ(lastChange(t), c_peakSample + 1);
}
