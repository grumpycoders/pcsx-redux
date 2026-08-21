/*

MIT License

Copyright (c) 2019 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once

#include "hwregs.h"

struct SPUVoice {
    uint16_t volumeLeft;
    uint16_t volumeRight;
    uint16_t sampleRate;
    uint16_t sampleStartAddr;
    uint16_t adsrLo;  // +0x08: release rate/mode, sustain rate/dir/mode
    uint16_t adsrHi;  // +0x0A: attack mode/rate, decay rate, sustain level
    uint16_t currentVolume;
    uint16_t sampleRepeatAddr;
};

#define SPU_VOICES ((volatile struct SPUVoice *)0x1f801c00)

// Reverb configuration area, 1F801DC0h..1F801DFFh (rev00..rev1F).
// Names match psx-spx: d* = SPU-RAM displacement/offset, m* = SPU-RAM
// src/dst address, v* = volume. All 16-bit.
struct SPUReverb {
    uint16_t dAPF1;    // +0x00 rev00 APF offset 1
    uint16_t dAPF2;    // +0x02 rev01 APF offset 2
    uint16_t vIIR;     // +0x04 rev02 reflection volume 1
    uint16_t vCOMB1;   // +0x06 rev03 comb volume 1
    uint16_t vCOMB2;   // +0x08 rev04 comb volume 2
    uint16_t vCOMB3;   // +0x0A rev05 comb volume 3
    uint16_t vCOMB4;   // +0x0C rev06 comb volume 4
    uint16_t vWALL;    // +0x0E rev07 reflection volume 2
    uint16_t vAPF1;    // +0x10 rev08 APF volume 1
    uint16_t vAPF2;    // +0x12 rev09 APF volume 2
    uint16_t mLSAME;   // +0x14 rev0A same-side reflect addr 1 left
    uint16_t mRSAME;   // +0x16 rev0B same-side reflect addr 1 right
    uint16_t mLCOMB1;  // +0x18 rev0C comb addr 1 left
    uint16_t mRCOMB1;  // +0x1A rev0D comb addr 1 right
    uint16_t mLCOMB2;  // +0x1C rev0E comb addr 2 left
    uint16_t mRCOMB2;  // +0x1E rev0F comb addr 2 right
    uint16_t dLSAME;   // +0x20 rev10 same-side reflect addr 2 left
    uint16_t dRSAME;   // +0x22 rev11 same-side reflect addr 2 right
    uint16_t mLDIFF;   // +0x24 rev12 diff-side reflect addr 1 left
    uint16_t mRDIFF;   // +0x26 rev13 diff-side reflect addr 1 right
    uint16_t mLCOMB3;  // +0x28 rev14 comb addr 3 left
    uint16_t mRCOMB3;  // +0x2A rev15 comb addr 3 right
    uint16_t mLCOMB4;  // +0x2C rev16 comb addr 4 left
    uint16_t mRCOMB4;  // +0x2E rev17 comb addr 4 right
    uint16_t dLDIFF;   // +0x30 rev18 diff-side reflect addr 2 left
    uint16_t dRDIFF;   // +0x32 rev19 diff-side reflect addr 2 right
    uint16_t mLAPF1;   // +0x34 rev1A APF addr 1 left
    uint16_t mRAPF1;   // +0x36 rev1B APF addr 1 right
    uint16_t mLAPF2;   // +0x38 rev1C APF addr 2 left
    uint16_t mRAPF2;   // +0x3A rev1D APF addr 2 right
    uint16_t vLIN;     // +0x3C rev1E input volume left
    uint16_t vRIN;     // +0x3E rev1F input volume right
};

#define SPU_REVERB ((volatile struct SPUReverb *)0x1f801dc0)

#define SPU_VOL_MAIN_LEFT HW_U16(0x1f801d80)
#define SPU_VOL_MAIN_RIGHT HW_U16(0x1f801d82)
#define SPU_REVERB_LEFT HW_U16(0x1f801d84)
#define SPU_REVERB_RIGHT HW_U16(0x1f801d86)
#define SPU_KEY_ON_LOW HW_U16(0x1f801d88)
#define SPU_KEY_ON_HIGH HW_U16(0x1f801d8a)
#define SPU_KEY_OFF_LOW HW_U16(0x1f801d8c)
#define SPU_KEY_OFF_HIGH HW_U16(0x1f801d8e)
#define SPU_PITCH_MOD_LOW HW_U16(0x1f801d90)
#define SPU_PITCH_MOD_HIGH HW_U16(0x1f801d92)
#define SPU_NOISE_EN_LOW HW_U16(0x1f801d94)
#define SPU_NOISE_EN_HIGH HW_U16(0x1f801d96)
#define SPU_REVERB_EN_LOW HW_U16(0x1f801d98)
#define SPU_REVERB_EN_HIGH HW_U16(0x1f801d9a)
#define SPU_REVERB_ADDR HW_U16(0x1f801da2)
// Sound RAM IRQ address (IRQ9). Triggers when a voice reads ADPCM data from
// this address; for stable IRQs, align to the 16-byte ADPCM block boundary.
#define SPU_IRQ_ADDR HW_U16(0x1f801da4)

#define SPU_RAM_DTA HW_U16(0x1f801da6)
#define SPU_CTRL HW_U16(0x1f801daa)
#define SPU_RAM_DTC HW_U16(0x1f801dac)
#define SPU_STATUS HW_U16(0x1f801dae)
#define SPU_VOL_CD_LEFT HW_U16(0x1f801db0)
#define SPU_VOL_CD_RIGHT HW_U16(0x1f801db2)
#define SPU_VOL_EXT_LEFT HW_U16(0x1f801db4)
#define SPU_VOL_EXT_RIGHT HW_U16(0x1f801db6)

static inline void muteSpu() {
    SPU_REVERB_RIGHT = 0;
    SPU_REVERB_LEFT = 0;
    SPU_VOL_MAIN_RIGHT = 0;
    SPU_VOL_MAIN_LEFT = 0;
}
