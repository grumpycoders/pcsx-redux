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
    uint16_t ad;
    uint16_t sr;
    uint16_t currentVolume;
    uint16_t sampleRepeatAddr;
};

#define SPU_VOICES ((volatile struct SPUVoice *)0x1f801c00)

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

#define SPU_RAM_DTA HW_U16(0x1f801da6)
#define SPU_CTRL HW_U16(0x1f801daa)
#define SPU_RAM_DTC HW_U16(0x1f801dac)
#define SPU_STATUS HW_U16(0x1f801dae)
#define SPU_VOL_CD_LEFT HW_U16(0x1f801db0)
#define SPU_VOL_CD_RIGHT HW_U16(0x1f801db2)
#define SPU_VOL_EXT_LEFT HW_U16(0x1f801db4)
#define SPU_VOL_EXT_RIGHT HW_U16(0x1f801db6)

static __inline__ void muteSpu() {
    SPU_REVERB_RIGHT = 0;
    SPU_REVERB_LEFT = 0;
    SPU_VOL_MAIN_RIGHT = 0;
    SPU_VOL_MAIN_LEFT = 0;
}
