/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include "psyqo/spu.hh"

#include <EASTL/atomic.h>

#include "EASTL/internal/atomic/atomic_memory_order.h"
#include "common/hardware/spu.h"

void psyqo::SPU::resetVoice(unsigned voiceID) {
    SPU_VOICES[voiceID].volumeLeft = 0;
    SPU_VOICES[voiceID].volumeRight = 0;
    SPU_VOICES[voiceID].sampleRate = 0;
    SPU_VOICES[voiceID].sampleStartAddr = 0;
    SPU_VOICES[voiceID].ad = 0x000f;
    SPU_VOICES[voiceID].currentVolume = 0;
    SPU_VOICES[voiceID].sampleRepeatAddr = 0;
    SPU_VOICES[voiceID].sr = 0x0000;
}

void psyqo::SPU::waitIdle() {
    do {
        for (unsigned c = 0; c < 256; c++) eastl::atomic_signal_fence(eastl::memory_order_relaxed);
    } while ((SPU_STATUS & 0x07ff) != 0);
}

void psyqo::SPU::reset() {
    SPU_VOL_MAIN_LEFT = 0x3800;
    SPU_VOL_MAIN_RIGHT = 0x3800;
    SPU_CTRL = 0;
    SPU_KEY_ON_LOW = 0;
    SPU_KEY_ON_HIGH = 0;
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    SPU_RAM_DTC = 4;
    SPU_VOL_CD_LEFT = 0;
    SPU_VOL_CD_RIGHT = 0;
    SPU_PITCH_MOD_LOW = 0;
    SPU_PITCH_MOD_HIGH = 0;
    SPU_NOISE_EN_LOW = 0;
    SPU_NOISE_EN_HIGH = 0;
    SPU_REVERB_EN_LOW = 0;
    SPU_REVERB_EN_HIGH = 0;
    SPU_VOL_EXT_LEFT = 0;
    SPU_VOL_EXT_RIGHT = 0;
    SPU_CTRL = 0x8000;

    for (unsigned i = 0; i < 24; i++) resetVoice(i);
}
