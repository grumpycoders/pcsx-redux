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

#include "common/hardware/dma.h"
#include "common/hardware/spu.h"
#include "psyqo/kernel.hh"

constexpr uint16_t DUMMY_SAMPLE_POSITION = 0x1000;
constexpr uint8_t DUMMY_SAMPLE_SIZE = 16;
alignas(4) constexpr uint8_t DUMMY_SAMPLE[] = {0x00, 0b101, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

void psyqo::SPU::dmaWrite(const uint32_t spuAddress, const void *ramAddress, const uint16_t dataSize,
                          const uint8_t blockSize) {
    Kernel::assert(blockSize % sizeof(uint32_t) == 0 && blockSize != 0 && blockSize <= 16, "Invalid DMA block size");
    SPU_CTRL &= ~(0b11 << 4);
    waitForStatus<uint16_t>(0b11 << 4, 0b00 << 4, &SPU_STATUS);
    SPU_CTRL |= 1 << 5;
    SPU_RAM_DTA = spuAddress / 8;
    waitForStatus<uint16_t>(1 << 5, 1 << 5, &SPU_STATUS);

    DPCR |= 1 << 19;
    DPCR &= ~(0b111 << 16);
    DPCR |= 0b100 << 16;
    DMA_CTRL[DMA_SPU].MADR = reinterpret_cast<uint32_t>(ramAddress);
    DMA_CTRL[DMA_SPU].BCR = blockSize | ((dataSize / blockSize) << 16);
    DMA_CTRL[DMA_SPU].CHCR = 1 | 1 << 9 | 1 << 24;

    waitForStatus<uint32_t>(1 << 24, 0 << 24, &DMA_CTRL[DMA_SPU].CHCR);
}

void psyqo::SPU::silenceChannels(const uint32_t channelMask) {
    SPU_KEY_OFF_LOW = channelMask & 0xffff;
    SPU_KEY_OFF_HIGH = (channelMask >> 16) & 0xffff;

    for (uint8_t channel = 0; channel < 24; channel++) {
        if (!((channelMask >> channel) & 1)) {
            continue;
        }
        SPU_VOICES[channel].volumeLeft = 0;
        SPU_VOICES[channel].volumeRight = 0;
        SPU_VOICES[channel].sampleRate = 0;
        SPU_VOICES[channel].sampleStartAddr = DUMMY_SAMPLE_POSITION / 8;
        SPU_VOICES[channel].sampleRepeatAddr = DUMMY_SAMPLE_POSITION / 8;
    }

    SPU_KEY_ON_LOW = channelMask & 0xffff;
    SPU_KEY_ON_HIGH = (channelMask >> 16) & 0xffff;
}

template <typename T>
bool psyqo::SPU::waitForStatus(const T mask, const T expected, const volatile T *value) {
    for (int timeout = 10000; timeout >= 0; timeout--) {
        if ((*value & mask) == expected) {
            return true;
        }
    }
    return false;
}

void psyqo::SPU::initialize() {
    SBUS_DEV4_CTRL = 1 | 0b1110 << 4 | 1 << 8 | 1 << 12 | 1 << 13 | 0b1001 << 16 | 0 << 24 | 1 << 29;
    DPCR |= 1 << 19;

    SPU_CTRL = 0;

    SPU_VOL_MAIN_LEFT = 0x7fff;
    SPU_VOL_MAIN_RIGHT = 0x7fff;
    SPU_REVERB_LEFT = 0;
    SPU_REVERB_RIGHT = 0;

    SPU_PITCH_MOD_LOW = 0;
    SPU_PITCH_MOD_HIGH = 0;
    SPU_NOISE_EN_LOW = 0;
    SPU_NOISE_EN_HIGH = 0;
    SPU_REVERB_EN_LOW = 0;
    SPU_REVERB_EN_HIGH = 0;
    SPU_REVERB_ADDR = 0xfffe;
    SPU_VOL_CD_LEFT = 0;
    SPU_VOL_CD_RIGHT = 0;
    SPU_VOL_EXT_LEFT = 0;
    SPU_VOL_EXT_RIGHT = 0;
    SPU_RAM_DTC = 4;

    dmaWrite(DUMMY_SAMPLE_POSITION, &DUMMY_SAMPLE, DUMMY_SAMPLE_SIZE, 4);

    SPU_CTRL = 1 << 15 | 1 << 14 | 1 << 6;

    silenceChannels(0xffffffff);
}

void psyqo::SPU::playADPCM(const uint8_t channelId, const uint16_t spuRamAddress, const ChannelPlaybackConfig &config,
                           const bool hardCut) {
    Kernel::assert(channelId < 24, "Invalid SPU channel ID");
    if (hardCut) {
        if (channelId > 15) {
            SPU_KEY_OFF_HIGH |= 1 << (channelId - 16);
        } else {
            SPU_KEY_OFF_LOW |= 1 << (channelId);
        }
    }

    SPU_VOICES[channelId].volumeLeft = config.volumeLeft;
    SPU_VOICES[channelId].volumeRight = config.volumeRight;
    SPU_VOICES[channelId].sampleRate = config.sampleRate.value;
    SPU_VOICES[channelId].sampleStartAddr = spuRamAddress / 8;
    SPU_VOICES[channelId].ad = config.adsr & 0xffff;
    SPU_VOICES[channelId].sr = (config.adsr >> 16) & 0xffff;

    if (channelId > 15) {
        SPU_KEY_ON_HIGH |= 1 << (channelId - 16);
    } else {
        SPU_KEY_ON_LOW |= 1 << (channelId);
    }
}

uint32_t psyqo::SPU::getNextFreeChannel() {
    for (uint8_t channel = 0; channel < 24; channel++) {
        if (SPU_VOICES[channel].currentVolume == 0) {
            return channel;
        }
    }
    return NO_FREE_CHANNEL;
}
