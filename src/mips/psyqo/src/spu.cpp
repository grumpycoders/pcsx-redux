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

#include "common/hardware/dma.h"
#include "common/hardware/spu.h"
#include "psyqo/kernel.hh"

constexpr uint16_t DUMMY_SAMPLE_POSITION = 0x1000;
alignas(4) constexpr uint8_t DUMMY_SAMPLE[] = {0x00, 0b101, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

namespace {

// Checks a transfer request, and resolves a block size of 0 to the largest one
// that divides dataSize evenly. Sizes are in bytes; the returned block size is
// always a multiple of a word, so it can be handed to the BCR math as is.
size_t validateTransfer(uint32_t spuAddress, const void* ramAddress, size_t dataSize, size_t blockSize) {
    using SPU = psyqo::SPU;
    psyqo::Kernel::assert((spuAddress % 8) == 0, "SPU DMA destination must be 8 bytes aligned");
    // Phrased as a subtraction so a wild spuAddress can't wrap the sum past the check.
    psyqo::Kernel::assert(spuAddress <= SPU::SOUND_RAM_SIZE && dataSize <= SPU::SOUND_RAM_SIZE - spuAddress,
                          "SPU DMA transfer runs past the end of sound RAM");
    psyqo::Kernel::assert((reinterpret_cast<uintptr_t>(ramAddress) & 3) == 0, "SPU DMA source must be 4 bytes aligned");
    psyqo::Kernel::assert(dataSize != 0 && (dataSize % SPU::ADPCM_BLOCK_SIZE) == 0,
                          "SPU DMA size must be a whole number of ADPCM blocks");
    if (blockSize == 0) {
        // dataSize is a multiple of ADPCM_BLOCK_SIZE, which is itself a power of
        // two no larger than MAX_DMA_BLOCK_SIZE, so this always terminates.
        blockSize = SPU::MAX_DMA_BLOCK_SIZE;
        while (dataSize % blockSize) blockSize >>= 1;
    }
    psyqo::Kernel::assert((blockSize % sizeof(uint32_t)) == 0 && blockSize != 0 && blockSize <= SPU::MAX_DMA_BLOCK_SIZE,
                          "Invalid SPU DMA block size");
    psyqo::Kernel::assert((dataSize % blockSize) == 0, "SPU DMA size isn't a multiple of the block size");
    psyqo::Kernel::assert((dataSize / blockSize) <= 0xffff, "SPU DMA block count doesn't fit in BCR");
    return blockSize;
}

// Points the SPU at spuAddress and programs the DMA channel, without starting it.
void setupTransfer(uint32_t spuAddress, const void* ramAddress, size_t dataSize, size_t blockSize) {
    SPU_CTRL &= ~(0b11 << 4);
    psyqo::Kernel::waitForStatus<uint16_t>(0b11 << 4, 0b00 << 4, &SPU_STATUS);
    SPU_CTRL |= 1 << 5;
    SPU_RAM_DTA = spuAddress / 8;
    psyqo::Kernel::waitForStatus<uint16_t>(1 << 5, 1 << 5, &SPU_STATUS);

    DPCR |= 1 << 19;
    DPCR &= ~(0b111 << 16);
    DPCR |= 0b100 << 16;
    DMA_CTRL[DMA_SPU].MADR = reinterpret_cast<uint32_t>(ramAddress);
    // The low half of BCR is the block size in words, the high half the number
    // of blocks, and the transfer is the product of the two.
    DMA_CTRL[DMA_SPU].BCR = (blockSize / sizeof(uint32_t)) | ((dataSize / blockSize) << 16);
}

}  // namespace

void psyqo::SPU::dmaWrite(const uint32_t spuAddress, const void* ramAddress, const size_t dataSize, size_t blockSize) {
    blockSize = validateTransfer(spuAddress, ramAddress, dataSize, blockSize);
    setupTransfer(spuAddress, ramAddress, dataSize, blockSize);
    DMA_CTRL[DMA_SPU].CHCR = 1 | 1 << 9 | 1 << 24;

    Kernel::waitForStatus<uint32_t>(1 << 24, 0 << 24, &DMA_CTRL[DMA_SPU].CHCR);
}

void psyqo::SPU::dmaWrite(const uint32_t spuAddress, const void* ramAddress, const size_t dataSize,
                          eastl::function<void()>&& callback, const DMA::DmaCallback dmaCallback) {
    Kernel::assert(m_initialized, "SPU::initAsync must be called before an asynchronous DMA transfer");
    // Guarding on the flag rather than on the callback, so that a transfer with
    // an empty callback still blocks a concurrent one.
    Kernel::assert(!m_transferPending, "Only one SPU DMA transfer at a time is permitted");
    size_t blockSize = validateTransfer(spuAddress, ramAddress, dataSize, 0);
    m_dmaCallback = eastl::move(callback);
    m_fromISR = dmaCallback == DMA::FROM_ISR;
    m_transferPending = true;
    setupTransfer(spuAddress, ramAddress, dataSize, blockSize);
    eastl::atomic_signal_fence(eastl::memory_order_release);
    DMA_CTRL[DMA_SPU].CHCR = 1 | 1 << 9 | 1 << 24;
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
        SPU_VOICES[channel].sampleRate = 0x1000;
        SPU_VOICES[channel].sampleStartAddr = DUMMY_SAMPLE_POSITION / 8;
        SPU_VOICES[channel].sampleRepeatAddr = DUMMY_SAMPLE_POSITION / 8;
    }

    SPU_KEY_ON_LOW = channelMask & 0xffff;
    SPU_KEY_ON_HIGH = (channelMask >> 16) & 0xffff;
}

void psyqo::SPU::initialize() {
    SBUS_DEV4_CTRL = 1 | 0b1110 << 4 | 1 << 8 | 1 << 12 | 1 << 13 | 0b1001 << 16 | 0 << 24 | 1 << 29;
    DPCR |= 1 << 19;

    SPU_CTRL = 0;

    SPU_VOL_MAIN_LEFT = 0x3fff;
    SPU_VOL_MAIN_RIGHT = 0x3fff;
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

    SPU_CTRL = 1 << 15 | 1 << 14 | 1 << 6;

    dmaWrite(DUMMY_SAMPLE_POSITION, &DUMMY_SAMPLE, sizeof(DUMMY_SAMPLE));

    silenceChannels(0xffffffff);
}

void psyqo::SPU::initAsync() {
    // The kernel already ran initialize() during startup, so all that's left is
    // to wire up the completion interrupt.
    Kernel::assert(!m_initialized, "SPU::initAsync called twice");
    m_initialized = true;
    m_dmaEventSlot = Kernel::registerDmaEvent(Kernel::DMA::SPU, [this]() {
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
        // Take the callback and clear the in-flight flag before running it, so
        // that a callback which queues the next transfer isn't rejected, and so
        // that the callback it installs doesn't get wiped afterwards.
        auto callback = eastl::move(m_dmaCallback);
        m_dmaCallback = nullptr;
        m_transferPending = false;
        if (!callback) return;
        if (m_fromISR) {
            callback();
        } else {
            Kernel::queueCallbackFromISR(eastl::move(callback));
        }
    });
    // Kernel::Internal::prepare zeroes DICR, so the completion interrupt has to
    // be armed here or the handler above will never run. Bits 16 to 22 are the
    // per channel enables, and the SPU is channel 4.
    uint32_t dicr = DICR;
    dicr &= 0xffffff;
    dicr |= 1 << 20;
    DICR = dicr;
}

void psyqo::SPU::playADPCM(const uint8_t channelId, const uint32_t spuRamAddress, const ChannelPlaybackConfig& config,
                           const bool hardCut) {
    Kernel::assert(channelId < 24, "Invalid SPU channel ID");
    Kernel::assert((spuRamAddress % 8) == 0, "ADPCM sample address must be 8 bytes aligned");
    Kernel::assert(spuRamAddress < SOUND_RAM_SIZE, "ADPCM sample address is past the end of sound RAM");
    if (hardCut) {
        if (channelId > 15) {
            SPU_KEY_OFF_HIGH = 1 << (channelId - 16);
        } else {
            SPU_KEY_OFF_LOW = 1 << (channelId);
        }
    }

    SPU_VOICES[channelId].volumeLeft = config.volumeLeft;
    SPU_VOICES[channelId].volumeRight = config.volumeRight;
    SPU_VOICES[channelId].sampleRate = config.sampleRate.value;
    SPU_VOICES[channelId].sampleStartAddr = spuRamAddress / 8;
    SPU_VOICES[channelId].adsrLo = config.adsr & 0xffff;
    SPU_VOICES[channelId].adsrHi = (config.adsr >> 16) & 0xffff;

    if (channelId > 15) {
        SPU_KEY_ON_HIGH = 1 << (channelId - 16);
    } else {
        SPU_KEY_ON_LOW = 1 << (channelId);
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
