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

#pragma once

#include <EASTL/functional.h>

#include "psyqo/fixed-point.hh"
#include "psyqo/kernel.hh"

namespace psyqo {

class SPU {
  public:
    /**
     * @brief The size of the SPU's sound RAM, in bytes.
     *
     * @details Voice start and repeat addresses are stored as `address / 8` in
     * a 16 bit register, which covers exactly this range and not one byte more.
     */
    static constexpr uint32_t SOUND_RAM_SIZE = 512 * 1024;

    /**
     * @brief The size of a single ADPCM block, in bytes.
     *
     * @details An ADPCM block is a two byte header followed by 28 samples
     * stored as 4 bit nibbles. The SPU only ever addresses sound RAM in whole
     * blocks, so every transfer into it is a multiple of this.
     */
    static constexpr size_t ADPCM_BLOCK_SIZE = 16;

    /**
     * @brief The largest DMA block size the SPU will accept, in bytes.
     *
     * @details The block size field of `BCR` counts words, and the SPU's fifo
     * tops out at 16 of them.
     */
    static constexpr size_t MAX_DMA_BLOCK_SIZE = 16 * sizeof(uint32_t);

    /**
     * @brief Resets the SPU to a known, silent state.
     *
     * @details The kernel calls this during application startup, so there is
     * normally no reason to call it again.
     */
    static void initialize();

    /**
     * @brief Enables asynchronous DMA transfers for this SPU object.
     *
     * @details Registers the SPU's DMA completion handler and arms the
     * corresponding interrupt, which is what lets the callback taking overload
     * of `dmaWrite` ever complete. Call it once, during application start.
     */
    void initAsync();

    /**
     * @brief Silences the given channels.
     *
     * @param channelMask A bitmask of the channels to silence.
     */
    static void silenceChannels(uint32_t channelMask);

    /**
     * @brief Synchronously uploads data to the SPU's sound RAM.
     *
     * @details Blocks until the transfer completes. All sizes are in bytes.
     *
     * @param spuAddress The destination address in sound RAM. Must be 8 byte
     * aligned, and the transfer has to fit within `SOUND_RAM_SIZE`.
     * @param ramAddress The source address in main RAM. Must be 4 byte aligned.
     * @param dataSize The number of bytes to transfer. Must be a non-zero
     * multiple of `ADPCM_BLOCK_SIZE`.
     * @param blockSize The DMA block size in bytes, or 0 to pick the largest
     * one dividing `dataSize`. Must be a multiple of 4 and no larger than
     * `MAX_DMA_BLOCK_SIZE`.
     */
    static void dmaWrite(uint32_t spuAddress, const void* ramAddress, size_t dataSize, size_t blockSize = 0);

    /**
     * @brief Asynchronously uploads data to the SPU's sound RAM.
     *
     * @details Returns as soon as the transfer has started, and requires
     * `initAsync` to have been called. Only one transfer may be in flight at a
     * time, but `callback` is free to start the next one.
     *
     * @param spuAddress The destination address in sound RAM. Must be 8 byte
     * aligned, and the transfer has to fit within `SOUND_RAM_SIZE`.
     * @param ramAddress The source address in main RAM. Must be 4 byte aligned,
     * and has to stay alive until the callback fires.
     * @param dataSize The number of bytes to transfer. Must be a non-zero
     * multiple of `ADPCM_BLOCK_SIZE`.
     * @param callback The function to call once the transfer has completed.
     * @param dmaCallback Whether to call it from the interrupt handler, or from
     * the main loop.
     */
    void dmaWrite(uint32_t spuAddress, const void* ramAddress, size_t dataSize, eastl::function<void()>&& callback,
                  DMA::DmaCallback dmaCallback = DMA::FROM_MAIN_LOOP);

    struct ChannelPlaybackConfig {
        FixedPoint<12, uint16_t> sampleRate;
        uint16_t volumeLeft, volumeRight;
        uint32_t adsr;
    };

    /**
     * @brief Starts playing an ADPCM sample on the given channel.
     *
     * @param channelId The channel to play on, 0 to 23.
     * @param spuRamAddress The address of the sample in sound RAM. Must be 8
     * byte aligned and within `SOUND_RAM_SIZE`.
     * @param config The volume, sample rate and ADSR settings to use.
     * @param hardCut Whether to key the channel off before keying it back on.
     */
    static void playADPCM(uint8_t channelId, uint32_t spuRamAddress, const ChannelPlaybackConfig& config, bool hardCut);
    static uint32_t getNextFreeChannel();

    static constexpr uint32_t NO_FREE_CHANNEL = 0xffffffff;
    static constexpr uint32_t BASE_SAMPLE_RATE = 44100;
    static constexpr uint16_t BASE_ALLOC_ADDR = 0x1010;

  private:
    eastl::function<void()> m_dmaCallback = nullptr;
    unsigned m_dmaEventSlot = 0;
    bool m_transferPending = false;
    bool m_fromISR = false;
    bool m_initialized = false;
};

}  // namespace psyqo
