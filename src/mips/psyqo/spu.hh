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

#include "fixed-point.hh"

namespace psyqo {

class SPU {
  public:
    static void initialize();
    static void silenceChannels(uint32_t channelMask);
    static void dmaWrite(uint32_t spuAddress, const void *ramAddress, uint16_t dataSize, uint8_t blockSize);

    struct ChannelPlaybackConfig {
        FixedPoint<12, uint16_t> sampleRate;
        uint16_t volumeLeft, volumeRight;
        uint32_t adsr;
    };

    static void playADPCM(uint8_t channelId, uint16_t spuRamAddress, const ChannelPlaybackConfig &config, bool hardCut);
    static uint32_t getNextFreeChannel();

    static constexpr uint32_t NO_FREE_CHANNEL = 0xffffffff;
    static constexpr uint32_t BASE_SAMPLE_RATE = 44100;

  private:
    template <typename T>
    static bool waitForStatus(T mask, T expected, const volatile T *value);
};

}  // namespace psyqo
