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

#include "supportpsx/adpcm.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

void PCSX::ADPCM::Encoder::reset(Mode mode) {
    m_lastBlockSamples[0][0] = 0.0;
    m_lastBlockSamples[0][1] = 0.0;
    m_lastBlockSamples[1][0] = 0.0;
    m_lastBlockSamples[1][1] = 0.0;
    m_anomalies[0][0] = 0.0;
    m_anomalies[0][0] = 0.0;
    m_anomalies[1][1] = 0.0;
    m_anomalies[1][1] = 0.0;
    for (unsigned i = 0; i < 10; i++) {
        m_factors[i] = 1.0;
    }
    switch (mode) {
        case Mode::Normal:
            break;
        case Mode::XA:
            m_factors[4] = 1000.0;
            break;
        case Mode::High:
            m_factors[2] = 1000.0;
            m_factors[3] = 1000.0;
            break;
        case Mode::Low:
            m_factors[2] = 1000.0;
            m_factors[4] = 1000.0;
            break;
        case Mode::FourBits:
            m_factors[1] = 1000.0;
            m_factors[2] = 1000.0;
            m_factors[3] = 1000.0;
            m_factors[4] = 1000.0;
            break;
    }
}

void PCSX::ADPCM::Encoder::convertToDoubles(std::span<const int16_t> input, std::span<double> output,
                                            unsigned channels) {
    // The original code here has a more complex mechanism, using an extra parameter, which then is used to
    // generate a filter waveform to process the input, but it's always set to 1.0, so we can simplify it
    // to just this simple loop. There might be other internal code that uses this parameter, but the
    // original encvag code doesn't seem to use it.
    for (int i = 0; i < 28; i++) {
        output[i] = static_cast<double>(input[i * channels]);
    }
}

void PCSX::ADPCM::Encoder::findFilterAndShift(std::span<const double> input, std::span<double> output,
                                              uint8_t* filterPtr, uint8_t* shiftPtr, unsigned channel) {
    double minMax = 1.8e+307;
    std::array<double, 5> filteredMax;
    std::array<std::array<double, 28>, 5> allFiltered;
    std::array<double, 2> samples;

    *filterPtr = 0;

    for (unsigned filter = 0; filter < 5; filter++) {
        samples[0] = m_lastBlockSamples[channel][0];
        samples[1] = m_lastBlockSamples[channel][1];
        filteredMax[filter] = 0.0;
        auto inputPtr = input;
        for (unsigned i = 0; i < 28; i++) {
            auto next = inputPtr[i];
            auto f = samples[0] * c_filters[filter][0] + samples[1] * c_filters[filter][1] + next;
            allFiltered[filter][i] = f;
            if (f <= 0.0) f = -f;
            if (filteredMax[filter] < f) filteredMax[filter] = f;
            samples[1] = samples[0];
            samples[0] = next;
        }
        auto factorized = m_factors[filter] * filteredMax[filter];
        if (factorized < minMax) {
            *filterPtr = filter;
            minMax = factorized;
        }
        if ((filter == 0) && (filteredMax[0] <= 7.0)) break;
    }
    m_lastBlockSamples[channel][0] = samples[0];
    m_lastBlockSamples[channel][1] = samples[1];
    unsigned filter = *filterPtr;
    std::copy(allFiltered[filter].begin(), allFiltered[filter].end(), output.begin());
    int maxI = filteredMax[filter] * m_factors[filter + 5];
    maxI = std::clamp(maxI, -32768, 32767);
    int mask = 0x4000;
    for (*shiftPtr = 0; *shiftPtr < 12; (*shiftPtr)++) {
        int compare = maxI + (mask >> 3);
        if ((mask & compare) != 0) return;
        mask >>= 1;
    }
}

void PCSX::ADPCM::Encoder::convert(std::span<const double> input, std::span<int16_t> output, uint8_t filter,
                                   uint8_t shift, unsigned channel, unsigned channels) {
    double multiplier = 1 << shift;
    auto& anomalies = m_anomalies[channel];
    for (unsigned i = 0; i < 28; i++) {
        auto sample = anomalies[0] * c_filters[filter][0] + anomalies[1] * c_filters[filter][1] + input[i];
        int sampleI = sample * multiplier;
        sampleI = std::clamp(sampleI, -32768, 32767);
        output[i * channels + channel] = sampleI;
        anomalies[1] = anomalies[0];
        anomalies[0] = (sampleI >> shift) - sample;
    }
}

void PCSX::ADPCM::Encoder::processBlock(const int16_t* input, int16_t* output, uint8_t* filterPtr, uint8_t* shiftPtr,
                                        unsigned channels) {
    if (channels > 2) {
        throw std::invalid_argument("Channels must be 1 or 2");
    }
    std::array<std::array<double, 28>, 2> converted;
    std::array<std::array<double, 28>, 2> filtered;
    auto inputSpan = std::span<const int16_t>(input, 28 * channels);
    convertToDoubles(inputSpan, converted[0], channels);
    if (channels == 2) {
        convertToDoubles(inputSpan.subspan(1), converted[1], channels);
    }
    for (unsigned channel = 0; channel < channels; channel++) {
        findFilterAndShift(converted[channel], filtered[channel], filterPtr + channel, shiftPtr + channel, channel);
        convert(filtered[channel], std::span<int16_t>(output, 28 * channels), filterPtr[channel], shiftPtr[channel],
                channel, channels);
    }
}

void PCSX::ADPCM::Encoder::blockTo4Bit(const int16_t* input, uint8_t* output, unsigned channels) {
    if (channels > 2) {
        throw std::invalid_argument("Channels must be 1 or 2");
    }
    for (unsigned i = 0; i < (14 * channels); i++) {
        auto s1 = (input[i * 2 + 0] + 2048) >> 12;
        auto s2 = (input[i * 2 + 1] + 2048) >> 12;
        output[i] = s1 | (s2 << 4);
    }
}

void PCSX::ADPCM::Encoder::blockTo8Bit(const int16_t* input, uint8_t* output, unsigned channels) {
    if (channels > 2) {
        throw std::invalid_argument("Channels must be 1 or 2");
    }
    for (unsigned i = 0; i < (28 * channels); i++) {
        output[i] = (input[i] + 128) >> 8;
    }
}

void PCSX::ADPCM::Encoder::processSPUBlock(const int16_t* input, uint8_t* output, BlockAttribute blockAttribute) {
    uint8_t filter;
    uint8_t shift;
    int16_t encoded[28];
    processBlock(input, encoded, &filter, &shift);

    uint8_t h1 = (shift & 0x0f) | ((filter & 0x0f) << 4);
    uint8_t h2 = 0;

    switch (blockAttribute) {
        case BlockAttribute::OneShot:
            break;
        case BlockAttribute::OneShotEnd:
            h2 = 0x01;
            break;
        case BlockAttribute::LoopStart:
            h2 = 0x06;
            break;
        case BlockAttribute::LoopBody:
            h2 = 0x02;
            break;
        case BlockAttribute::LoopEnd:
            h2 = 0x03;
            break;
    }

    output[0] = h1;
    output[1] = h2;

    blockTo4Bit(encoded, output + 2);
}

void PCSX::ADPCM::Encoder::finishSPU(uint8_t* output) {
    output[0] = 0;
    output[1] = 7;
    std::memset(output + 2, 0x77, 14);
}

void PCSX::ADPCM::Encoder::processXABlock(const int16_t* input, uint8_t* output, XAMode xaMode, unsigned channels) {
    if (channels > 2) {
        throw std::invalid_argument("Channels must be 1 or 2");
    }
    if (channels == 1) {
        uint8_t filter;
        uint8_t shift;
        int16_t encoded[28];
        if (xaMode == XAMode::FourBits) {
            for (unsigned i = 0; i < 8; i++) {
                processBlock(input + i * 28, encoded, &filter, &shift, 1);
                uint8_t h = (shift & 0x0f) | ((filter & 0x0f) << 4);
                unsigned offset = (i & 3) + (i >> 2) * 8;
                output[offset + 0] = h;
                output[offset + 4] = h;
                blockTo4Bit(encoded, output + 16 + 14 * i, 1);
            }
        } else {
            for (unsigned i = 0; i < 4; i++) {
                processBlock(input + i * 28, encoded, &filter, &shift, 1);
                uint8_t h = (shift & 0x0f) | ((filter & 0x0f) << 4);
                output[i + 0] = h;
                output[i + 4] = h;
                output[i + 8] = h;
                output[i + 12] = h;
                blockTo8Bit(encoded, output + 16 + 28 * i, 1);
            }
        }
    } else {
        uint8_t filter[2];
        uint8_t shift[2];
        int16_t encoded[56];
        if (xaMode == XAMode::FourBits) {
            for (unsigned i = 0; i < 4; i++) {
                processBlock(input + i * 56, encoded, filter, shift, 2);
                uint8_t h0 = (shift[0] & 0x0f) | ((filter[0] & 0x0f) << 4);
                uint8_t h1 = (shift[1] & 0x0f) | ((filter[1] & 0x0f) << 4);
                unsigned offset = (i & 1) + (i >> 1) * 4;
                output[offset * 2 + 0] = h0;
                output[offset * 2 + 1] = h1;
                output[offset * 2 + 4] = h0;
                output[offset * 2 + 5] = h1;
                blockTo4Bit(encoded, output + 16 + 28 * i, 2);
            }
        } else {
            for (unsigned i = 0; i < 2; i++) {
                processBlock(input + i * 56, encoded, filter, shift, 2);
                uint8_t h0 = (shift[0] & 0x0f) | ((filter[0] & 0x0f) << 4);
                uint8_t h1 = (shift[1] & 0x0f) | ((filter[1] & 0x0f) << 4);
                output[i * 2 + 0] = h0;
                output[i * 2 + 1] = h1;
                output[i * 2 + 4] = h0;
                output[i * 2 + 5] = h1;
                output[i * 2 + 8] = h0;
                output[i * 2 + 9] = h1;
                output[i * 2 + 12] = h0;
                output[i * 2 + 13] = h1;
                blockTo8Bit(encoded, output + 16 + 56 * i, 2);
            }
        }
    }
}
