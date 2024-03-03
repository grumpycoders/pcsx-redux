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

#include <stdint.h>

#include <array>
#include <span>

namespace PCSX {

// The point of this code is to roughly re-create Sony's ADPCM encoder from the original Psy-Q development
// kit. The encoder is used to convert 16-bit PCM audio into 4-bit or 8-bit ADPCM audio, which is used by
// the PlayStation's SPU and XA decoder chip. The API is meant to be similar to the original encvag API,
// but with some modernizations and improvements. The input is expected to be blocks of 28 samples of
// 16-bit signed little endian PCM audio. While there are some minor differences in the encoder, the
// output should be very similar to the original encoder, following the same algorithm, which is the goal
// of this code. It is possible to have a better encoder however, and there are certainly other projects
// that are doing so.
namespace ADPCM {

class Encoder {
  public:
    // The mode of the encoder. Normal is the default, and is used for most audio. XA is used for XA audio,
    // limiting itself to the first 4 filters. The XA mode is an addition to this API, and the semantics
    // of the other modes is the same as the original encvag API.
    enum class Mode {
        Normal,
        XA,
        High,
        Low,
        FourBits,
    };

    // The block attribute of the encoder. This is when creating SPU blocks, and is used to signal to
    // the SPU how to handle the block. The semantics of the block attributes is the same as the original
    // encvag API.
    enum class BlockAttribute {
        OneShot,     // Block flags 0x00
        OneShotEnd,  // Block flags 0x01
        LoopStart,   // Block flags 0x06
        LoopBody,    // Block flags 0x02
        LoopEnd,     // Block flags 0x03
    };

    enum class XAMode {
        FourBits,
        EightBits,
    };

    // Initialize the encoder with the given mode. Calling this function is mandatory before using the encoder,
    // and between different instruments, as the encoder state is not reset between calls to the various encoding
    // functions, which is by design with how ADPCM encoding works. The mode is set to Normal by default.
    void reset(Mode mode = Mode::Normal);

    // Process a block of 28 samples, and set the filter and shift values for this block. This function is
    // not part of the original encvag API, but is exposed here to allow for more flexibility in the encoder.
    // The output is another block of 28 samples, but with the filter and shift values applied. The block
    // needs to be then processed using blockTo4Bit or blockTo8Bit to get the final output. The shift value
    // will be between 0 and 12, and the filter value will be between 0 and 4. If encoding for 8-bit ADPCM,
    // the shift value will need to be adjusted to be between 0 and 8, with the following formula:
    //      shift8 = max(0, shift - 4)
    // The channels parameter is used to specify the number of channels in the input block. The input block
    // is expected to be interleaved, but the output buffer will NOT be interlaced. The maximum number of
    // channels is 2, for stereo audio, and the default is 1, for mono audio. This means that the input and
    // output blocks are expected to be 28 * channels * sizeof(int16_t) bytes long. The filterPtr and shiftPtr
    // are used to store the filter and shift values for the current block, and are expected to be 1 or 2 bytes
    // long, depending on the number of channels.
    void processBlock(const int16_t* input, int16_t* output, uint8_t* filterPtr, uint8_t* shiftPtr,
                      unsigned channels = 1, XAMode mode = XAMode::FourBits);

    // Process a block of 28 pre-processed samples into 4-bit ADPCM audio. This will pack the input samples
    // into proper ADPCM format, and the output buffer needs to be 14 bytes long.
    void blockTo4Bit(const int16_t* input, uint8_t* output);

    // Process a block of 28 pre-processed samples into 8-bit ADPCM audio. This will pack the input samples
    // into proper ADPCM format, and the output buffer needs to be 28 bytes long.
    void blockTo8Bit(const int16_t* input, uint8_t* output);

    // Process a block of 28 samples into 16 bytes of output, suitable for SPU decoding.
    void processSPUBlock(const int16_t* input, uint8_t* output, BlockAttribute blockAttribute);

    // Finish the SPU encoding process, and write the final 16 bytes of the SPU block. Use this after the last block of
    // samples, only when using one shot blocks.
    void finishSPU(uint8_t* output);

    // Process enough samples to fill a single XA block, and write the final output. The XA mode selects between 4-bit
    // and 8-bit ADPCM. The channels parameter can be either 1 or 2. An XA block is exactly 128 bytes long, and the
    // size of the input buffer will vary depending on the encoding mode and number of channels. The input buffer
    // will require the following number of samples and bytes:
    //      4-bit mono: 224 samples aka 448 bytes
    //      4-bit stereo: 112 samples aka 448 bytes
    //      8-bit mono: 112 samples aka 224 bytes
    //      8-bit stereo: 56 samples aka 224 bytes
    // The XA mode is an addition to the original encvag API, and requires the encoder to be reset with the XA mode.
    // When writing XA audio, a single MODE2 FORM2 sector is expected to contain 18 blocks of 128 bytes each, for a
    // total of 2304 bytes. The subheader encoding isn't covered by this API, and is expected to be handled by the
    // user. The last 4 bytes of the MODE2 FORM2 sector should either be the yellow book checksum, or set to 0.
    void processXABlock(const int16_t* input, uint8_t* output, XAMode xaMode, unsigned channels);

  private:
    // The original encvag code uses this to force some filters to be discarded, by setting the factors
    // to 1000.0 instead of 1.0. This is used when calling reset with a mode different than Normal.
    std::array<double, 10> m_factors;
    // These two are the stateful variables of the encoder, and are used to keep track of the previous
    // samples and anomalies, which are used to calculate the filter and shift values for the next block.
    std::array<std::array<double, 2>, 2> m_lastBlockSamples;
    std::array<std::array<double, 2>, 2> m_anomalies;
    // Early versions of the encoder only used 4 filters, and the XA mode is meant to mimic that behavior.
    static constexpr std::array<std::array<double, 2>, 5> c_filters = {{
        {0.0, 0.0},            // 0
        {-0.9375, 0.0},        // 1
        {-1.796875, 0.8125},   // 2
        {-1.53125, 0.859375},  // 3
        {-1.90625, 0.9375},    // 4
    }};

    void convertToDoubles(std::span<const int16_t> input, std::span<double> output, unsigned channels);
    void findFilterAndShift(std::span<const double> input, std::span<double> output, uint8_t* filterPtr,
                            uint8_t* shiftPtr, unsigned channel);
    void convert(std::span<const double> input, std::span<int16_t> output, uint8_t filter, uint8_t shift,
                 unsigned channel, XAMode xaMode);
};

}  // namespace ADPCM

}  // namespace PCSX
