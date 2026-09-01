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

#include "supportpsx/adpcmlua.h"

#include <stdint.h>

#include "supportpsx/adpcm.h"

namespace {

PCSX::ADPCM::Encoder* newAdpcmEncoder() { return new PCSX::ADPCM::Encoder(); }
void destroyAdpcmEncoder(PCSX::ADPCM::Encoder* encoder) { delete encoder; }
void adpcmEncoderReset(PCSX::ADPCM::Encoder* encoder, PCSX::ADPCM::Encoder::Mode mode) { encoder->reset(mode); }
void adpcmEncoderProcessBlock(PCSX::ADPCM::Encoder* encoder, const int16_t* in, int16_t* out, uint8_t* filterPtr,
                              uint8_t* shiftPtr, unsigned channels) {
    encoder->processBlock(in, out, filterPtr, shiftPtr, channels);
}
void adpcmEncoderProcessSPUBlock(PCSX::ADPCM::Encoder* encoder, const int16_t* input, uint8_t* output,
                                 PCSX::ADPCM::Encoder::BlockAttribute blockAttribute) {
    encoder->processSPUBlock(input, output, blockAttribute);
}
void adpcmEncoderFinishSPU(PCSX::ADPCM::Encoder* encoder, uint8_t* output) { encoder->finishSPU(output); }
void adpcmEncoderProcessXABlock(PCSX::ADPCM::Encoder* encoder, const int16_t* input, uint8_t* output,
                                PCSX::ADPCM::Encoder::XAMode mode, unsigned channels) {
    encoder->processXABlock(input, output, mode, channels);
}

template <typename T, size_t S>
void registerSymbol(PCSX::Lua L, const char (&name)[S], const T ptr) {
    L.push<S>(name);
    L.push((void*)ptr);
    L.settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

void registerAllSymbols(PCSX::Lua L) {
    L.getfieldtable("_CLIBS", LUA_REGISTRYINDEX);
    L.push("SUPPORTPSX_ADPCM");
    L.newtable();
    REGISTER(L, newAdpcmEncoder);
    REGISTER(L, destroyAdpcmEncoder);
    REGISTER(L, adpcmEncoderReset);
    REGISTER(L, adpcmEncoderProcessBlock);
    REGISTER(L, adpcmEncoderProcessSPUBlock);
    REGISTER(L, adpcmEncoderFinishSPU);
    REGISTER(L, adpcmEncoderProcessXABlock);
    L.settable();
    L.pop();
}

}  // namespace

void PCSX::LuaSupportPSX::open_adpcm(Lua L) {
    static int lualoader = 1;
    static const char* binffi = (
#include "supportpsx/adpcmffi.lua"
    );
    registerAllSymbols(L);
    L.load(binffi, "src:supportpsx/adpcmffi.lua");
}
