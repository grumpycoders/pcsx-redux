-- lualoader, R"EOF(--
-- MIT License
--
-- Copyright (c) 2024 PCSX-Redux authors
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
ffi.cdef [[

enum AdpcmEncoderMode {
    Normal,
    XA,
    High,
    Low,
    FourBits,
};

enum AdpcmEncoderBlockAttribute {
    OneShot,
    OneShotEnd,
    LoopStart,
    LoopBody,
    LoopEnd,
};

enum XAMode {
    FourBits,
    EightBits,
};

typedef struct { char opaque[?]; } LuaAdpcmEncoder;

LuaAdpcmEncoder* newAdpcmEncoder();
void destroyAdpcmEncoder(LuaAdpcmEncoder* encoder);
void adpcmEncoderReset(LuaAdpcmEncoder* encoder, enum AdpcmEncoderMode);
void adpcmEncoderProcessBlock(LuaAdpcmEncoder* encoder, const void* in, void* out, uint8_t* filterPtr,
                              uint8_t* shiftPtr, unsigned channels);
void adpcmEncoderProcessSPUBlock(LuaAdpcmEncoder* encoder, const void* input, void* output,
                                 enum AdpcmEncoderBlockAttribute);
void adpcmEncoderFinishSPU(LuaAdpcmEncoder* encoder, uint8_t* output);
void adpcmEncoderProcessXABlock(LuaAdpcmEncoder* encoder, const int16_t* input, uint8_t* output,
                                enum XAMode, unsigned channels);

]]

local C = ffi.load 'SUPPORTPSX_ADPCM'

local uint8_t = ffi.typeof 'uint8_t'

PCSX.Adpcm = {
    NewEncoder = function()
        local wrapped = C.newAdpcmEncoder()
        local encoder = {
            _wrapped = wrapped,
            _proxy = newproxy(),
            reset = function(self, mode)
                if mode == nil then mode = 'Normal' end
                C.adpcmEncoderReset(self._wrapped, mode)
            end,
            processBlock = function(self, inData, outData, channels)
                local filterPtr = ffi.new(uint8_t)
                local shiftPtr = ffi.new(uint8_t)
                if type(outData) == 'number' then
                    channels = outData
                    outData = nil
                end
                if outData == nil then
                    outData = Support.NewLuaBuffer(56)
                end
                if channels == nil then
                    channels = 1
                end
                local inp = inData
                local out = outData
                if Support.isLuaBuffer(inp) then
                    local size = #inp
                    if size < 56 then
                        inp = Support.NewLuaBuffer(56)
                        ffi.fill(inp.data, 56, 0)
                        ffi.copy(inp.data, inData.data, size)
                    end
                    inp = inp.data
                end
                if Support.isLuaBuffer(out) then
                    if out:maxsize() < 56 then error('output buffer too small') end
                    out:resize(56)
                    out = out.data
                end
                C.adpcmEncoderProcessBlock(self._wrapped, inp, out, filterPtr, shiftPtr, channels)
                return outData, filterPtr[1], shiftPtr[1]
            end,
            processSPUBlock = function(self, inData, outData, blockAttribute)
                if type(outdata) == 'string' and blockAttribute == nil then
                    blockAttribute = outData
                    outData = nil
                end
                if outData == nil then
                    outData = Support.NewLuaBuffer(16)
                end
                if blockAttribute == nil then
                    blockAttribute = 'OneShot'
                end
                local inp = inData
                local out = outData
                if Support.isLuaBuffer(inp) then
                    local size = #inp
                    if size < 56 then
                        inp = Support.NewLuaBuffer(56)
                        ffi.fill(inp.data, 56, 0)
                        ffi.copy(inp.data, inData.data, size)
                    end
                    inp = inp.data
                end
                if Support.isLuaBuffer(out) then
                    if out:maxsize() < 16 then error('output buffer too small') end
                    out:resize(16)
                    out = out.data
                end
                C.adpcmEncoderProcessSPUBlock(self._wrapped, inp, out, blockAttribute)
                return outData
            end,
            finishSPU = function(self, outData)
                if outData == nil then
                    outData = Support.NewLuaBuffer(16)
                end
                local out = outData
                if Support.isLuaBuffer(out) then
                    out = out.data
                end
                C.adpcmEncoderFinishSPU(self._wrapped, out)
                return outData
            end,
            processXABlock = function(self, inData, outData, mode, channels)
                if type(outData) == 'string' and mode == nil and channels == nil then
                    mode = outData
                    outData = nil
                end
                if type(outData) == 'number' and mode == nil and channels == nil then
                    channels = outData
                    outData = nil
                end
                if type(mode) == 'number' and channels == nil then
                    channels = mode
                    mode = nil
                end
                if outData == nil then
                    outData = Support.NewLuaBuffer(128)
                end
                if mode == nil then
                    mode = 'FourBits'
                end
                if channels == nil then
                    channels = 1
                end
                local inp = inData
                local out = outData
                if Support.isLuaBuffer(inp) then
                    local theoreticalSize = 28 * 4 * (mode == 'FourBits' and 2 or 1)
                    local size = #inp
                    if size < theoreticalSize then
                        inp = Support.NewLuaBuffer(theoreticalSize)
                        ffi.fill(inp.data, theoreticalSize, 0)
                        ffi.copy(inp.data, inData.data, size)
                    end
                    inp = inp.data
                end
                if Support.isLuaBuffer(out) then
                    if out:maxsize() < 128 then error('output buffer too small') end
                    out:resize(128)
                    out = out.data
                end
                C.adpcmEncoderProcessXABlock(self._wrapped, inp, out, mode, channels)
                return outData
            end,
        }
        debug.setmetatable(encoder._proxy, { __gc = function() C.destroyAdpcmEncoder(encoder._wrapped) end })
        return encoder
    end
}

-- )EOF"
