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
    XAFourBits,
    XAEightBits,
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

typedef struct { char opaque[?]; } LuaAdpcmDecoder;

LuaAdpcmDecoder* newAdpcmDecoder();
void destroyAdpcmDecoder(LuaAdpcmDecoder* decoder);
void adpcmDecoderReset(LuaAdpcmDecoder* decoder);
uint8_t adpcmDecoderDecodeSPUBlock(LuaAdpcmDecoder* decoder, const void* input, void* output);
unsigned adpcmDecoderDecodeXASoundGroup(LuaAdpcmDecoder* decoder, const void* input, void* output,
                                        unsigned bitsPerSample, unsigned channels);

]]

local C = ffi.load 'SUPPORTPSX_ADPCM'


-- Returns a pointer to the input data, and its size if known. Accepts a LuaBuffer, a Lua string,
-- or a raw ffi pointer; the caller has to keep the original object alive during the call, and
-- a pointer has to reach as far as the call reads or writes, since its size cannot be checked.
local function decoderInput(inData, needed, name)
    if Support.isLuaBuffer(inData) then
        if #inData < needed then error(name .. ': input buffer too small, needs ' .. needed .. ' bytes') end
        return inData.data
    elseif type(inData) == 'string' then
        if #inData < needed then error(name .. ': input string too small, needs ' .. needed .. ' bytes') end
        return ffi.cast('const uint8_t*', inData)
    elseif type(inData) == 'cdata' then
        return inData
    end
    error(name .. ': input must be a LuaBuffer, a string, or a pointer')
end

-- Returns the object to hand back to the caller, and the pointer to write to.
local function decoderOutput(outData, bytes, name)
    if outData == nil then outData = Support.NewLuaBuffer(bytes) end
    if Support.isLuaBuffer(outData) then
        if outData:maxsize() < bytes then error(name .. ': output buffer too small, needs ' .. bytes .. ' bytes') end
        outData:resize(bytes)
        return outData, outData.data
    elseif type(outData) == 'cdata' then
        return outData, outData
    end
    error(name .. ': output must be a LuaBuffer or a pointer')
end

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
                local filterPtr = ffi.new('uint8_t[2]')
                local shiftPtr = ffi.new('uint8_t[2]')
                if type(outData) == 'number' then
                    channels = outData
                    outData = nil
                end
                if channels == nil then channels = 1 end
                local blockSize = 56 * channels
                if outData == nil then outData = Support.NewLuaBuffer(blockSize) end
                local inp = inData
                local out = outData
                if Support.isLuaBuffer(inp) then
                    local size = #inp
                    if size < blockSize then
                        inp = Support.NewLuaBuffer(blockSize)
                        ffi.fill(inp.data, blockSize, 0)
                        ffi.copy(inp.data, inData.data, size)
                    end
                    inp = inp.data
                end
                if Support.isLuaBuffer(out) then
                    if out:maxsize() < blockSize then error('output buffer too small') end
                    out:resize(blockSize)
                    out = out.data
                end
                C.adpcmEncoderProcessBlock(self._wrapped, inp, out, filterPtr, shiftPtr, channels)
                if channels == 2 then return outData, filterPtr[0], shiftPtr[0], filterPtr[1], shiftPtr[1] end
                return outData, filterPtr[0], shiftPtr[0]
            end,
            processSPUBlock = function(self, inData, outData, blockAttribute)
                if type(outData) == 'string' and blockAttribute == nil then
                    blockAttribute = outData
                    outData = nil
                end
                if outData == nil then outData = Support.NewLuaBuffer(16) end
                if blockAttribute == nil then blockAttribute = 'OneShot' end
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
                if outData == nil then outData = Support.NewLuaBuffer(16) end
                local out = outData
                if Support.isLuaBuffer(out) then out = out.data end
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
                if outData == nil then outData = Support.NewLuaBuffer(128) end
                if mode == nil then mode = 'XAFourBits' end
                if channels == nil then channels = 1 end
                local inp = inData
                local out = outData
                if Support.isLuaBuffer(inp) then
                    local theoreticalSize = 28 * 4 * (mode == 'XAFourBits' and 2 or 1) * 2
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
    end,
    NewDecoder = function()
        local wrapped = C.newAdpcmDecoder()
        local decoder = {
            _wrapped = wrapped,
            _proxy = newproxy(),
            reset = function(self) C.adpcmDecoderReset(self._wrapped) end,
            -- Decodes one 16-byte SPU block into 28 int16_t samples.
            -- Returns the output object (a new LuaBuffer of 56 bytes by default), and the block's flags byte.
            decodeSPUBlock = function(self, inData, outData)
                local inp = decoderInput(inData, 16, 'decodeSPUBlock')
                local out
                outData, out = decoderOutput(outData, 56, 'decodeSPUBlock')
                local flags = C.adpcmDecoderDecodeSPUBlock(self._wrapped, inp, out)
                return outData, flags
            end,
            -- Decodes one 128-byte XA sound group. bitsPerSample is 4 or 8, and channels is 1 or 2.
            -- Stereo output is interleaved. Returns the output object (a new LuaBuffer by default), and
            -- the number of int16_t values written.
            decodeXASoundGroup = function(self, inData, outData, bitsPerSample, channels)
                if type(outData) == 'number' then
                    channels = bitsPerSample
                    bitsPerSample = outData
                    outData = nil
                end
                if bitsPerSample == nil then bitsPerSample = 4 end
                if channels == nil then channels = 1 end
                if bitsPerSample ~= 4 and bitsPerSample ~= 8 then
                    error('decodeXASoundGroup: bitsPerSample must be 4 or 8')
                end
                if channels ~= 1 and channels ~= 2 then error('decodeXASoundGroup: channels must be 1 or 2') end
                local count = bitsPerSample == 4 and 224 or 112
                local inp = decoderInput(inData, 128, 'decodeXASoundGroup')
                local out
                outData, out = decoderOutput(outData, count * 2, 'decodeXASoundGroup')
                local written = C.adpcmDecoderDecodeXASoundGroup(self._wrapped, inp, out, bitsPerSample, channels)
                return outData, tonumber(written)
            end,
        }
        debug.setmetatable(decoder._proxy, { __gc = function() C.destroyAdpcmDecoder(decoder._wrapped) end })
        return decoder
    end,
}

-- )EOF"
