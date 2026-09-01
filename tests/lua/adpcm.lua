--   Copyright (C) 2024 PCSX-Redux authors
--
--   This program is free software; you can redistribute it and/or modify
--   it under the terms of the GNU General Public License as published by
--   the Free Software Foundation; either version 2 of the License, or
--   (at your option) any later version.
--
--   This program is distributed in the hope that it will be useful,
--   but WITHOUT ANY WARRANTY; without even the implied warranty of
--   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--   GNU General Public License for more details.
--
--   You should have received a copy of the GNU General Public License
--   along with this program; if not, write to the
--   Free Software Foundation, Inc.,
--   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

local lu = require 'luaunit'
local ffi = require 'ffi'

TestAdpcm = {}

local function swapEndian32(x)
    return bit.bor(
        bit.lshift(bit.band(x, 0x000000FF), 24),
        bit.lshift(bit.band(x, 0x0000FF00), 8),
        bit.rshift(bit.band(x, 0x00FF0000), 8),
        bit.rshift(bit.band(x, 0xFF000000), 24)
    )
end

local function generateToneSample(frequency, sampleRate, t)
    return math.sin(2 * math.pi * frequency * t / sampleRate)
end

local function generateDTMF(frequency1, frequency2, sampleRate, t)
    return generateToneSample(frequency1, sampleRate, t) + generateToneSample(frequency2, sampleRate, t)
end

local DTMFFrequencies = {
    { 697, 1209 },
    { 697, 1336 },
    { 697, 1477 },
    { 697, 1633 },
    { 770, 1209 },
    { 770, 1336 },
    { 770, 1477 },
    { 770, 1633 },
    { 852, 1209 },
    { 852, 1336 },
    { 852, 1477 },
    { 852, 1633 },
    { 941, 1209 },
    { 941, 1336 },
    { 941, 1477 },
    { 941, 1633 },
}

local function generateMonoWaveform(frequency1, frequency2, sampleRate, duration)
    local size = duration * sampleRate
    local samples = ffi.new('int16_t[?]', size)
    for t = 0, duration * sampleRate - 1 do
        samples[t] = 10000 * generateDTMF(frequency1, frequency2, sampleRate, t)
    end
    return samples, size
end

local function generateStereoWaveform(frequency1, frequency2, frequency3, frequency4, sampleRate, duration)
    local size = duration * sampleRate
    local samples = ffi.new('int16_t[?]', size * 2)
    for t = 0, duration * sampleRate - 1 do
        samples[2 * t + 0] = 10000 * generateDTMF(frequency1, frequency2, sampleRate, t)
        samples[2 * t + 1] = 10000 * generateDTMF(frequency3, frequency4, sampleRate, t)
    end
    return samples, size
end

local function generateDTMF1(sampleRate, duration)
    local samples, size = generateMonoWaveform(DTMFFrequencies[1][1], DTMFFrequencies[1][2], sampleRate, duration)
    lu.assertEquals(size % 28, 0)
    return samples, size
end

local function generateDTMFStereo(sampleRate, duration)
    local samples, size = generateStereoWaveform(DTMFFrequencies[1][1], DTMFFrequencies[1][2], DTMFFrequencies[6][1], DTMFFrequencies[6][2], sampleRate, duration)
    lu.assertEquals(size % 28, 0)
    return samples, size
end

function TestAdpcm:test_simpleSPU()
    local sampleRate = 44100
    local duration = 1
    local samples, size = generateDTMF1(sampleRate, duration)
    local e = PCSX.Adpcm.NewEncoder()
    e:reset 'Normal'
    local blockCount = size / 28
    local ptr = ffi.cast('int16_t *', samples)
    local file = Support.File.buffer()
    file:write('VAGp')
    file:writeU32(0)
    file:writeU32(0)
    file:writeU32(swapEndian32((blockCount + 4) * 16))
    file:writeU32(swapEndian32(sampleRate))
    for i = 1, 11 do
        file:writeU32(0)
    end
    local out = Support.NewLuaBuffer(16)
    for i = 1, blockCount do
        e:processSPUBlock(ptr, out, i == blockCount and 'OneShotEnd' or 'OneShot')
        ptr = ptr + 28
        file:write(out)
    end
    e:finishSPU(out)
    file:write(out)
    file:close()
end

function TestAdpcm:test_simpleXA()
    local sampleRate = 37800
    local duration = 20
    local samples, size = generateDTMFStereo(sampleRate, duration)
    local e = PCSX.Adpcm.NewEncoder()
    e:reset 'XA'
    local blockCount = size / 112
    local ptr = ffi.cast('int16_t *', samples)
    local file = Support.File.buffer()
    local out = Support.NewLuaBuffer(128)
    for i = 1, blockCount do
        if (i % 18) == 1 then
            file:writeU8(0)
            file:writeU32(0xffffffff)
            file:writeU32(0xffffffff)
            file:writeU16(0xffff)
            file:writeU32(0)
            file:writeU8(2)
            file:writeU32(0x01640001)
            file:writeU32(0x01640001)
        end
        e:processXABlock(ptr, out, 'XAFourBits', 2)
        ptr = ptr + 112 * 2
        file:write(out)
        if (i % 18) == 0 then
            for j = 1, 6 do
                file:writeU32(0)
            end
        end
    end
    file:close()
end
