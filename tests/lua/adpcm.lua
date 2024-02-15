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
    local size = 2 * duration * sampleRate
    local samples = ffi.new('int16_t[?]', size)
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

function TestAdpcm:test_simpleSPU()
    local sampleRate = 44100
    local duration = 1
    local samples, size = generateDTMF1(sampleRate, duration)
    local e = PCSX.Adpcm.NewEncoder()
    e:reset 'Normal'
    local blockCount = size / 28
    local ptr = ffi.cast('int16_t *', samples)
    local out = Support.NewLuaBuffer(16)
    for i = 1, blockCount do
        e:processSPUBlock(ptr, out, i == blockCount and 'OneShotEnd' or 'OneShot')
        ptr = ptr + 28
    end
    e:finishSPU(out)
end
