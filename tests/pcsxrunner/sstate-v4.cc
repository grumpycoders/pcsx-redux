/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "gtest/gtest.h"
#include "main/main.h"

// A v4 save state is a v5 one with 1MB of VRAM. The script saves a state, rewrites it
// as v4 (version 4, VRAM cut to its first 1MB), and loads it. A RAM marker changed after
// saving must come back, and on a 1MB console the upper bank must still read the
// open-bus 0xFFFF a fresh console has there. The unmodified v5 state must load too.
static const char c_v4SaveState[] = R"(
local ram = ffi.cast('uint32_t*', PCSX.getMemPtr())
local marker = 0x100100 / 4

local function varint(s, pos)
    local v, mul = 0, 1
    while true do
        local b = s:byte(pos)
        pos = pos + 1
        v = v + bit.band(b, 0x7f) * mul
        if b < 0x80 then return v, pos end
        mul = mul * 128
    end
end

local function putvarint(v)
    local out = {}
    repeat
        local b = v % 128
        v = math.floor(v / 128)
        if v > 0 then b = b + 128 end
        out[#out + 1] = string.char(b)
    until v == 0
    return table.concat(out)
end

-- Returns { {number, wiretype, raw key, payload} } for one message.
local function fields(s)
    local ret, pos = {}, 1
    while pos <= #s do
        local start = pos
        local key
        key, pos = varint(s, pos)
        local num, wt = math.floor(key / 8), key % 8
        local payload
        if wt == 0 then
            local p = pos
            _, pos = varint(s, pos)
            payload = s:sub(p, pos - 1)
        elseif wt == 1 then
            payload = s:sub(pos, pos + 7)
            pos = pos + 8
        elseif wt == 2 then
            local len
            len, pos = varint(s, pos)
            payload = s:sub(pos, pos + len - 1)
            pos = pos + len
        elseif wt == 5 then
            payload = s:sub(pos, pos + 3)
            pos = pos + 4
        else
            error('wire type ' .. wt)
        end
        ret[#ret + 1] = { num, wt, s:sub(start, start + #putvarint(key) - 1), payload }
    end
    return ret
end

local function encode(list)
    local out = {}
    for _, f in ipairs(list) do
        out[#out + 1] = f[3]
        if f[2] == 2 then out[#out + 1] = putvarint(#f[4]) end
        out[#out + 1] = f[4]
    end
    return table.concat(out)
end

local function toV4(s)
    local top = fields(s)
    for _, f in ipairs(top) do
        if f[1] == 1 then
            local name = 'PCSX-Redux SaveState v4'
            f[4] = '\10' .. putvarint(#name) .. name .. '\16\4'
        elseif f[1] == 5 then
            local gpu = fields(f[4])
            for _, g in ipairs(gpu) do
                if g[1] == 3 then
                    if #g[4] ~= 0x200000 then error('v5 VRAM is ' .. #g[4] .. ' bytes') end
                    g[4] = g[4]:sub(1, 0x100000)
                end
            end
            f[4] = encode(gpu)
        end
    end
    return encode(top)
end

local function toSlice(s)
    local slice = Support.File.createEmptySlice()
    slice:resize(#s)
    ffi.copy(slice.mutable, s, #s)
    return slice
end

local function upperBankIsOpenBus()
    local vram = tostring(PCSX.GPU.getVRAM())
    if #vram ~= 0x200000 then return false end
    return vram:sub(0x100001) == string.rep('\255', 0x100000)
end

local frames = 0
local v5
V4SaveStateListener = PCSX.Events.createEventListener('GPU::Vsync', function()
    frames = frames + 1
    if frames == 60 then
        ram[marker] = 0x12345678
        v5 = tostring(PCSX.createSaveState())
        local v4 = toV4(v5)
        ram[marker] = 0xdeadbeef
        PCSX.loadSaveState(toSlice(v4))
    elseif frames == 62 then
        if ram[marker] ~= 0x12345678 then print('v4 save state did not load') PCSX.quit(1) return end
        if not upperBankIsOpenBus() then print('v4 load wrote the upper VRAM bank') PCSX.quit(2) return end
        ram[marker] = 0xdeadbeef
        PCSX.loadSaveState(toSlice(v5))
    elseif frames == 64 then
        if ram[marker] ~= 0x12345678 then print('v5 save state did not load') PCSX.quit(3) return end
        PCSX.quit(0)
    end
end)
)";

TEST(SaveStateV4, LoadsIntoLowerBank) {
    // The open-bus check is a software-GPU property, so do not inherit a persisted renderer.
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-interpreter",
                        "-softgpu", "-1mbvram", "-exec", c_v4SaveState);
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}
