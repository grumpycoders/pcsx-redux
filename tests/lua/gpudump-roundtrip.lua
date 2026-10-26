--   Copyright (C) 2026 PCSX-Redux authors
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

-- Records the OpenBIOS shell with the GPU dump recorder, replays the dump into
-- the dump player, and checks that the replayed VRAM matches the live VRAM.
-- A replay stopped one frame short must not match, or the comparison proves
-- nothing. Exits with 0 on success, 1 on a mismatch, 2 on a timeout.

local ffi = require('ffi')

local function countDiffs(a, b)
    if a.size ~= b.size then return -1 end
    local pa = ffi.cast('const uint16_t*', a.data)
    local pb = ffi.cast('const uint16_t*', b.data)
    local n = 0
    for i = 0, a.size / 2 - 1 do
        if pa[i] ~= pb[i] then n = n + 1 end
    end
    return n
end

local function check(path)
    local live = PCSX.GPU.getVRAM()
    if not PCSX.GPU.DumpPlayer.load(path) then
        print('unable to load ' .. path)
        return false
    end
    local steps = 0
    while PCSX.GPU.DumpPlayer.step() do steps = steps + 1 end
    local diffs = countDiffs(live, PCSX.GPU.DumpPlayer.getVRAM())
    PCSX.GPU.DumpPlayer.rewind()
    for i = 1, steps - 1 do PCSX.GPU.DumpPlayer.step() end
    local control = countDiffs(live, PCSX.GPU.DumpPlayer.getVRAM())
    print(string.format('%s: %d frames, %d pixels differ, %d when one frame short', path, steps, diffs, control))
    return steps > 0 and diffs == 0 and control > 0
end

-- The player's logger keeps one dump frame: the second frame's list must not hold the first one's
-- commands, whatever the emulator is doing meanwhile, and a rewind replays to the same counts.
local function checkLogger(path)
    if not PCSX.GPU.DumpPlayer.load(path) then return false end
    PCSX.GPU.DumpPlayer.setLogging(true)
    PCSX.GPU.DumpPlayer.rewind()
    PCSX.GPU.DumpPlayer.step()
    local first = PCSX.GPU.DumpPlayer.getLoggedCount()
    PCSX.GPU.DumpPlayer.step()
    local second = PCSX.GPU.DumpPlayer.getLoggedCount()
    PCSX.GPU.DumpPlayer.rewind()
    PCSX.GPU.DumpPlayer.step()
    PCSX.GPU.DumpPlayer.step()
    local again = PCSX.GPU.DumpPlayer.getLoggedCount()
    PCSX.GPU.DumpPlayer.setLogging(false)
    print(string.format('%s: player logger %d then %d commands, %d after a rewind', path, first, second, again))
    -- The first list also holds the restore sequence that rewind() plays before the first frame.
    return first > 0 and second > 0 and second < first and second == again
end

-- A frame that sends no commands shows an empty list, not the previous frame's commands. Two VSync
-- packets appended to the dump end it on a frame with nothing in it.
local function checkEmptyFrame(path)
    local src = io.open(path, 'rb')
    if not src then return false end
    local data = src:read('*a')
    src:close()
    local padded = path .. '-empty.gpd'
    local dst = io.open(padded, 'wb')
    local vsync = string.char(0, 0, 0, 2)
    dst:write(data .. vsync .. vsync)
    dst:close()
    local loaded = PCSX.GPU.DumpPlayer.load(padded)
    os.remove(padded)
    if not loaded then return false end
    PCSX.GPU.DumpPlayer.setLogging(true)
    PCSX.GPU.DumpPlayer.rewind()
    local busiest, last = 0, -1
    while PCSX.GPU.DumpPlayer.step() do
        last = PCSX.GPU.DumpPlayer.getLoggedCount()
        if last > busiest then busiest = last end
    end
    PCSX.GPU.DumpPlayer.setLogging(false)
    print(string.format('%s: busiest frame %d commands, empty last frame %d', path, busiest, last))
    return busiest > 0 and last == 0
end

local tmp = os.tmpname()
os.remove(tmp)
local first, second = tmp .. '-1.gpd', tmp .. '-2.gpd'

-- A dump has to end on a frame that changed VRAM, or the one-frame-short
-- control matches by construction. The shell does not redraw on every vsync,
-- so each stop waits for the first vsync at or past its mark that did.
local vsyncs = 0
local ok = true
local previous
local stage = 0
Listener = PCSX.Events.createEventListener('GPU::Vsync', function()
    vsyncs = vsyncs + 1
    local vram = PCSX.GPU.getVRAM()
    local current = ffi.string(vram.data, vram.size)
    local changed = previous ~= nil and current ~= previous
    previous = current
    if stage == 0 and vsyncs >= 60 then
        PCSX.GPU.startDump(first)
        stage = 1
    elseif stage == 1 and vsyncs >= 120 and changed then
        PCSX.GPU.stopDump()
        ok = check(first) and ok
        ok = checkLogger(first) and ok
        ok = checkEmptyFrame(first) and ok
        stage = 2
    elseif stage == 2 and vsyncs >= 150 then
        -- The player keeps its GPU while the emulated one runs on.
        PCSX.GPU.startDump(second)
        stage = 3
    elseif stage == 3 and vsyncs >= 240 and changed then
        PCSX.GPU.stopDump()
        ok = check(second) and ok
        os.remove(first)
        os.remove(second)
        PCSX.quit(ok and 0 or 1)
    elseif vsyncs > 1000 then
        PCSX.quit(2)
    end
end)
