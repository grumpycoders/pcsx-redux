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

local tmp = os.tmpname()
os.remove(tmp)
local first, second = tmp .. '-1.gpd', tmp .. '-2.gpd'

local vsyncs = 0
local ok = true
Listener = PCSX.Events.createEventListener('GPU::Vsync', function()
    vsyncs = vsyncs + 1
    if vsyncs == 60 then
        PCSX.GPU.startDump(first)
    elseif vsyncs == 120 then
        PCSX.GPU.stopDump()
        ok = check(first) and ok
    elseif vsyncs == 150 then
        -- The player keeps its GPU while the emulated one runs on.
        PCSX.GPU.startDump(second)
    elseif vsyncs == 240 then
        PCSX.GPU.stopDump()
        ok = check(second) and ok
        os.remove(first)
        os.remove(second)
        PCSX.quit(ok and 0 or 1)
    elseif vsyncs > 1000 then
        PCSX.quit(2)
    end
end)
