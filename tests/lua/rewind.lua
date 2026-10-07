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

local lu = require 'luaunit'
local ffi = require 'ffi'

TestRewind = {}

local function ram32(offset)
    return ffi.cast('uint32_t*', PCSX.getMemPtr() + offset)
end

function TestRewind:test_empty()
    while PCSX.getRewindStateCount() > 0 do PCSX.rewindState() end
    lu.assertFalse(PCSX.rewindState())
end

function TestRewind:test_restores_ram_and_registers()
    while PCSX.getRewindStateCount() > 0 do PCSX.rewindState() end
    local word = ram32(0x1f0000)
    local regs = PCSX.getRegisters()
    word[0] = 0x11111111
    regs.GPR.n.t0 = 0x1234
    PCSX.createRewindState()
    word[0] = 0x22222222
    regs.GPR.n.t0 = 0x5678
    PCSX.createRewindState()
    word[0] = 0x33333333
    regs.GPR.n.t0 = 0x9abc
    lu.assertEquals(PCSX.getRewindStateCount(), 2)

    lu.assertTrue(PCSX.rewindState())
    lu.assertEquals(word[0], 0x22222222)
    lu.assertEquals(regs.GPR.n.t0, 0x5678)
    lu.assertEquals(PCSX.getRewindStateCount(), 1)

    lu.assertTrue(PCSX.rewindState())
    lu.assertEquals(word[0], 0x11111111)
    lu.assertEquals(regs.GPR.n.t0, 0x1234)
    lu.assertEquals(PCSX.getRewindStateCount(), 0)
end

function TestRewind:test_ring_is_bounded_and_reuses_slots()
    while PCSX.getRewindStateCount() > 0 do PCSX.rewindState() end
    local word = ram32(0x1f0004)
    for i = 1, 70 do
        word[0] = i
        PCSX.createRewindState()
    end
    lu.assertEquals(PCSX.getRewindStateCount(), 60)
    lu.assertTrue(PCSX.rewindState())
    lu.assertEquals(word[0], 70)
    for i = 2, 60 do PCSX.rewindState() end
    lu.assertEquals(word[0], 11)
    lu.assertFalse(PCSX.rewindState())
end

-- Runs a few guest instructions that open a stack frame and spill ra, so the machine holds a
-- real call stack, then parks the cpu in a loop.
local function runIntoCallStack()
    local code = ram32(0x100000)
    code[0] = 0x27bdffe0 -- addiu sp, sp, -32
    code[1] = 0xafbf001c -- sw ra, 28(sp)
    code[2] = 0x08040002 -- j 0x80100008
    code[3] = 0x00000000 -- nop
    PCSX.invalidateCache()
    local regs = PCSX.getRegisters()
    regs.GPR.n.sp = 0x801fff00
    regs.GPR.n.ra = 0x80100100
    regs.pc = 0x80100000
    local co = coroutine.running()
    PCSX.nextTick(function()
        PCSX.pauseEmulator()
        coroutine.resume(co)
    end)
    PCSX.resumeEmulator()
    coroutine.yield()
end

-- Every capture into a recycled slot must replace what the slot held, not add to it. A slot
-- that accumulates feeds itself back through restore and doubles on every round trip.
function TestRewind:test_round_trips_on_recycled_slots_stay_flat()
    if PCSX.settings.emulator.Dynarec then lu.skip('only the interpreter records call stacks') end
    while PCSX.getRewindStateCount() > 0 do PCSX.rewindState() end
    local before = PCSX.createSaveState().size
    runIntoCallStack()
    local size = PCSX.createSaveState().size
    -- A few bytes of varint jitter between round trips are normal; a call stack is more.
    local slack = 16
    if size - before <= slack then lu.skip('no call stack was recorded, nothing could accumulate') end
    for i = 1, 32 do
        PCSX.createRewindState()
        lu.assertTrue(PCSX.rewindState())
        lu.assertTrue(math.abs(PCSX.createSaveState().size - size) <= slack, 'round trip ' .. i)
    end
end
