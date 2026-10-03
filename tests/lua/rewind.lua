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
