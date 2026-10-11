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

TestCallGuest = {}

local CODE = 0x80100000
local SRC = 0x80140000
local DST = 0x80160000

local function ram32(addr)
    return ffi.cast('uint32_t*', PCSX.getMemPtr() + (addr - 0x80000000))
end

local function ram8(addr)
    return ffi.cast('uint8_t*', PCSX.getMemPtr() + (addr - 0x80000000))
end

local function poke(addr, words)
    local p = ram32(addr)
    for i, w in ipairs(words) do p[i - 1] = w end
end

local function writeLutMapped()
    return ffi.cast('void**', PCSX.getWriteLUT())[0x8000] ~= nil
end

-- The recompilers can't stop on an arbitrary pc, so under them callGuest must refuse.
local function interpreter()
    poke(CODE, { 0x03e00008, 0x00000000 }) -- jr ra ; nop
    local ok, err = pcall(PCSX.callGuest, { pc = CODE })
    if ok then return true end
    lu.assertStrContains(tostring(err), 'needs the interpreter')
    return false
end

-- A cold machine boots with the caches isolated, which nulls the RAM write LUT and makes
-- every guest store vanish. This is the BIOS reset code's BIU write; it's what makes stores land.
local function enableStores()
    poke(CODE, { 0x3c080001, 0x3508e988, 0x3c01fffe, 0xac280130, 0x03e00008, 0x00000000 })
    local r = PCSX.callGuest { pc = CODE }
    lu.assertEquals(r.status, 'returned')
    lu.assertFalse(r.storesDropped)
end

function TestCallGuest:test_refuses_without_interpreter()
    if interpreter() then lu.skip('running on the interpreter') end
end

function TestCallGuest:test_stores_dropped_tracks_the_write_lut()
    if not interpreter() then lu.skip('needs the interpreter') end
    poke(CODE, { 0x03e00008, 0x00000000 }) -- jr ra ; nop
    local mapped = writeLutMapped()
    local r = PCSX.callGuest { pc = CODE }
    lu.assertEquals(r.storesDropped, not mapped)
    enableStores()
    lu.assertTrue(writeLutMapped())
end

function TestCallGuest:test_returns_value_and_restores_cpu()
    if not interpreter() then lu.skip('needs the interpreter') end
    local regs = PCSX.getRegisters()
    regs.GPR.n.t0 = 0x12345678
    regs.GPR.n.ra = 0xdeadbee0
    local pcBefore = regs.pc
    poke(CODE, { 0x03e00008, 0x00851021 }) -- jr ra ; addu v0,a0,a1
    local r = PCSX.callGuest { pc = CODE, args = { 40, 2 } }
    lu.assertEquals(r.status, 'returned')
    lu.assertEquals(r.v0, 42)
    lu.assertEquals(r.depth, 0)
    lu.assertTrue(r.cycles > 0)
    lu.assertEquals(regs.GPR.n.t0, 0x12345678)
    lu.assertEquals(regs.GPR.n.ra, 0xdeadbee0)
    lu.assertEquals(regs.pc, pcBefore)
end

function TestCallGuest:test_fifth_argument_goes_on_the_stack()
    if not interpreter() then lu.skip('needs the interpreter') end
    -- The fifth argument is written through the bus, so on a cold machine it would vanish.
    enableStores()
    poke(CODE, { 0x8fa20010, 0x00000000, 0x03e00008, 0x00000000 }) -- lw v0,16(sp) ; nop ; jr ra ; nop
    local r = PCSX.callGuest { pc = CODE, args = { 1, 2, 3, 4, 0xcafe } }
    lu.assertEquals(r.status, 'returned')
    lu.assertEquals(r.v0, 0xcafe)
end

function TestCallGuest:test_runaway_callee_runs_out_of_cycles()
    if not interpreter() then lu.skip('needs the interpreter') end
    local regs = PCSX.getRegisters()
    local pcBefore = regs.pc
    poke(CODE, { 0x1000ffff, 0x00000000 }) -- b . ; nop
    local r = PCSX.callGuest { pc = CODE, cycles = 10000 }
    lu.assertEquals(r.status, 'cycles')
    lu.assertTrue(r.pc == CODE or r.pc == CODE + 4)
    lu.assertEquals(regs.pc, pcBefore)
end

function TestCallGuest:test_faulting_callee_reports_the_exception()
    if not interpreter() then lu.skip('needs the interpreter') end
    local regs = PCSX.getRegisters()
    local pcBefore = regs.pc
    poke(CODE, { 0x8c020001, 0x00000000, 0x03e00008, 0x00000000 }) -- lw v0,1(zero) ; nop ; jr ra ; nop
    local r = PCSX.callGuest { pc = CODE }
    lu.assertEquals(r.status, 'exception')
    lu.assertEquals(r.exceptionCode, 4) -- AdEL
    lu.assertEquals(r.epc, CODE)
    lu.assertEquals(r.badVAddr, 1)
    lu.assertEquals(regs.pc, pcBefore)
end

function TestCallGuest:test_rejects_bad_arguments()
    lu.assertFalse(pcall(PCSX.callGuest, {}))
    lu.assertFalse(pcall(PCSX.callGuest, { pc = CODE + 2 }))
    lu.assertFalse(pcall(PCSX.callGuest, { pc = CODE, ra = 0x8f000001 }))
    lu.assertFalse(pcall(PCSX.callGuest, { pc = CODE, sp = 0x801ffff4 }))
    lu.assertFalse(pcall(PCSX.callGuest, { pc = CODE, isolate = 1 }))
    lu.assertFalse(pcall(PCSX.callGuest, { pc = CODE, isolate = 'disk' }))
    lu.assertFalse(pcall(PCSX.callGuest, { pc = CODE, args = 3 }))
end

-- memcpy(a1, a0, a2) a byte at a time.
local COPIER = {
    0x90880000, -- loop: lbu t0,0(a0)
    0x24c6ffff, --       addiu a2,a2,-1
    0xa0a80000, --       sb t0,0(a1)
    0x24840001, --       addiu a0,a0,1
    0x14c0fffb, --       bnez a2,loop
    0x24a50001, --       addiu a1,a1,1
    0x03e00008, --       jr ra
    0x00000000, --       nop
}

local function payload(n)
    local t = {}
    for i = 1, n do t[i] = string.char((i * 7 + 3) & 0xff) end
    return table.concat(t)
end

function TestCallGuest:test_stage_fetch_without_isolation_keeps_the_writes()
    if not interpreter() then lu.skip('needs the interpreter') end
    enableStores()
    poke(CODE, COPIER)
    local data = payload(256)
    ffi.fill(ram8(DST), 256, 0)
    local r = PCSX.callGuest {
        pc = CODE, args = { SRC, DST, #data }, dirty = true,
        stage = { { addr = SRC, data = data } },
        fetch = { { addr = DST, size = #data } },
    }
    lu.assertEquals(r.status, 'returned')
    lu.assertEquals(r.out[1], data)
    lu.assertEquals(r.dirty, { 0x80160000 })
    lu.assertEquals(ffi.string(ram8(DST), #data), data)
end

function TestCallGuest:test_ram_isolation_rolls_back_writes_and_staging()
    if not interpreter() then lu.skip('needs the interpreter') end
    enableStores()
    poke(CODE, COPIER)
    local data = payload(256)
    local srcBefore = string.rep('S', 256)
    local dstBefore = string.rep('D', 256)
    ffi.copy(ram8(SRC), srcBefore, 256)
    ffi.copy(ram8(DST), dstBefore, 256)
    local r = PCSX.callGuest {
        pc = CODE, args = { SRC, DST, #data }, isolate = 'ram',
        stage = { { addr = SRC, data = data } },
        fetch = { { addr = DST, size = #data } },
    }
    lu.assertEquals(r.status, 'returned')
    lu.assertEquals(r.out[1], data)
    -- Only the page the callee wrote, not the one we staged into.
    lu.assertEquals(r.dirty, { 0x80160000 })
    lu.assertEquals(r.nonRamAccesses, 0)
    lu.assertEquals(ffi.string(ram8(DST), 256), dstBefore)
    lu.assertEquals(ffi.string(ram8(SRC), 256), srcBefore)
end

function TestCallGuest:test_full_isolation_rolls_back_writes()
    if not interpreter() then lu.skip('needs the interpreter') end
    enableStores()
    poke(CODE, COPIER)
    local data = payload(64)
    local dstBefore = string.rep('F', 64)
    ffi.copy(ram8(DST), dstBefore, 64)
    local r = PCSX.callGuest {
        pc = CODE, args = { SRC, DST, #data }, isolate = 'full',
        stage = { { addr = SRC, data = data } },
        fetch = { { addr = DST, size = #data } },
    }
    lu.assertEquals(r.status, 'returned')
    lu.assertEquals(r.out[1], data)
    lu.assertEquals(ffi.string(ram8(DST), 64), dstBefore)
end

function TestCallGuest:test_hardware_access_is_counted()
    if not interpreter() then lu.skip('needs the interpreter') end
    -- lui at,0x1f80 ; lw v0,0x1070(at) ; nop ; jr ra ; nop
    poke(CODE, { 0x3c011f80, 0x8c221070, 0x00000000, 0x03e00008, 0x00000000 })
    local r = PCSX.callGuest { pc = CODE, isolate = 'ram' }
    lu.assertEquals(r.status, 'returned')
    lu.assertTrue(r.nonRamAccesses > 0)
    -- And the scratchpad, which a RAM snapshot covers, doesn't count.
    -- lui at,0x1f80 ; lw v0,0x10(at) ; nop ; jr ra ; nop
    poke(CODE, { 0x3c011f80, 0x8c220010, 0x00000000, 0x03e00008, 0x00000000 })
    r = PCSX.callGuest { pc = CODE, isolate = 'ram' }
    lu.assertEquals(r.nonRamAccesses, 0)
end

-- restoreState() from a vsync listener runs in the middle of Counters::update(). Like a save
-- state load, it has to wait for the main loop rather than swap the state under that frame.
function TestCallGuest:test_restore_state_waits_for_the_main_loop()
    local loop = CODE + 0x200
    poke(loop, { 0x08000000 + ((loop & 0x0fffffff) >> 2), 0x00000000 }) -- j loop ; nop
    PCSX.invalidateCache()
    PCSX.getRegisters().pc = loop
    local word = ram32(0x801f0010)
    word[0] = 0x11111111
    PCSX.captureState()
    word[0] = 0x22222222

    local co = coroutine.running()
    local r = { inListener = false }
    local loaded = PCSX.Events.createEventListener('ExecutionFlow::SaveStateLoaded', function()
        r.loadedInListener = r.inListener
        r.loaded = true
    end)
    local vsync
    vsync = PCSX.Events.createEventListener('GPU::Vsync', function()
        if not r.asked then
            r.asked = true
            r.inListener = true
            PCSX.restoreState()
            r.inListener = false
            r.wordAfterCall = word[0]
            r.captureError = select(2, pcall(PCSX.captureState))
        elseif r.loaded then
            vsync:remove()
            loaded:remove()
            PCSX.pauseEmulator()
            -- The first event loop tick after a vsync pause still runs on the emulation stack.
            local timer, ticks = luv.new_timer(), 0
            timer:start(0, 1, function()
                ticks = ticks + 1
                if ticks < 2 then return end
                timer:stop()
                timer:close()
                coroutine.resume(co)
            end)
        end
    end)
    PCSX.resumeEmulator()
    coroutine.yield()

    lu.assertEquals(r.wordAfterCall, 0x22222222)
    lu.assertStrContains(tostring(r.captureError), 'still waiting for the main loop')
    lu.assertFalse(r.loadedInListener, 'state replaced under the vsync listener')
    lu.assertEquals(word[0], 0x11111111)
end
