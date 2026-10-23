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


-- Drives the gdb server over a real socket: steps forward, then reverse-steps and
-- reverse-continues back over the same instructions, and expects the same registers.

local lu = require 'luaunit'
local ffi = require 'ffi'

TestGdbReverse = {}

local PORT = 3462
local CODE = 0x80100000

local function ram32(addr)
    return ffi.cast('uint32_t*', PCSX.getMemPtr() + (addr - 0x80000000))
end

local function j(addr) return 0x08000000 + bit.rshift(bit.band(addr, 0x0fffffff), 2) end

local client, co, buffer, packets

local function checksum(s)
    local sum = 0
    for i = 1, #s do sum = sum + s:byte(i) end
    return string.format('%02x', sum % 256)
end

local function parse()
    while true do
        buffer = buffer:gsub('^%++', '')
        local data, sum, rest = buffer:match('^%$([^#]*)#(%x%x)(.*)$')
        if not data then return end
        buffer = rest
        client:write('+')
        packets[#packets + 1] = data
    end
end

local function recv()
    while #packets == 0 do coroutine.yield() end
    return table.remove(packets, 1)
end

local function send(cmd)
    client:write('$' .. cmd .. '#' .. checksum(cmd))
end

local function command(cmd)
    send(cmd)
    return recv()
end

local function connect()
    co = coroutine.running()
    buffer, packets = '', {}
    client = luv.new_tcp()
    client:connect('127.0.0.1', PORT, function(err)
        lu.assertNil(err)
        client:read_start(function(rerr, chunk)
            if chunk then
                buffer = buffer .. chunk
                parse()
            end
            if coroutine.status(co) == 'suspended' then coroutine.resume(co) end
        end)
        coroutine.resume(co)
    end)
    coroutine.yield()
end

local savedDebug

function TestGdbReverse:setUp()
    if PCSX.settings.emulator.Dynarec then lu.skip('reverse execution needs the interpreter') end
    savedDebug = PCSX.settings.emulator.Debug.Debug
    PCSX.settings.emulator.Debug.Debug = true
    while PCSX.getRewindStateCount() > 0 do PCSX.rewindState() end
    -- A loop with no branch out of it, so every step stays on known code.
    local p = ram32(CODE)
    p[0] = 0x25080001 -- addiu t0, t0, 1
    p[1] = 0x25290003 -- addiu t1, t1, 3
    p[2] = j(CODE)
    p[3] = 0x00000000
    PCSX.invalidateCache()
    local regs = PCSX.getRegisters()
    regs.CP0.r[12] = bit.band(regs.CP0.r[12], bit.bnot(1))
    regs.pc = CODE
    PCSX.createRewindState()
    connect()
end

function TestGdbReverse:tearDown()
    if client then
        client:close()
        client = nil
    end
    if savedDebug ~= nil then PCSX.settings.emulator.Debug.Debug = savedDebug end
    savedDebug = nil
end

function TestGdbReverse:test_advertised()
    lu.assertStrContains(command('qSupported:multiprocess+'), 'ReverseStep+;ReverseContinue+')
end

function TestGdbReverse:test_reverse_step()
    local N = 12
    local regs = { command('g') }
    for i = 1, N do
        lu.assertEquals(command('s'), 'T05')
        regs[i + 1] = command('g')
    end
    for i = N, 1, -1 do
        lu.assertEquals(command('bs'), 'T05')
        lu.assertEquals(command('g'), regs[i], 'reverse step back to ' .. (i - 1))
    end
    -- Back on the snapshot itself: there is nothing older.
    lu.assertEquals(command('bs'), 'T05replaylog:begin;')
    lu.assertEquals(command('g'), regs[1])
end

function TestGdbReverse:test_reverse_continue()
    local N = 4
    lu.assertEquals(command('Z0,' .. string.format('%08x', CODE + 4) .. ',4'), 'OK')
    local hits = {}
    for i = 1, N do
        lu.assertEquals(command('c'), 'T05')
        hits[i] = command('g')
    end
    for i = N - 1, 1, -1 do
        lu.assertEquals(command('bc'), 'T05')
        lu.assertEquals(command('g'), hits[i], 'reverse continue back to hit ' .. i)
    end
    -- No hit between the snapshot and the first one: stops at the snapshot.
    lu.assertEquals(command('bc'), 'T05replaylog:begin;')
    lu.assertEquals(command('z0,' .. string.format('%08x', CODE + 4) .. ',4'), 'OK')
end

function TestGdbReverse:test_no_ring()
    while PCSX.getRewindStateCount() > 0 do PCSX.rewindState() end
    lu.assertEquals(command('bs'), 'E01')
    lu.assertEquals(command('bc'), 'E01')
end
