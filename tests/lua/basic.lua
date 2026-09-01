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

TestBasic = {}

function TestBasic:test_basic()
    lu.assertEquals(1, 1)
end

function TestBasic:test_coroutine()
    local testCoroutine = coroutine.running()
    PCSX.nextTick(function()
        coroutine.resume(testCoroutine, 42)
    end)
    local r = coroutine.yield()
    lu.assertEquals(r, 42)
end
