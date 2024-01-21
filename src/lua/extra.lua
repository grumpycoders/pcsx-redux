-- lualoader, R"EOF(--
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
Support.extra = {

    loadfile = function(name)
        return loadstring(Support._internal.loadfile(name), '@' .. name)
    end,

    dofile = function(name)
        local func, msg = loadstring(Support._internal.loadfile(name), '@' .. name)
        if func then return func() end
        error(msg)
    end,

    open = function(name)
        return Support.File._createFileWrapper(ffi.cast('LuaFile*', Support._internal.open(name)))
    end,

    safeFFI = function(name, func, ...)
        local status, ret = pcall(func, ...)
        if status then return ret end
        error('FFI call failed in ' .. name .. ': ' .. ret)
    end

}
-- )EOF"
