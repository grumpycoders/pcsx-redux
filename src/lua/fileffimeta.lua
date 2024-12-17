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
local C = ffi.load 'SUPPORT_FILE'

local sliceMeta = {
    __tostring = function(slice) return ffi.string(C.getSliceData(slice._wrapper), C.getSliceSize(slice._wrapper)) end,
    __len = function(slice) return tonumber(C.getSliceSize(slice._wrapper)) end,
    __index = function(slice, index)
        if type(index) == 'number' and index >= 0 and index < C.getSliceSize(slice._wrapper) then
            local data = C.getSliceData(slice._wrapper)
            local buffer = ffi.cast('const uint8_t*', data)
            return buffer[index]
        elseif index == 'data' then
            return C.getSliceData(slice._wrapper)
        elseif index == 'size' then
            return tonumber(C.getSliceSize(slice._wrapper))
        end
        error('Unknown index `' .. index .. '` for LuaSlice')
    end,
    __newindex = function(slice, index, value) end,
}

local function createSliceWrapper(wrapper)
    local slice = { _wrapper = ffi.gc(wrapper, C.destroySlice), _type = 'Slice' }
    return setmetatable(slice, sliceMeta)
end

local bufferMeta = {
    __tostring = function(buffer) return ffi.string(buffer.data, buffer.size) end,
    __len = function(buffer) return buffer.size end,
    __index = function(buffer, index)
        if type(index) == 'number' and index >= 0 and index < buffer.size then
            return buffer.data[index]
        elseif index == 'maxsize' then
            return function(buffer) return ffi.sizeof(buffer) - 4 end
        elseif index == 'resize' then
            return function(buffer, size)
                if size > buffer:maxsize() then error('buffer size too large') end
                buffer.size = size
            end
        elseif index == 'pbSlice' then
            return Support._internal.createPBSliceFromBuffer(buffer)
        elseif index == 'cast' then
            return function(buffer, ctype)
                return ffi.cast(ctype, buffer.data)
            end
        end
        error('Unknown index `' .. index .. '` for LuaBuffer')
    end,
    __newindex = function(buffer, index, value)
        if type(index) == 'number' and index >= 0 and index < buffer.size then
            buffer.data[index] = value
        else
            error('Unknown or immutable index `' .. index .. '` for LuaBuffer')
        end
    end,
}

local LuaBuffer = ffi.metatype('LuaBuffer', bufferMeta)

Support.File._LuaBuffer = LuaBuffer
Support.File._createSliceWrapper = createSliceWrapper

-- )EOF"
