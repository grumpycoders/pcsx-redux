-- lualoader, R"EOF(--
--   Copyright (C) 2023 PCSX-Redux authors
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
ffi.cdef [[
typedef struct { float x, y; } ImVec2;

unsigned imguiGetCurrentViewportId();
unsigned imguiGetViewportFlags(unsigned id);
void imguiSetViewportFlags(unsigned id, unsigned flags);
void imguiGetViewportPos(unsigned id, ImVec2*);
void imguiGetViewportSize(unsigned id, ImVec2*);
void imguiGetViewportWorkPos(unsigned id, ImVec2*);
void imguiGetViewportWorkSize(unsigned id, ImVec2*);
float imguiGetViewportDpiScale(unsigned id);
]]

local C = ffi.load 'IMGUIEXTRA'

imgui.extra = {
    ImVec2 = {
        New = function(x, y)
            local ret = ffi.new('ImVec2')
            ret.x = x or 0
            ret.y = y or 0
            return ret
        end,
    },
    getCurrentViewportId = C.imguiGetCurrentViewportId,
    getViewportFlags = C.imguiGetViewportFlags,
    setViewportFlags = C.imguiSetViewportFlags,
    getViewportPos = function(id)
        local ret = ffi.new('ImVec2[1]')
        C.imguiGetViewportPos(id, ret)
        return ret[0]
    end,
    getViewportSize = function(id)
        local ret = ffi.new('ImVec2[1]')
        C.imguiGetViewportSize(id, ret)
        return ret[0]
    end,
    getViewportWorkPos = function(id)
        local ret = ffi.new('ImVec2[1]')
        C.imguiGetViewportWorkPos(id, ret)
        return ret[0]
    end,
    getViewportWorkSize = function(id)
        local ret = ffi.new('ImVec2[1]')
        C.imguiGetViewportWorkSize(id, ret)
        return ret[0]
    end,
    getViewportDpiScale = C.imguiGetViewportDpiScale,
}

-- )EOF"
