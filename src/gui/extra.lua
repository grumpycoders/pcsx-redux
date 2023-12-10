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
PCSX.Helpers = PCSX.Helpers or {}
PCSX.Helpers.UI = {
    imageCoordinates = function(x, y, w, h, imageW, imageH)
        local cX, cY = imgui.GetCursorPos()
        local wX, wY = imgui.GetWindowPos()
        local viewportId = imgui.extra.getCurrentViewportId()
        local viewportPos = imgui.extra.getViewportPos(viewportId)
        cX = cX + wX - viewportPos.x + x / w * imageW
        cY = cY + wY - viewportPos.y + y / h * imageH
        return cX, cY
    end,
}

-- )EOF"
