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
if not imgui.safe then imgui.safe = {} end

function imgui.safe.builder(proxy, finalIfShown, final)
    local function builder(...)
        local args = { ... }
        local lambda = args[#args]
        if type(lambda) ~= 'function' then error('Last argument must be a function') end
        args[#args] = nil
        local rets = { proxy(...) }
        local shown = rets[1]
        local status, err = pcall(function() lambda(table.unpack(args)) end)
        if shown and finalIfShown then finalIfShown() end
        if final then final() end
        if not status then error(err) end
        return table.unpack(rets)
    end
    return builder
end

imgui.safe.Begin = imgui.safe.builder(imgui.Begin, nil, imgui.End)
imgui.safe.BeginChild = imgui.safe.builder(imgui.BeginChild, imgui.EndChild)
imgui.safe.BeginChildFrame = imgui.safe.builder(imgui.BeginChildFrame, imgui.EndChildFrame)
imgui.safe.BeginChild_4 = imgui.safe.builder(imgui.BeginChild_4, imgui.EndChild)
imgui.safe.BeginCombo = imgui.safe.builder(imgui.BeginCombo, imgui.EndCombo)
imgui.safe.BeginDisabled = imgui.safe.builder(imgui.BeginDisabled, imgui.EndDisabled)
imgui.safe.BeginDragDropSource = imgui.safe.builder(imgui.BeginDragDropSource, imgui.EndDragDropSource)
imgui.safe.BeginDragDropTarget = imgui.safe.builder(imgui.BeginDragDropTarget, imgui.EndDragDropTarget)
imgui.safe.BeginGroup = imgui.safe.builder(imgui.BeginGroup, imgui.EndGroup)
imgui.safe.BeginListBox = imgui.safe.builder(imgui.BeginListBox, imgui.EndListBox)
imgui.safe.BeginMainMenuBar = imgui.safe.builder(imgui.BeginMainMenuBar, imgui.EndMainMenuBar)
imgui.safe.BeginMenu = imgui.safe.builder(imgui.BeginMenu, imgui.EndMenu)
imgui.safe.BeginMenuBar = imgui.safe.builder(imgui.BeginMenuBar, imgui.EndMenuBar)
imgui.safe.BeginPopup = imgui.safe.builder(imgui.BeginPopup, imgui.EndPopup)
imgui.safe.BeginPopupContextItem = imgui.safe.builder(imgui.BeginPopupContextItem, imgui.EndPopup)
imgui.safe.BeginPopupContextVoid = imgui.safe.builder(imgui.BeginPopupContextVoid, imgui.EndPopup)
imgui.safe.BeginPopupContextWindow = imgui.safe.builder(imgui.BeginPopupContextWindow, imgui.EndPopup)
imgui.safe.BeginPopupModal = imgui.safe.builder(imgui.BeginPopupModal, imgui.EndPopup)
imgui.safe.BeginTabBar = imgui.safe.builder(imgui.BeginTabBar, imgui.EndTabBar)
imgui.safe.BeginTabItem = imgui.safe.builder(imgui.BeginTabItem, imgui.EndTabItem)
imgui.safe.BeginTable = imgui.safe.builder(imgui.BeginTable, imgui.EndTable)
imgui.safe.BeginTooltip = imgui.safe.builder(imgui.BeginTooltip, imgui.EndTooltip)

-- )EOF"
