-- lualoader, R"EOF(--
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
if not implot.safe then implot.safe = {} end

-- Same contract as imgui.safe.builder in gui/imguisafe.lua, which is reused
-- when the imgui safe helpers are loaded.
local builder = imgui and imgui.safe and imgui.safe.builder
if not builder then
    builder = function(proxy, finalIfShown, final)
        return function(...)
            local n = select('#', ...)
            local args = { ... }
            local lambda = args[n]
            if type(lambda) ~= 'function' then error('Last argument must be a function') end
            local rets = { proxy(unpack(args, 1, n - 1)) }
            local shown = rets[1]
            local status, err = true
            if shown then
                status, err = pcall(function() lambda(unpack(args, 1, n - 1)) end)
                if finalIfShown then finalIfShown() end
            end
            if final then final() end
            if not status then error(err) end
            return unpack(rets)
        end
    end
end

-- ImPlot requires each End call only when the matching Begin returned true.
implot.safe.BeginPlot = builder(implot.BeginPlot, implot.EndPlot)
implot.safe.BeginSubplots = builder(implot.BeginSubplots, implot.EndSubplots)
implot.safe.BeginAlignedPlots = builder(implot.BeginAlignedPlots, implot.EndAlignedPlots)
implot.safe.BeginLegendPopup = builder(implot.BeginLegendPopup, implot.EndLegendPopup)
implot.safe.BeginDragDropTargetPlot = builder(implot.BeginDragDropTargetPlot, implot.EndDragDropTarget)
implot.safe.BeginDragDropTargetAxis = builder(implot.BeginDragDropTargetAxis, implot.EndDragDropTarget)
implot.safe.BeginDragDropTargetLegend = builder(implot.BeginDragDropTargetLegend, implot.EndDragDropTarget)
implot.safe.BeginDragDropSourcePlot = builder(implot.BeginDragDropSourcePlot, implot.EndDragDropSource)
implot.safe.BeginDragDropSourceAxis = builder(implot.BeginDragDropSourceAxis, implot.EndDragDropSource)
implot.safe.BeginDragDropSourceItem = builder(implot.BeginDragDropSourceItem, implot.EndDragDropSource)

-- )EOF"
