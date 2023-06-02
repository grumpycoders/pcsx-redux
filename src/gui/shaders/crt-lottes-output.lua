-- lualoader, R"EOF(--
--   Copyright (C) 2022 PCSX-Redux authors
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
local locSrcSize = -1
local locDstSize = -1
local locWarp = -1
local locMask = -1
local locMaskType = -1
local locGrey = -1

local srcSize = { X = 0, Y = 0 }
local dstSize = { X = 0, Y = 0 }

local function Reset()
    warp = 1.0
    mask = 0.5
    masktype = 1
    grey = false
end

local function Constructor(shaderProgramID)
    locSrcSize = gl.glGetUniformLocation(shaderProgramID, 'u_srcSize')
    locDstSize = gl.glGetUniformLocation(shaderProgramID, 'u_dstSize')
    locWarp = gl.glGetUniformLocation(shaderProgramID, 'u_warp')
    locMask = gl.glGetUniformLocation(shaderProgramID, 'u_mask')
    locMaskType = gl.glGetUniformLocation(shaderProgramID, 'u_masktype')
    locGrey = gl.glGetUniformLocation(shaderProgramID, 'u_grey')
    Reset()
end
Constructor(shaderProgramID)

function Image(textureID, srcSizeX, srcSizeY, dstSizeX, dstSizeY)
    srcSize.X = srcSizeX
    srcSize.Y = srcSizeY
    dstSize.X = dstSizeX
    dstSize.Y = dstSizeY
    imgui.Image(textureID, dstSizeX, dstSizeY, 0, 0, 1, 1)
end

function Draw()
    if not configureme then return end
    local shoulddraw, lc
    local changed = false
    shoulddraw, configureme = imgui.Begin(t_('Output CRT Shader Configuration'), true)
    if not shoulddraw then
        imgui.End()
        return true
    end

    lc, warp = imgui.SliderFloat(t_('Warp intensity'), warp, 0.0, 8.0, '%0.3f')
    if (lc) then changed = true end
    lc, mask = imgui.SliderFloat(t_('Mask intensity'), mask, 0.0, 1.0, '%0.3f')
    if (lc) then changed = true end
    lc, grey = imgui.Checkbox(t_('Greyscale'), grey)
    if (lc) then changed = true end
    local masknames = { t_('Trinitron'), t_('Trinitron 2x'), t_('Trio') }
    local maskname = masknames[masktype]
    shoulddraw = imgui.BeginCombo(t_('Mask type'), maskname)
    if shoulddraw then
        for i = 1, 3 do
            if imgui.Selectable(masknames[i], i == masktype) then
                masktype = i
                changed = true
            end
        end
        imgui.EndCombo()
    end

    if (imgui.Button(t_('Reset to defaults'))) then
        Reset()
        changed = true
    end

    imgui.End()
    return changed
end

function BindAttributes(textureID, shaderProgramID)
    gl.glUniform2f(locSrcSize, srcSize.X, srcSize.Y)
    gl.glUniform2f(locDstSize, dstSize.X, dstSize.Y)
    gl.glUniform1f(locWarp, warp)
    gl.glUniform1f(locMask, mask)
    gl.glUniform1i(locMaskType, masktype)
    gl.glUniform1i(locGrey, grey and 1 or 0)
end

-- )EOF"
