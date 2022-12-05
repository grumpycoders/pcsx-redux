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
local locSrcLoc = -1
local locSrcSize = -1
local locDstSize = -1
local locHardPix = -1
local locHardScan = -1
local locUseSrgb = -1
local locEnabled = -1
local locScanlines = -1

local function Reset()
    hardPix = 1.5
    hardScan = 4.5
    useSrgb = false
    enabled = true
    scanlines = true
    nearest = true
end

local function Constructor(shaderProgramID)
    locSrcLoc = gl.glGetUniformLocation(shaderProgramID, 'u_srcLoc')
    locSrcSize = gl.glGetUniformLocation(shaderProgramID, 'u_srcSize')
    locDstSize = gl.glGetUniformLocation(shaderProgramID, 'u_dstSize')
    locHardPix = gl.glGetUniformLocation(shaderProgramID, 'u_hardPix')
    locHardScan = gl.glGetUniformLocation(shaderProgramID, 'u_hardScan')
    locUseSrgb = gl.glGetUniformLocation(shaderProgramID, 'u_useSrgb')
    locEnabled = gl.glGetUniformLocation(shaderProgramID, 'u_enabled')
    locScanlines = gl.glGetUniformLocation(shaderProgramID, 'u_scanlines')
    Reset()
end

Constructor(shaderProgramID)

function Draw()
    if not configureme then return end
    local shoulddraw, lc
    local changed = false
    shoulddraw, configureme = imgui.Begin(t_('Offscreen CRT shader Configuration'), true)
    if not shoulddraw then
        imgui.End()
        return true
    end

    lc, enabled = imgui.Checkbox(t_('Enable gaussian blur'), enabled)
    if (lc) then changed = true end
    lc, hardPix = imgui.SliderFloat(t_('Hard Pixel factor'), hardPix, 0.0, 3, '%.3f')
    if (lc) then changed = true end
    lc, hardScan = imgui.SliderFloat(t_('Hard Scanline factor'), hardScan, 0.0, 20.0, '%.3f')
    if (lc) then changed = true end
    lc, scanlines = imgui.Checkbox(t_('Enable Scanlines'), scanlines)
    if (lc) then changed = true end
    lc, useSrgb = imgui.Checkbox(t_('Use S-rgb'), useSrgb)
    if (lc) then changed = true end
    lc, nearest = imgui.Checkbox(t_('Use Nearest'), nearest)
    if (lc) then changed = true end

    if (imgui.Button(t_('Reset to defaults'))) then
        Reset()
        changed = true
    end

    imgui.End()
    return changed
end

function BindAttributes(textureID, shaderProgramID, srcLocX, srcLocY, srcSizeX, srcSizeY, dstSizeX, dstSizeY)
    gl.glUniform2f(locSrcLoc, srcLocX, srcLocY)
    gl.glUniform2f(locSrcSize, srcSizeX, srcSizeY)
    gl.glUniform2f(locDstSize, dstSizeX, dstSizeY)
    gl.glUniform1f(locHardPix, -hardPix)
    gl.glUniform1f(locHardScan, -hardScan)
    gl.glUniform1i(locUseSrgb, useSrgb and 1 or 0)
    gl.glUniform1i(locEnabled, enabled and 1 or 0)
    gl.glUniform1f(locScanlines, scanlines)
    if nearest then
        gl.glTexParameteri(gl.GL_TEXTURE_2D, gl.GL_TEXTURE_MIN_FILTER, gl.GL_NEAREST)
        gl.glTexParameteri(gl.GL_TEXTURE_2D, gl.GL_TEXTURE_MAG_FILTER, gl.GL_NEAREST)
    else
        gl.glTexParameteri(gl.GL_TEXTURE_2D, gl.GL_TEXTURE_MIN_FILTER, gl.GL_LINEAR)
        gl.glTexParameteri(gl.GL_TEXTURE_2D, gl.GL_TEXTURE_MAG_FILTER, gl.GL_LINEAR)
    end
end

-- )EOF"
