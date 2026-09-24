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

-- File viewers for the ISO browser: TIM images, and raw pixel data with a
-- user-supplied geometry. The ISO browser calls PCSX.FileViewers.open(file)
-- when the user asks to view a file, then calls draw() on the returned object
-- every frame inside its window, and close() once the window is closed.
--
-- Everything decodes into an RGBA buffer uploaded as a GL texture, re-uploaded
-- only when a knob changes. Sub-byte pixels are taken low bits first, as the
-- GPU stores them.

PCSX.FileViewers = PCSX.FileViewers or {}

local MAX_DIM = 4096

-- 15-bit colour to 0xAABBGGRR. 0x0000 is transparent, as the GPU treats it
-- when drawing textures.
local function psxColour(c)
    if c == 0 then return 0 end
    local r = c & 0x1f
    local g = (c >> 5) & 0x1f
    local b = (c >> 10) & 0x1f
    r = (r << 3) | (r >> 2)
    g = (g << 3) | (g >> 2)
    b = (b << 3) | (b >> 2)
    return 0xff000000 | (b << 16) | (g << 8) | r
end

local function grey(v, max)
    local g = math.floor(v * 255 / max)
    return 0xff000000 | (g << 16) | (g << 8) | g
end

-- A texture holder: upload(pix, w, h) replaces the content, draw(zoom) shows it.
local function newTexture()
    local t = {}
    function t:upload(pix, w, h)
        if not self.id then
            local id = ffi.new('GLuint[1]')
            gl.glGenTextures(1, id)
            self.id = id[0]
        end
        gl.glBindTexture(gl.GL_TEXTURE_2D, self.id)
        gl.glTexParameteri(gl.GL_TEXTURE_2D, gl.GL_TEXTURE_MIN_FILTER, gl.GL_NEAREST)
        gl.glTexParameteri(gl.GL_TEXTURE_2D, gl.GL_TEXTURE_MAG_FILTER, gl.GL_NEAREST)
        gl.glPixelStorei(gl.GL_UNPACK_ALIGNMENT, 4)
        gl.glTexImage2D(gl.GL_TEXTURE_2D, 0, gl.GL_RGBA, w, h, 0, gl.GL_RGBA, gl.GL_UNSIGNED_BYTE, pix)
        self.w, self.h = w, h
    end
    function t:draw(zoom)
        if self.id and self.w then imgui.Image(tonumber(self.id), self.w * zoom, self.h * zoom) end
    end
    function t:delete()
        if not self.id then return end
        local id = ffi.new('GLuint[1]', self.id)
        gl.glDeleteTextures(1, id)
        self.id = nil
    end
    return t
end

-- Reads `count` pixels of `bpp` bits starting at `byteOffset` into `data`,
-- calling put(index, value).
local function readPixels(data, size, byteOffset, bpp, count, put)
    if bpp >= 8 then
        local step = bpp / 8
        for i = 0, count - 1 do
            local p = byteOffset + i * step
            if p + step > size then return end
            local v
            if bpp == 8 then
                v = data[p]
            elseif bpp == 16 then
                v = data[p] + data[p + 1] * 256
            else
                v = data[p] + data[p + 1] * 256 + data[p + 2] * 65536
            end
            put(i, v)
        end
    else
        local perByte = 8 / bpp
        local mask = (1 << bpp) - 1
        for i = 0, count - 1 do
            local p = byteOffset + math.floor(i / perByte)
            if p >= size then return end
            local shift = (i % perByte) * bpp
            put(i, (data[p] >> shift) & mask)
        end
    end
end

-- Reads the first `limit` bytes of the file, or all of it if it is shorter.
local function readHead(file, limit)
    local size = math.min(file:size(), limit)
    return file:readAt(size, 0), size
end

local timBpp = { [0] = 4, [1] = 8, [2] = 16, [3] = 24 }

-- Returns a description of the TIM in `file`, or nil if it is not structurally
-- one. A TIM whose pixel block claims more bytes than the file holds is
-- returned with truncated = true.
function PCSX.FileViewers.parseTim(file)
    local size = file:size()
    if size < 20 or file:readU32At(0) ~= 0x10 then return nil end
    local flags = file:readU32At(4)
    if (flags & ~0xf) ~= 0 then return nil end
    local tim = { bpp = timBpp[flags & 3], hasClut = (flags & 8) ~= 0, size = size }
    local off = 8
    if tim.hasClut then
        local len = file:readU32At(off)
        local w, h = file:readU16At(off + 8), file:readU16At(off + 10)
        if len ~= 12 + w * h * 2 or off + len > size then return nil end
        tim.clut = { x = file:readU16At(off + 4), y = file:readU16At(off + 6), w = w, h = h, offset = off + 12 }
        off = off + len
    end
    if off + 12 > size then return nil end
    local len = file:readU32At(off)
    local w, h = file:readU16At(off + 8), file:readU16At(off + 10)
    if w == 0 or h == 0 then return nil end
    local expected = 12 + w * h * 2
    if len ~= expected then
        -- Some games ship a pixel block length field larger than the pixels,
        -- with w * h ending exactly at the end of the file. Accept that case
        -- and nothing looser.
        if off + expected ~= size then return nil end
        tim.badLength = len
    end
    tim.pix = { x = file:readU16At(off + 4), y = file:readU16At(off + 6), w = w, h = h, offset = off + 12 }
    tim.truncated = off + expected > size
    tim.width = math.floor(w * 16 / tim.bpp)
    tim.height = h
    tim.tooLarge = tim.width > MAX_DIM or tim.height > MAX_DIM
    if tim.clut and tim.bpp <= 8 then
        tim.paletteSize = tim.bpp == 4 and 16 or 256
        tim.palettes = math.max(1, math.floor(tim.clut.w * tim.clut.h / tim.paletteSize))
    end
    return tim
end

local function timInfo(tim)
    local lines = {
        string.format('%d bpp, %dx%d pixels, VRAM %d,%d', tim.bpp, tim.width, tim.height, tim.pix.x, tim.pix.y),
    }
    if tim.clut then
        lines[#lines + 1] = string.format('CLUT block %dx%d at VRAM %d,%d', tim.clut.w, tim.clut.h, tim.clut.x, tim.clut.y)
    end
    if tim.badLength then
        lines[#lines + 1] = string.format('Pixel block length field says %d, the pixels take %d.',
            tim.badLength, tim.pix.w * tim.pix.h * 2 + 12)
    end
    if tim.truncated then
        lines[#lines + 1] = string.format('Pixel block needs %d bytes, the file has %d.',
            tim.pix.w * tim.pix.h * 2 + 12, tim.size - tim.pix.offset + 12)
    end
    if tim.tooLarge then
        lines[#lines + 1] = string.format('Larger than %dx%d, not displayed.', MAX_DIM, MAX_DIM)
    end
    return table.concat(lines, '\n')
end

local function decodeTim(file, tim, palette)
    local data, size = readHead(file, tim.pix.offset + tim.pix.w * tim.pix.h * 2)
    local w, h = tim.width, tim.height
    local pix = ffi.new('uint32_t[?]', w * h)
    local lut
    if tim.paletteSize then
        lut = {}
        local base = tim.clut.offset + palette * tim.paletteSize * 2
        for i = 0, tim.paletteSize - 1 do
            local p = base + i * 2
            lut[i] = p + 1 < size and psxColour(data[p] + data[p + 1] * 256) or 0
        end
    end
    readPixels(data, size, tim.pix.offset, tim.bpp, w * h, function(i, v)
        if lut then
            pix[i] = lut[v] or 0
        elseif tim.bpp == 16 then
            pix[i] = psxColour(v)
        elseif tim.bpp == 24 then
            pix[i] = 0xff000000 | v
        else
            pix[i] = grey(v, (1 << tim.bpp) - 1)
        end
    end)
    return pix, w, h
end

-- Viewer for a structurally valid TIM. openFile() returns the file to decode.
function PCSX.FileViewers.timViewer(openFile, tim)
    local v = { name = 'TIM', palette = 0, zoom = 2, texture = newTexture() }
    function v.draw()
        imgui.TextUnformatted(timInfo(tim))
        if tim.truncated or tim.tooLarge then return end
        local dirty = not v.uploaded
        if tim.palettes and tim.palettes > 1 then
            local changed, n = imgui.SliderInt('palette', v.palette, 0, tim.palettes - 1)
            if changed then v.palette, dirty = n, true end
        end
        local zc, z = imgui.SliderInt('zoom', v.zoom, 1, 8)
        if zc then v.zoom = z end
        if dirty then
            local ok, err = pcall(function() v.texture:upload(decodeTim(openFile(), tim, v.palette)) end)
            v.err = not ok and tostring(err) or nil
            v.uploaded = true
        end
        if v.err then imgui.TextUnformatted('Error: ' .. v.err) end
        v.texture:draw(v.zoom)
    end
    function v.close() v.texture:delete() end
    return v
end

local rawBpps = { 1, 2, 4, 8, 16, 24 }

-- Viewer for arbitrary data with a user-supplied geometry.
function PCSX.FileViewers.rawViewer(openFile)
    local v = { name = 'Raw image', bppIndex = 4, width = 256, height = 0, header = 0, zoom = 2, texture = newTexture() }
    function v.draw()
        local dirty = not v.uploaded
        for i, b in ipairs(rawBpps) do
            if i > 1 then imgui.SameLine() end
            if imgui.RadioButton(b .. ' bpp', v.bppIndex == i) then
                if v.bppIndex ~= i then v.bppIndex, dirty = i, true end
            end
        end
        imgui.PushItemWidth(200)
        local c, n
        c, n = imgui.InputInt('width', v.width, 1, 16)
        if c then v.width, dirty = math.max(1, math.min(MAX_DIM, n)), true end
        c, n = imgui.InputInt('height (0 = fit)', v.height, 1, 16)
        if c then v.height, dirty = math.max(0, math.min(MAX_DIM, n)), true end
        c, n = imgui.InputInt('header bytes', v.header, 1, 16)
        if c then v.header, dirty = math.max(0, n), true end
        c, n = imgui.SliderInt('zoom', v.zoom, 1, 8)
        if c then v.zoom = n end
        imgui.PopItemWidth()
        if dirty then
            local ok, err = pcall(function()
                local file = openFile()
                local bpp = rawBpps[v.bppIndex]
                local w = v.width
                local available = math.max(0, file:size() - v.header)
                local h = v.height
                if h == 0 then h = math.ceil(available * 8 / bpp / w) end
                h = math.max(1, math.min(MAX_DIM, h))
                local data, size = readHead(file, v.header + math.ceil(w * h * bpp / 8))
                local pix = ffi.new('uint32_t[?]', w * h)
                local max = bpp <= 8 and ((1 << bpp) - 1) or nil
                readPixels(data, size, v.header, bpp, w * h, function(i, val)
                    if bpp == 16 then
                        pix[i] = 0xff000000 | psxColour(val)
                    elseif bpp == 24 then
                        pix[i] = 0xff000000 | val
                    else
                        pix[i] = grey(val, max)
                    end
                end)
                v.texture:upload(pix, w, h)
                v.info = string.format('%dx%d, %d bytes after the header', w, h, available)
            end)
            v.err = not ok and tostring(err) or nil
            v.uploaded = true
        end
        if v.info then imgui.TextUnformatted(v.info) end
        if v.err then imgui.TextUnformatted('Error: ' .. v.err) end
        v.texture:draw(v.zoom)
    end
    function v.close() v.texture:delete() end
    return v
end

-- Entry point for the ISO browser. `file` is the LuaFile pointer it hands
-- over. Returns an object with draw() and close().
function PCSX.FileViewers.open(file)
    file = Support.File._createFileWrapper(ffi.cast('LuaFile*', file))
    local function openFile() return file end
    local viewers = {}
    local tim = PCSX.FileViewers.parseTim(file)
    if tim then viewers[#viewers + 1] = PCSX.FileViewers.timViewer(openFile, tim) end
    viewers[#viewers + 1] = PCSX.FileViewers.rawViewer(openFile)
    local ret = {}
    function ret.draw()
        imgui.safe.BeginTabBar('viewers', function()
            for _, v in ipairs(viewers) do
                imgui.safe.BeginTabItem(v.name, function()
                    imgui.safe.BeginChild('view', 0, 0, 0, imgui.constant.WindowFlags.HorizontalScrollbar, v.draw)
                end)
            end
        end)
    end
    function ret.close()
        for _, v in ipairs(viewers) do v.close() end
        file:close()
    end
    return ret
end
