--[[
MIT License

Copyright (c) 2025 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
--]]

-- This is the companion Lua script for the PCSX-Redux Lua editor demo.
-- See pcsxlua.cpp for the C++ side of the demo.

local addresses = {}
PCSX.execSlots[255] = function()
  local mem = PCSX.getMemPtr()
  local regs = PCSX.getRegisters().GPR.n
  local name = ffi.string(mem + bit.band(regs.a1, 0x7fffff))
  addresses[name] = regs.a0
end

function DrawImguiFrame()
  imgui.safe.Begin('Lua editor demo', true, function()
    local mem = PCSX.getMemoryAsFile()
    local addr = addresses['pcsxLuaScene.m_bg']
    if type(addr) == 'number' then
      local color = { r = mem:readU8At(addr + 0) / 255, g = mem:readU8At(addr + 1) / 255, b = mem:readU8At(addr + 2) / 255 }
      local modified, n = imgui.extra.ColorEdit3('bgColor', color)
      if modified then
        mem:writeU8At(n.r * 255, addr + 0)
        mem:writeU8At(n.g * 255, addr + 1)
        mem:writeU8At(n.b * 255, addr + 2)
      end
    end
  end)
end
