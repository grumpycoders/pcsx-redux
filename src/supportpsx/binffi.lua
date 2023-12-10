-- lualoader, R"EOF(--
-- MIT License
--
-- Copyright (c) 2023 PCSX-Redux authors
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
local C = ffi.load 'SUPPORTPSX_BINARY'

ffi.cdef [[

enum Region { UNKNOWN, NTSC, PAL };

struct BinaryLoaderInfo {
    enum Region region;
    uint32_t pc;
    uint32_t sp;
    uint32_t gp;
};

struct PS1PackerOptions {
    uint32_t tload;
    bool shell;
    bool nopad;
    bool booty;
    bool raw;
    bool rom;
    bool cpe;
};

bool binaryLoaderLoad(LuaFile* src, LuaFile* dest, struct BinaryLoaderInfo* info);
void ps1PackerPack(LuaFile* src, LuaFile* dest, uint32_t addr, uint32_t pc, uint32_t gp, uint32_t sp,
          struct PS1PackerOptions options);
uint32_t uclPack(LuaFile* src, LuaFile* dest);
uint32_t writeUclDecomp(LuaFile* dest);

]]

PCSX.Binary = {}

PCSX.Binary.load = function(src, dest)
    if type(src) ~= 'table' or src._type ~= 'File' then error('Expected a File object as first argument') end
    if type(dest) ~= 'table' or dest._type ~= 'File' then error('Expected a File object as second argument') end
    local info = ffi.new('struct BinaryLoaderInfo')
    if not C.binaryLoaderLoad(src._wrapper, dest._wrapper, info) then return nil end
    local ret = {}
    if info.region ~= 'UNKNOWN' then ret.region = info.region end
    if info.pc ~= 0 then ret.pc = info.pc end
    if info.sp ~= 0 then ret.sp = info.sp end
    if info.gp ~= 0 then ret.gp = info.gp end
    return ret
end

PCSX.Binary.pack = function(src, dest, addr, pc, gp, sp, options)
    if type(src) ~= 'table' or src._type ~= 'File' then error('Expected a File object as first argument') end
    if type(dest) ~= 'table' or dest._type ~= 'File' then error('Expected a File object as second argument') end
    if type(addr) ~= 'number' then error('Expected a number as third argument') end
    if type(pc) ~= 'number' then error('Expected a number as fourth argument') end
    if gp == nil then gp = 0 end
    if type(gp) ~= 'number' then error('Expected a number as fifth argument') end
    if sp == nil then sp = 0 end
    if type(sp) ~= 'number' then error('Expected a number as sixth argument') end
    if options == nil then options = {} end
    if type(options) ~= 'table' then error('Expected a table as seventh argument') end
    local opts = ffi.new('struct PS1PackerOptions')
    opts.tload = options.tload and options.tload or 0
    opts.booty = options.booty and true or false
    opts.shell = options.shell and true or false
    opts.nopad = options.nopad and true or false
    opts.raw = options.raw and true or false
    opts.rom = options.rom and true or false
    opts.cpe = options.cpe and true or false
    C.ps1PackerPack(src._wrapper, dest._wrapper, addr, pc, gp, sp, opts)
end

PCSX.Binary.createExe = function(src, dest, addr, pc, gp, sp)
    if type(src) ~= 'table' or src._type ~= 'File' then error('Expected a File object as first argument') end
    if type(dest) ~= 'table' or dest._type ~= 'File' then error('Expected a File object as second argument') end
    if type(addr) ~= 'number' then error('Expected a number as third argument') end
    if type(pc) ~= 'number' then error('Expected a number as fourth argument') end
    if gp == nil then gp = 0 end
    if type(gp) ~= 'number' then error('Expected a number as fifth argument') end
    if sp == nil then sp = 0 end
    if type(sp) ~= 'number' then error('Expected a number as sixth argument') end

    local size = src:size()
    size = bit.band(size + 0x7ff, bit.bnot(0x7ff))

    dest:writeU32(0x582d5350)
    dest:writeU32(0x45584520)
    dest:writeU32(0)
    dest:writeU32(0)
    dest:writeU32(pc)
    dest:writeU32(gp)
    dest:writeU32(addr)
    dest:writeU32(size)
    dest:writeU32(0)
    dest:writeU32(0)
    dest:writeU32(0)
    dest:writeU32(0)
    dest:writeU32(sp)
    while dest:size() < 0x800 do dest:writeU8(0) end
    dest:write(src:read(src:size()))
    while bit.band(dest:size(), 0x7ff) ~= 0 do dest:writeU8(0) end
end

PCSX.Binary.createCpe = function(src, dest, addr, pc)
    if type(src) ~= 'table' or src._type ~= 'File' then error('Expected a File object as first argument') end
    if type(dest) ~= 'table' or dest._type ~= 'File' then error('Expected a File object as second argument') end
    if type(addr) ~= 'number' then error('Expected a number as third argument') end
    if type(pc) ~= 'number' then error('Expected a number as fourth argument') end

    local size = src:size()

    dest:writeU32(0x01455043)
    dest:writeU16(0x0008)
    dest:writeU8(3)
    dest:writeU16(0x0090)
    dest:writeU32(pc)
    dest:writeU8(1)
    dest:writeU32(addr)
    dest:writeU32(size)
    dest:write(src:read(src:size()))
    dest:writeU8(0)
end

if type(PCSX.Misc) ~= 'table' then PCSX.Misc = {} end

PCSX.Misc.uclPack = function(src, dest)
    if type(src) ~= 'table' or src._type ~= 'File' then error('Expected a File object as first argument') end
    if type(dest) ~= 'table' or dest._type ~= 'File' then error('Expected a File object as second argument') end
    return C.uclPack(src._wrapper, dest._wrapper)
end

PCSX.Misc.writeUclDecomp = function(dest)
    if type(dest) ~= 'table' or dest._type ~= 'File' then error('Expected a File object as first argument') end
    return C.writeUclDecomp(dest._wrapper)
end

-- )EOF"
