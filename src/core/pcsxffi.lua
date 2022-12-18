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
ffi.cdef [[
typedef union {
    struct {
        uint32_t r0, at, v0, v1, a0, a1, a2, a3;
        uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
        uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
        uint32_t t8, t9, k0, k1, gp, sp, s8, ra;
        uint32_t lo, hi;
    } n;
    uint32_t r[34];
} psxGPRRegs;

typedef union {
    uint32_t r[32];
} psxCP0Regs;

typedef union {
    uint32_t r[32];
} psxCP2Data;

typedef union {
    uint32_t r[32];
} psxCP2Ctrl;

typedef struct {
    psxGPRRegs GPR;
    psxCP0Regs CP0;
    psxCP2Data CP2D;
    psxCP2Ctrl CP2C;
    uint32_t pc;
} psxRegisters;

enum BreakpointType { Exec, Read, Write };
typedef struct { uint8_t opaque[?]; } Breakpoint;

uint8_t* getMemPtr();
uint8_t* getRomPtr();
uint8_t* getScratchPtr();
psxRegisters* getRegisters();
Breakpoint* addBreakpoint(uint32_t address, enum BreakpointType type, unsigned width, const char* cause, bool (*invoker)(uint32_t address, unsigned width, const char* cause));
void enableBreakpoint(Breakpoint*);
void disableBreakpoint(Breakpoint*);
bool breakpointEnabled(Breakpoint*);
void removeBreakpoint(Breakpoint*);
void pauseEmulator();
void resumeEmulator();
void softResetEmulator();
void hardResetEmulator();
void luaMessage(const char* msg, bool error);
void luaLog(const char* msg);
void jumpToPC(uint32_t address);
void jumpToMemory(uint32_t address, unsigned width);

typedef enum { BPP_16, BPP_24 } ScreenShotBPP;

typedef struct {
    LuaSlice* data;
    uint16_t width, height;
    ScreenShotBPP bpp;
} LuaScreenShot;

LuaScreenShot takeScreenShot();

LuaSlice* createSaveState();
void loadSaveStateFromSlice(LuaSlice*);
void loadSaveStateFromFile(LuaFile*);
]]

local C = ffi.load 'PCSX'

local function removeBreakpoint(bp)
    C.removeBreakpoint(ffi.gc(bp._wrapper, nil))
    bp._wrapper = ffi.cast('Breakpoint*', 0)
    if bp._invokercb ~= nil then
        bp._invokercb:free()
        bp._invokercb = nil
    end
end

local function defaultInvoker(address, width, cause)
    C.pauseEmulator()
    return true
end

local validBpTypes = { Exec = true, Read = true, Write = true }

local function addBreakpoint(address, bptype, width, cause, invoker)
    if type(address) ~= 'number' then error 'PCSX.addBreakpoint needs an address' end
    if bptype == nil then bptype = 'Exec' end
    if not validBpTypes[bptype] then error 'PCSX.addBreakpoint needs a valid breakpoint type' end
    if width == nil then width = 4 end
    if type(width) ~= 'number' then error 'PCSX.addBreakpoint needs a width that is a number' end
    if cause == nil then cause = '' end
    if type(cause) == 'function' and invoker == nil then
        invoker = cause
        cause = ''
    end
    if type(cause) ~= 'string' then error 'PCSX.addBreakpoint needs a cause that is a string' end
    local invokercb = defaultInvoker
    if invoker ~= nil then
        if type(invoker) ~= 'function' then error 'PCSX.addBreakpoint needs an invoker that is a function' end
        invokercb = function(address, width, cause)
            cause = ffi.string(cause)
            local ret = invoker(address, width, cause)
            if ret == false then
                return false
            else
                return true
            end
        end
    end
    invokercb = ffi.cast('bool (*)(uint32_t address, unsigned width, const char* cause)', invokercb)
    local wrapper = C.addBreakpoint(address, bptype, width, cause, invokercb)
    local bp = {
        _wrapper = wrapper,
        _proxy = newproxy(),
        _invokercb = invokercb,
        enable = function(bp) C.enableBreakpoint(bp._wrapper) end,
        disable = function(bp) C.disableBreakpoint(bp._wrapper) end,
        isEnabled = function(bp) return C.breakpointEnabled(bp._wrapper) end,
        remove = function(bp) removeBreakpoint(bp) end,
    }
    -- Use a proxy instead of doing this on the wrapper directly using ffi.gc, because of a bug in LuaJIT,
    -- where circular references on finalizers using ffi.gc won't actually collect anything.
    debug.setmetatable(bp._proxy, { __gc = function() removeBreakpoint(bp) end })
    return bp
end

local function printLike(callback, ...)
    local s = ''
    for i, v in ipairs({ ... }) do s = s .. tostring(v) .. ' ' end
    callback(s)
end

local function jumpToPC(pc)
    if type(pc) ~= 'number' then error 'PCSX.GUI.jumpToPC requires a numeric address' end
    C.jumpToPC(pc)
end

local function jumpToMemory(address, width)
    if type(address) ~= 'number' then error 'PCSX.GUI.jumpToMemory requires a numeric address' end
    if width == nil then width = 1 end
    if type(width) ~= 'number' then error 'PCSX.GUI.jumpToMemory requires a numeric width' end
    C.jumpToMemory(address, width)
end

PCSX = {
    getMemPtr = function() return C.getMemPtr() end,
    getRomPtr = function() return C.getRomPtr() end,
    getScratchPtr = function() return C.getScratchPtr() end,
    getRegisters = function() return C.getRegisters() end,
    addBreakpoint = addBreakpoint,
    pauseEmulator = function() C.pauseEmulator() end,
    resumeEmulator = function() C.resumeEmulator() end,
    softResetEmulator = function() C.softResetEmulator() end,
    hardResetEmulator = function() C.hardResetEmulator() end,
    log = function(...) printLike(C.luaLog, ...) end,
    GUI = { jumpToPC = jumpToPC, jumpToMemory = jumpToMemory },
    nextTick = function(f)
        local oldCleanup = AfterPollingCleanup
        AfterPollingCleanup = function()
            if oldCleanup then oldCleanup() end
            f()
        end
    end,
    GPU = {
        takeScreenShot = function()
            local ss = C.takeScreenShot()
            return { data = Support.File._createSliceWrapper(ss.data), width = ss.width, height = ss.height, bpp = ss.bpp }
        end,
    },
    createSaveState = function()
        local slice = C.createSaveState()
        return Support.File._createSliceWrapper(slice)
    end,
    loadSaveState = function(obj)
        if type(obj) ~= 'table' then error('loadSaveState: requires an object as input') end
        if obj._type == 'Slice' then
            C.loadSaveStateFromSlice(obj._wrapper)
        elseif obj._type == 'File' then
            C.loadSaveStateFromFile(obj._wrapper)
        else
            error('loadSaveState: requires a Slice or File as input')
        end
    end,
}

print = function(...) printLike(function(s) C.luaMessage(s, false) end, ...) end
printError = function(...) printLike(function(s) C.luaMessage(s, true) end, ...) end

-- )EOF"
