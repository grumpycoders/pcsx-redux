--lualoader, R"EOF(--

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

uint8_t* getMemPtr();
uint8_t* getRomPtr();
uint8_t* getScratchPtr();
psxRegisters* getRegisters();
void* addBreakpoint(uint32_t address, enum BreakpointType type, unsigned width, const char* cause, bool (*invoker)());
void enableBreakpoint(void*);
void disableBreakpoint(void*);
bool breakpointEnabled(void*);
void removeBreakpoint(void*);
void pauseEmulator();
void resumeEmulator();
void softResetEmulator();
void hardResetEmulator();
void luaMessage(const char* msg, bool error);
void luaLog(const char* msg);
void jumpToPC(uint32_t address);
void jumpToMemory(uint32_t address, unsigned width);
]]

local C = ffi.load 'PCSX'

local function garbageCollect(bp)
    C.removeBreakpoint(bp.wrapper)
    bp.invokercb:free()
end

local meta = { __gc = garbageCollect }

local function defaultInvoker()
    C.pauseEmulator()
    return true
end

local validBpTypes = {
    Exec = true,
    Read = true,
    Write = true,
}

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
        if type(invoker) ~= 'function' then
            error 'PCSX.addBreakpoint needs an invoker that is a function'
        end
        invokercb = function()
            local ret = invoker()
            if ret == false then return false else return true end
        end
    end
    local invokercb = ffi.cast('bool (*)()', invokercb)
    local wrapper = C.addBreakpoint(address, bptype, width, cause, invokercb)
    local bp = {
        wrapper = wrapper,
        invokercb = invokercb,
    }
    setmetatable(bp, meta)
    return bp
end

local function printLike(callback, ...)
    local s = ''
    for i, v in ipairs({...}) do
        s = s .. tostring(v) .. ' '
    end
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
    getMemPtr = function() return C.getMemPtr end,
    getRomPtr = function() return C.getRomPtr end,
    getScratchPtr = function() return C.getScratchPtr end,
    getRegisters = C.getRegisters,
    addBreakpoint = addBreakpoint,
    enableBreakpoint = function(bp) C.enableBreakpoint(bp.wrapper) end,
    disableBreakpoint = function(bp) C.disableBreakpoint(bp.wrapper) end,
    breakpointEnabled = function(bp) return C.breakpointEnabled(bp.wrapper) end,
    pauseEmulator = function() C.pauseEmulator() end,
    resumeEmulator = function() C.resumeEmulator() end,
    softResetEmulator = function() C.softResetEmulator() end,
    hardResetEmulator = function() C.hardResetEmulator() end,
    log = function(...) printLike(C.luaLog, ...) end,
    GUI = {
        jumpToPC = jumpToPC,
        jumpToMemory = jumpToMemory,
    },
}

print = function(...) printLike(function(s) C.luaMessage(s, false) end, ...) end
printError = function(...) printLike(function(s) C.luaMessage(s, true) end, ...) end

-- )EOF"
