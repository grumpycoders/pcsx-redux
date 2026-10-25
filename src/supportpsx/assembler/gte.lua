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
local checkGPR = PCSX.Assembler.Internals.checks.gpr
local checkImm16 = PCSX.Assembler.Internals.checks.imm16
local checkGTE0 = PCSX.Assembler.Internals.checks.gte0
local checkGTE1 = PCSX.Assembler.Internals.checks.gte1

PCSX.Assembler.Internals.gteInstructions = {
    mfc2 = function(args)
        if #args ~= 2 then error('mfc2 takes two arguments') end
        return { base = 0x48000000, rt = checkGPR(args[1]), rd = checkGTE0(args[2]) }
    end,

    mtc2 = function(args)
        if #args ~= 2 then error('mtc2 takes two arguments') end
        return { base = 0x48800000, rt = checkGPR(args[1]), rd = checkGTE0(args[2]) }
    end,

    cfc2 = function(args)
        if #args ~= 2 then error('cfc2 takes two arguments') end
        return { base = 0x48400000, rt = checkGPR(args[1]), rd = checkGTE1(args[2]) }
    end,

    ctc2 = function(args)
        if #args ~= 2 then error('ctc2 takes two arguments') end
        return { base = 0x48c00000, rt = checkGPR(args[1]), rd = checkGTE1(args[2]) }
    end,

    lwc2 = function(args)
        if #args ~= 3 then error('lwc2 takes three arguments') end
        return { base = 0xc8000000, rt = checkGTE0(args[1]), imm16 = checkImm16(args[2]), rs = checkGPR(args[3]) }
    end,

    swc2 = function(args)
        if #args ~= 3 then error('swc2 takes three arguments') end
        return { base = 0xe8000000, rt = checkGTE0(args[1]), imm16 = checkImm16(args[2]), rs = checkGPR(args[3]) }
    end,

    rtps = function(args)
        if #args ~= 0 then error('rtps takes no arguments') end
        return { base = 0x4a180001 }
    end,

    nclip = function(args)
        if #args ~= 0 then error('nclip takes no arguments') end
        return { base = 0x4a180006 }
    end,

    op = function(args)
        if #args ~= 0 then error('op takes no arguments') end
        return { base = 0x4a18000c }
    end,

    dpcs = function(args)
        if #args ~= 0 then error('dpcs takes no arguments') end
        return { base = 0x4a180010 }
    end,

    intpl = function(args)
        if #args ~= 0 then error('intpl takes no arguments') end
        return { base = 0x4a180011 }
    end,

    -- mvmva sf, mx, v, cv, lm: sf shift (0/1), mx matrix (0 RT, 1 LLM, 2 LCM), v vector (0-2 V0-V2,
    -- 3 IR), cv translation (0 TR, 1 BK, 2 FC, 3 none), lm clamp (0/1). No arguments keeps the old
    -- default encoding.
    mvmva = function(args)
        if #args == 0 then return { base = 0x4a180012 } end
        if #args ~= 5 then error('mvmva takes zero or five arguments') end
        local limits = { 1, 3, 3, 3, 1 }
        for i, v in ipairs(args) do
            if type(v) ~= 'number' or v ~= math.floor(v) or v < 0 or v > limits[i] then
                error('Invalid mvmva argument ' .. i)
            end
        end
        local sf, mx, v, cv, lm = args[1], args[2], args[3], args[4], args[5]
        return {
            base = bit.bor(0x4a400012, bit.lshift(sf, 19), bit.lshift(mx, 17), bit.lshift(v, 15), bit.lshift(cv, 13),
                           bit.lshift(lm, 10)),
        }
    end,

    ncds = function(args)
        if #args ~= 0 then error('ncds takes no arguments') end
        return { base = 0x4a180013 }
    end,

    cdp = function(args)
        if #args ~= 0 then error('cdp takes no arguments') end
        return { base = 0x4a180014 }
    end,

    ncdt = function(args)
        if #args ~= 0 then error('ncdt takes no arguments') end
        return { base = 0x4a180016 }
    end,

    nccs = function(args)
        if #args ~= 0 then error('nccs takes no arguments') end
        return { base = 0x4a18001b }
    end,

    cc = function(args)
        if #args ~= 0 then error('cc takes no arguments') end
        return { base = 0x4a18001c }
    end,

    ncs = function(args)
        if #args ~= 0 then error('ncs takes no arguments') end
        return { base = 0x4a18001e }
    end,

    nct = function(args)
        if #args ~= 0 then error('nct takes no arguments') end
        return { base = 0x4a180020 }
    end,

    sqr = function(args)
        if #args ~= 0 then error('sqr takes no arguments') end
        return { base = 0x4a180028 }
    end,

    dcpl = function(args)
        if #args ~= 0 then error('dcpl takes no arguments') end
        return { base = 0x4a180029 }
    end,

    dpct = function(args)
        if #args ~= 0 then error('dpct takes no arguments') end
        return { base = 0x4a18002a }
    end,

    avsz3 = function(args)
        if #args ~= 0 then error('avsz3 takes no arguments') end
        return { base = 0x4a18002d }
    end,

    avsz4 = function(args)
        if #args ~= 0 then error('avsz4 takes no arguments') end
        return { base = 0x4a18002e }
    end,

    rtpt = function(args)
        if #args ~= 0 then error('rtpt takes no arguments') end
        return { base = 0x4a180030 }
    end,

    gpf = function(args)
        if #args ~= 0 then error('gpf takes no arguments') end
        return { base = 0x4a18003d }
    end,

    gpl = function(args)
        if #args ~= 0 then error('gpl takes no arguments') end
        return { base = 0x4a18003e }
    end,

    ncct = function(args)
        if #args ~= 0 then error('ncct takes no arguments') end
        return { base = 0x4a18003f }
    end,
}

-- )EOF"
