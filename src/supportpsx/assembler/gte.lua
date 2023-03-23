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

local checkGPR = PCSX.Assembler.Internals.checks.gpr
local checkImm16 = PCSX.Assembler.Internals.checks.imm16
local checkGTE0 = PCSX.Assembler.Internals.checks.gte0
local checkGTE1 = PCSX.Assembler.Internals.checks.gte1

PCSX.Assembler.Internals.gteInstructions = {
    mfc2 = function(args)
        if #args ~= 2 then
            error("mfc2 takes two arguments")
        end
        return {
            base = 0x44000000,
            rt = checkGPR(args[1]),
            rd = checkGTE0(args[2]),
        }
    end,

    mtc2 = function(args)
        if #args ~= 2 then
            error("mtc2 takes two arguments")
        end
        return {
            base = 0x44800000,
            rt = checkGPR(args[1]),
            rd = checkGTE0(args[2]),
        }
    end,

    cfc2 = function(args)
        if #args ~= 2 then
            error("cfc2 takes two arguments")
        end
        return {
            base = 0x44c00000,
            rt = checkGPR(args[1]),
            rd = checkGTE1(args[2]),
        }
    end,

    ctc2 = function(args)
        if #args ~= 2 then
            error("ctc2 takes two arguments")
        end
        return {
            base = 0x44e00000,
            rt = checkGPR(args[1]),
            rd = checkGTE1(args[2]),
        }
    end,

    lwc2 = function(args)
        if #args ~= 3 then
            error("lwc2 takes three arguments")
        end
        return {
            base = 0xc4000000,
            rt = checkGTE0(args[1]),
            imm16 = checkImm16(args[2]),
            rs = checkGPR(args[3]),
        }
    end,

    swc2 = function(args)
        if #args ~= 3 then
            error("swc2 takes three arguments")
        end
        return {
            base = 0xe4000000,
            rt = checkGTE0(args[1]),
            imm16 = checkImm16(args[2]),
            rs = checkGPR(args[3]),
        }
    end,

    rtps = function(args)
        if #args ~= 0 then
            error("rtps takes no arguments")
        end
        return {
            base = 0x4a180001,
        }
    end,

    nclip = function(args)
        if #args ~= 0 then
            error("nclip takes no arguments")
        end
        return {
            base = 0x4a180006,
        }
    end,

    op = function(args)
        if #args ~= 0 then
            error("op takes no arguments")
        end
        return {
            base = 0x4a18000c,
        }
    end,

    dpcs = function(args)
        if #args ~= 0 then
            error("dpcs takes no arguments")
        end
        return {
            base = 0x4a180010,
        }
    end,

    intpl = function(args)
        if #args ~= 0 then
            error("intpl takes no arguments")
        end
        return {
            base = 0x4a180011,
        }
    end,

    mvmva = function(args)
        if #args ~= 0 then
            error("mvmva takes no arguments")
        end
        return {
            base = 0x4a180012,
        }
    end,

    ncds = function(args)
        if #args ~= 0 then
            error("ncds takes no arguments")
        end
        return {
            base = 0x4a180013,
        }
    end,

    cdp = function(args)
        if #args ~= 0 then
            error("cdp takes no arguments")
        end
        return {
            base = 0x4a180014,
        }
    end,

    ncdt = function(args)
        if #args ~= 0 then
            error("ncdt takes no arguments")
        end
        return {
            base = 0x4a180016,
        }
    end,

    nccs = function(args)
        if #args ~= 0 then
            error("nccs takes no arguments")
        end
        return {
            base = 0x4a18001b,
        }
    end,

    cc = function(args)
        if #args ~= 0 then
            error("cc takes no arguments")
        end
        return {
            base = 0x4a18001c,
        }
    end,

    ncs = function(args)
        if #args ~= 0 then
            error("ncs takes no arguments")
        end
        return {
            base = 0x4a18001e,
        }
    end,

    nct = function(args)
        if #args ~= 0 then
            error("nct takes no arguments")
        end
        return {
            base = 0x4a180020,
        }
    end,

    sqr = function(args)
        if #args ~= 0 then
            error("sqr takes no arguments")
        end
        return {
            base = 0x4a180028,
        }
    end,

    dcpl = function(args)
        if #args ~= 0 then
            error("dcpl takes no arguments")
        end
        return {
            base = 0x4a180029,
        }
    end,

    dpct = function(args)
        if #args ~= 0 then
            error("dpct takes no arguments")
        end
        return {
            base = 0x4a18002a,
        }
    end,

    avsz3 = function(args)
        if #args ~= 0 then
            error("avsz3 takes no arguments")
        end
        return {
            base = 0x4a18002d,
        }
    end,

    avsz4 = function(args)
        if #args ~= 0 then
            error("avsz4 takes no arguments")
        end
        return {
            base = 0x4a18002e,
        }
    end,

    rtpt = function(args)
        if #args ~= 0 then
            error("rtpt takes no arguments")
        end
        return {
            base = 0x4a180030,
        }
    end,

    gpf = function(args)
        if #args ~= 0 then
            error("gpf takes no arguments")
        end
        return {
            base = 0x4a18003d,
        }
    end,

    gpl = function(args)
        if #args ~= 0 then
            error("gpl takes no arguments")
        end
        return {
            base = 0x4a18003e,
        }
    end,

    ncct = function(args)
        if #args ~= 0 then
            error("ncct takes no arguments")
        end
        return {
            base = 0x4a18003f,
        }
    end,
}

-- )EOF"
