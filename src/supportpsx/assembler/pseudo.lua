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

local bit = require("bit")

local checkGPR = PCSX.Assembler.Internals.checks.gpr
local checkBImm16 = PCSX.Assembler.Internals.checks.bimm16
local checkImm16 = PCSX.Assembler.Internals.checks.imm16

PCSX.Assembler.Internals.pseudoInstructions = {
    nop = function(args)
        if #args ~= 0 then
            error("nop takes no arguments")
        end
        return {
            base = 0x00000000,
        }
    end,

    move = function(args)
        if #args ~= 2 then
            error("move takes two arguments")
        end
        return {
            base = 0x00000021,
            rd = checkGPR(args[1]),
            rs = checkGPR(args[2]),
            rt = 0,
        }
    end,

    li = function(args)
        if #args ~= 2 then
            error("li takes two arguments")
        end
        if type(args[2]) ~= "number" then
            error("li second argument must be a number")
        end
        local imm = args[2]
        if imm < -0x8000 or imm > 0xffff then
            return {
                {
                    base = 0x3c000000,
                    rt = checkGPR(args[1]),
                    imm16 = bit.rshift(imm, 16),
                },
                {
                    base = 0x34000000,
                    rt = checkGPR(args[1]),
                    imm16 = bit.band(imm, 0xffff),
                },
            }
        else
            return {
                base = 0x3c000000,
                rt = checkGPR(args[1]),
                imm16 = args[2],
            }
        end
    end,

    la = function(args)
        if #args ~= 2 then
            error("la takes two arguments")
        end
        if type(args[2]) ~= "string" then
            error("la second argument must be a string")
        end
        return {
            {
                base = 0x3c000000,
                rt = checkGPR(args[1]),
                hi16 = args[2],
            },
            {
                base = 0x24000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
            },
        }
    end,

    not_ = function(args)
        if #args < 1 or #args > 2 then
            error("not takes one or two arguments")
        end
        if #args == 1 then
            return {
                base = 0x00000027,
                rd = checkGPR(args[1]),
                rs = checkGPR(args[1]),
                rt = 0,
            }
        end
        return {
            base = 0x00000027,
            rd = checkGPR(args[1]),
            rs = checkGPR(args[2]),
            rt = 0,
        }
    end,

    neg = function(args)
        if #args < 1 or #args > 2 then
            error("neg takes one or two arguments")
        end
        if #args == 1 then
            return {
                base = 0x00000023,
                rd = checkGPR(args[1]),
                rs = 0,
                rt = checkGPR(args[1]),
            }
        end
        return {
            base = 0x00000023,
            rd = checkGPR(args[1]),
            rs = 0,
            rt = checkGPR(args[2]),
        }
    end,

    b = function(args)
        if #args ~= 1 then
            error("b takes one argument")
        end
        return {
            base = 0x10000000,
            imm16 = checkBImm16(args[1], 1),
        }
    end,

    bal = function(args)
        if #args ~= 1 then
            error("bal takes one argument")
        end
        return {
            base = 0x04110000,
            imm16 = checkBImm16(args[1], 1),
        }
    end,

    blt = function(args)
        if #args ~= 3 then
            error("blt takes three arguments")
        end
        return {
            {
                base = 0x0000002a,
                rd = 1,
                rs = checkGPR(args[1]),
                rt = checkGPR(args[2]),
            },
            {
                base = 0x14000000,
                rs = 1,
                rt = 0,
                imm16 = checkBImm16(args[3], 2),
            },
        }
    end,

    bltu = function(args)
        if #args ~= 3 then
            error("bltu takes three arguments")
        end
        return {
            {
                base = 0x0000002b,
                rd = 1,
                rs = checkGPR(args[1]),
                rt = checkGPR(args[2]),
            },
            {
                base = 0x14000000,
                rs = 1,
                rt = 0,
                imm16 = checkBImm16(args[3], 2),
            },
        }
    end,

    bgt = function(args)
        if #args ~= 3 then
            error("bgt takes three arguments")
        end
        return {
            {
                base = 0x0000002a,
                rd = 1,
                rs = checkGPR(args[1]),
                rt = checkGPR(args[2]),
            },
            {
                base = 0x14000000,
                rs = 1,
                rt = 0,
                imm16 = checkBImm16(args[3], 2),
            },
        }
    end,

    bgtu = function(args)
        if #args ~= 3 then
            error("bgtu takes three arguments")
        end
        return {
            {
                base = 0x0000002b,
                rd = 1,
                rs = checkGPR(args[1]),
                rt = checkGPR(args[2]),
            },
            {
                base = 0x14000000,
                rs = 1,
                rt = 0,
                imm16 = checkBImm16(args[3], 2),
            },
        }
    end,

    beq = function(args)
        if #args ~= 3 then
            error("beq takes three arguments")
        end
        return {
            {
                base = 0x10000000,
                rs = checkGPR(args[1]),
                rt = checkGPR(args[2]),
                imm16 = checkBImm16(args[3], 1),
            },
        }
    end,

    ulw = function(args)
        if #args ~= 3 then
            error("ulw takes three arguments")
        end
        if type(args[2]) == "string" then
            return {
                {
                    base = 0x88000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[3]),
                },
                {
                    base = 0x98000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[3]),
                },
            }
        end
        return {
            {
                base = 0x88000000,
                rt = checkGPR(args[1]),
                imm16 = checkImm16(args[2], 2),
                rs = checkGPR(args[3]),
            },
            {
                base = 0x98000000,
                rt = checkGPR(args[1]),
                imm16 = checkImm16(args[2], 2),
                rs = checkGPR(args[3]),
            },
        }
    end,

    usw = function(args)
        if #args ~= 3 then
            error("usw takes three arguments")
        end
        if type(args[2]) == "string" then
            return {
                {
                    base = 0xa8000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[3]),
                },
                {
                    base = 0xb8000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[3]),
                },
            }
        end
        return {
            {
                base = 0xa8000000,
                rt = checkGPR(args[1]),
                imm16 = checkImm16(args[2], 2),
                rs = checkGPR(args[3]),
            },
            {
                base = 0xb8000000,
                rt = checkGPR(args[1]),
                imm16 = checkImm16(args[2], 2),
                rs = checkGPR(args[3]),
            },
        }
    end,

    subi = function(args)
        if #args < 2 or #args > 3 then
            error("subi takes two or three arguments")
        end
        if #args == 2 then
            return {
                base = 0x24000000,
                rt = checkGPR(args[1]),
                rs = checkGPR(args[1]),
                imm16 = checkImm16(-args[2], 1),
            }
        end
        return {
            base = 0x24000000,
            rt = checkGPR(args[1]),
            rs = checkGPR(args[2]),
            imm16 = checkImm16(-args[3], 1),
        }
    end,
}

for k, v in pairs(PCSX.Assembler.Internals.pseudoInstructions) do
    if k:sub(-1) == "_" then
        local newKey = k:sub(1, -2)
        PCSX.Assembler.Internals.pseudoInstructions[newKey] = v
        PCSX.Assembler.Internals.pseudoInstructions[k] = nil
    end
end

-- )EOF"
