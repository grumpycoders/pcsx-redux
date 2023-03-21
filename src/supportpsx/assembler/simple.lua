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

local checkImm26 = PCSX.Assembler.Internals.checks.imm26
local checkBImm16 = PCSX.Assembler.Internals.checks.bimm16
local checkImm16 = PCSX.Assembler.Internals.checks.imm16
local checkGPR = PCSX.Assembler.Internals.checks.gpr

PCSX.Assembler.Internals.simpleInstructions = {
    j = function(args)
        if #args ~= 1 then
            error("j takes one argument")
        end
        return {
            base = 0x08000000,
            imm26 = checkImm26(args[1], 1),
        }
    end,

    jal = function(args)
        if #args ~= 1 then
            error("jal takes one argument")
        end
        return {
            base = 0x0c000000,
            imm26 = checkImm26(args[1], 1),
        }
    end,

    beq = function(args)
        if #args ~= 3 then
            error("beq takes three arguments")
        end
        return {
            base = 0x10000000,
            rs = checkGPR(args[1]),
            rt = checkGPR(args[2]),
            bimm16 = checkBImm16(args[3], 3),
        }
    end,

    bne = function(args)
        if #args ~= 3 then
            error("bne takes three arguments")
        end
        return {
            base = 0x14000000,
            rs = checkGPR(args[1]),
            rt = checkGPR(args[2]),
            bimm16 = checkBImm16(args[3], 3),
        }
    end,

    blez = function(args)
        if #args ~= 2 then
            error("blez takes two arguments")
        end
        return {
            base = 0x18000000,
            rs = checkGPR(args[1]),
            bimm16 = checkBImm16(args[2], 2),
        }
    end,

    bgtz = function(args)
        if #args ~= 2 then
            error("bgtz takes two arguments")
        end
        return {
            base = 0x1c000000,
            rs = checkGPR(args[1]),
            bimm16 = checkBImm16(args[2], 2),
        }
    end,

    addi = function(args)
        if #args < 2 or #args > 3 then
            error("addi takes two or three arguments")
        end
        if #args == 2 then
            return {
                base = 0x20000000,
                rt = checkGPR(args[1]),
                rs = checkGPR(args[1]),
                imm16 = checkImm16(args[2], 2),
            }
        end
        return {
            base = 0x20000000,
            rt = checkGPR(args[1]),
            rs = checkGPR(args[2]),
            imm16 = checkImm16(args[3], 3),
    }
    end,

    addiu = function(args)
        if #args < 2 or #args > 3 then
            error("addiu takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) == "string" then
                return {
                    base = 0x24000000,
                    rt = checkGPR(args[1]),
                    rs = checkGPR(args[1]),
                    lo16 = args[2]
                }
            end
            return {
                base = 0x24000000,
                rt = checkGPR(args[1]),
                rs = checkGPR(args[1]),
                imm16 = checkImm16(args[2], 2),
            }
        end
        if type(args[3]) == "string" then
            return {
                base = 0x24000000,
                rt = checkGPR(args[1]),
                rs = checkGPR(args[2]),
                lo16 = args[3]
            }
        end
        return {
            base = 0x24000000,
            rt = checkGPR(args[1]),
            rs = checkGPR(args[2]),
            imm16 = checkImm16(args[3], 3),
        }
    end,

    slti = function(args)
        if #args ~= 3 then
            error("slti takes three arguments")
        end
        return {
            base = 0x28000000,
            rt = checkGPR(args[1]),
            rs = checkGPR(args[2]),
            imm16 = checkImm16(args[3], 3),
        }
    end,

    sltiu = function(args)
        if #args ~= 3 then
            error("sltiu takes three arguments")
        end
        return {
            base = 0x2c000000,
            rt = checkGPR(args[1]),
            rs = checkGPR(args[2]),
            imm16 = checkImm16(args[3], 3),
        }
    end,

    andi = function(args)
        if #args < 2 or #args > 3 then
            error("andi takes two or three arguments")
        end
        if #args == 2 then
            return {
                base = 0x30000000,
                rt = checkGPR(args[1]),
                rs = checkGPR(args[1]),
                imm16 = checkImm16(args[2], 2),
            }
        end
        return {
            base = 0x30000000,
            rt = checkGPR(args[1]),
            rs = checkGPR(args[2]),
            imm16 = checkImm16(args[3], 3),
        }
    end,

    ori = function(args)
        if #args < 2 or #args > 3 then
            error("ori takes two or three arguments")
        end
        if #args == 2 then
            return {
                base = 0x34000000,
                rt = checkGPR(args[1]),
                rs = checkGPR(args[1]),
                imm16 = checkImm16(args[2], 2),
            }
        end
        return {
            base = 0x34000000,
            rt = checkGPR(args[1]),
            rs = checkGPR(args[2]),
            imm16 = checkImm16(args[3], 3),
        }
    end,

    xori = function(args)
        if #args < 2 or #args > 3 then
            error("xori takes two or three arguments")
        end
        if #args == 2 then
            return {
                base = 0x38000000,
                rt = checkGPR(args[1]),
                rs = checkGPR(args[1]),
                imm16 = checkImm16(args[2], 2),
            }
        end
        return {
            base = 0x38000000,
            rt = checkGPR(args[1]),
            rs = checkGPR(args[2]),
            imm16 = checkImm16(args[3], 3),
        }
    end,

    lui = function(args)
        if #args ~= 2 then
            error("lui takes two arguments")
        end
        if type(args[2]) == "string" then
            return {
                base = 0x3c000000,
                rt = checkGPR(args[1]),
                hi16 = args[2]
            }
        end
        return {
            base = 0x3c000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
        }
    end,
}

-- )EOF"
