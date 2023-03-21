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

local checkImm16 = PCSX.Assembler.Internals.checks.imm16
local checkGPR = PCSX.Assembler.Internals.checks.gpr

PCSX.Assembler.Internals.loadAndStoreInstructions = {
    lb = function(args)
        if #args < 2 or #args > 3 then
            error("lb takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("lb takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = checkGPR(args[1]),
                    hi16 = args[2],
                },
                {
                    base = 0x80000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[1]),
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0x80000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0x80000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    lh = function(args)
        if #args < 2 or #args > 3 then
            error("lh takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("lh takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = checkGPR(args[1]),
                    hi16 = args[2],
                },
                {
                    base = 0x84000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[1]),
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0x84000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0x84000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    lwl = function(args)
        if #args < 2 or #args > 3 then
            error("lwl takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("lwl takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = checkGPR(args[1]),
                    hi16 = args[2],
                },
                {
                    base = 0x88000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[1]),
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0x88000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0x88000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    lw = function(args)
        if #args < 2 or #args > 3 then
            error("lw takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("lw takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = checkGPR(args[1]),
                    hi16 = args[2],
                },
                {
                    base = 0x8c000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[1]),
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0x8c000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0x8c000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    lbu = function(args)
        if #args < 2 or #args > 3 then
            error("lbu takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("lbu takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = checkGPR(args[1]),
                    hi16 = args[2],
                },
                {
                    base = 0x90000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[1]),
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0x90000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0x90000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    lhu = function(args)
        if #args < 2 or #args > 3 then
            error("lhu takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("lhu takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = checkGPR(args[1]),
                    hi16 = args[2],
                },
                {
                    base = 0x94000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[1]),
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0x94000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0x94000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    lwr = function(args)
        if #args < 2 or #args > 3 then
            error("lwr takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("lwr takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = checkGPR(args[1]),
                    hi16 = args[2],
                },
                {
                    base = 0x98000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = checkGPR(args[1]),
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0x98000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0x98000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    sb = function(args)
        if #args < 2 or #args > 3 then
            error("sb takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("sb takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = 1,
                    hi16 = args[2],
                },
                {
                    base = 0xa0000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = 1,
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0xa0000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0xa0000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    sh = function(args)
        if #args < 2 or #args > 3 then
            error("sh takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("sh takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = 1,
                    hi16 = args[2],
                },
                {
                    base = 0xa4000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = 1,
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0xa4000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0xa4000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    swl = function(args)
        if #args < 2 or #args > 3 then
            error("swl takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("swl takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = 1,
                    hi16 = args[2],
                },
                {
                    base = 0xa8000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = 1,
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0xa8000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0xa8000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    sw = function(args)
        if #args < 2 or #args > 3 then
            error("sw takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("sw takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = 1,
                    hi16 = args[2],
                },
                {
                    base = 0xac000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = 1,
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0xac000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0xac000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,

    swr = function(args)
        if #args < 2 or #args > 3 then
            error("swr takes two or three arguments")
        end
        if #args == 2 then
            if type(args[2]) ~= "string" then
                error("swr takes a label as its second argument when given two arguments")
            end
            return {
                {
                    base = 0x3c000000,
                    rt = 1,
                    hi16 = args[2],
                },
                {
                    base = 0xb0000000,
                    rt = checkGPR(args[1]),
                    lo16 = args[2],
                    rs = 1,
                },
            }
        end
        if type(args[2]) == "string" then
            return {
                base = 0xb8000000,
                rt = checkGPR(args[1]),
                lo16 = args[2],
                rs = checkGPR(args[3]),
            }
        end
        return {
            base = 0xb8000000,
            rt = checkGPR(args[1]),
            imm16 = checkImm16(args[2], 2),
            rs = checkGPR(args[3]),
        }
    end,
}

-- )EOF"
