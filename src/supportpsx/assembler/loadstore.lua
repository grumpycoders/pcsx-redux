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
