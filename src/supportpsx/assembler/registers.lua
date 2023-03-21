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

local gpr = {
    r0 = 0, r1 = 1, r2 = 2, r3 = 3, r4 = 4, r5 = 5, r6 = 6, r7 = 7,
    r8 = 8, r9 = 9, r10 = 10, r11 = 11, r12 = 12, r13 = 13, r14 = 14, r15 = 15,
    r16 = 16, r17 = 17, r18 = 18, r19 = 19, r20 = 20, r21 = 21, r22 = 22, r23 = 23,
    r24 = 24, r25 = 25, r26 = 26, r27 = 27, r28 = 28, r29 = 29, r30 = 30, r31 = 31,
    zero = 0, at = 1, v0 = 2, v1 = 3, a0 = 4, a1 = 5, a2 = 6, a3 = 7,
    t0 = 8, t1 = 9, t2 = 10, t3 = 11, t4 = 12, t5 = 13, t6 = 14, t7 = 15,
    s0 = 16, s1 = 17, s2 = 18, s3 = 19, s4 = 20, s5 = 21, s6 = 22, s7 = 23,
    t8 = 24, t9 = 25, k0 = 26, k1 = 27, gp = 28, sp = 29, fp = 30, ra = 31,
}

local gteRegistersSet0 = {
    vxz0 = 0, vz0 = 1, vxy1 = 2, vyz1 = 3, vxz1 = 4, vz1 = 5, rgb = 6, otz = 7,
    ir0 = 8, ir1 = 9, ir2 = 10, ir3 = 11, sxy0 = 12, sxy1 = 13, sxy2 = 14, sxyp = 15,
    sz0 = 16, sz1 = 17, sz2 = 18, sz3 = 19, rgb0 = 20, rgb1 = 21, rgb2 = 22, res1 = 23,
    mac0 = 24, mac1 = 25, mac2 = 26, mac3 = 27, irgb = 28, orgb = 29, lzcs = 30, lzcr = 31,
}

local gteRegistersSet1 = {
    r11r12 = 0, r13r21 = 1, r22r23 = 2, r31r32 = 3, r33 = 4, trx = 5, try = 6, trz = 7,
    l11l12 = 8, l13l21 = 9, l22l23 = 10, l31l32 = 11, l33 = 12, rbk = 13, gbk = 14, bbk = 15,
    lr1lr2 = 16, lr3lg1 = 17, lg2lg3 = 18, lb1lb2 = 19, lb3 = 20, rfc = 21, gfc = 22, bfc = 23,
    ofx = 24, ofy = 25, h = 26, dqa = 27, dqb = 28, zsf3 = 29, zsf4 = 30, flag = 31,
}

local cop0Registers = {
    bpc = 3, bda = 5, dcic = 12, badv = 8, bdam = 9, bpcm = 11, sr = 12, cause = 13, epc = 14, prid = 15,
}

PCSX.Assembler.Internals.checks.gpr = function(reg)
    if type(reg) == "number" then
        if reg < 0 or reg > 31 then
            error("Invalid GPR: " .. reg)
        end
        return reg
    end
    if type(reg) == "string" then
        reg = reg:lower()
        if reg:sub(1, 1) == "$" then
            reg = reg:sub(2)
        end
    end
    if gpr[reg] ~= nil then
        return gpr[reg]
    end
    error("Unknown GPR: " .. reg)
end

PCSX.Assembler.Internals.checks.cop0 = function(reg)
    if type(reg) == "number" then
        if reg < 0 or reg > 31 then
            error("Invalid COP0 register: " .. reg)
        end
        return reg
    end
    if type(reg) == "string" then
        reg = reg:lower()
        if reg:sub(1, 1) == "$" then
            reg = reg:sub(2)
        end
    end
    if cop0Registers[reg] ~= nil then
        return cop0Registers[reg]
    end
    error("Unknown COP0 register: " .. reg)
end

PCSX.Assembler.Internals.checks.gte0 = function(reg)
    if type(reg) == "number" then
        if reg < 0 or reg > 31 then
            error("Invalid GTE register: " .. reg)
        end
        return reg
    end
    if type(reg) == "string" then
        reg = reg:lower()
        if reg:sub(1, 1) == "$" then
            reg = reg:sub(2)
        end
    end
    if gteRegistersSet0[reg] ~= nil then
        return gteRegistersSet0[reg]
    end
    error("Unknown GTE register: " .. reg)
end

PCSX.Assembler.Internals.checks.gte1 = function(reg)
    if type(reg) == "number" then
        if reg < 0 or reg > 31 then
            error("Invalid GTE register: " .. reg)
        end
        return reg
    end
    if type(reg) == "string" then
        reg = reg:lower()
        if reg:sub(1, 1) == "$" then
            reg = reg:sub(2)
        end
    end
    if gteRegistersSet1[reg] ~= nil then
        return gteRegistersSet1[reg]
    end
    error("Unknown GTE register: " .. reg)
end

-- )EOF"
