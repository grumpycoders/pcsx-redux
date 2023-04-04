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

PCSX.Assembler = {}
PCSX.Assembler.Internals = {}
PCSX.Assembler.Internals.checks = {}

PCSX.Assembler.Internals.checks.imm26 = function(imm, place)
    if type(imm) == "number" then
        if (imm % 4) ~= 0 then
            error("Immediate must be a multiple of 4: " .. imm)
        end
        imm = imm / 4
        if imm < 0 or imm > 0x3ffffff then
            error("Immediate out of range: " .. imm)
        end
        return imm
    end
    if type(imm) == "string" then
        return imm
    end
    error("Argument " .. place .. " must be a number or a label")
end

PCSX.Assembler.Internals.checks.imm20 = function(imm, place)
    if type(imm) == "number" then
        if imm < 0 or imm > 0xfffff then
            error("Immediate out of range: " .. imm)
        end
        return imm
    end
    error("Argument " .. place .. " must be a number")
end

PCSX.Assembler.Internals.checks.bimm16 = function(imm, place)
    if type(imm) == "number" then
        if (imm % 4) ~= 0 then
            error("Immediate must be a multiple of 4: " .. imm)
        end
        imm = imm / 4
        if imm < -0x8000 or imm > 0x7fff then
            error("Immediate out of range: " .. imm)
        end
        return imm
    end
    if type(imm) == "string" then
        return imm
    end
    error("Argument " .. place .. " must be a number or a label")
end

PCSX.Assembler.Internals.checks.imm16 = function(imm, place)
    if type(imm) == "number" then
        if imm < -0x8000 or imm > 0xffff then
            error("Immediate out of range: " .. imm)
        end
        return imm
    end
    error("Argument " .. place .. " must be a number")
end

PCSX.Assembler.Internals.checks.imm5 = function(imm, place)
    if type(imm) == "number" then
        if imm < 0 or imm > 0x1f then
            error("Immediate out of range: " .. imm)
        end
        return imm
    end
    error("Argument " .. place .. " must be a number")
end

PCSX.Assembler.New = function()
    local function compileOne(code, baseAddress)
        local ret = code.base
        local hi16 = code.hi16
        if hi16 then
            if type(hi16) == "string" then
                local symbol = PCSX.Assembler.resolveSymbol(hi16)
                if not symbol then
                    error("Unknown symbol: " .. hi16)
                end
                hi16 = symbol.address
            end
            ret = bit.bor(ret, bit.rshift(hi16, 16))
            if (bit.band(hi16, 0x8000) ~= 0) then
                ret = ret + 1
            end
        end
        local lo16 = code.lo16
        if lo16 then
            if type(lo16) == "string" then
                local symbol = PCSX.Assembler.resolveSymbol(lo16)
                if not symbol then
                    error("Unknown symbol: " .. lo16)
                end
                lo16 = symbol.address
            end
            ret = bit.bor(ret, bit.band(lo16, 16))
        end
        local imm26 = code.imm26
        if imm26 then
            if type(imm26) == "string" then
                local symbol = PCSX.Assembler.resolveSymbol(imm26)
                if not symbol then
                    error("Unknown symbol: " .. imm26)
                end
                if (symbol.address % 4) ~= 0 then
                    error("Jump address must be a multiple of 4: " .. imm26)
                end
                if (bit.band(0xfc000000, bit.bxor(symbol.address, baseAddress)) ~= 0) then
                    error("Jump address out of range: " .. imm26)
                end
                imm26 = bit.band(symbol.address / 4, 0x3ffffff)
            end
            ret = bit.bor(ret, imm26)
        end
        if code.imm16 then
            ret = bit.bor(ret, bit.band(code.imm16, 0xffff))
        end
        local bimm16 = code.bimm16
        if bimm16 then
            if type(bimm16) == "string" then
                local symbol = PCSX.Assembler.resolveSymbol(bimm16)
                if not symbol then
                    error("Unknown symbol: " .. bimm16)
                end
                if (symbol.address % 4) ~= 0 then
                    error("Branch address must be a multiple of 4: " .. bimm16)
                end
                local offset = (symbol.address - baseAddress) / 4
                if offset < -0x8000 or offset > 0x7fff then
                    error("Branch out of range: " .. bimm16)
                end
                bimm16 = offset
            end
            ret = bit.bor(ret, bit.band(bimm16, 0xffff))
        end
        if code.imm5 then
            ret = bit.bor(ret, code.imm5)
        end
        if code.imm20 then
            ret = bit.bor(ret, bit.lshift(code.imm20, 6))
        end
        if code.rs then
            ret = bit.bor(ret, bit.lshift(code.rs, 21))
        end
        if code.rt then
            ret = bit.bor(ret, bit.lshift(code.rt, 16))
        end
        if code.rd then
            ret = bit.bor(ret, bit.lshift(code.rd, 11))
        end
        return ret
    end
    local function split(str, sep)
        local ret = {}
        for str in string.gmatch(str, "([^" .. sep .. "]+)") do
            table.insert(ret, str)
        end
        return ret
    end
    local function trim(str)
        return string.gsub(str, "^%s*(.-)%s*$", "%1")
    end
    local function parseOneString(self, line)
        local parts = split(line, " \\(\\),")
        local args = {}
        for _, v in ipairs(parts) do
            v = trim(v)
            if v ~= "" then
                if string.match(v, "^%d") then
                    table.insert(args, tonumber(v))
                else
                    table.insert(args, v)
                end
            end
        end
        local opcode = args[1]
        table.remove(args, 1)
        self[opcode](args)
    end
    local assembler = {
        __code = {},
        parse = function(self, code)
            local lines = split(code, "\n")
            for _, v in ipairs(lines) do
                v = trim(v)
                if v ~= "" then
                    parseOneString(self, v)
                end
            end
            return self
        end,
        compileToUint32Table = function(self, baseAddress)
            local ret = {}
            for _, v in ipairs(self.__code) do
                table.insert(ret, compileOne(v, baseAddress))
                baseAddress = baseAddress + 4
            end
            return ret
        end,
        compileToMemory = function(self, memory, baseAddress, memoryStartAddress)
            local offset = baseAddress - memoryStartAddress
            for _, v in ipairs(self.__code) do
                local compiled = compileOne(v, baseAddress)
                memory[offset] = bit.band(compiled, 0xff)
                memory[offset + 1] = bit.band(bit.rshift(compiled, 8), 0xff)
                memory[offset + 2] = bit.band(bit.rshift(compiled, 16), 0xff)
                memory[offset + 3] = bit.band(bit.rshift(compiled, 24), 0xff)
                baseAddress = baseAddress + 4
                offset = offset + 4
            end
            return self
        end,
        compileToFile = function(self, file, baseAddress, fileStartAddress)
            if type(file) ~= 'table' or file._type ~= 'File' then
                error("Invalid first argument: not a file")
            end
            if type(baseAddress) ~= "number" then
                error("Invalid second argument: not a number")
            end
            if fileStartAddress == nil then fileStartAddress = 0 end
            if type(fileStartAddress) ~= "number" then
                error("Invalid third argument: not a number")
            end
            local offset = baseAddress - fileStartAddress
            for _, v in ipairs(self.__code) do
                local compiled = compileOne(v, baseAddress)
                file:writeU32At(compiled, offset)
                baseAddress = baseAddress + 4
                offset = offset + 4
            end
            return self
        end,
    }
    local wrapper = function(self, f, name, args)
        if #args ~= 1 or type(args[1]) ~= "table" then
            error("Invalid arguments for instruction " .. name)
        end
        local ret = f(table.unpack(args))
        if type(ret) == "table" and type(ret[1]) == "table" then
            for _, v in ipairs(ret) do
                table.insert(self.__code, v)
            end
        else
            table.insert(self.__code, ret)
        end
        return ret
    end
    local meta = {
        __index = function(self, key)
            local instr = PCSX.Assembler.Internals.simpleInstructions[key]
            if instr then
                return function(...) return wrapper(self, instr, key, { ... }) end
            end
            instr = PCSX.Assembler.Internals.loadAndStoreInstructions[key]
            if instr then
                return function(...) return wrapper(self, instr, key, { ... }) end
            end
            instr = PCSX.Assembler.Internals.specialInstructions[key]
            if instr then
                return function(...) return wrapper(self, instr, key, { ... }) end
            end
            instr = PCSX.Assembler.Internals.bcondInstructions[key]
            if instr then
                return function(...) return wrapper(self, instr, key, { ... }) end
            end
            instr = PCSX.Assembler.Internals.cop0Instructions[key]
            if instr then
                return function(...) return wrapper(self, instr, key, { ... }) end
            end
            instr = PCSX.Assembler.Internals.gteInstructions[key]
            if instr then
                return function(...) return wrapper(self, instr, key, { ... }) end
            end
            instr = PCSX.Assembler.Internals.pseudoInstructions[key]
            if instr then
                return function(...) return wrapper(self, instr, key, { ... }) end
            end
            error("Unknown instruction " .. key)
        end
    }
    setmetatable(assembler, meta)
    return assembler
end

-- )EOF"
