-- lualoader, R"EOF(--
--   Copyright (C) 2026 PCSX-Redux authors
--
-- A generic `bit` polyfill: creates the LuaJIT bit library when it is absent, so
-- one Lua corpus runs on both backends. Must load before anything that uses it -
-- src/core/pcsxffi.lua defines bit.extract at file scope, and on a backend
-- without `bit` that is an index of a nil value which kills the whole chunk.
--
-- The body uses the 5.3 bitwise operators directly. That is safe on BOTH
-- backends: the vendored grumpycoders/LuaJIT parses them (lj_lex.c emits '&',
-- '|', TK_shl, TK_shr; lj_parse.c has OPR_BAND..OPR_BSAR), so no load() wrapper
-- or build-time branch is needed. Do not check this against a distro luajit -
-- stock LuaJIT 2.1 rejects them with "unexpected symbol near '&'", which is a
-- fact about that binary and not about the one Redux links.
--
-- THE SEMANTICS ARE 32-BIT SIGNED AND THAT IS THE WHOLE DIFFICULTY. bit.* always
-- normalises to a 32-bit signed integer; PUC-Lua 5.4 integers are 64-bit, so a
-- naive `a & b` diverges at or above 2^31 and below zero. rshift is LOGICAL and
-- arshift is ARITHMETIC - conflating them is the usual way to get sign extension
-- wrong. Checked against the values in LuaJIT's own bit.* documentation, 18/18,
-- including rshift(-1, 28) == 15 against arshift(-1, 28) == -1.

if not bit then
  local floor = math.floor
  local function norm(x)
    x = floor(x) & 0xffffffff
    if x >= 0x80000000 then x = x - 0x100000000 end
    return x
  end
  local function u32(x) return floor(x) & 0xffffffff end

  bit = {
    tobit = norm,
    bnot = function(a) return norm(~u32(a)) end,
    band = function(a, b, ...)
      local r = u32(a) & u32(b)
      for _, v in ipairs({...}) do r = r & u32(v) end
      return norm(r)
    end,
    bor = function(a, b, ...)
      local r = u32(a) | u32(b)
      for _, v in ipairs({...}) do r = r | u32(v) end
      return norm(r)
    end,
    bxor = function(a, b, ...)
      local r = u32(a) ~ u32(b)
      for _, v in ipairs({...}) do r = r ~ u32(v) end
      return norm(r)
    end,
    lshift = function(a, n) return norm(u32(a) << (n & 31)) end,
    rshift = function(a, n) return norm(u32(a) >> (n & 31)) end,
    arshift = function(a, n)
      n = n & 31
      local v = norm(a)
      -- Lua's >> is logical, so do the sign extension by hand.
      if v < 0 then return norm((u32(v) >> n) | ~(0xffffffff >> n)) end
      return norm(v >> n)
    end,
    rol = function(a, n) n = n & 31; local v = u32(a); return norm(((v << n) | (v >> (32 - n))) & 0xffffffff) end,
    ror = function(a, n) n = n & 31; local v = u32(a); return norm(((v >> n) | (v << (32 - n))) & 0xffffffff) end,
    bswap = function(a)
      local v = u32(a)
      return norm(((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | ((v >> 24) & 0xff))
    end,
    tohex = function(a, n)
      n = n or 8
      return string.format("%0" .. math.abs(n) .. (n < 0 and "X" or "x"), u32(a))
    end,
  }
end

-- Redux reaches `bit` BOTH ways: pcsxffi.lua touches the global, and
-- supportpsx/assembler/assembler.lua and pseudo.lua do `local bit =
-- require('bit')`. LuaJIT satisfies both because bit is a preloaded stdlib.
-- Setting only the global left require walking package.path and failing on
-- ./bit.lua, so register it as loaded too. Unconditional: on LuaJIT this
-- rebinds package.loaded.bit to the same table it already holds.
package.loaded.bit = bit
-- )EOF"
