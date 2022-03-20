--lualoader, R"EOF(--

--[[ LuaJIT FFI reflection Library ]]--
--[[ Copyright (C) 2014 Peter Cawley <lua@corsix.org>. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
--]]
reflect = {}

local CTState, init_CTState
local miscmap, init_miscmap

local function gc_str(gcref) -- Convert a GCref (to a GCstr) into a string
  if gcref ~= 0 then
    local ts = ffi.cast("uint32_t*", gcref)
    return ffi.string(ts + 4, ts[3])
  end
end

local typeinfo = ffi.typeinfo or function(id)
  -- ffi.typeof is present in LuaJIT v2.1 since 8th Oct 2014 (d6ff3afc)
  -- this is an emulation layer for older versions of LuaJIT
  local ctype = (CTState or init_CTState()).tab[id]
  return {
    info = ctype.info,
    size = bit.bnot(ctype.size) ~= 0 and ctype.size,
    sib = ctype.sib ~= 0 and ctype.sib,
    name = gc_str(ctype.name),
  }
end

local function memptr(gcobj)
  return tonumber(tostring(gcobj):match"%x*$", 16)
end

init_CTState = function()
  -- Relevant minimal definitions from lj_ctype.h
  ffi.cdef [[
    typedef struct CType {
      uint32_t info;
      uint32_t size;
      uint16_t sib;
      uint16_t next;
      uint32_t name;
    } CType;

    typedef struct CTState {
      CType *tab;
      uint32_t top;
      uint32_t sizetab;
      void *L;
      void *g;
      void *finalizer;
      void *miscmap;
    } CTState;
  ]]

  -- Acquire a pointer to this Lua universe's CTState
  local co = coroutine.create(function()end) -- Any live coroutine will do.
  local uintgc = ffi.abi"gc64" and "uint64_t" or "uint32_t"
  local uintgc_ptr = ffi.typeof(uintgc .. "*")
  local G = ffi.cast(uintgc_ptr, ffi.cast(uintgc_ptr, memptr(co))[2])
  -- In global_State, `MRef ctype_state` is immediately before `GCRef gcroot[GCROOT_MAX]`.
  -- We first find (an entry in) gcroot by looking for a metamethod name string.
  local anchor = ffi.cast(uintgc, ffi.cast("const char*", "__index"))
  local i = 0
  while math.abs(tonumber(G[i] - anchor)) > 64 do
    i = i + 1
  end
  -- We then work backwards looking for something resembling ctype_state.
  repeat
    i = i - 1
    CTState = ffi.cast("CTState*", G[i])
  until ffi.cast(uintgc_ptr, CTState.g) == G

  return CTState
end

init_miscmap = function()
  -- Acquire the CTState's miscmap table as a Lua variable
  local t = {}; t[0] = t
  local uptr = ffi.cast("uintptr_t", (CTState or init_CTState()).miscmap)
  if ffi.abi"gc64" then
    local tvalue = ffi.cast("uint64_t**", memptr(t))[2]
    tvalue[0] = bit.bor(bit.lshift(bit.rshift(tvalue[0], 47), 47), uptr)
  else
    local tvalue = ffi.cast("uint32_t*", memptr(t))[2]
    ffi.cast("uint32_t*", tvalue)[ffi.abi"le" and 0 or 1] = ffi.cast("uint32_t", uptr)
  end
  miscmap = t[0]
  return miscmap
end

-- Information for unpacking a `struct CType`.
-- One table per CT_* constant, containing:
-- * A name for that CT_
-- * Roles of the cid and size fields.
-- * Whether the sib field is meaningful.
-- * Zero or more applicable boolean flags.
local CTs = {[0] =
  {"int",
    "", "size", false,
    {0x08000000, "bool"},
    {0x04000000, "float", "subwhat"},
    {0x02000000, "const"},
    {0x01000000, "volatile"},
    {0x00800000, "unsigned"},
    {0x00400000, "long"},
  },
  {"struct",
    "", "size", true,
    {0x02000000, "const"},
    {0x01000000, "volatile"},
    {0x00800000, "union", "subwhat"},
    {0x00100000, "vla"},
  },
  {"ptr",
    "element_type", "size", false,
    {0x02000000, "const"},
    {0x01000000, "volatile"},
    {0x00800000, "ref", "subwhat"},
  },
  {"array",
    "element_type", "size", false,
    {0x08000000, "vector"},
    {0x04000000, "complex"},
    {0x02000000, "const"},
    {0x01000000, "volatile"},
    {0x00100000, "vla"},
  },
  {"void",
    "", "size", false,
    {0x02000000, "const"},
    {0x01000000, "volatile"},
  },
  {"enum",
    "type", "size", true,
  },
  {"func",
    "return_type", "nargs", true,
    {0x00800000, "vararg"},
    {0x00400000, "sse_reg_params"},
  },
  {"typedef", -- Not seen
    "element_type", "", false,
  },
  {"attrib", -- Only seen internally
    "type", "value", true,
  },
  {"field",
    "type", "offset", true,
  },
  {"bitfield",
    "", "offset", true,
    {0x08000000, "bool"},
    {0x02000000, "const"},
    {0x01000000, "volatile"},
    {0x00800000, "unsigned"},
  },
  {"constant",
    "type", "value", true,
    {0x02000000, "const"},
  },
  {"extern", -- Not seen
    "CID", "", true,
  },
  {"kw", -- Not seen
    "TOK", "size",
  },
}

-- Set of CType::cid roles which are a CTypeID.
local type_keys = {
  element_type = true,
  return_type = true,
  value_type = true,
  type = true,
}

-- Create a metatable for each CT.
local metatables = {
}
for _, CT in ipairs(CTs) do
  local what = CT[1]
  local mt = {__index = {}}
  metatables[what] = mt
end

-- Logic for merging an attribute CType onto the annotated CType.
local CTAs = {[0] =
  function(a, refct) error("TODO: CTA_NONE") end,
  function(a, refct) error("TODO: CTA_QUAL") end,
  function(a, refct)
    a = 2^a.value
    refct.alignment = a
    refct.attributes.align = a
  end,
  function(a, refct)
    refct.transparent = true
    refct.attributes.subtype = refct.typeid
  end,
  function(a, refct) refct.sym_name = a.name end,
  function(a, refct) error("TODO: CTA_BAD") end,
}

-- C function calling conventions (CTCC_* constants in lj_refct.h)
local CTCCs = {[0] = 
  "cdecl",
  "thiscall",
  "fastcall",
  "stdcall",
}

local function refct_from_id(id) -- refct = refct_from_id(CTypeID)
  local ctype = typeinfo(id)
  local CT_code = bit.rshift(ctype.info, 28)
  local CT = CTs[CT_code]
  local what = CT[1]
  local refct = setmetatable({
    what = what,
    typeid = id,
    name = ctype.name,
  }, metatables[what])

  -- Interpret (most of) the CType::info field
  for i = 5, #CT do
    if bit.band(ctype.info, CT[i][1]) ~= 0 then
      if CT[i][3] == "subwhat" then
        refct.what = CT[i][2]
      else
        refct[CT[i][2]] = true
      end
    end
  end
  if CT_code <= 5 then
    refct.alignment = bit.lshift(1, bit.band(bit.rshift(ctype.info, 16), 15))
  elseif what == "func" then
    refct.convention = CTCCs[bit.band(bit.rshift(ctype.info, 16), 3)]
  end

  if CT[2] ~= "" then -- Interpret the CType::cid field
    local k = CT[2]
    local cid = bit.band(ctype.info, 0xffff)
    if type_keys[k] then
      if cid == 0 then
        cid = nil
      else
        cid = refct_from_id(cid)
      end
    end
    refct[k] = cid
  end

  if CT[3] ~= "" then -- Interpret the CType::size field
    local k = CT[3]
    refct[k] = ctype.size or (k == "size" and "none")
  end

  if what == "attrib" then
    -- Merge leading attributes onto the type being decorated.
    local CTA = CTAs[bit.band(bit.rshift(ctype.info, 16), 0xff)]
    if refct.type then
      local ct = refct.type
      ct.attributes = {}
      CTA(refct, ct)
      ct.typeid = refct.typeid
      refct = ct
    else
      refct.CTA = CTA
    end
  elseif what == "bitfield" then
    -- Decode extra bitfield fields, and make it look like a normal field.
    refct.offset = refct.offset + bit.band(ctype.info, 127) / 8
    refct.size = bit.band(bit.rshift(ctype.info, 8), 127) / 8
    refct.type = {
      what = "int",
      bool = refct.bool,
      const = refct.const,
      volatile = refct.volatile,
      unsigned = refct.unsigned,
      size = bit.band(bit.rshift(ctype.info, 16), 127),
    }
    refct.bool, refct.const, refct.volatile, refct.unsigned = nil
  end

  if CT[4] then -- Merge sibling attributes onto this type.
    while ctype.sib do
      local entry = typeinfo(ctype.sib)
      if CTs[bit.rshift(entry.info, 28)][1] ~= "attrib" then break end
      if bit.band(entry.info, 0xffff) ~= 0 then break end
      local sib = refct_from_id(ctype.sib)
      sib:CTA(refct)
      ctype = entry
    end
  end

  return refct
end

local function sib_iter(s, refct)
  repeat
    local ctype = typeinfo(refct.typeid)
    if not ctype.sib then return end
    refct = refct_from_id(ctype.sib)
  until refct.what ~= "attrib" -- Pure attribs are skipped.
  return refct
end

local function siblings(refct)
  -- Follow to the end of the attrib chain, if any.
  while refct.attributes do
    refct = refct_from_id(refct.attributes.subtype or typeinfo(refct.typeid).sib)
  end

  return sib_iter, nil, refct
end

metatables.struct.__index.members = siblings
metatables.func.__index.arguments = siblings
metatables.enum.__index.values = siblings

local function find_sibling(refct, name)
  local num = tonumber(name)
  if num then
    for sib in siblings(refct) do
      if num == 1 then
        return sib
      end
      num = num - 1
    end
  else
    for sib in siblings(refct) do
      if sib.name == name then
        return sib
      end
    end
  end
end

metatables.struct.__index.member = find_sibling
metatables.func.__index.argument = find_sibling
metatables.enum.__index.value = find_sibling

function reflect.typeof(x) -- refct = reflect.typeof(ct)
  return refct_from_id(tonumber(ffi.typeof(x)))
end

function reflect.getmetatable(x) -- mt = reflect.getmetatable(ct)
  return (miscmap or init_miscmap())[-tonumber(ffi.typeof(x))]
end

-- )EOF"
