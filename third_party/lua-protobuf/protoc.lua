--lualoader, R"EOF(--

local string = string
local tonumber = tonumber
local setmetatable = setmetatable
local error = error
local ipairs = ipairs
local io = io
local table = table
local math = math
local assert = assert
local tostring = tostring
local type = type
local insert_tab = table.insert

local function meta(name, t)
   t = t or {}
   t.__name  = name
   t.__index = t
   return t
end

local function default(t, k, def)
   local v = t[k]
   if not v then
      v = def or {}
      t[k] = v
   end
   return v
end

local Lexer = require 'pb.Lexer'

local Parser = meta "Parser" do
Parser.typemap = {}
Parser.loaded  = {}
Parser.paths   = { "", "." }

function Parser.new()
   local self = {}
   self.typemap = {}
   self.loaded  = {}
   self.paths   = { "", "." }
   return setmetatable(self, Parser)
end

function Parser:reset()
   self.typemap = {}
   self.loaded  = {}
   return self
end

function Parser:error(msg)
   return self.lex:error(msg)
end

function Parser:addpath(path)
   insert_tab(self.paths, path)
end

function Parser:parsefile(name)
   local info = self.loaded[name]
   if info then return info end
   local errors = {}
   for _, path in ipairs(self.paths) do
      local fn = path ~= "" and path.."/"..name or name
      local fh, err = io.open(fn)
      if fh then
         local content = fh:read "*a"
         info = self:parse(content, name)
         fh:close()
         return info
      end
      insert_tab(errors, err or fn..": ".."unknown error")
   end
   local import_fallback = self.unknown_import
   if import_fallback == true then
      info = import_fallback
   elseif import_fallback then
      info = import_fallback(self, name)
   end
   if not info then
      error("module load error: "..name.."\n\t"..table.concat(errors, "\n\t"))
   end
   return info
end

-- parser

local toplevel = require 'pb.TopLevel'

local function make_context(self, lex)
   local ctx = {
      syntax  = "proto2";
      locmap  = {};
      prefix  = ".";
      lex     = lex;
   }
   ctx.loaded  = self.loaded
   ctx.typemap = self.typemap
   ctx.paths   = self.paths
   ctx.proto3_optional =
      self.proto3_optional or self.experimental_allow_proto3_optional
   ctx.unknown_type = self.unknown_type
   ctx.unknown_import = self.unknown_import
   ctx.on_import = self.on_import

   return setmetatable(ctx, Parser)
end

function Parser:parse(src, name)
   local loaded = self.loaded[name]
   if loaded then
      if loaded == true then
         error("loop loaded: "..name)
      end
      return loaded
   end

   name = name or "<input>"
   self.loaded[name] = true
   local lex = Lexer.new(name, src)
   local ctx = make_context(self, lex)
   local info = { name = lex.name, syntax = ctx.syntax }

   local syntax = lex:keyword('syntax', 'opt')
   if syntax then
      info.syntax = lex:expected '=' :quote()
      ctx.syntax  = info.syntax
      lex:line_end()
   end

   while not lex:eof() do
      local ident = lex:ident()
      local top_parser = toplevel[ident]
      if top_parser then
         top_parser(ctx, lex, info)
      else
         lex:error("unknown keyword '"..ident.."'")
      end
      lex:line_end "opt"
   end
   self.loaded[name] = name ~= "<input>" and info or nil
   return ctx:resolve(lex, info)
end

-- resolver

local function empty() end

local function iter(t, k)
   local v = t[k]
   if v then return ipairs(v) end
   return empty
end

local function check_dup(self, lex, typ, map, k, v)
   local old = map[v[k]]
   if old then
      local ln, co = lex:pos2loc(self.locmap[old])
      lex:error("%s '%s' exists, previous at %d:%d",
                typ, v[k], ln, co)
   end
   map[v[k]] = v
end

local function check_type(self, lex, tname)
   if tname:match "^%." then
      local t = self.typemap[tname]
      if not t then
         return lex:error("unknown type '%s'", tname)
      end
      return t, tname
   end
   local prefix = self.prefix
   for i = #prefix+1, 1, -1 do
      local op = prefix[i]
      prefix[i] = tname
      local tn = table.concat(prefix, ".", 1, i)
      prefix[i] = op
      local t = self.typemap[tn]
      if t then return t, tn end
   end
   local tn, t
   local type_fallback = self.unknown_type
   if type_fallback then
      if type_fallback == true then
         tn = true
      elseif type(type_fallback) == 'string' then
         tn = tname:match(type_fallback) and true
      else
         tn = type_fallback(self, tname)
      end
   end
   if tn then
      t = types[t or "message"]
      if tn == true then tn = "."..tname end
      return t, tn
   end
   return lex:error("unknown type '%s'", tname)
end

local function check_field(self, lex, info)
   if info.extendee then
      local t, tn = check_type(self, lex, info.extendee)
      if t ~= types.message then
         lex:error("message type expected in extension")
      end
      info.extendee = tn
   end
   if info.type_name then
      local t, tn = check_type(self, lex, info.type_name)
      info.type      = t
      info.type_name = tn
   end
end

local function check_enum(self, lex, info)
   local names, numbers = {}, {}
   for _, v in iter(info, 'value') do
      lex.pos = assert(self.locmap[v])
      check_dup(self, lex, 'enum name', names, 'name', v)
      if not (info.options and info.options.allow_alias) then
          check_dup(self, lex, 'enum number', numbers, 'number', v)
      end
   end
end

local function check_message(self, lex, info)
   insert_tab(self.prefix, info.name)
   local names, numbers = {}, {}
   for _, v in iter(info, 'field') do
      lex.pos = assert(self.locmap[v])
      check_dup(self, lex, 'field name', names, 'name', v)
      check_dup(self, lex, 'field number', numbers, 'number', v)
      check_field(self, lex, v)
   end
   for _, v in iter(info, 'nested_type') do
      check_message(self, lex, v)
   end
   for _, v in iter(info, 'extension') do
      lex.pos = assert(self.locmap[v])
      check_field(self, lex, v)
   end
   self.prefix[#self.prefix] = nil
end

local function check_service(self, lex, info)
   local names = {}
   for _, v in iter(info, 'method') do
      lex.pos = self.locmap[v]
      check_dup(self, lex, 'rpc name', names, 'name', v)
      local t, tn = check_type(self, lex, v.input_type)
      v.input_type = tn
      if t ~= types.message then
         lex:error "message type expected in parameter"
      end
      t, tn = check_type(self, lex, v.output_type)
      v.output_type = tn
      if t ~= types.message then
         lex:error "message type expected in return"
      end
   end
end

function Parser:resolve(lex, info)
   self.prefix = { "", info.package }
   for _, v in iter(info, 'message_type') do
      check_message(self, lex, v)
   end
   for _, v in iter(info, 'enum_type') do
      check_enum(self, lex, v)
   end
   for _, v in iter(info, 'service') do
      check_service(self, lex, v)
   end
   for _, v in iter(info, 'extension') do
      lex.pos = assert(self.locmap[v])
      check_field(self, lex, v)
   end
   self.prefix = nil
   return info
end

end

local has_pb, pb = pcall(require, "pb") do
if has_pb then
function Parser.reload()
   assert(pb.load(require 'pb.Descriptor'), "load descriptor msg failed")
end

local function do_compile(self, f, ...)
   if self.include_imports then
      local old = self.on_import
      local infos = {}
      function self.on_import(info)
         insert_tab(infos, info)
      end
      local r = f(...)
      insert_tab(infos, r)
      self.on_import = old
      return { file = infos }
   end
   return { file = { f(...) } }
end

function Parser:compile(s, name)
   if self == Parser then self = Parser.new() end
   local set = do_compile(self, self.parse, self, s, name)
   return pb.encode('.google.protobuf.FileDescriptorSet', set)
end

function Parser:compilefile(fn)
   if self == Parser then self = Parser.new() end
   local set = do_compile(self, self.parsefile, self, fn)
   return pb.encode('.google.protobuf.FileDescriptorSet', set)
end

function Parser:load(s, name)
   if self == Parser then self = Parser.new() end
   local ret, pos = pb.load(self:compile(s, name))
   if ret then return ret, pos end
   error("load failed at offset "..pos)
end

function Parser:loadfile(fn)
   if self == Parser then self = Parser.new() end
   local ret, pos = pb.load(self:compilefile(fn))
   if ret then return ret, pos end
   error("load failed at offset "..pos)
end

Parser.reload()

end
end

return Parser

-- )EOF"
