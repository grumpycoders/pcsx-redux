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

local toplevel = {} do

local labels = { optional = 1; required = 2; repeated = 3 }

local key_types = {
   int32    = 5;  int64    = 3;  uint32   = 13;
   uint64   = 4;  sint32   = 17; sint64   = 18;
   fixed32  = 7;  fixed64  = 6;  sfixed32 = 15;
   sfixed64 = 16; bool     = 8;  string   = 9;
}

local com_types = {
   group    = 10; message  = 11; enum     = 14;
}

local types = {
   double   = 1;  float    = 2;  int32    = 5;
   int64    = 3;  uint32   = 13; uint64   = 4;
   sint32   = 17; sint64   = 18; fixed32  = 7;
   fixed64  = 6;  sfixed32 = 15; sfixed64 = 16;
   bool     = 8;  string   = 9;  bytes    = 12;
   group    = 10; message  = 11; enum     = 14;
}

local function register_type(self, lex, tname, typ)
   if not tname:match "%."then
      tname = self.prefix..tname
   end
   if self.typemap[tname] then
      return lex:error("type %s already defined", tname)
   end
   self.typemap[tname] = typ
end

local function type_info(lex, tname)
   local tenum = types[tname]
   if com_types[tname] then
      return lex:error("invalid type name: "..tname)
   elseif tenum then
      tname = nil
   end
   return tenum, tname
end

local function map_info(lex)
   local keyt = lex:ident "key type"
   if not key_types[keyt] then
      return lex:error("invalid key type: "..keyt)
   end
   local valt = lex:expected "," :type_name()
   local name = lex:expected ">" :ident()
   local ident = name:gsub("^%a", string.upper)
                     :gsub("_(%a)", string.upper).."Entry"
   local kt, ktn = type_info(lex, keyt)
   local vt, vtn = type_info(lex, valt)
   return name, types.message, ident, {
      name = ident,
      field = {
         {
            name      = "key",
            number    = 1;
            label     = labels.optional,
            type      = kt,
            type_name = ktn
         },
         {
            name      = "value",
            number    = 2;
            label     = labels.optional,
            type      = vt,
            type_name = vtn
         },
      },
      options = { map_entry = true }
   }
end

local function inline_option(lex, info)
   if lex:test "%[" then
      info = info or {}
      while true do
         local name  = lex:option_name()
         local value = lex:expected '=' :constant()
         info[name] = value
         if lex:test "%]" then
            return info
         end
         lex:expected ','
      end
   end
end

local function field(self, lex, ident)
   local name, typ, type_name, map_entry
   if ident == "map" and lex:test "%<" then
      name, typ, type_name, map_entry = map_info(lex)
      self.locmap[map_entry.field[1]] = lex.pos
      self.locmap[map_entry.field[2]] = lex.pos
      register_type(self, lex, type_name, types.message)
   else
      typ, type_name = type_info(lex, ident)
      name = lex:ident()
   end
   local info = {
      name      = name,
      number    = lex:expected "=":integer(),
      label     = ident == "map" and labels.repeated or labels.optional,
      type      = typ,
      type_name = type_name
   }
   local options = inline_option(lex)
   if options then
      info.default_value, options.default = tostring(options.default), nil
      info.json_name, options.json_name = options.json_name, nil
      if options.packed and options.packed == "false" then
         options.packed = false
      end
      info.options = options
   end
   if info.number <= 0 then
      lex:error("invalid tag number: "..info.number)
   end
   return info, map_entry
end

local function label_field(self, lex, ident, parent)
   local label = labels[ident]
   local info, map_entry
   if not label then
      if self.syntax == "proto2" and ident ~= "map" then
         return lex:error("proto2 disallow missing label")
      end
      return field(self, lex, ident)
   end
   local proto3_optional = label == labels.optional and self.syntax == "proto3"
   if proto3_optional and not (self.proto3_optional and parent) then
      return lex:error("proto3 disallow 'optional' label")
   end
   info, map_entry = field(self, lex, lex:type_name())
   if proto3_optional then
      local ot = default(parent, "oneof_decl")
      info.oneof_index = #ot
      ot[#ot+1] = { name = "optional_" .. info.name }
   else
      info.label = label
   end
   return info, map_entry
end

function toplevel:package(lex, info)
   local package = lex:full_ident 'package name'
   lex:line_end()
   info.package = package
   self.prefix = "."..package.."."
   return self
end

function toplevel:import(lex, info)
   local mode = lex:ident('"weak" or "public"', 'opt') or "public"
   if mode ~= 'weak' and mode ~= 'public' then
      return lex:error '"weak or "public" expected'
   end
   local name = lex:quote()
   lex:line_end()
   local result = self:parsefile(name)
   if self.on_import then
      self.on_import(result)
   end
   local dep = default(info, 'dependency')
   local index = #dep
   dep[index+1] = name
   if mode == "public" then
      local it = default(info, 'public_dependency')
      insert_tab(it, index)
   else
      local it = default(info, 'weak_dependency')
      insert_tab(it, index)
   end
end

local msgbody = {} do

function msgbody:message(lex, info)
   local nested_type = default(info, 'nested_type')
   insert_tab(nested_type, toplevel.message(self, lex))
   return self
end

function msgbody:enum(lex, info)
   local nested_type = default(info, 'enum_type')
   insert_tab(nested_type, toplevel.enum(self, lex))
   return self
end

function msgbody:extend(lex, info)
   local extension = default(info, 'extension')
   local nested_type = default(info, 'nested_type')
   local ft, mt = toplevel.extend(self, lex, {})
   for _, v in ipairs(ft) do
      insert_tab(extension, v)
   end
   for _, v in ipairs(mt) do
      insert_tab(nested_type, v)
   end
   return self
end

function msgbody:extensions(lex, info)
   local rt = default(info, 'extension_range')
   local idx = #rt
   repeat
      local start = lex:integer "field number range"
      local stop = math.floor(2^29)
      if lex:keyword('to', 'opt') then
         if not lex:keyword('max', 'opt') then
            stop = lex:integer "field number range end or 'max'"
         end
         insert_tab(rt, { start = start, ['end'] = stop })
      else
         insert_tab(rt, { start = start, ['end'] = start })
      end
   until not lex:test ','
   rt[idx+1].options = inline_option(lex)
   lex:line_end()
   return self
end

function msgbody:reserved(lex, info)
   lex:whitespace()
   if not lex '^%d' then
      local rt = default(info, 'reserved_name')
      repeat
         insert_tab(rt, (lex:quote()))
      until not lex:test ','
   else
      local rt = default(info, 'reserved_range')
      local first = true
      repeat
         local start = lex:integer(first and 'field name or number range'
                                    or 'field number range')
         if lex:keyword('to', 'opt') then
            if lex:keyword('max', 'opt') then
               insert_tab(rt, { start = start, ['end'] = 2^29-1 })
            else
               local stop = lex:integer 'field number range end'
               insert_tab(rt, { start = start, ['end'] = stop })
            end
         else
            insert_tab(rt, { start = start, ['end'] = start })
         end
         first = false
      until not lex:test ','
   end
   lex:line_end()
   return self
end

function msgbody:oneof(lex, info)
   local fs = default(info, "field")
   local ts = default(info, "nested_type")
   local ot = default(info, "oneof_decl")
   local index = #ot + 1
   local oneof = { name = lex:ident() }
   lex:expected "{"
   while not lex:test "}" do
      local ident = lex:type_name()
      if ident == "option" then
         toplevel.option(self, lex, oneof)
      else
         local f, t = field(self, lex, ident)
         self.locmap[f] = lex.pos
         if t then insert_tab(ts, t) end
         f.oneof_index = index - 1
         insert_tab(fs, f)
      end
      lex:line_end 'opt'
   end
   ot[index] = oneof
end

function msgbody:option(lex, info)
   toplevel.option(self, lex, info)
end

end

function toplevel:message(lex, info)
   local name = lex:ident 'message name'
   local typ = { name = name }
   register_type(self, lex, name, types.message)
   local prefix = self.prefix
   self.prefix = prefix..name.."."
   lex:expected "{"
   while not lex:test "}" do
      local ident, pos = lex:type_name()
      local body_parser = msgbody[ident]
      if body_parser then
         body_parser(self, lex, typ)
      else
         local fs = default(typ, 'field')
         local f, t = label_field(self, lex, ident, typ)
         self.locmap[f] = pos
         insert_tab(fs, f)
         if t then
            local ts = default(typ, 'nested_type')
            insert_tab(ts, t)
         end
      end
      lex:line_end 'opt'
   end
   lex:line_end 'opt'
   if info then
      info = default(info, 'message_type')
      insert_tab(info, typ)
   end
   self.prefix = prefix
   return typ
end

function toplevel:enum(lex, info)
   local name, pos = lex:ident 'enum name'
   local enum = { name = name }
   self.locmap[enum] = pos
   register_type(self, lex, name, types.enum)
   lex:expected "{"
   while not lex:test "}" do
      local ident, pos = lex:ident 'enum constant name'
      if ident == 'option' then
         toplevel.option(self, lex, enum)
      elseif ident == 'reserved' then
         msgbody.reserved(self, lex, enum)
      else
         local values  = default(enum, 'value')
         local number  = lex:expected '=' :integer()
         local value = {
            name    = ident,
            number  = number,
            options = inline_option(lex)
         }
         self.locmap[value] = pos
         insert_tab(values, value)
      end
      lex:line_end 'opt'
   end
   lex:line_end 'opt'
   if info then
      info = default(info, 'enum_type')
      insert_tab(info, enum)
   end
   return enum
end

function toplevel:option(lex, info)
   local ident = lex:option_name()
   lex:expected "="
   local value = lex:constant()
   lex:line_end()
   local options = info and default(info, 'options') or {}
   options[ident] = value
   return options, self
end

function toplevel:extend(lex, info)
   local name = lex:type_name()
   local ft = info and default(info, 'extension') or {}
   local mt = info and default(info, 'message_type') or {}
   lex:expected "{"
   while not lex:test "}" do
      local ident, pos = lex:type_name()
      local f, t = label_field(self, lex, ident)
      self.locmap[f] = pos
      f.extendee = name
      insert_tab(ft, f)
      insert_tab(mt, t)
      lex:line_end 'opt'
   end
   return ft, mt
end

local svr_body = {} do

function svr_body:rpc(lex, info)
   local name, pos = lex:ident "rpc name"
   local rpc = { name = name }
   self.locmap[rpc] = pos
   local _, tn
   lex:expected "%("
   rpc.client_streaming = lex:keyword("stream", "opt")
   _, tn = type_info(lex, lex:type_name())
   if not tn then return lex:error "rpc input type must by message" end
   rpc.input_type = tn
   lex:expected "%)" :expected "returns" :expected "%("
   rpc.server_streaming = lex:keyword("stream", "opt")
   _, tn = type_info(lex, lex:type_name())
   if not tn then return lex:error "rpc output type must by message" end
   rpc.output_type = tn
   lex:expected "%)"
   if lex:test "{" then
      while not lex:test "}" do
         lex:line_end "opt"
         lex:keyword "option"
         toplevel.option(self, lex, rpc)
      end
   end
   lex:line_end "opt"
   local t = default(info, "method")
   insert_tab(t, rpc)
end

function svr_body:option(lex, info)
   return toplevel.option(self, lex, info)
end

function svr_body.stream(_, lex)
   lex:error "stream not implement yet"
end

end

function toplevel:service(lex, info)
   local name, pos = lex:ident 'service name'
   local svr = { name = name }
   self.locmap[svr] = pos
   lex:expected "{"
   while not lex:test "}" do
      local ident = lex:type_name()
      local body_parser = svr_body[ident]
      if body_parser then
         body_parser(self, lex, svr)
      else
         return lex:error "expected 'rpc' or 'option' in service body"
      end
      lex:line_end 'opt'
   end
   lex:line_end 'opt'
   if info then
      info = default(info, 'service')
      insert_tab(info, svr)
   end
   return svr
end

end

return toplevel

-- )EOF"
