Taken and adapted from https://github.com/corsix/ffi-reflect.

LuaJIT FFI reflection library
===========

Quick examples:
```lua
local ffi = require "ffi"
local reflect = require "reflect"

ffi.cdef 'int sc(const char*, const char*) __asm__("strcmp");'
print(reflect.typeof(ffi.C.sc).sym_name) --> "strcmp"

for refct in reflect.typeof"int(*)(int x, int y)".element_type:arguments() do
  print(refct.name)
end --> x, y

t = {}
assert(reflect.getmetatable(ffi.metatype("struct {}", t)) == t)
```

For the full API reference, see http://corsix.github.io/ffi-reflect/.
