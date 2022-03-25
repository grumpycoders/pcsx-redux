local ffi = require "ffi"
local reflect = require "reflect"
assert((function()return reflect.typeof("void").what == "void" end)())
assert((function()return reflect.typeof("const void").what == "void" end)())
assert((function()return reflect.typeof("long").what == "int" end)())
assert((function()return reflect.typeof("volatile unsigned __int64").what == "int" end)())
assert((function()return reflect.typeof("double").what == "float" end)())
assert((function()return reflect.typeof("const float").what == "float" end)())
assert((function()
ffi.cdef "enum E{X,Y};"
return reflect.typeof("enum E").what == "enum" end)())
assert((function()
ffi.cdef "enum Bool{False,True};"
return reflect.typeof("enum Bool"):value("False").what == "constant" end)())
assert((function()return reflect.typeof("char*").what == "ptr" end)())
assert((function()return reflect.typeof("int(*)(void)").what == "ptr" end)())
assert((function()return reflect.typeof("char&").what == "ref" end)())
assert((function()return reflect.typeof("char[16]").what == "array" end)())
assert((function()return reflect.typeof("int[?]").what == "array" end)())
assert((function()return reflect.typeof("struct{int x; int y;}").what == "struct" end)())
assert((function()return reflect.typeof("union{int x; int y;}").what == "union" end)())
assert((function()
ffi.cdef "int strcmp(const char*, const char*);"
return reflect.typeof(ffi.C.strcmp).what == "func" end)())
assert((function()return reflect.typeof("int(*)(void)").element_type.what == "func" end)())
assert((function()return reflect.typeof("struct{int x;}"):member("x").what == "field" end)())
assert((function()
ffi.cdef "int strcmp(const char*, const char*);"
return reflect.typeof(ffi.C.strcmp):argument(2).what == "field" end)())
assert((function()return reflect.typeof("struct{int x:2;}"):member("x").what == "bitfield" end)())
assert((function()return reflect.typeof("struct{int x; int y;}"):member(2).name == "y" end)())
assert((function()return reflect.typeof("struct{int x; int y;}").name == nil end)())
assert((function()
ffi.cdef 'int sc(const char*, const char*) __asm__("strcmp");'
return reflect.typeof(ffi.C.sc).name == "sc" end)())
assert((function()
ffi.cdef 'int sc(const char*, const char*) __asm__("strcmp");'
return reflect.typeof(ffi.C.sc).sym_name == "strcmp" end)())
assert((function()
ffi.cdef "int strcmp(const char*, const char*);"
return reflect.typeof(ffi.C.strcmp).sym_name == nil end)())
assert((function()return reflect.typeof("__int32").size == 4 end)())
assert((function()return reflect.typeof("__int32[2]").size == 8 end)())
assert((function()return reflect.typeof("__int32[]").size == "none" end)())
assert((function()return reflect.typeof("__int32[?]").size == "none" end)())
assert((function()return reflect.typeof("struct{__int32 count; __int32 data[?];}").size == 4 end)())
assert((function()return reflect.typeof("struct{}").size == 0 end)())
assert((function()return reflect.typeof("void").size == "none" end)())
assert((function()return reflect.typeof("struct{int f:5;}"):member("f").size == 5 / 8 end)())
assert((function()return reflect.typeof("struct{__int32 x; __int32 y; __int32 z;}"):member("z").offset == 8 end)())
assert((function()return reflect.typeof("struct{int x : 3; int y : 4; int z : 5;}"):member("z").offset == 7 / 8 end)())
assert((function()return reflect.typeof("int(*)(int x, int y)").element_type:argument("y").offset == 1 end)())
assert((function()return reflect.typeof("struct{__int32 a; __int32 b;}").alignment == 4 end)())
assert((function()return reflect.typeof("__declspec(align(16)) int").alignment == 16 end)())
assert((function()return reflect.typeof("int").const == nil end)())
assert((function()return reflect.typeof("const int").const == true end)())
assert((function()return reflect.typeof("const char*").const == nil end)())
assert((function()return reflect.typeof("const char*").element_type.const == true end)())
assert((function()return reflect.typeof("char* const").const == true end)())
assert((function()return reflect.typeof("int").volatile == nil end)())
assert((function()return reflect.typeof("volatile int").volatile == true end)())
assert((function()return reflect.typeof("char*").element_type.size == 1 end)())
assert((function()return reflect.typeof("char&").element_type.size == 1 end)())
assert((function()return reflect.typeof("char[32]").element_type.size == 1 end)())
assert((function()return reflect.typeof("struct{float x; unsigned y;}"):member("y").type.unsigned == true end)())
assert((function()return reflect.typeof("int(*)(uint64_t)").element_type:argument(1).type.size == 8 end)())
assert((function()
ffi.cdef "int strcmp(const char*, const char*);"
return reflect.typeof(ffi.C.strcmp).return_type.what == "int" end)())
assert((function()return reflect.typeof("void*(*)(void)").element_type.return_type.what == "ptr" end)())
assert((function()return reflect.typeof("bool").bool == true end)())
assert((function()return reflect.typeof("int").bool == nil end)())
assert((function()return reflect.typeof("_Bool int").bool == true end)())
assert((function()return reflect.typeof("int32_t").unsigned == nil end)())
assert((function()return reflect.typeof("uint32_t").unsigned == true end)())
assert((function()return reflect.typeof("long int").long == true end)())
assert((function()return reflect.typeof("short int").long == nil end)())
assert((function()return reflect.typeof("int[?]").vla == true end)())
assert((function()return reflect.typeof("int[2]").vla == nil end)())
assert((function()return reflect.typeof("int[]").vla == nil end)())
assert((function()return reflect.typeof("struct{int num; int data[?];}").vla == true end)())
assert((function()return reflect.typeof("struct{int num; int data[];}").vla == nil end)())
assert((function()local pieces = {} local function print(s) pieces[#pieces + 1] = tostring(s) end 
for refct in reflect.typeof [[
  struct {
    int a;
    union { int b; int c; };
    struct { int d; int e; };
    int f;
  }
]]:members() do print(refct.transparent) end --> nil, true, true, nil
return table.concat(pieces, ", ") == "nil, true, true, nil" end)())
assert((function()
ffi.cdef "int strcmp(const char*, const char*);"
return reflect.typeof(ffi.C.strcmp).nargs == 2 end)())
assert((function()
ffi.cdef "int printf(const char*, ...);"
return reflect.typeof(ffi.C.printf).nargs == 1 end)())
assert((function()
ffi.cdef "int strcmp(const char*, const char*);"
return reflect.typeof(ffi.C.strcmp).vararg == nil end)())
assert((function()
ffi.cdef "int printf(const char*, ...);"
return reflect.typeof(ffi.C.printf).vararg == true end)())
assert((function()return reflect.typeof("int(__stdcall *)(int)").element_type.convention == "stdcall" end)())
assert((function()local pieces = {} local function print(s) pieces[#pieces + 1] = tostring(s) end 
if not ffi.abi "win" then return "Windows-only example" end
ffi.cdef "void* LoadLibraryA(const char*)"
print(reflect.typeof(ffi.C.LoadLibraryA).convention) --> cdecl
ffi.C.LoadLibraryA("kernel32")
print(reflect.typeof(ffi.C.LoadLibraryA).convention) --> stdcall
return table.concat(pieces, ", ") == "cdecl, stdcall" end)())
assert((function()local pieces = {} local function print(s) pieces[#pieces + 1] = tostring(s) end for refct in reflect.typeof("struct{int x; int y;}"):members() do print(refct.name) end --> x, y
return table.concat(pieces, ", ") == "x, y" end)())
assert((function()local pieces = {} local function print(s) pieces[#pieces + 1] = tostring(s) end 
for refct in reflect.typeof[[
  struct {
    int a;
    union {
    	int b;
    	int c;
    };
    int d : 2;
    struct {
      int e;
      int f;
    };
  }
]]:members() do print(refct.what) end --> field, union, bitfield, struct
return table.concat(pieces, ", ") == "field, union, bitfield, struct" end)())
assert((function()local pieces = {} local function print(s) pieces[#pieces + 1] = tostring(s) end 
ffi.cdef "int strcmp(const char*, const char*);"
for refct in reflect.typeof(ffi.C.strcmp):arguments() do print(refct.type.what) end --> ptr, ptr
return table.concat(pieces, ", ") == "ptr, ptr" end)())
assert((function()local pieces = {} local function print(s) pieces[#pieces + 1] = tostring(s) end 
for refct in reflect.typeof"int(*)(int x, int y)".element_type:arguments() do print(refct.name) end --> x, y
return table.concat(pieces, ", ") == "x, y" end)())
assert((function()local pieces = {} local function print(s) pieces[#pieces + 1] = tostring(s) end 
ffi.cdef "enum EV{EV_A = 1, EV_B = 10, EV_C = 100};"
for refct in reflect.typeof("enum EV"):values() do print(refct.name) end --> EV_A, EV_B, EV_C
return table.concat(pieces, ", ") == "EV_A, EV_B, EV_C" end)())
assert((function()local t = {}
return reflect.getmetatable(ffi.metatype("struct {}", t)) == t end)())
assert((function()local pieces = {} local function print(s) pieces[#pieces + 1] = tostring(s) end
local function rec_members(refct, f)
  if refct.members then
    for refct in refct:members() do
      rec_members(refct, f)
    end
  else
    f(refct)
  end
end
rec_members(reflect.typeof [[
  struct {
    int a;
    union { struct { int b; }; int c; };
    struct { int d; union { int e; }; };
    int f;
  }
]], function(refct) print(refct.name) end)
return table.concat(pieces, ", ") == "a, b, c, d, e, f" end)())
print "PASS"
