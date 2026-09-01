/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/
#include "supportpsx/assembler.h"

#include "lua/luawrapper.h"

void PCSX::LuaSupportPSX::open_assembler(Lua L) {
    static int lualoader = 8;
    static const char* assembler = (
#include "supportpsx/assembler/assembler.lua"
    );
    static const char* registers = (
#include "supportpsx/assembler/registers.lua"
    );
    static const char* simple = (
#include "supportpsx/assembler/simple.lua"
    );
    static const char* loadstore = (
#include "supportpsx/assembler/loadstore.lua"
    );
    static const char* extra = (
#include "supportpsx/assembler/extra.lua"
    );
    static const char* gte = (
#include "supportpsx/assembler/gte.lua"
    );
    static const char* pseudo = (
#include "supportpsx/assembler/pseudo.lua"
    );
    static const char* symbols = (
#include "supportpsx/assembler/symbols.lua"
    );
    L.load(assembler, "src:supportpsx/assembler/assembler.lua");
    L.load(registers, "src:supportpsx/assembler/registers.lua");
    L.load(simple, "src:supportpsx/assembler/simple.lua");
    L.load(loadstore, "src:supportpsx/assembler/loadstore.lua");
    L.load(extra, "src:supportpsx/assembler/extra.lua");
    L.load(gte, "src:supportpsx/assembler/gte.lua");
    L.load(pseudo, "src:supportpsx/assembler/pseudo.lua");
    L.load(symbols, "src:supportpsx/assembler/symbols.lua");
}
