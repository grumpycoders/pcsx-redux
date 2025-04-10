/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#include "psyqo-lua/lua.hh"

#include "psyqo/kernel.hh"
#include "psyqo/xprintf.h"

extern "C" {
int sprintf_for_Lua(char* buf, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int ret = vsprintf(buf, fmt, ap);
    va_end(ap);
    return ret;
}
}

static constexpr char PSYQO_FIXEDPOINT_METATABLE[] = "psyqo.FixedPoint";

// FixedPoint implementation

void psyqo::Lua::push(FixedPoint<> fp) {
    // Get the FixedPoint constructor from registry
    getMetatable(PSYQO_FIXEDPOINT_METATABLE);
    getField(-1, "new");
    pushNumber(fp.raw());
    call(1, 1);  // Create new FixedPoint table
    remove(-2);  // Remove metatable from stack
}

void psyqo::Lua::push(lua_CPPFunction f) {
    lua_pushlightuserdata(L, reinterpret_cast<void*>(f));
    lua_pushcclosure(
        L,
        [](lua_State* L) -> int {
            lua_CPPFunction f = reinterpret_cast<lua_CPPFunction>(lua_touserdata(L, lua_upvalueindex(1)));
            psyqo::Lua lua(L);
            return f(lua);
        },
        1);
}

// Check if value at index is a FixedPoint
bool psyqo::Lua::isFixedPoint(int idx) {
    if (!isTable(idx)) return false;

    // Check if it has a _raw field and the correct metatable
    getMetatable(idx);
    getMetatable(PSYQO_FIXEDPOINT_METATABLE);
    bool result = lua_rawequal(L, -1, -2);
    pop(2);  // Pop both metatables

    return result;
}

// Get FixedPoint from stack at index idx
psyqo::FixedPoint<> psyqo::Lua::toFixedPoint(int idx) {
    if (!isFixedPoint(idx)) return {};

    getField(idx, "_raw");
    intptr_t raw = toNumber(-1);
    pop(1);

    return FixedPoint<>(static_cast<int32_t>(raw), FixedPoint<>::RAW);
}

// Check and get FixedPoint (with error if not FixedPoint)
psyqo::FixedPoint<> psyqo::Lua::checkFixedPoint(int idx) {
    if (!isFixedPoint(idx)) {
        error("Expected FixedPoint, got %s", typeName(idx));
        return {};
    }

    getField(idx, "_raw");
    intptr_t raw = toNumber(-1);
    pop(1);

    return FixedPoint<>(static_cast<int32_t>(raw), FixedPoint<>::RAW);
}

// Optional FixedPoint (returns default if not present or nil)
psyqo::FixedPoint<> psyqo::Lua::optFixedPoint(int idx, FixedPoint<> def) {
    if (isNoneOrNil(idx)) return def;
    return checkFixedPoint(idx);
}

psyqo::Lua::Lua() : L(luaL_newstate()) {
    static_assert(sizeof(Lua) == sizeof(lua_State*));
    Kernel::assert(L, "Couldn't create Lua VM");
    lua_atpanic(L, [](lua_State* L) -> int {
        const char* errorMsg = lua_tolstring(L, 1, nullptr);
        Kernel::abort(errorMsg);
    });
    setupFixedPointMetatable();
}

psyqo::Lua& psyqo::Lua::operator=(Lua&& oL) noexcept {
    if (this == &oL) return *this;

    Kernel::assert(!L, "Can't assign a Lua VM to another one.");

    L = oL.L;
    oL.L = nullptr;

    return *this;
}

void psyqo::Lua::close() {
    Kernel::assert(L, "Can't close an already closed VM");

    lua_close(L);
    L = nullptr;
}

lua_Number psyqo::Lua::toNumber(int idx, bool* isnum) {
    int success;
    lua_Number n = lua_tonumberx(L, idx, &success);
    if (isnum) *isnum = success;
    return n;
}

int psyqo::Lua::error(const char* fmt, ...) {
    va_list argp;
    va_start(argp, fmt);
    luaL_where(L, 1);
    lua_pushvfstring(L, fmt, argp);
    va_end(argp);
    lua_concat(L, 2);
    return lua_error(L);
}

void psyqo::Lua::push(const char* fmt, ...) {
    va_list argp;
    va_start(argp, fmt);
    lua_pushvfstring(L, fmt, argp);
    va_end(argp);
}

void psyqo::Lua::setupFixedPointMetatable() {
    // Check if metatable already exists
    if (newMetatable(PSYQO_FIXEDPOINT_METATABLE) == 0) {
        // Metatable already exists, just pop it
        pop(1);
        return;
    }

    // Create C++ implemented methods for operations that are more complex
    push([](psyqo::Lua L) {
        if (!L.isFixedPoint(1)) {
            return L.error("First argument must be a FixedPoint");
        }

        // Get the first FixedPoint
        auto fp1 = L.toFixedPoint(1);

        if (L.isNumber(2)) {
            // FixedPoint * number
            lua_Number n = L.checkNumber(2);
            auto result = fp1 * n;
            L.push(result);
        } else if (L.isFixedPoint(2)) {
            // FixedPoint * FixedPoint
            auto fp2 = L.toFixedPoint(2);
            auto result = fp1 * fp2;
            L.push(result);
        } else {
            return L.error("Cannot multiply FixedPoint by this type");
        }

        return 1;
    });
    setField(1, "__mul");

    push([](psyqo::Lua L) {
        if (!L.isFixedPoint(1)) {
            return L.error("First argument must be a FixedPoint");
        }

        // Get the first FixedPoint
        auto fp1 = L.toFixedPoint(1);

        if (L.isNumber(2)) {
            // FixedPoint / number
            lua_Number n = L.checkNumber(2);
            if (n == 0) return L.error("Division by zero");

            auto result = fp1 / n;
            L.push(result);
        } else if (L.isFixedPoint(2)) {
            // FixedPoint / FixedPoint
            auto fp2 = L.toFixedPoint(2);
            if (fp2.raw() == 0) return L.error("Division by zero");

            auto result = fp1 / fp2;
            L.push(result);
        } else {
            return L.error("Cannot divide FixedPoint by this type");
        }

        return 1;
    });
    setField(1, "__div");

    push([](psyqo::Lua L) {
        if (!L.isFixedPoint(1)) {
            return L.error("Expected FixedPoint table");
        }

        auto fp = L.toFixedPoint(1);
        int32_t raw = fp.raw();

        // Convert to simple string representation
        int integer = raw >> 12;
        unsigned fraction = raw & 0xfff;

        if (fraction == 0) {
            L.push("%d", integer);
        } else {
            unsigned decimal = (fraction * 1000) >> 12;
            L.push("%d.%03u", integer, decimal);
        }

        return 1;
    });
    setField(1, "__tostring");

    // We'll use an embedded Lua script to define most of the FixedPoint functionality
    static const char fixedPointScript[] = R"lua(
    return function(metatable)
        FixedPoint = metatable

        -- Simple operations can be done directly in Lua
        function FixedPoint.__add(a, b)
            local raw_a = a._raw
            if type(b) == "number" then
                -- FixedPoint + number (treated as integer)
                return FixedPoint.new(raw_a + bit.lshift(b, 12))
            elseif type(b) == "table" and b._raw then
                -- FixedPoint + FixedPoint
                return FixedPoint.new(raw_a + b._raw)
            else
                error("Cannot add FixedPoint to this type")
            end
        end

        function FixedPoint.__sub(a, b)
            local raw_a = a._raw
            if type(b) == "number" then
                -- FixedPoint - number (treated as integer)
                return FixedPoint.new(raw_a - bit.lshift(b, 12))
            elseif type(b) == "table" and b._raw then
                -- FixedPoint - FixedPoint
                return FixedPoint.new(raw_a - b._raw)
            else
                error("Cannot subtract this type from FixedPoint")
            end
        end

        function FixedPoint.__unm(a)
            -- Unary minus
            return FixedPoint.new(-a._raw)
        end

        function FixedPoint.__eq(a, b)
            if type(b) == "table" and b._raw then
                return a._raw == b._raw
            elseif type(b) == "number" then
                -- Compare with an integer number (shifted)
                return a._raw == bit.lshift(b, 12)
            else
                return false
            end
        end

        function FixedPoint.__lt(a, b)
            if type(b) == "table" and b._raw then
                return a._raw < b._raw
            elseif type(b) == "number" then
                -- Compare with an integer number (shifted)
                return a._raw < bit.lshift(b, 12)
            else
                error("Cannot compare FixedPoint with this type")
            end
        end

        function FixedPoint.__le(a, b)
            if type(b) == "table" and b._raw then
                return a._raw <= b._raw
            elseif type(b) == "number" then
                -- Compare with an integer number (shifted)
                return a._raw <= bit.lshift(b, 12)
            else
                error("Cannot compare FixedPoint with this type")
            end
        end

        -- Get raw value
        function FixedPoint:raw()
            return self._raw
        end

        -- Method to convert to a simple number (for simple calculations)
        function FixedPoint:toNumber()
            return (self._raw + 2048) / 4096
        end

        -- Create a new FixedPoint from raw value
        function FixedPoint.new(raw_value)
            return setmetatable({_raw = raw_value}, FixedPoint)
        end
    end
    )lua";

    // Load the Lua script
    if (loadBuffer(fixedPointScript, sizeof(fixedPointScript) - 1) != 0) {
        const char* errorMsg = toString(2);
        psyqo::Kernel::abort(errorMsg);
    }

    // Get the function
    if (pcall(0, 1) != 0) {
        const char* errorMsg = toString(2);
        psyqo::Kernel::abort(errorMsg);
    }

    // And call it with the metatable for finishing the setup
    copy(1);
    if (pcall(1, 0) != 0) {
        const char* errorMsg = toString(2);
        psyqo::Kernel::abort(errorMsg);
    }

    pop();
}
