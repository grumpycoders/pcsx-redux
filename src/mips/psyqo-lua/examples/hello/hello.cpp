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

#include "EASTL/string.h"
#include "common/syscalls/syscalls.h"
#include "psyqo-lua/lua.hh"
#include "psyqo/application.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/scene.hh"

namespace {

// Simple Lua script for demonstration
constexpr const char DEMO_SCRIPT[] = R"(
-- Simple Lua script to show psyqo::Lua functionality
function factorial(n)
    if n <= 1 then
        return 1
    else
        return n * factorial(n - 1)
    end
end

-- Calculate some values
results = {
    factorial = factorial(5),
    message = 'Hello from Lua!',
    number = 42,
    table = {1, 2, 3, 'testing'}
}

-- Call our C++ function
greet 'Lua script'

return results
)";

// C++ function to be called from Lua
int luaGreet(psyqo::Lua L) {
    // Get the name parameter from Lua
    const char* name = L.checkString(1);

    // Print to debug output (if available)
    ramsyscall_printf("Greeting from C++: Hello, %s!\n", name);

    // No return values
    return 0;
}

class LuaExample final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    psyqo::Lua L;

    // Results from Lua execution
    eastl::string m_luaMessage;
    int m_luaNumber = 0;
    int m_luaFactorial = 0;
    bool m_luaSuccess = false;
};

class LuaExampleScene final : public psyqo::Scene {
    void frame() override;
};

LuaExample luaExample;
LuaExampleScene luaExampleScene;

}  // namespace

void LuaExample::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);

    // Initialize Lua and register our functions
    L.push(luaGreet);
    L.setGlobal("greet");

    // Execute our demo script
    if (L.loadBuffer(DEMO_SCRIPT, "demo") == 0) {
        // Script loaded successfully, now execute it
        if (L.pcall(0, 1) == 0) {
            // Script executed successfully
            m_luaSuccess = true;

            // Get the results table
            if (L.isTable(-1)) {
                // Extract factorial result
                L.getField(-1, "factorial");
                if (L.isNumber(-1)) {
                    m_luaFactorial = L.toNumber(-1);
                }
                L.pop();

                // Extract message
                L.getField(-1, "message");
                if (L.isString(-1)) {
                    m_luaMessage = L.toString(-1);
                }
                L.pop();

                // Extract number
                L.getField(-1, "number");
                if (L.isNumber(-1)) {
                    m_luaNumber = L.toNumber(-1);
                }
                L.pop();
            }

            // Clean stack
            L.pop();
        } else {
            // Script execution failed, get error message
            m_luaMessage = "Error: ";
            m_luaMessage += L.isString(-1) ? L.toString(-1) : "Unknown error";
            L.pop();
        }
    } else {
        // Script loading failed, get error message
        m_luaMessage = "Error loading script: ";
        m_luaMessage += L.isString(-1) ? L.toString(-1) : "Unknown error";
        L.pop();
    }
}

void LuaExample::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&luaExampleScene);
}

void LuaExampleScene::frame() {
    auto& gpu = luaExample.gpu();
    auto& font = luaExample.m_font;
    psyqo::Color textColor = {.r = 255, .g = 255, .b = 255};

    // Clear the screen with a nice background color
    gpu.clear({{.r = 0, .g = 64, .b = 91}});

    // Display title
    font.print(gpu, "PSYQo Lua Example", {{.x = 16, .y = 32}}, textColor);

    if (luaExample.m_luaSuccess) {
        // Display results from Lua execution
        font.print(gpu, "Lua script executed successfully!", {{.x = 16, .y = 64}}, textColor);
        font.printf(gpu, {{.x = 16, .y = 80}}, textColor, "Message from Lua: %s", luaExample.m_luaMessage.c_str());
        font.printf(gpu, {{.x = 16, .y = 96}}, textColor, "Number from Lua: %d", luaExample.m_luaNumber);
        font.printf(gpu, {{.x = 16, .y = 112}}, textColor, "Factorial(5) from Lua: %d", luaExample.m_luaFactorial);

        // Example of calling Lua function from C++
        luaExample.L.getGlobal("factorial");
        luaExample.L.pushNumber(7);  // Calculate factorial of 7
        if (luaExample.L.pcall(1, 1) != 0) {
            // Error occurred
            font.print(gpu, "Error calling factorial(7):", {{.x = 16, .y = 128}}, textColor);
            font.print(gpu, luaExample.L.toString(-1), {{.x = 16, .y = 144}}, textColor);
        } else {
            int factorial7 = luaExample.L.toNumber(-1);
            font.printf(gpu, {{.x = 16, .y = 144}}, textColor, "Calling factorial(7) from C++: %d", factorial7);
        }
        luaExample.L.pop();
    } else {
        // Display error message
        font.print(gpu, "Lua script execution failed:", {{.x = 16, .y = 64}}, textColor);
        font.print(gpu, luaExample.m_luaMessage.c_str(), {{.x = 16, .y = 80}}, textColor);
    }
}

int main() { return luaExample.run(); }
