/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "main/terminalui.h"

#include <chrono>
#include <thread>

#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "fmt/format.h"
#include "ftxui/component/app.hpp"
#include "ftxui/component/component.hpp"
#include "ftxui/component/event.hpp"
#include "ftxui/component/loop.hpp"
#include "ftxui/dom/elements.hpp"
#include "ftxui/screen/terminal.hpp"
#include "lua/luawrapper.h"

#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

namespace {
constexpr size_t c_maxLogLines = 10000;
constexpr size_t c_maxLuaLines = 1000;
constexpr int c_luaPaneHeight = 10;
}  // namespace

PCSX::TerminalUI::TerminalUI() {}
PCSX::TerminalUI::~TerminalUI() { close(); }

bool PCSX::TerminalUI::isTerminal() { return isatty(fileno(stdin)) && isatty(fileno(stdout)); }

void PCSX::TerminalUI::appendLines(std::deque<Line>& dest, std::string& pending, const std::string& msg, bool error) {
    pending += msg;
    size_t start = 0;
    size_t nl;
    while ((nl = pending.find('\n', start)) != std::string::npos) {
        dest.push_back({pending.substr(start, nl - start), error});
        start = nl + 1;
    }
    pending.erase(0, start);
}

bool PCSX::TerminalUI::addLog(LogClass logClass, const std::string& msg) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        appendLines(m_log, m_logPending, msg, false);
        while (m_log.size() > c_maxLogLines) m_log.pop_front();
    }
    if (m_loop) m_app->RequestAnimationFrame();
    return true;
}

void PCSX::TerminalUI::addLuaLog(const std::string& msg, bool error) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string pending;
        appendLines(m_lua, pending, msg + "\n", error);
        while (m_lua.size() > c_maxLuaLines) m_lua.pop_front();
    }
    if (m_loop) m_app->RequestAnimationFrame();
}

void PCSX::TerminalUI::addNotification(const std::string& notification) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_notification = notification;
    }
    if (m_loop) m_app->RequestAnimationFrame();
}

void PCSX::TerminalUI::execute(const std::string& cmd) {
    if (cmd.empty()) return;
    if (m_history.empty() || m_history.back() != cmd) m_history.push_back(cmd);
    m_historyPos = m_history.size();
    addLuaLog("> " + cmd, false);
    auto L = *g_emulator->m_lua;
    const int top = L.gettop();
    try {
        System::setCrashReportTag("user_lua", "console");
        // Try it as an expression first, so typing `PCSX.getRegisters().pc` shows the value.
        // Probe quietly: L.load() reports its own syntax errors, and a failed probe is expected.
        std::string expr = "return " + cmd;
        if (luaL_loadbuffer(L.getState(), expr.data(), expr.size(), "console:") != 0) {
            L.pop();
            L.load(cmd, "console:", false);
        }
        int n = L.pcall();
        int first = L.gettop() - n + 1;
        for (int i = first; i < first + n; i++) addLuaLog(formatResult(i), false);
    } catch (std::exception& e) {
        addLuaLog(e.what(), true);
    }
    if (L.gettop() > top) L.pop(L.gettop() - top);
}

std::string PCSX::TerminalUI::formatResult(int index) {
    auto L = *g_emulator->m_lua;
    if (L.type(index) == LUA_TNUMBER) return fmt::format("{}", L.tonumber(index));
    // Tables, functions and userdata have no string form of their own; ask Lua's tostring.
    lua_State* s = L.getState();
    lua_getglobal(s, "tostring");
    lua_pushvalue(s, index);
    std::string value = "(unprintable)";
    if (lua_pcall(s, 1, 1, 0) == 0 && lua_isstring(s, -1)) {
        size_t len;
        const char* str = lua_tolstring(s, -1, &len);
        value.assign(str, len);
    }
    lua_pop(s, 1);
    return value;
}

void PCSX::TerminalUI::historyMove(int delta) {
    if (m_history.empty()) return;
    if (delta < 0 && m_historyPos > 0) m_historyPos--;
    if (delta > 0 && m_historyPos < m_history.size()) m_historyPos++;
    m_input = m_historyPos < m_history.size() ? m_history[m_historyPos] : "";
}

void PCSX::TerminalUI::init(std::function<void()> applyArguments) {
    loadSettings();
    applyArguments();
    finishLoadSettings();

    m_app = std::make_unique<ftxui::App>(ftxui::App::Fullscreen());
    m_app->TrackMouse(false);
    m_app->HandlePipedInput(false);
    // The terminal is only taken over on the first update(), so a failure during the rest of
    // startup leaves it untouched.
    m_layout = buildLayout();
}

namespace {
ftxui::Elements renderLines(const std::deque<PCSX::TerminalUI::Line>& lines, int height, int scroll) {
    using namespace ftxui;
    Elements out;
    int end = static_cast<int>(lines.size()) - scroll;
    int start = std::max(0, end - height);
    for (int i = start; i < end; i++) {
        auto t = text(lines[i].text);
        out.push_back(lines[i].error ? t | color(Color::Red) : t);
    }
    return out;
}
}  // namespace

std::shared_ptr<ftxui::ComponentBase> PCSX::TerminalUI::buildLayout() {
    using namespace ftxui;
    InputOption inputOption;
    inputOption.multiline = false;
    inputOption.on_enter = [this]() {
        std::string cmd = m_input;
        m_input.clear();
        execute(cmd);
    };
    auto input = Input(&m_input, "Lua", inputOption);

    auto layout = Renderer(input, [this, input]() {
        std::lock_guard<std::mutex> lock(m_mutex);
        // Log gets everything left after the Lua pane, the separator, the input line and the status line.
        int logHeight = std::max(1, Terminal::Size().dimy - c_luaPaneHeight - 3);
        auto status = hbox({
            text(g_system->running() ? " RUNNING " : " PAUSED ") | inverted,
            text(fmt::format(" pc={:08x} ", g_emulator->m_cpu->m_regs.pc)),
            text(m_logScroll ? fmt::format(" scrolled -{} ", m_logScroll) : ""),
            filler(),
            text(m_notification),
            text(" F5 run/pause  PgUp/PgDn scroll  Ctrl-C quit "),
        });
        return vbox({
            vbox(renderLines(m_log, logHeight, m_logScroll)) | size(HEIGHT, EQUAL, logHeight),
            separator(),
            vbox(renderLines(m_lua, c_luaPaneHeight, 0)) | size(HEIGHT, EQUAL, c_luaPaneHeight),
            hbox({text("> "), input->Render() | flex}),
            status,
        });
    });
    return CatchEvent(layout, [this](Event event) { return handleEvent(event); });
}

bool PCSX::TerminalUI::handleEvent(const ftxui::Event& event) {
    using ftxui::Event;
    if (event == Event::ArrowUp || event == Event::ArrowDown) {
        historyMove(event == Event::ArrowUp ? -1 : 1);
        return true;
    }
    if (event == Event::PageUp || event == Event::PageDown) {
        std::lock_guard<std::mutex> lock(m_mutex);
        int page = std::max(1, ftxui::Terminal::Size().dimy / 2);
        m_logScroll += event == Event::PageUp ? page : -page;
        m_logScroll = std::clamp(m_logScroll, 0, std::max(0, static_cast<int>(m_log.size()) - 1));
        return true;
    }
    if (event != Event::F5) return false;
    if (g_system->running()) {
        g_system->pause();
    } else {
        g_system->resume();
    }
    return true;
}

void PCSX::TerminalUI::setLua(Lua L) { setLuaCommon(L); }

void PCSX::TerminalUI::close() {
    // The loop owns the terminal state; destroying it restores the screen.
    m_loop.reset();
    m_layout.reset();
    m_app.reset();
}

void PCSX::TerminalUI::update(bool vsync) {
    tick();
    if (!m_loop && m_layout) m_loop = std::make_unique<ftxui::Loop>(m_app.get(), m_layout);
    if (m_loop) {
        // Nothing else asks for a redraw while the CPU runs, so the status line would sit still.
        auto now = std::chrono::steady_clock::now();
        if (g_system->running() && now - m_lastRedraw >= std::chrono::milliseconds(100)) {
            m_lastRedraw = now;
            m_app->RequestAnimationFrame();
        }
        m_loop->RunOnce();
        if (m_loop->HasQuitted()) {
            close();
            g_system->quit();
            return;
        }
    }
    if (!g_system->running()) {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(10ms);
    }
}
