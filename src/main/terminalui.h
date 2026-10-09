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

#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "core/ui.h"

namespace ftxui {
class App;
class ComponentBase;
class Loop;
struct Event;
}  // namespace ftxui

namespace PCSX {

// Interactive text mode, selected with -tui when both stdin and stdout are a terminal.
// The console log takes the screen, with a Lua REPL underneath it.
class TerminalUI : public UI {
  public:
    TerminalUI();
    ~TerminalUI();
    static bool isTerminal();
    bool addLog(LogClass logClass, const std::string& msg) override;
    void addLuaLog(const std::string& msg, bool error) override;
    void init(std::function<void()> applyArguments) override;
    void setLua(Lua L) override;
    void close() override;
    void update(bool vsync = false) override;
    void addNotification(const std::string& notification) override;

    struct Line {
        std::string text;
        bool error = false;
    };

  private:
    void appendLines(std::deque<Line>& dest, std::string& pending, const std::string& msg, bool error);
    void execute(const std::string& cmd);
    void historyMove(int delta);
    std::string formatResult(int index);
    std::shared_ptr<ftxui::ComponentBase> buildLayout();
    bool handleEvent(const ftxui::Event& event);

    std::mutex m_mutex;
    std::deque<Line> m_log;
    std::deque<Line> m_lua;
    std::string m_logPending;
    std::string m_input;
    std::vector<std::string> m_history;
    size_t m_historyPos = 0;
    int m_logScroll = 0;
    std::string m_notification;
    std::chrono::steady_clock::time_point m_lastRedraw;
    std::unique_ptr<ftxui::App> m_app;
    std::shared_ptr<ftxui::ComponentBase> m_layout;
    std::unique_ptr<ftxui::Loop> m_loop;
};

}  // namespace PCSX
