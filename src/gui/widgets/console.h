/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include <functional>
#include <string>
#include <vector>

#include "imgui.h"

namespace PCSX {
class GUI;
namespace Widgets {

class Console {
  public:
    Console(bool& show) : m_show(show) {}
    void setCmdExec(std::function<void(const std::string&)> cmdExec) { m_cmdExec = cmdExec; }

    void addLog(const std::string& str) { m_items.push_back(std::make_pair(LineType::NORMAL, str)); }
    void addLog(std::string&& str) { m_items.push_back(std::make_pair(LineType::NORMAL, std::move(str))); }
    void addError(const std::string& str) { m_items.push_back(std::make_pair(LineType::ERRORMSG, str)); }
    void addError(std::string&& str) { m_items.push_back(std::make_pair(LineType::ERRORMSG, std::move(str))); }

    void draw(const char* title, GUI* gui);

    bool& m_show;

  private:
    static int TextEditCallbackStub(ImGuiInputTextCallbackData* data) {
        Console* console = (Console*)data->UserData;
        return console->TextEditCallback(data);
    }

    int TextEditCallback(ImGuiInputTextCallbackData* data);

    std::string InputBuf;
    enum class LineType {
        NORMAL,
        COMMAND,
        ERRORMSG,
    };
    std::vector<std::pair<LineType, std::string>> m_items;
    std::vector<std::string> m_history;
    int m_historyPos = -1;  // -1: new line, 0..History.Size-1 browsing history.
    bool m_autoScroll = true;
    bool m_scrollToBottom = false;
    bool m_mono = true;
    std::function<void(const std::string&)> m_cmdExec;
};

}  // namespace Widgets
}  // namespace PCSX
