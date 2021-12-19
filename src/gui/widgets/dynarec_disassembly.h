//
// Created by Caleb Yates on 12/16/21.
//

#pragma once
#include "imgui.h"
#include <string>
#include <vector>
#include <string>

namespace PCSX {
class GUI;

namespace Widgets {

class Disassembly {

public:
    Disassembly() = default;

    void draw(GUI*, const char*);
    void addLog(const std::string& str) {
        if (m_items.size() >= 320000) m_items.clear();
        m_items.push_back(str);
    }
    bool m_show = false;



private:
    enum class disassemblerResult {NONE, INVALID_BFR, INVALID_BFR_SIZE, CS_INIT_FAIL, CS_DIS_FAIL, SUCCESS};
    std::vector<std::string> m_items;
    std::vector<std::string> m_history;
    int m_historyPos = -1;  // -1: new line, 0..History.Size-1 browsing history.
    bool m_autoScroll = true;
    bool m_scrollToBottom = false;
    bool m_mono = true;
    bool m_showError = false;
    bool m_tryDisassembly = false;
    bool m_outputFile = false;
    disassemblerResult m_result = disassemblerResult::NONE;
    disassemblerResult disassembleBuffer();

};

}  // namespace Widgets
}  // namespace PCSX
