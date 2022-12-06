/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include <optional>

#include "gui/widgets/zep-lua.h"
#include "repl/mode_repl.h"
#include "zep/editor.h"
#include "zep/filesystem.h"
#include "zep/imgui/display_imgui.h"
#include "zep/mode_standard.h"
#include "zep/mode_vim.h"
#include "zep/tab_window.h"
#include "zep/theme.h"
#include "zep/window.h"

struct ImFont;

namespace PCSX {
class GUI;
namespace Widgets {

class ZepEditor final : public Zep::IZepComponent, public Zep::IZepReplProvider {
  public:
    ZepEditor(const std::string& name);

    virtual ~ZepEditor() {}

    void Destroy() {
        m_editor->UnRegisterCallback(this);
        m_editor.reset();
    }

    void draw(GUI* gui);

    virtual Zep::ZepEditor& GetEditor() const override final { return *m_editor; }

    void setText(const std::string& str) {
        auto buffer = m_editor->GetMRUBuffer();
        buffer->SetText(str);
    }

    std::string getText() {
        auto buffer = m_editor->GetMRUBuffer();
        return buffer->GetBufferText(buffer->Begin(), buffer->End());
    }

    bool hasTextChanged() {
        auto currentTime = m_editor->GetMRUBuffer()->GetLastUpdateTime();
        if (m_lastUpdateTime.has_value() && (m_lastUpdateTime.value() == currentTime)) {
            return false;
        }
        m_lastUpdateTime = currentTime;
        return true;
    }

  private:
    std::unique_ptr<Zep::ZepEditor> m_editor;
    std::optional<decltype(m_editor->GetMRUBuffer()->GetLastUpdateTime())> m_lastUpdateTime;
    std::optional<float> m_dpiScale;
    ImFont* m_font = nullptr;

    virtual std::string ReplParse(Zep::ZepBuffer& buffer, const Zep::GlyphIterator& cursorOffset,
                                  Zep::ReplParseType type) override;
    virtual std::string ReplParse(const std::string& str) override;
    virtual bool ReplIsFormComplete(const std::string& str, int& indent) override;
    virtual void Notify(std::shared_ptr<Zep::ZepMessage> message) override;
};

}  // namespace Widgets
}  // namespace PCSX
