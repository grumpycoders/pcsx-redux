
#include "gui/widgets/named_savestates.h"

#include "core/cdrom.h"
#include "core/debug.h"
#include "gui/gui.h"
#include "imgui.h"
#include "imgui_internal.h"

void PCSX::Widgets::NamedSaveStates::draw(GUI* gui, const char* title) {
    ImGui::SetNextWindowPos(ImVec2(520, 30), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    ImGuiStyle& style = ImGui::GetStyle();
    const float heightSeparator = style.ItemSpacing.y;
    const float footerHeight = (heightSeparator * 2 + ImGui::GetTextLineHeightWithSpacing()) * 4;
    const float glyphWidth = ImGui::GetFontSize();

    // Any ImGui::Text() preceeding a ImGui::InputText() will be incorrectly aligned, use this value to awkwardly account for this
    // Luckily this value is consistent no matter what the UI main font size is set to
    const float verticalAlignAdjust = 3.0f;

    // Create a button for each named save state
    ImGui::BeginChild("SaveStatesList", ImVec2(0, -footerHeight), true);
    auto saveStates = getNamedSaveStates(gui);
    for (const auto& saveStatePair : saveStates) {
        // The button is invisible so we can adjust the highlight separately
        if (ImGui::InvisibleButton(saveStatePair.second.c_str(),
                                   ImVec2(-FLT_MIN, glyphWidth + style.FramePadding.y * 2),
                                   ImGuiButtonFlags_PressedOnClick | ImGuiButtonFlags_PressedOnDoubleClick)) {
            // Copy the name to the input box
            strcpy(m_namedSaveNameString, saveStatePair.second.c_str());
            // Load the save state if it was a double-click
            if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                loadSaveState(gui, saveStatePair.first);
            }
        }
        // Add a base coloured rect - highlight it if hovering over the button or the current InputText below matches it
        bool matches = StringsHelpers::strcasecmp(m_namedSaveNameString, saveStatePair.second.c_str());
        bool hovered = ImGui::IsItemHovered();
        ImGui::GetWindowDrawList()->AddRectFilled(
            ImGui::GetCurrentContext()->LastItemData.Rect.Min, ImGui::GetCurrentContext()->LastItemData.Rect.Max,
            ImGui::ColorConvertFloat4ToU32(
                ImGui::GetStyle()
                    .Colors[matches ? ImGuiCol_HeaderActive : (hovered ? ImGuiCol_HeaderHovered : ImGuiCol_Header)]));
        // Finally the butotn text
        ImGui::GetWindowDrawList()->AddText(
            ImVec2(ImGui::GetCurrentContext()->LastItemData.Rect.Min.x + style.FramePadding.y,
                   ImGui::GetCurrentContext()->LastItemData.Rect.Min.y + style.FramePadding.y),
            ImGui::GetColorU32(ImGuiCol_Text), saveStatePair.second.c_str());
    }
    ImGui::EndChild();

    // Move the leading text down to align with the following InputText()
    float posY = ImGui::GetCursorPosY();
    ImGui::SetCursorPosY(posY + verticalAlignAdjust);

    ImGui::Text(_("Filename: "));
    ImGui::SameLine();
    ImGui::Text(gui->getSaveStatePrefix(true).c_str());
    ImGui::SameLine(0.0f, 0.0f);

    // Restore the vertical value
    ImGui::SetCursorPosY(posY);

    // Ensure that we don't add invalid characters to the filename
    // This also filters on pasted text
    struct TextFilters {
        static int FilterNonPathCharacters(ImGuiInputTextCallbackData* data) {
            // Filter the core problematic characters for Windows and Linux
            // Anything remaining outside of [a-zA-Z0-9._-] is also allowed
            switch (data->EventChar) {
                case '\\':
                case '/':
                case '<':
                case '>':
                case '|':
                case '\"':
                case ':':
                case '?':
                case '*':
                case 0:
                    return 1;
            }
            return 0;
        }
    };

    ImGui::InputTextWithHint("##SaveNameInput", "Enter the name of your save state here", m_namedSaveNameString,
        NAMED_SAVE_STATE_LENGTH_MAX, ImGuiInputTextFlags_CallbackCharFilter, TextFilters::FilterNonPathCharacters);
    ImGui::SameLine(0.0f, 0.0f);

    // Trailing text alignment also needs adjusting, but in the opposite direction
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() - verticalAlignAdjust);
    ImGui::Text(gui->getSaveStatePostfix().c_str());

    ImGui::Separator();

    // Add various buttons based on whether a save state exists with that name
    auto found = std::find_if(saveStates.begin(), saveStates.end(), [=](auto saveStatePair) {
        return strlen(m_namedSaveNameString) > 0 &&
               StringsHelpers::strcasecmp(m_namedSaveNameString, saveStatePair.second.c_str());
        });
    bool exists = found != saveStates.end();

    float width = ImGui::GetCurrentContext()->LastItemData.Rect.GetWidth();
    ImVec2 buttonDims = ImVec2(-FLT_MIN, glyphWidth + style.FramePadding.y * 2);
    ImVec2 halfDims = ImVec2((width - (style.FramePadding.x * 6.0f)) * 0.5f, buttonDims.y);

    if (!exists) {
        if (strlen(m_namedSaveNameString) > 0) {
            // The save state doesn't exist, and the name is valid
            std::string pathStr = fmt::format("{}{}{}", gui->getSaveStatePrefix(true), m_namedSaveNameString, gui->getSaveStatePostfix());
            std::filesystem::path newPath = pathStr;
            if (ImGui::Button(_("Create save"), buttonDims)) {
                saveSaveState(gui, newPath);
            }
        }
    } else {
        // The save state exists
        if (ImGui::Button(_("Overwrite save"), halfDims)) {
            saveSaveState(gui, found->first);
        }
        ImGui::SameLine();
        if (ImGui::Button(_("Load save"), halfDims)) {
            loadSaveState(gui, found->first);
        }
        // Add a deliberate spacer before the delete button
        // There is no delete confirmation, and this makes a mis-click less likely to hit it
        ImGui::Dummy(buttonDims);
        if (ImGui::Button(_("Delete save"), buttonDims)) {
            deleteSaveState(found->first);
        }
    }

    ImGui::End();
}

std::vector<std::pair<std::filesystem::path, std::string>> PCSX::Widgets::NamedSaveStates::getNamedSaveStates(GUI* gui) {
    std::vector<std::pair<std::filesystem::path, std::string>> names;

    // Get the filename prefix to use, which follows the typical save state format, with a separator between gameID and name
    std::string prefix = gui->getSaveStatePrefix(true);
    std::string postfix = gui->getSaveStatePostfix();

    // Loop the root directory
    std::error_code ec;
    if (std::filesystem::exists(std::filesystem::current_path(), ec)) {
        for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::current_path(), ec)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                if (filename.find(prefix) == 0 &&
                    filename.rfind(postfix) == filename.length() - postfix.length()) {
                    std::string niceName = filename.substr(prefix.length(), filename.length() - (prefix.length() + postfix.length()));
                    // Only support names that fit within the character limit
                    if (niceName.length() < NAMED_SAVE_STATE_LENGTH_MAX) {
                        names.emplace_back(entry.path(), niceName);
                    }
                }
            }
        }
    }

    return names;
}

void PCSX::Widgets::NamedSaveStates::saveSaveState(GUI* gui, std::filesystem::path saveStatePath) {
    g_system->log(LogClass::UI, "Saving named save state: %s\n", saveStatePath.filename().string().c_str());
    gui->saveSaveState(saveStatePath);
}

void PCSX::Widgets::NamedSaveStates::loadSaveState(GUI* gui, std::filesystem::path saveStatePath) {
    g_system->log(LogClass::UI, "Loading named save state: %s\n", saveStatePath.filename().string().c_str());
    gui->loadSaveState(saveStatePath);
}

void PCSX::Widgets::NamedSaveStates::deleteSaveState(std::filesystem::path saveStatePath) {
    g_system->log(LogClass::UI, "Deleting named save state: %s\n", saveStatePath.filename().string().c_str());
    std::remove(saveStatePath.string().c_str());
}
