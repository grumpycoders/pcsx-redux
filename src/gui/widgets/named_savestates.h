
#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace PCSX {

class GUI;
namespace Widgets {

class NamedSaveStates {
  public:
    NamedSaveStates(bool& show) : m_show(show) {}
    void draw(GUI* gui, const char* title);
    bool& m_show;

    std::vector<std::pair<std::filesystem::path, std::string>> getNamedSaveStates(GUI* gui);

  private:
    static constexpr int NAMED_SAVE_STATE_LENGTH_MAX = 128;

    void saveSaveState(GUI* gui, std::filesystem::path saveStatePath);
    void loadSaveState(GUI* gui, std::filesystem::path saveStatePath);
    void deleteSaveState(std::filesystem::path saveStatePath);

    char m_namedSaveNameString[NAMED_SAVE_STATE_LENGTH_MAX] = "";
};

}  // namespace Widgets

}  // namespace PCSX
