
#pragma once

#include <string>
#include <vector>
#include <filesystem>

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
    void saveSaveState(GUI* gui, std::filesystem::path saveStatePath);
    void loadSaveState(GUI* gui, std::filesystem::path saveStatePath);
    void deleteSaveState(std::filesystem::path saveStatePath);

    char m_namedSaveNameString[128] = "";
};

}  // namespace Widgets

}  // namespace PCSX
