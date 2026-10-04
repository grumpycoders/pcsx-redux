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

#include <filesystem>
#include <fstream>
#include <stdexcept>

#include "core/system.h"
#include "gtest/gtest.h"

namespace {

class TestSystem final : public PCSX::System {
  public:
    void softReset() override {}
    void hardReset() override {}
    void biosPutc(int) override {}
    const PCSX::Arguments& getArgs() const override { throw std::logic_error("unused"); }
    void printf(std::string&&) override {}
    void log(PCSX::LogClass, std::string&&) override {}
    void message(std::string&&) override {}
    void luaMessage(const std::string&, bool) override {}
    void update(bool) override {}
    void close() override {}
    void purgeAllEvents() override {}
    void testQuit(int) override {}
};

const char* const c_poFile = R"(msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\n"

#: src/a.cc:1
msgid "Mono"
msgstr "Mono-fr"

#: src/b.cc:1
msgctxt "Audio channels"
msgid "Mono"
msgstr "Mono-audio"

msgctxt ""
"Multi"
"line"
msgid ""
"Split "
"string"
msgstr "Split-ctx"

#, fuzzy
msgctxt "Playback"
msgid "Pause"
msgstr "Pause-fuzzy"

msgid "Last"
msgstr "Last-fr"
)";

}  // namespace

TEST(I18n, Context) {
    auto path = std::filesystem::temp_directory_path() / "pcsx-redux-i18n-test.po";
    {
        std::ofstream out(path, std::ios::binary);
        out << c_poFile;
    }
    TestSystem system;
    ASSERT_TRUE(system.loadLocale("Test", path));
    system.activateLocale("Test");
    auto* oldSystem = PCSX::g_system;
    PCSX::g_system = &system;
    EXPECT_STREQ(_("Mono"), "Mono-fr");
    EXPECT_STREQ(C_("Audio channels", "Mono"), "Mono-audio");
    EXPECT_STREQ(C_("Multiline", "Split string"), "Split-ctx");
    EXPECT_STREQ(C_("Playback", "Pause"), "Pause");
    EXPECT_STREQ(C_("Other", "Mono"), "Mono");
    EXPECT_STREQ(lC_("Audio channels", "Mono")(), "Mono-audio");
    EXPECT_STREQ(_("Last"), "Last-fr");
    PCSX::g_system = oldSystem;
    std::filesystem::remove(path);
}
