/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include "core/ui.h"

#include <fstream>

#include "core/pad.h"
#include "core/psxemulator.h"
#include "core/spu.h"

bool PCSX::UI::loadSettings() {
    std::ifstream cfg("pcsx.json");
    auto& emuSettings = g_emulator->settings;
    bool safeMode = m_args.get<bool>("safe").value_or(false) || m_args.get<bool>("testmode").value_or(false);
    if (cfg.is_open() && !safeMode) {
        try {
            cfg >> m_settingsJson;
        } catch (...) {
        }
        if ((m_settingsJson.count("emulator") == 1) && m_settingsJson["emulator"].is_object()) {
            emuSettings.deserialize(m_settingsJson["emulator"]);
        }

        PCSX::g_emulator->m_spu->setCfg(m_settingsJson);
        PCSX::g_emulator->m_pads->setCfg(m_settingsJson);
        return true;
    } else {
        PCSX::g_emulator->m_pads->setDefaults();
        return false;
    }
}

void PCSX::UI::finishLoadSettings() {
    bool safeMode = m_args.get<bool>("safe").value_or(false) || m_args.get<bool>("testmode").value_or(false);
    auto& emuSettings = g_emulator->settings;
    g_system->activateLocale(emuSettings.get<Emulator::SettingLocale>());
    g_system->m_eventBus->signal(Events::SettingsLoaded{safeMode});
}

void PCSX::UI::setLuaCommon(Lua L) {
    L.load(R"(
print("PCSX-Redux Lua Console")
print(jit.version)
print((function(status, ...)
  local ret = "JIT: " .. (status and "ON" or "OFF")
  for i, v in ipairs({...}) do
    ret = ret .. " " .. v
  end
  return ret
end)(jit.status()))
)",
           "ui startup");
}

void PCSX::UI::tick() {
    uv_run(g_system->getLoop(), UV_RUN_NOWAIT);
    auto L = *g_emulator->m_lua;
    L.getfield("AfterPollingCleanup", LUA_GLOBALSINDEX);
    if (!L.isnil()) {
        try {
            L.pcall();
        } catch (...) {
        }
        L.push();
        L.setfield("AfterPollingCleanup", LUA_GLOBALSINDEX);
    } else {
        L.pop();
    }
}
