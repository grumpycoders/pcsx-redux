/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include <SDL.h>

#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "flags.h"
#include "gui/gui.h"
#include "spu/interface.h"

#include "main/settings.h"

static PCSX::GUI *s_gui;

class SystemImpl : public PCSX::System {
    virtual void printf(const char *fmt, ...) final {
        // print message to debugging console
        va_list a;
        va_start(a, fmt);
        s_gui->addLog(fmt, a);
        va_end(a);
    }

    virtual void biosPrintf(const char *fmt, ...) final {
        // print message to debugging console
        va_list a;
        va_start(a, fmt);
        s_gui->addLog(fmt, a);
        va_end(a);
    }

    virtual void biosPrintf(const char *fmt, va_list a) final { s_gui->addLog(fmt, a); }

    virtual void message(const char *fmt, ...) final {
        // display message to user as a pop-up
        va_list a;
        va_start(a, fmt);
        s_gui->addLog(fmt, a);
        s_gui->addNotification(fmt, a);
        va_end(a);
    }

    virtual void log(const char *facility, const char *fmt, va_list a) final { s_gui->addLog(fmt, a); }

    virtual void update() final {
        // called on vblank to update states
        s_gui->update();
    }

    virtual void runGui() final {
        // called when the UI needs to show up
    }

    virtual void reset() final {
        // debugger is requesting a reset
    }

    virtual void close() final {
        // emulator is requesting a shutdown of the emulation
    }
};

using json = nlohmann::json;

int main(int argc, char **argv) {
    const flags::args args(argc, argv);

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_AUDIO) != 0) {
        assert(0);
    }

    PCSX::g_system = new SystemImpl;
    s_gui = new PCSX::GUI(args);
    s_gui->init();

    PCSX::g_emulator.config().PsxAuto = true;
    PCSX::g_emulator.config().HLE = false;
    PCSX::g_emulator.config().SlowBoot = true;
    PCSX::g_emulator.config().BiosDir = ".";
    PCSX::g_emulator.config().Bios = "bios.bin";
    PCSX::g_emulator.config().Cpu = PCSX::Emulator::CPU_DYNAREC;

    SetIsoFile("test.img");
    LoadPlugins();
    PCSX::g_emulator.m_gpu->open(s_gui);
    PCSX::g_emulator.m_cdrom->m_iso.open();
    PCSX::g_emulator.m_spu->open();

    PCSX::g_emulator.EmuInit();
    PCSX::g_emulator.EmuReset();

    CheckCdrom();
    LoadCdrom();

    while (!PCSX::g_system->quitting()) {
        if (PCSX::g_system->running()) {
            PCSX::g_emulator.m_psxCpu->Execute();
        } else {
            s_gui->update();
        }
    }

    PCSX::g_emulator.m_spu->close();
    PCSX::g_emulator.m_gpu->close();
    PCSX::g_emulator.m_cdrom->m_iso.close();

    PCSX::g_emulator.m_psxCpu->psxShutdown();
    PCSX::g_emulator.m_spu->shutdown();
    PCSX::g_emulator.m_gpu->shutdown();
    PCSX::g_emulator.m_cdrom->m_iso.shutdown();

    s_gui->close();

    delete s_gui;
    delete PCSX::g_system;

    return 0;
}
