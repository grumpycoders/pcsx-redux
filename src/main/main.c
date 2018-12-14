#include <zlib.h>

#include <SDL.h>

#include "psxcommon.h"
#include "r3000a.h"
#include "gui/gui.h"

void SysPrintf(const char *fmt, ...) {
    // print message to debugging console
}

void SysMessage(const char *fmt, ...) {
    // display message to user as a pop-up
}

void SysUpdate() {
    // called on vblank to update states
    GUI_flip();
}

void SysRunGui() {
    // called when the UI needs to show up
}

void SysReset() {
    // debugger is requesting a reset
}

void SysClose() {
    // emulator is requesting a shutdown of the emulation
}

int main() {
    GUI_init();

    memset(&Config, 0, sizeof(PcsxConfig));
    Config.PsxAuto = 1;
    Config.HLE = 1;

    SetIsoFile("test.img");
    LoadPlugins();

    EmuInit();
    EmuReset();

    CDR_open();
    CheckCdrom();
    LoadCdrom();

    psxCpu = &psxInt;
    psxCpu->Init();
    psxCpu->Execute();

    return 0;
}
