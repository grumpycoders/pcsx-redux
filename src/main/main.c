#include <zlib.h>

#include <SDL.h>

#include "gui/gui.h"
#include "psxcommon.h"
#include "r3000a.h"

void SysPrintf(const char *fmt, ...) {
    // print message to debugging console
    va_list a;
    va_start(a, fmt);
    vprintf(fmt, a);
    va_end(a);
}

void SysMessage(const char *fmt, ...) {
    // display message to user as a pop-up
    va_list a;
    va_start(a, fmt);
    vprintf(fmt, a);
    va_end(a);
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
    unsigned int texture = GUI_init();

    memset(&Config, 0, sizeof(PcsxConfig));
    Config.PsxAuto = 1;
    Config.HLE = 0;
    Config.SlowBoot = 0;
    strcpy(Config.BiosDir, ".");
    strcpy(Config.Bios, "bios.bin");

    SetIsoFile("test.img");
    LoadPlugins();

    GPU_open(texture);

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
