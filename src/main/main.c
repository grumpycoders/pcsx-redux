#include <zlib.h>

#include "psxcommon.h"
#include "r3000a.h"

void SysPrintf(const char *fmt, ...) {
    // print message to debugging console
}

void SysMessage(const char *fmt, ...) {
    // display message to user as a pop-up
}

void SysUpdate() {
    // called on vblank to update states
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
    memset(&Config, 0, sizeof(PcsxConfig));
    Config.PsxAuto = 1;
    Config.HLE = 1;

    LoadPlugins();
    cdrIsoInit();

    EmuInit();
    EmuReset();

    SetIsoFile("test.img");
    CDR_open();
    CheckCdrom();
    LoadCdrom();

    psxCpu = &psxInt;
    psxCpu->Init();
    psxCpu->Execute();
}
