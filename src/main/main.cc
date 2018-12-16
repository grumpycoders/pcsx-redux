#include <SDL.h>

#include "core/psxcommon.h"
#include "core/r3000a.h"
#include "gui/gui.h"

class SystemImpl : public PCSX::System {
    virtual void SysPrintf(const char *fmt, ...) override {
        // print message to debugging console
        va_list a;
        va_start(a, fmt);
        vprintf(fmt, a);
        va_end(a);
    }

    virtual void SysBiosPrintf(const char *fmt, ...) override {
        // print message to debugging console
        va_list a;
        va_start(a, fmt);
        vprintf(fmt, a);
        va_end(a);
    }

    virtual void SysBiosPrintf(const char *fmt, va_list a) override {
        // print message to debugging console
        vprintf(fmt, a);
    }

    virtual void SysMessage(const char *fmt, ...) override {
        // display message to user as a pop-up
        va_list a;
        va_start(a, fmt);
        vprintf(fmt, a);
        va_end(a);
    }

    virtual void SysLog(const char *facility, const char *fmt, va_list a) override {
        vprintf(fmt, a);
    }

    virtual void SysUpdate() override {
        // called on vblank to update states
        GUI_flip();
    }

    virtual void SysRunGui() override {
        // called when the UI needs to show up
    }

    virtual void SysReset() override {
        // debugger is requesting a reset
    }

    virtual void SysClose() override {
        // emulator is requesting a shutdown of the emulation
    }
};

int main(int argc, char *argv[]) {
    unsigned int texture = GUI_init();

    PCSX::system = new SystemImpl;

    memset(&g_config, 0, sizeof(PcsxConfig));
    g_config.PsxAuto = 1;
    g_config.HLE = 0;
    g_config.SlowBoot = 0;
    strcpy(g_config.BiosDir, ".");
    strcpy(g_config.Bios, "bios.bin");

    SetIsoFile("test.img");
    LoadPlugins();

    GPU_open(texture);

    EmuInit();
    EmuReset();

    CDR_open();
    CheckCdrom();
    LoadCdrom();

    g_psxCpu = &g_psxInt;
    g_psxCpu->Init();
    g_psxCpu->Execute();

    // temporary, to make sure the code doesn't get removed at link time
    g_psxCpu = &g_psxRec;
    g_psxCpu->Init();
    g_psxCpu->Execute();

    return 0;
}
