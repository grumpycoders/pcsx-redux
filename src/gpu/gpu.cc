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

#define NOMINMAX

#include <stdint.h>
#include <time.h>

#include <algorithm>

#include "core/psxmem.h"
#include "gpu/cfg.h"
#include "gpu/debug.h"
#include "gpu/draw.h"
#include "gpu/externals.h"
#include "gpu/fps.h"
#include "gpu/gpu.h"
#include "gpu/interface.h"
#include "gpu/key.h"
#include "gpu/menu.h"
#include "gpu/prim.h"

////////////////////////////////////////////////////////////////////////
// GPU globals
////////////////////////////////////////////////////////////////////////

bool bSkipNextFrame = false;
uint32_t dwLaceCnt = 0;
int iColDepth;
int iWindowMode;
int16_t sDispWidths[8] = {256, 320, 512, 640, 368, 384, 512, 640};
PSXDisplay_t PSXDisplay;
PSXDisplay_t PreviousPSXDisplay;
int32_t lSelectedSlot = 0;
bool bChangeWinMode = false;
bool bDoLazyUpdate = false;
int iFakePrimBusy = 0;
int iRumbleVal = 0;
int iRumbleTime = 0;
time_t tStart;

void PCSX::GPU::impl::init()  // GPU INIT
{
    memset(ulStatusControl, 0, 256 * sizeof(uint32_t));  // init save state scontrol field
    memset(lGPUInfoVals, 0x00, 16 * sizeof(uint32_t));

    SetFPSHandler();

    PSXDisplay.RGB24 = false;  // init some stuff
    PSXDisplay.Interlaced = false;
    PSXDisplay.DrawOffset.x = 0;
    PSXDisplay.DrawOffset.y = 0;
    PSXDisplay.DisplayMode.x = 320;
    PSXDisplay.DisplayMode.y = 240;
    PreviousPSXDisplay.DisplayMode.x = 320;
    PreviousPSXDisplay.DisplayMode.y = 240;
    PSXDisplay.Disabled = false;
    PreviousPSXDisplay.Range.x0 = 0;
    PreviousPSXDisplay.Range.y0 = 0;
    PSXDisplay.Range.x0 = 0;
    PSXDisplay.Range.x1 = 0;
    PreviousPSXDisplay.DisplayModeNew.y = 0;
    PSXDisplay.Double = 1;
    lGPUdataRet = 0x400;

    m_dmaDirection = DMA_IDLE;

    // Reset transfer values, to prevent mis-transfer of data
    // do we still need this?

    // device initialised already !
    lGPUstatusRet = 0x14802000;
    GPUIsIdle();
    GPUIsReadyForCommands();
    bDoVSyncUpdate = true;
}

void PCSX::GPU::impl::open(GUI *gui) {
    m_gui = gui;
    InitFPS();

    bDoVSyncUpdate = true;

    ulInitDisplay();  // setup direct draw
}

void PCSX::GPU::impl::close() {
    CloseDisplay();  // shutdown direct draw
}

void PCSX::GPU::impl::shutdown() {}

////////////////////////////////////////////////////////////////////////
// Update display (swap buffers)
////////////////////////////////////////////////////////////////////////

bool updateDisplay(void)  // UPDATE DISPLAY
{
    bool didUpdate = false;
    if (PSXDisplay.Disabled)  // disable?
    {
        DoClearFrontBuffer();  // -> clear frontbuffer
        return false;          // -> and bye
    }

    if (dwActFixes & 32)  // pc fps calculation fix
    {
        if (UseFrameLimit)
            PCFrameCap();  // -> brake
                           //        if (UseFrameSkip || ulKeybits & KEY_SHOWFPS) PCcalcfps();
    }

    if (iFastFwd)  // fastfwd ?
    {
        static int fpscount;
        UseFrameSkip = 1;

        if (!bSkipNextFrame) {
            DoBufferSwap();  // -> to skip or not to skip
            didUpdate = true;
        }
        if (fpscount % 6)  // -> skip 6/7 frames
            bSkipNextFrame = true;
        else
            bSkipNextFrame = false;
        fpscount++;
        if (fpscount >= (int)fFrameRateHz) fpscount = 0;
        return false;
    }

    if (UseFrameSkip)  // skip ?
    {
        if (!bSkipNextFrame) {
            DoBufferSwap();  // -> to skip or not to skip
            didUpdate = true;
        }
        if (dwActFixes & 0xa0)  // -> pc fps calculation fix/old skipping fix
        {
            if ((fps_skip < fFrameRateHz) && !(bSkipNextFrame))  // -> skip max one in a row
            {
                bSkipNextFrame = true;
                fps_skip = fFrameRateHz;
            } else
                bSkipNextFrame = false;
        } else
            FrameSkip();
    } else  // no skip ?
    {
        DoBufferSwap();  // -> swap
        didUpdate = true;
    }
    return didUpdate;
}

////////////////////////////////////////////////////////////////////////
// roughly emulated screen centering bits... not complete !!!
////////////////////////////////////////////////////////////////////////

void ChangeDispOffsetsX(void)  // X CENTER
{
    int32_t lx, l;

    if (!PSXDisplay.Range.x1) return;

    l = PreviousPSXDisplay.DisplayMode.x;

    l *= (int32_t)PSXDisplay.Range.x1;
    l /= 2560;
    lx = l;
    l &= 0xfffffff8;

    if (l == PreviousPSXDisplay.Range.y1) return;  // abusing range.y1 for
    PreviousPSXDisplay.Range.y1 = (int16_t)l;      // storing last x range and test

    if (lx >= PreviousPSXDisplay.DisplayMode.x) {
        PreviousPSXDisplay.Range.x1 = (int16_t)PreviousPSXDisplay.DisplayMode.x;
        PreviousPSXDisplay.Range.x0 = 0;
    } else {
        PreviousPSXDisplay.Range.x1 = (int16_t)l;

        PreviousPSXDisplay.Range.x0 = (PSXDisplay.Range.x0 - 500) / 8;

        if (PreviousPSXDisplay.Range.x0 < 0) PreviousPSXDisplay.Range.x0 = 0;

        if ((PreviousPSXDisplay.Range.x0 + lx) > PreviousPSXDisplay.DisplayMode.x) {
            PreviousPSXDisplay.Range.x0 = (int16_t)(PreviousPSXDisplay.DisplayMode.x - lx);
            PreviousPSXDisplay.Range.x0 += 2;  //???

            PreviousPSXDisplay.Range.x1 += (int16_t)(lx - l);
        }
        DoClearScreenBuffer();
    }

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////

void ChangeDispOffsetsY(void)  // Y CENTER
{
    int iT, iO = PreviousPSXDisplay.Range.y0;
    int iOldYOffset = PreviousPSXDisplay.DisplayModeNew.y;

    // new

    if ((PreviousPSXDisplay.DisplayModeNew.x + PSXDisplay.DisplayModeNew.y) > 512) {
        int dy1 = 512 - PreviousPSXDisplay.DisplayModeNew.x;
        int dy2 = (PreviousPSXDisplay.DisplayModeNew.x + PSXDisplay.DisplayModeNew.y) - 512;

        if (dy1 >= dy2) {
            PreviousPSXDisplay.DisplayModeNew.y = -dy2;
        } else {
            PSXDisplay.DisplayPosition.y = 0;
            PreviousPSXDisplay.DisplayModeNew.y = -dy1;
        }
    } else
        PreviousPSXDisplay.DisplayModeNew.y = 0;

    // eon

    if (PreviousPSXDisplay.DisplayModeNew.y != iOldYOffset)  // if old offset!=new offset: recalc height
    {
        PSXDisplay.Height = PSXDisplay.Range.y1 - PSXDisplay.Range.y0 + PreviousPSXDisplay.DisplayModeNew.y;
        PSXDisplay.DisplayModeNew.y = PSXDisplay.Height * PSXDisplay.Double;
    }

    //

    if (PSXDisplay.PAL)
        iT = 48;
    else
        iT = 28;

    if (PSXDisplay.Range.y0 >= iT) {
        PreviousPSXDisplay.Range.y0 = (int16_t)((PSXDisplay.Range.y0 - iT - 4) * PSXDisplay.Double);
        if (PreviousPSXDisplay.Range.y0 < 0) PreviousPSXDisplay.Range.y0 = 0;
        PSXDisplay.DisplayModeNew.y += PreviousPSXDisplay.Range.y0;
    } else
        PreviousPSXDisplay.Range.y0 = 0;

    if (iO != PreviousPSXDisplay.Range.y0) {
        DoClearScreenBuffer();
    }
}

////////////////////////////////////////////////////////////////////////
// check if update needed
////////////////////////////////////////////////////////////////////////

void updateDisplayIfChanged(void)  // UPDATE DISPLAY IF CHANGED
{
    if ((PSXDisplay.DisplayMode.y == PSXDisplay.DisplayModeNew.y) &&
        (PSXDisplay.DisplayMode.x == PSXDisplay.DisplayModeNew.x)) {
        if ((PSXDisplay.RGB24 == PSXDisplay.RGB24New) && (PSXDisplay.Interlaced == PSXDisplay.InterlacedNew)) return;
    }

    PSXDisplay.RGB24 = PSXDisplay.RGB24New;  // get new infos

    PSXDisplay.DisplayMode.y = PSXDisplay.DisplayModeNew.y;
    PSXDisplay.DisplayMode.x = PSXDisplay.DisplayModeNew.x;
    PreviousPSXDisplay.DisplayMode.x =            // previous will hold
        std::min(640, PSXDisplay.DisplayMode.x);  // max 640x512... that's
    PreviousPSXDisplay.DisplayMode.y =            // the size of my
        std::min(512, PSXDisplay.DisplayMode.y);  // back buffer surface
    PSXDisplay.Interlaced = PSXDisplay.InterlacedNew;

    PSXDisplay.DisplayEnd.x =  // calc end of display
        PSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
    PSXDisplay.DisplayEnd.y =
        PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;
    PreviousPSXDisplay.DisplayEnd.x = PreviousPSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
    PreviousPSXDisplay.DisplayEnd.y =
        PreviousPSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;

    ChangeDispOffsetsX();

    if (iFrameLimit == 2) SetAutoFrameCap();  // -> set it

    if (UseFrameSkip) updateDisplay();  // stupid stuff when frame skipping enabled
}

////////////////////////////////////////////////////////////////////////

void ChangeWindowMode(void)  // TOGGLE FULLSCREEN - WINDOW
{
    //    GPUclose();
    iWindowMode = !iWindowMode;
    //    GPUopen(textureId);
    bChangeWinMode = false;
    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// gun cursor func: player=0-7, x=0-511, y=0-255
////////////////////////////////////////////////////////////////////////

extern "C" void GPUcursor(int iPlayer, int x, int y) {
    if (iPlayer < 0) return;
    if (iPlayer > 7) return;

    usCursorActive |= (1 << iPlayer);

    if (x < 0) x = 0;
    if (x > 511) x = 511;
    if (y < 0) y = 0;
    if (y > 255) y = 255;

    ptCursorPoint[iPlayer].x = x;
    ptCursorPoint[iPlayer].y = y;
}

////////////////////////////////////////////////////////////////////////
// update lace is called evry VSync
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::impl::updateLace()  // VSYNC
{
    if (!(dwActFixes & 1)) lGPUstatusRet ^= 0x80000000;  // odd/even bit

    if (!(dwActFixes & 32))  // std fps limitation?
        CheckFrameRate();

    if (PSXDisplay.Interlaced)  // interlaced mode?
    {
        if (bDoVSyncUpdate && PSXDisplay.DisplayMode.x > 0 && PSXDisplay.DisplayMode.y > 0) {
            if (updateDisplay()) m_debugger.nextFrame();
        }
    } else  // non-interlaced?
    {
        if (dwActFixes & 64)  // lazy screen update fix
        {
            if (bDoLazyUpdate && !UseFrameSkip) {
                if (updateDisplay()) m_debugger.nextFrame();
            }
            bDoLazyUpdate = false;
        } else {
            if (bDoVSyncUpdate && !UseFrameSkip) {            // some primitives drawn?
                if (updateDisplay()) m_debugger.nextFrame();  // -> update display
            }
        }
    }

    bDoVSyncUpdate = false;  // vsync done
}

////////////////////////////////////////////////////////////////////////
// process read request from GPU status register
////////////////////////////////////////////////////////////////////////

uint32_t PCSX::GPU::impl::readStatus(void)  // READ STATUS
{
    if (dwActFixes & 1) {
        static int iNumRead = 0;  // odd/even hack
        if ((iNumRead++) == 2) {
            iNumRead = 0;
            lGPUstatusRet ^= 0x80000000;  // interlaced bit toggle... we do it on every 3 read status... needed by some
                                          // games (like ChronoCross) with old epsxe versions (1.5.2 and older)
        }
    }

    // if(GetAsyncKeyState(VK_SHIFT)&32768) auxprintf("1 %08x\n",lGPUstatusRet);

    if (iFakePrimBusy)  // 27.10.2007 - PETE : emulating some 'busy' while drawing... pfff
    {
        iFakePrimBusy--;

        if (iFakePrimBusy & 1)  // we do a busy-idle-busy-idle sequence after/while drawing prims
        {
            GPUIsBusy();
            GPUIsNotReadyForCommands();
        } else {
            GPUIsIdle();
            GPUIsReadyForCommands();
        }
        //   auxprintf("2 %08x\n",lGPUstatusRet);
    }

    return lGPUstatusRet;
}

////////////////////////////////////////////////////////////////////////
// processes data send to GPU status register
// these are always single packet commands.
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::impl::writeStatus(uint32_t gdata)  // WRITE STATUS
{
    uint32_t lCommand = (gdata >> 24) & 0xff;

    ulStatusControl[lCommand] = gdata;  // store command for freezing

    switch (lCommand) {
        //--------------------------------------------------//
        // reset gpu
        case 0x00:
            m_debugger.addEvent([&]() { return new Debug::Reset(); });
            memset(lGPUInfoVals, 0x00, 16 * sizeof(uint32_t));
            lGPUstatusRet = 0x14802000;
            PSXDisplay.Disabled = 1;
            m_dmaDirection = DMA_IDLE;
            PSXDisplay.DrawOffset.x = PSXDisplay.DrawOffset.y = 0;
            m_prim.reset();
            PSXDisplay.RGB24 = false;
            PSXDisplay.Interlaced = false;
            return;
        //--------------------------------------------------//
        // dis/enable display
        case 0x03:
            m_debugger.addEvent([&]() { return new Debug::DisplayEnable(gdata & 1); });
            PreviousPSXDisplay.Disabled = PSXDisplay.Disabled;
            PSXDisplay.Disabled = (gdata & 1);

            if (PSXDisplay.Disabled)
                lGPUstatusRet |= GPUSTATUS_DISPLAYDISABLED;
            else
                lGPUstatusRet &= ~GPUSTATUS_DISPLAYDISABLED;
            return;

        //--------------------------------------------------//
        // setting transfer mode
        case 0x04:
            gdata &= 0xffffff;
            m_debugger.addEvent([&]() { return new Debug::DMASetup(gdata); }, gdata == 1 || gdata > 3);
            gdata &= 0x03;  // Only want the lower two bits
            m_dmaDirection = DmaDirection(gdata);
            lGPUstatusRet &= ~GPUSTATUS_DMABITS;  // Clear the current settings of the DMA bits
            lGPUstatusRet |= (gdata << 29);       // Set the DMA bits according to the received data

            return;
        //--------------------------------------------------//
        // setting display position
        case 0x05: {
            m_debugger.addEvent([&]() { return new Debug::DisplayStart(gdata & 0xffffff); }, gdata & 0xf80000);
            PreviousPSXDisplay.DisplayPosition.x = PSXDisplay.DisplayPosition.x;
            PreviousPSXDisplay.DisplayPosition.y = PSXDisplay.DisplayPosition.y;

            ////////
            /*
                 PSXDisplay.DisplayPosition.y = (int16_t)((gdata>>10)&0x3ff);
                 if (PSXDisplay.DisplayPosition.y & 0x200)
                  PSXDisplay.DisplayPosition.y |= 0xfffffc00;
                 if(PSXDisplay.DisplayPosition.y<0)
                  {
                   PreviousPSXDisplay.DisplayModeNew.y=PSXDisplay.DisplayPosition.y/PSXDisplay.Double;
                   PSXDisplay.DisplayPosition.y=0;
                  }
                 else PreviousPSXDisplay.DisplayModeNew.y=0;
            */

            // new
            PSXDisplay.DisplayPosition.y = (int16_t)((gdata >> 10) & 0x1ff);

            // store the same val in some helper var, we need it on later compares
            PreviousPSXDisplay.DisplayModeNew.x = PSXDisplay.DisplayPosition.y;

            if ((PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y) > 512) {
                int dy1 = 512 - PSXDisplay.DisplayPosition.y;
                int dy2 = (PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y) - 512;

                if (dy1 >= dy2) {
                    PreviousPSXDisplay.DisplayModeNew.y = -dy2;
                } else {
                    PSXDisplay.DisplayPosition.y = 0;
                    PreviousPSXDisplay.DisplayModeNew.y = -dy1;
                }
            } else
                PreviousPSXDisplay.DisplayModeNew.y = 0;
            // eon

            PSXDisplay.DisplayPosition.x = (int16_t)(gdata & 0x3ff);
            PSXDisplay.DisplayEnd.x = PSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
            PSXDisplay.DisplayEnd.y =
                PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;
            PreviousPSXDisplay.DisplayEnd.x = PreviousPSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
            PreviousPSXDisplay.DisplayEnd.y =
                PreviousPSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;

            bDoVSyncUpdate = true;

            if (!(PSXDisplay.Interlaced))  // stupid frame skipping option
            {
                if (UseFrameSkip) updateDisplay();
                if (dwActFixes & 64) bDoLazyUpdate = true;
            }
        }
            return;
        //--------------------------------------------------//
        // setting width
        case 0x06:
            m_debugger.addEvent([&]() { return new Debug::HDispRange(gdata & 0xffffff); });
            PSXDisplay.Range.x0 = (int16_t)(gdata & 0x7ff);
            PSXDisplay.Range.x1 = (int16_t)((gdata >> 12) & 0xfff);

            PSXDisplay.Range.x1 -= PSXDisplay.Range.x0;

            ChangeDispOffsetsX();

            return;
        //--------------------------------------------------//
        // setting height
        case 0x07: {
            m_debugger.addEvent([&]() { return new Debug::VDispRange(gdata & 0xffffff); });
            PSXDisplay.Range.y0 = (int16_t)(gdata & 0x3ff);
            PSXDisplay.Range.y1 = (int16_t)((gdata >> 10) & 0x3ff);

            PreviousPSXDisplay.Height = PSXDisplay.Height;

            PSXDisplay.Height = PSXDisplay.Range.y1 - PSXDisplay.Range.y0 + PreviousPSXDisplay.DisplayModeNew.y;

            if (PreviousPSXDisplay.Height != PSXDisplay.Height) {
                PSXDisplay.DisplayModeNew.y = PSXDisplay.Height * PSXDisplay.Double;

                ChangeDispOffsetsY();

                updateDisplayIfChanged();
            }
            return;
        }
        //--------------------------------------------------//
        // setting display infos
        case 0x08:
            m_debugger.addEvent([&]() { return new Debug::SetDisplayMode(gdata & 0xffffff); });
            PSXDisplay.DisplayModeNew.x = sDispWidths[(gdata & 0x03) | ((gdata & 0x40) >> 4)];

            if (gdata & 0x04)
                PSXDisplay.Double = 2;
            else
                PSXDisplay.Double = 1;

            PSXDisplay.DisplayModeNew.y = PSXDisplay.Height * PSXDisplay.Double;

            ChangeDispOffsetsY();

            PSXDisplay.PAL = (gdata & 0x08) ? true : false;            // if 1 - PAL mode, else NTSC
            PSXDisplay.RGB24New = (gdata & 0x10) ? true : false;       // if 1 - TrueColor
            PSXDisplay.InterlacedNew = (gdata & 0x20) ? true : false;  // if 1 - Interlace

            lGPUstatusRet &= ~GPUSTATUS_WIDTHBITS;                               // Clear the width bits
            lGPUstatusRet |= (((gdata & 0x03) << 17) | ((gdata & 0x40) << 10));  // Set the width bits

            if (PSXDisplay.InterlacedNew) {
                if (!PSXDisplay.Interlaced) {
                    PreviousPSXDisplay.DisplayPosition.x = PSXDisplay.DisplayPosition.x;
                    PreviousPSXDisplay.DisplayPosition.y = PSXDisplay.DisplayPosition.y;
                }
                lGPUstatusRet |= GPUSTATUS_INTERLACED;
            } else
                lGPUstatusRet &= ~GPUSTATUS_INTERLACED;

            if (PSXDisplay.PAL)
                lGPUstatusRet |= GPUSTATUS_PAL;
            else
                lGPUstatusRet &= ~GPUSTATUS_PAL;

            if (PSXDisplay.Double == 2)
                lGPUstatusRet |= GPUSTATUS_DOUBLEHEIGHT;
            else
                lGPUstatusRet &= ~GPUSTATUS_DOUBLEHEIGHT;

            if (PSXDisplay.RGB24New)
                lGPUstatusRet |= GPUSTATUS_RGB24;
            else
                lGPUstatusRet &= ~GPUSTATUS_RGB24;

            updateDisplayIfChanged();

            return;
        //--------------------------------------------------//
        // ask about GPU version and other stuff
        case 0x10:
            m_debugger.addEvent([&]() { return new Debug::GetDisplayInfo(gdata & 0xffffff); });
            gdata &= 0xff;

            switch (gdata) {
                case 0x02:
                    lGPUdataRet = lGPUInfoVals[INFO_TW];  // tw infos
                    return;
                case 0x03:
                    lGPUdataRet = lGPUInfoVals[INFO_DRAWSTART];  // draw start
                    return;
                case 0x04:
                    lGPUdataRet = lGPUInfoVals[INFO_DRAWEND];  // draw end
                    return;
                case 0x05:
                case 0x06:
                    lGPUdataRet = lGPUInfoVals[INFO_DRAWOFF];  // draw offset
                    return;
                case 0x07:
                    lGPUdataRet = 0x02;  // gpu type
                    return;
                case 0x08:
                case 0x0F:  // some bios addr?
                    lGPUdataRet = 0xBFC03720;
                    return;
            }
            return;
            //--------------------------------------------------//

        default:
            m_debugger.addEvent(
                [&]() {
                    char cmd[9];
                    std::snprintf(cmd, 9, "%08x", gdata);
                    return new Debug::Invalid(_("Unsupported WriteStatus command 0x") + std::string(cmd));
                },
                true);
            return;
    }
}

////////////////////////////////////////////////////////////////////////
// core read from vram
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::impl::readDataMem(uint32_t *feed, int transferSize, uint32_t hwAddr) {
    if (m_dmaDirection != DMA_READ) {
        m_debugger.addEvent([&]() { return new Debug::Invalid("writeDmaMem with DmaDirection not DMA_WRITE"); });
        return;
    }

#if 0
    if (DataReadMode != DR_VRAMTRANSFER) {
        m_debugger.addEvent([]() { return new Debug::Verbose(_("Status read")); });
        return;
    }

    m_debugger.addEvent([&]() {
        return new Debug::VRAMRead(hwAddr, iSize, VRAMReadInfo.x, VRAMReadInfo.y, VRAMReadInfo.Width,
                                   VRAMReadInfo.Height);
    });
#endif

    GPUIsBusy();
    while (transferSize) {
        if (!m_processor->wantsFullMemoryRead()) {
            bool okayToFeed = transferSize;
            while (okayToFeed) {
                uint32_t word = m_processor->processRead();
                *feed++ = SWAP_LEu32(word);
                transferSize--;
                okayToFeed = !m_processor->wantsFullMemoryRead() && transferSize;
                lGPUdataRet = word;
            }
        } else {
            transferSize -= m_processor->readFullMemory(feed, transferSize);
        }
    }
    lGPUstatusRet &= ~GPUSTATUS_READYFORVRAM;
    GPUIsIdle();
}

void PCSX::GPU::impl::writeDataMem(const uint32_t *feed, int transferSize, uint32_t hwAddr) {
    if (m_dmaDirection != DMA_WRITE) {
        m_debugger.addEvent([&]() { return new Debug::Invalid("writeDmaMem with DmaDirection not DMA_WRITE"); });
        return;
    }
    GPUIsBusy();
    GPUIsNotReadyForCommands();
    while (transferSize) {
        if (!m_processor->wantsFullMemoryWrite()) {
            bool okayToFeed = transferSize;
            while (okayToFeed) {
                uint32_t word = SWAP_LEu32(*feed++);
                transferSize--;
                m_processor->processWrite(word);
                okayToFeed = !m_processor->wantsFullMemoryWrite() && transferSize;
                lGPUdataRet = word;
            }
        } else {
            transferSize -= m_processor->writeFullMemory(feed, transferSize);
        }
    }
    GPUIsReadyForCommands();
    GPUIsIdle();
}

////////////////////////////////////////////////////////////////////////
// sets all kind of act fixes
////////////////////////////////////////////////////////////////////////

void SetFixes(void) {
    bool bOldPerformanceCounter = UsePerformanceCounter;  // store curr timer mode

    if (dwActFixes & 0x10)  // check fix 0x10
        UsePerformanceCounter = false;
    else
        SetFPSHandler();

    if (bOldPerformanceCounter != UsePerformanceCounter)  // we have change it?
        InitFPS();                                        // -> init fps again

    if (dwActFixes & 0x02)
        sDispWidths[4] = 384;
    else
        sDispWidths[4] = 368;
}

////////////////////////////////////////////////////////////////////////
// process gpu commands
////////////////////////////////////////////////////////////////////////

uint32_t lUsedAddr[3];

__inline bool CheckForEndlessLoop(uint32_t laddr) {
    if (laddr == lUsedAddr[1]) return true;
    if (laddr == lUsedAddr[2]) return true;

    if (laddr < lUsedAddr[0])
        lUsedAddr[1] = laddr;
    else
        lUsedAddr[2] = laddr;
    lUsedAddr[0] = laddr;
    return false;
}

int32_t PCSX::GPU::impl::dmaChain(uint32_t *baseAddrL, uint32_t addr) {
    uint32_t dmaMem;
    unsigned char *baseAddrB;
    int16_t count;
    unsigned int DMACommandCounter = 0;

    GPUIsBusy();

    lUsedAddr[0] = lUsedAddr[1] = lUsedAddr[2] = 0xffffff;

    baseAddrB = (unsigned char *)baseAddrL;

    do {
        addr &= 0x1FFFFC;
        if (DMACommandCounter++ > 2000000) break;
        if (::CheckForEndlessLoop(addr)) break;

        count = baseAddrB[addr + 3];

        dmaMem = addr + 4;

        if (count > 0) writeDataMem(&baseAddrL[dmaMem >> 2], count, dmaMem);

        addr = baseAddrL[addr >> 2] & 0xffffff;
    } while (addr != 0xffffff);

    GPUIsIdle();

    return 0;
}

////////////////////////////////////////////////////////////////////////
// Freeze
////////////////////////////////////////////////////////////////////////

void PCSX::GPU::impl::save(SaveStates::GPU &gpu) {
    gpu.get<SaveStates::GPUStatus>().value = lGPUstatusRet;
    gpu.get<SaveStates::GPUControl>().copyFrom(reinterpret_cast<uint8_t *>(ulStatusControl));
    //    gpu.get<SaveStates::GPUVRam>().copyFrom(psxVub);
}

void PCSX::GPU::impl::load(const SaveStates::GPU &gpu) {
    lGPUstatusRet = gpu.get<SaveStates::GPUStatus>().value;
    gpu.get<SaveStates::GPUControl>().copyTo(reinterpret_cast<uint8_t *>(ulStatusControl));
    //    gpu.get<SaveStates::GPUVRam>().copyTo(psxVub);

    // RESET TEXTURE STORE HERE, IF YOU USE SOMETHING LIKE THAT

    writeStatus(ulStatusControl[0]);
    writeStatus(ulStatusControl[1]);
    writeStatus(ulStatusControl[2]);
    writeStatus(ulStatusControl[3]);
    writeStatus(ulStatusControl[8]);  // try to repair things
    writeStatus(ulStatusControl[6]);
    writeStatus(ulStatusControl[7]);
    writeStatus(ulStatusControl[5]);
    writeStatus(ulStatusControl[4]);
}

////////////////////////////////////////////////////////////////////////

void GPUsetfix(uint32_t dwFixBits) { dwEmuFixes = dwFixBits; }

////////////////////////////////////////////////////////////////////////

void GPUsetframelimit(uint32_t option) {
    bInitCap = true;

    if (option == 1) {
        UseFrameLimit = 1;
        UseFrameSkip = 0;
        iFrameLimit = 2;
        SetAutoFrameCap();
        // BuildDispMenu(0);
    } else {
        UseFrameLimit = 0;
    }
}

////////////////////////////////////////////////////////////////////////

extern "C" void GPUvisualVibration(uint32_t iSmall, uint32_t iBig) {}
