/***************************************************************************
                          fps.c  -  description
                             -------------------
    begin                : Sun Oct 28 2001
    copyright            : (C) 2001 by Pete Bernert
    email                : BlackDove@addcom.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version. See also the license.txt file for *
 *   additional informations.                                              *
 *                                                                         *
 ***************************************************************************/

//*************************************************************************//
// History of changes:
//
// 2007/10/27 - Pete
// - Added Nagisa's changes for SSSPSX as a special gpu config option
//
// 2005/04/15 - Pete
// - Changed user frame limit to floating point value
//
// 2003/07/30 - Pete
// - fixed frame limitation if "old skipping method" is used
//
// 2002/12/14 - Pete
// - improved skipping and added some skipping security code
//
// 2002/11/24 - Pete
// - added new frameskip func
//
// 2001/10/28 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include "stdafx.h"

#define _IN_FPS

#include "gpu/soft/externals.h"
#include "gpu/soft/fps.h"
#include "gpu/soft/gpu.h"

////////////////////////////////////////////////////////////////////////
// FPS stuff
////////////////////////////////////////////////////////////////////////

#ifdef _WIN32
LARGE_INTEGER CPUFrequency, PerformanceCounter;
#else
#include <unistd.h>
typedef uint32_t DWORD;
#endif

float fFrameRateHz = 0;
DWORD dwFrameRateTicks = 16;
float fFrameRate;
int iFrameLimit;
int UseFrameLimit = 0;
int UseFrameSkip = 0;
bool bSSSPSXLimit = false;

////////////////////////////////////////////////////////////////////////
// FPS skipping / limit
////////////////////////////////////////////////////////////////////////

bool bInitCap = true;
float fps_skip = 0;
float fps_cur = 0;

////////////////////////////////////////////////////////////////////////

#define MAXLACE 16

void CheckFrameRate(void) {
    if (UseFrameSkip)  // skipping mode?
    {
        if (!(dwActFixes & 0x80))  // not old skipping mode?
        {
            dwLaceCnt++;                                // -> store cnt of vsync between frames
            if (dwLaceCnt >= MAXLACE && UseFrameLimit)  // -> if there are many laces without screen toggling,
            {                                           //    do std frame limitation
                if (dwLaceCnt == MAXLACE) bInitCap = true;

                if (bSSSPSXLimit)
                    FrameCapSSSPSX();
                else
                    FrameCap();
            }
        } else if (UseFrameLimit) {
            if (bSSSPSXLimit)
                FrameCapSSSPSX();
            else
                FrameCap();
        }
        calcfps();  // -> calc fps display in skipping mode
    } else          // non-skipping mode:
    {
        if (UseFrameLimit) FrameCap();           // -> do it
//        if (ulKeybits & KEY_SHOWFPS) calcfps();  // -> and calc fps display
    }
}

////////////////////////////////////////////////////////////////////////
// WIN VERSION
////////////////////////////////////////////////////////////////////////

#ifdef _WIN32

bool IsPerformanceCounter = false;

void FrameCap(void)  // frame limit func
{
    static DWORD curticks, lastticks, _ticks_since_last_update;
    static DWORD TicksToWait = 0;
    static LARGE_INTEGER CurrentTime;
    static LARGE_INTEGER LastTime;
    static bool SkipNextWait = false;
    bool Waiting = true;

    //---------------------------------------------------------
    if (bInitCap) {
        bInitCap = false;
        if (IsPerformanceCounter) QueryPerformanceCounter(&LastTime);
        lastticks = timeGetTime();
        TicksToWait = 0;
        return;
    }
    //---------------------------------------------------------

    if (IsPerformanceCounter) {
        QueryPerformanceCounter(&CurrentTime);
        _ticks_since_last_update = CurrentTime.LowPart - LastTime.LowPart;

        //---------------------------------------------------------
        curticks = timeGetTime();
        if (_ticks_since_last_update > (CPUFrequency.LowPart >> 1)) {
            if (curticks < lastticks)
                _ticks_since_last_update = dwFrameRateTicks + TicksToWait + 1;
            else
                _ticks_since_last_update = (CPUFrequency.LowPart * (curticks - lastticks)) / 1000;
        }
        //---------------------------------------------------------

        if ((_ticks_since_last_update > TicksToWait) || (CurrentTime.LowPart < LastTime.LowPart)) {
            LastTime.HighPart = CurrentTime.HighPart;
            LastTime.LowPart = CurrentTime.LowPart;

            lastticks = curticks;

            if ((_ticks_since_last_update - TicksToWait) > dwFrameRateTicks)
                TicksToWait = 0;
            else
                TicksToWait = dwFrameRateTicks - (_ticks_since_last_update - TicksToWait);
        } else {
            while (Waiting) {
                QueryPerformanceCounter(&CurrentTime);
                _ticks_since_last_update = CurrentTime.LowPart - LastTime.LowPart;

                //---------------------------------------------------------
                curticks = timeGetTime();
                if (_ticks_since_last_update > (CPUFrequency.LowPart >> 1)) {
                    if (curticks < lastticks)
                        _ticks_since_last_update = TicksToWait + 1;
                    else
                        _ticks_since_last_update = (CPUFrequency.LowPart * (curticks - lastticks)) / 1000;
                }
                //---------------------------------------------------------

                if ((_ticks_since_last_update > TicksToWait) || (CurrentTime.LowPart < LastTime.LowPart)) {
                    Waiting = false;

                    lastticks = curticks;

                    LastTime.HighPart = CurrentTime.HighPart;
                    LastTime.LowPart = CurrentTime.LowPart;
                    TicksToWait = dwFrameRateTicks;
                }
            }
        }
    } else {
        curticks = timeGetTime();
        _ticks_since_last_update = curticks - lastticks;

        if ((_ticks_since_last_update > TicksToWait) || (curticks < lastticks)) {
            lastticks = curticks;

            if ((_ticks_since_last_update - TicksToWait) > dwFrameRateTicks)
                TicksToWait = 0;
            else
                TicksToWait = dwFrameRateTicks - (_ticks_since_last_update - TicksToWait);
        } else {
            while (Waiting) {
                curticks = timeGetTime();
                _ticks_since_last_update = curticks - lastticks;
                if ((_ticks_since_last_update > TicksToWait) || (curticks < lastticks)) {
                    Waiting = false;
                    lastticks = curticks;
                    TicksToWait = dwFrameRateTicks;
                }
            }
        }
    }
}

void FrameCapSSSPSX(void)  // frame limit func SSSPSX
{
    static DWORD reqticks, curticks;
    static double offset;

    //---------------------------------------------------------
    if (bInitCap) {
        bInitCap = false;
        reqticks = curticks = timeGetTime();
        offset = 0;
        return;
    }
    //---------------------------------------------------------
    offset += 1000 / fFrameRateHz;
    reqticks += (DWORD)offset;
    offset -= (DWORD)offset;

    curticks = timeGetTime();
    if ((signed int)(reqticks - curticks) > 60)
        Sleep((reqticks - curticks) /
              2);  // pete: a simple Sleep doesn't burn 100% cpu cycles, but it isn't as exact as a brute force loop
    if ((signed int)(curticks - reqticks) > 60) reqticks += (curticks - reqticks) / 2;
}

////////////////////////////////////////////////////////////////////////

#define MAXSKIP 120

void FrameSkip(void) {
    static int iNumSkips = 0, iAdditionalSkip = 0;  // number of additional frames to skip
    static DWORD dwLastLace = 0;                    // helper var for frame limitation
    static DWORD curticks, lastticks, _ticks_since_last_update;
    static LARGE_INTEGER CurrentTime;
    static LARGE_INTEGER LastTime;

    if (!dwLaceCnt) return;  // important: if no updatelace happened, we ignore it completely

    if (iNumSkips)  // we are in pure skipping mode?
    {
        dwLastLace += dwLaceCnt;  // -> calc frame limit helper (number of laces)
        bSkipNextFrame = true;    // -> we skip next frame as well
        iNumSkips--;              // -> ok, one done
    } else                        // ok, no additional skipping has to be done...
    {                             // we check now, if some limitation is needed, or a new skipping has to get started
        DWORD dwWaitTime;

        if (bInitCap || bSkipNextFrame)  // first time or we skipped before?
        {
            if (UseFrameLimit && !bInitCap)  // frame limit wanted and not first time called?
            {
                DWORD dwT = _ticks_since_last_update;  // -> that's the time of the last drawn frame
                dwLastLace +=
                    dwLaceCnt;  // -> and that's the number of updatelace since the start of the last drawn frame

                if (IsPerformanceCounter)  // -> now we calc the time of the last drawn frame + the time we spent
                                           // skipping
                {
                    QueryPerformanceCounter(&CurrentTime);
                    _ticks_since_last_update = dwT + CurrentTime.LowPart - LastTime.LowPart;
                } else {
                    curticks = timeGetTime();
                    _ticks_since_last_update = dwT + curticks - lastticks;
                }

                dwWaitTime =
                    dwLastLace * dwFrameRateTicks;  // -> and now we calc the time the real psx would have needed

                if (_ticks_since_last_update < dwWaitTime)  // -> we were too fast?
                {
                    if ((dwWaitTime - _ticks_since_last_update) >  // -> some more security, to prevent
                        (60 * dwFrameRateTicks))                   //    wrong waiting times
                        _ticks_since_last_update = dwWaitTime;

                    while (_ticks_since_last_update < dwWaitTime)  // -> loop until we have reached the real psx time
                    {                                              //    (that's the additional limitation, yup)
                        if (IsPerformanceCounter) {
                            QueryPerformanceCounter(&CurrentTime);
                            _ticks_since_last_update = dwT + CurrentTime.LowPart - LastTime.LowPart;
                        } else {
                            curticks = timeGetTime();
                            _ticks_since_last_update = dwT + curticks - lastticks;
                        }
                    }
                } else  // we were still too slow ?!!?
                {
                    if (iAdditionalSkip <
                        MAXSKIP)  // -> well, somewhen we really have to stop skipping on very slow systems
                    {
                        iAdditionalSkip++;         // -> inc our watchdog var
                        dwLaceCnt = 0;             // -> reset lace count
                        if (IsPerformanceCounter)  // -> ok, start time of the next frame
                            QueryPerformanceCounter(&LastTime);
                        lastticks = timeGetTime();
                        return;  // -> done, we will skip next frame to get more speed (SkipNextFrame still true)
                    }
                }
            }

            bInitCap = false;          // -> ok, we have inited the frameskip func
            iAdditionalSkip = 0;       // -> init additional skip
            bSkipNextFrame = false;    // -> we don't skip the next frame
            if (IsPerformanceCounter)  // -> we store the start time of the next frame
                QueryPerformanceCounter(&LastTime);
            lastticks = timeGetTime();
            dwLaceCnt = 0;  // -> and we start to count the laces
            dwLastLace = 0;
            _ticks_since_last_update = 0;
            return;  // -> done, the next frame will get drawn
        }

        bSkipNextFrame = false;  // init the frame skip signal to 'no skipping' first

        if (IsPerformanceCounter)  // get the current time (we are now at the end of one drawn frame)
        {
            QueryPerformanceCounter(&CurrentTime);
            _ticks_since_last_update = CurrentTime.LowPart - LastTime.LowPart;
        } else {
            curticks = timeGetTime();
            _ticks_since_last_update = curticks - lastticks;
        }

        dwLastLace = dwLaceCnt;                     // store curr count (frame limitation helper)
        dwWaitTime = dwLaceCnt * dwFrameRateTicks;  // calc the 'real psx lace time'

        if (_ticks_since_last_update > dwWaitTime)  // hey, we needed way too long for that frame...
        {
            if (UseFrameLimit)  // if limitation, we skip just next frame,
            {                   // and decide after, if we need to do more
                iNumSkips = 0;
            } else {
                iNumSkips = _ticks_since_last_update / dwWaitTime;  // -> calc number of frames to skip to catch up
                iNumSkips--;                                        // -> since we already skip next frame, one down
                if (iNumSkips > MAXSKIP) iNumSkips = MAXSKIP;       // -> well, somewhere we have to draw a line
            }
            bSkipNextFrame = true;  // -> signal for skipping the next frame
        } else                      // we were faster than real psx? fine :)
            if (UseFrameLimit)      // frame limit used? so we wait til the 'real psx time' has been reached
        {
            if (dwLaceCnt > MAXLACE)  // -> security check
                _ticks_since_last_update = dwWaitTime;

            while (_ticks_since_last_update < dwWaitTime)  // just do a waiting loop...
            {
                if (IsPerformanceCounter) {
                    QueryPerformanceCounter(&CurrentTime);
                    _ticks_since_last_update = CurrentTime.LowPart - LastTime.LowPart;
                } else {
                    curticks = timeGetTime();
                    _ticks_since_last_update = curticks - lastticks;
                }
            }
        }

        if (IsPerformanceCounter)  // ok, start time of the next frame
            QueryPerformanceCounter(&LastTime);
        lastticks = timeGetTime();
    }

    dwLaceCnt = 0;  // init lace counter
}

////////////////////////////////////////////////////////////////////////

void calcfps(void)  // fps calculations
{
    static DWORD curticks, _ticks_since_last_update, lastticks;
    static long fps_cnt = 0;
    static DWORD fps_tck = 1;
    static LARGE_INTEGER CurrentTime;
    static LARGE_INTEGER LastTime;
    static long fpsskip_cnt = 0;
    static DWORD fpsskip_tck = 1;

    if (IsPerformanceCounter) {
        QueryPerformanceCounter(&CurrentTime);
        _ticks_since_last_update = CurrentTime.LowPart - LastTime.LowPart;

        //--------------------------------------------------//
        curticks = timeGetTime();
        if (_ticks_since_last_update > (CPUFrequency.LowPart >> 1))
            _ticks_since_last_update = (CPUFrequency.LowPart * (curticks - lastticks)) / 1000;
        lastticks = curticks;
        //--------------------------------------------------//

        if (UseFrameSkip && !UseFrameLimit && _ticks_since_last_update)
            fps_skip = min(fps_skip, (((float)CPUFrequency.LowPart) / ((float)_ticks_since_last_update) + 1.0f));

        LastTime.HighPart = CurrentTime.HighPart;
        LastTime.LowPart = CurrentTime.LowPart;
    } else {
        curticks = timeGetTime();
        _ticks_since_last_update = curticks - lastticks;

        if (UseFrameSkip && !UseFrameLimit && _ticks_since_last_update)
            fps_skip = min(fps_skip, ((float)1000 / (float)_ticks_since_last_update + 1.0f));

        lastticks = curticks;
    }

    if (UseFrameSkip && UseFrameLimit) {
        fpsskip_tck += _ticks_since_last_update;

        if (++fpsskip_cnt == 2) {
            if (IsPerformanceCounter)
                fps_skip = ((float)CPUFrequency.LowPart) / ((float)fpsskip_tck) * 2.0f;
            else
                fps_skip = (float)2000 / (float)fpsskip_tck;

            fps_skip += 6.0f;

            fpsskip_cnt = 0;
            fpsskip_tck = 1;
        }
    }

    fps_tck += _ticks_since_last_update;

    if (++fps_cnt == 10) {
        if (IsPerformanceCounter)
            fps_cur = ((float)CPUFrequency.LowPart) / ((float)fps_tck) * 10.0f;
        else
            fps_cur = (float)10000 / (float)fps_tck;

        fps_cnt = 0;
        fps_tck = 1;

        if (UseFrameLimit && fps_cur > fFrameRateHz)  // optical adjust ;) avoids flickering fps display
            fps_cur = fFrameRateHz;
    }
}

////////////////////////////////////////////////////////////////////////
// PC FPS skipping / limit
////////////////////////////////////////////////////////////////////////

void PCFrameCap(void) {
    static DWORD curticks, lastticks, _ticks_since_last_update;
    static DWORD TicksToWait = 0;
    static LARGE_INTEGER CurrentTime;
    static LARGE_INTEGER LastTime;
    bool Waiting = true;

    while (Waiting) {
        if (IsPerformanceCounter) {
            QueryPerformanceCounter(&CurrentTime);
            _ticks_since_last_update = CurrentTime.LowPart - LastTime.LowPart;

            //------------------------------------------------//
            curticks = timeGetTime();
            if (_ticks_since_last_update > (CPUFrequency.LowPart >> 1)) {
                if (curticks < lastticks)
                    _ticks_since_last_update = TicksToWait + 1;
                else
                    _ticks_since_last_update = (CPUFrequency.LowPart * (curticks - lastticks)) / 1000;
            }
            //------------------------------------------------//

            if ((_ticks_since_last_update > TicksToWait) || (CurrentTime.LowPart < LastTime.LowPart)) {
                Waiting = false;
                lastticks = curticks;
                LastTime.HighPart = CurrentTime.HighPart;
                LastTime.LowPart = CurrentTime.LowPart;
                TicksToWait = (unsigned long)(CPUFrequency.LowPart / fFrameRateHz);
            }
        } else {
            curticks = timeGetTime();
            _ticks_since_last_update = curticks - lastticks;
            if ((_ticks_since_last_update > TicksToWait) || (curticks < lastticks)) {
                Waiting = false;
                lastticks = curticks;
                TicksToWait = (1000 / (DWORD)fFrameRateHz);
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCcalcfps(void) {
    static DWORD curticks, _ticks_since_last_update, lastticks;
    static long fps_cnt = 0;
    static float fps_acc = 0;
    static LARGE_INTEGER CurrentTime;
    static LARGE_INTEGER LastTime;
    float CurrentFPS = 0;

    if (IsPerformanceCounter) {
        QueryPerformanceCounter(&CurrentTime);
        _ticks_since_last_update = CurrentTime.LowPart - LastTime.LowPart;

        //--------------------------------------------------//
        curticks = timeGetTime();
        if (_ticks_since_last_update > (CPUFrequency.LowPart >> 1))
            _ticks_since_last_update = (CPUFrequency.LowPart * (curticks - lastticks)) / 1000;
        lastticks = curticks;
        //--------------------------------------------------//

        if (_ticks_since_last_update) {
            CurrentFPS = ((float)CPUFrequency.LowPart) / ((float)_ticks_since_last_update);
        } else
            CurrentFPS = 0;
        LastTime.HighPart = CurrentTime.HighPart;
        LastTime.LowPart = CurrentTime.LowPart;
    } else {
        curticks = timeGetTime();
        if (_ticks_since_last_update = curticks - lastticks)
            CurrentFPS = (float)1000 / (float)_ticks_since_last_update;
        else
            CurrentFPS = 0;
        lastticks = curticks;
    }

    fps_acc += CurrentFPS;

    if (++fps_cnt == 10) {
        fps_cur = fps_acc / 10;
        fps_acc = 0;
        fps_cnt = 0;
    }

    fps_skip = CurrentFPS + 1.0f;
}

////////////////////////////////////////////////////////////////////////

void SetAutoFrameCap(void) {
    if (iFrameLimit == 1) {
        fFrameRateHz = fFrameRate;
        if (IsPerformanceCounter)
            dwFrameRateTicks = (DWORD)(CPUFrequency.LowPart / fFrameRateHz);
        else
            dwFrameRateTicks = (1000 / (DWORD)fFrameRateHz);
        return;
    }

    if (dwActFixes & 32) {
        if (PSXDisplay.Interlaced)
            fFrameRateHz = PSXDisplay.PAL ? 50.0f : 60.0f;
        else
            fFrameRateHz = PSXDisplay.PAL ? 25.0f : 30.0f;
    } else {
        // fFrameRateHz = PSXDisplay.PAL?50.0f:59.94f;
        if (PSXDisplay.PAL) {
            if (lGPUstatusRet & GPUSTATUS_INTERLACED)
                fFrameRateHz = 33868800.0f / 677343.75f;  // 50.00238
            else
                fFrameRateHz = 33868800.0f / 680595.00f;  // 49.76351
        } else {
            if (lGPUstatusRet & GPUSTATUS_INTERLACED)
                fFrameRateHz = 33868800.0f / 565031.25f;  // 59.94146
            else
                fFrameRateHz = 33868800.0f / 566107.50f;  // 59.82750
        }

        if (IsPerformanceCounter)
            dwFrameRateTicks = (DWORD)(CPUFrequency.LowPart / fFrameRateHz);
        else
            dwFrameRateTicks = (1000 / (DWORD)fFrameRateHz);
    }
}

////////////////////////////////////////////////////////////////////////

void SetFPSHandler(void) {
    if (QueryPerformanceFrequency(&CPUFrequency))  // timer mode
        IsPerformanceCounter = true;
    else
        IsPerformanceCounter = false;
}

////////////////////////////////////////////////////////////////////////

void InitFPS(void) {
    bInitCap = true;

    if (fFrameRateHz == 0) {
        if (iFrameLimit == 2)
            fFrameRateHz = 59.94f;  // auto framerate? set some init val (no pal/ntsc known yet)
        else
            fFrameRateHz = fFrameRate;  // else set user framerate
    }

    if (IsPerformanceCounter)
        dwFrameRateTicks = (DWORD)(CPUFrequency.LowPart / fFrameRateHz);
    else
        dwFrameRateTicks = (1000 / (DWORD)fFrameRateHz);
}

////////////////////////////////////////////////////////////////////////

#else

////////////////////////////////////////////////////////////////////////
// LINUX VERSION
////////////////////////////////////////////////////////////////////////

#define TIMEBASE 100000

unsigned long timeGetTime() {
    struct timeval tv;
    gettimeofday(&tv, 0);                         // well, maybe there are better ways
    return tv.tv_sec * 100000 + tv.tv_usec / 10;  // to do that, but at least it works
}

void FrameCap(void) {
    static unsigned long curticks, lastticks, _ticks_since_last_update;
    static unsigned long TicksToWait = 0;
    bool Waiting = true;

    {
        curticks = timeGetTime();
        _ticks_since_last_update = curticks - lastticks;

        if ((_ticks_since_last_update > TicksToWait) || (curticks < lastticks)) {
            lastticks = curticks;

            if ((_ticks_since_last_update - TicksToWait) > dwFrameRateTicks)
                TicksToWait = 0;
            else
                TicksToWait = dwFrameRateTicks - (_ticks_since_last_update - TicksToWait);
        } else {
            while (Waiting) {
                curticks = timeGetTime();
                _ticks_since_last_update = curticks - lastticks;
                if ((_ticks_since_last_update > TicksToWait) || (curticks < lastticks)) {
                    Waiting = false;
                    lastticks = curticks;
                    TicksToWait = dwFrameRateTicks;
                }
            }
        }
    }
}

void FrameCapSSSPSX(void)  // frame limit func SSSPSX
{
    static DWORD reqticks, curticks;
    static double offset;

    //---------------------------------------------------------
    if (bInitCap) {
        bInitCap = false;
        reqticks = curticks = timeGetTime();
        offset = 0;
        return;
    }
    //---------------------------------------------------------
    offset += 1000 / fFrameRateHz;
    reqticks += (DWORD)offset;
    offset -= (DWORD)offset;

    curticks = timeGetTime();
    if ((signed int)(reqticks - curticks) > 60)
        usleep((reqticks - curticks) *
               500L);  // pete: a simple Sleep doesn't burn 100% cpu cycles, but it isn't as exact as a brute force loop

    if ((signed int)(curticks - reqticks) > 60) reqticks += (curticks - reqticks) / 2;
}

////////////////////////////////////////////////////////////////////////

#define MAXSKIP 120

void FrameSkip(void) {
    static int iNumSkips = 0, iAdditionalSkip = 0;  // number of additional frames to skip
    static DWORD dwLastLace = 0;                    // helper var for frame limitation
    static DWORD curticks, lastticks, _ticks_since_last_update;

    if (!dwLaceCnt) return;  // important: if no updatelace happened, we ignore it completely

    if (iNumSkips)  // we are in skipping mode?
    {
        dwLastLace += dwLaceCnt;  // -> calc frame limit helper (number of laces)
        bSkipNextFrame = true;    // -> we skip next frame
        iNumSkips--;              // -> ok, one done
    } else                        // ok, no additional skipping has to be done...
    {                             // we check now, if some limitation is needed, or a new skipping has to get started
        DWORD dwWaitTime;

        if (bInitCap || bSkipNextFrame)  // first time or we skipped before?
        {
            if (UseFrameLimit && !bInitCap)  // frame limit wanted and not first time called?
            {
                DWORD dwT = _ticks_since_last_update;  // -> that's the time of the last drawn frame
                dwLastLace +=
                    dwLaceCnt;  // -> and that's the number of updatelace since the start of the last drawn frame

                curticks =
                    timeGetTime();  // -> now we calc the time of the last drawn frame + the time we spent skipping
                _ticks_since_last_update = dwT + curticks - lastticks;

                dwWaitTime =
                    dwLastLace * dwFrameRateTicks;  // -> and now we calc the time the real psx would have needed

                if (_ticks_since_last_update < dwWaitTime)  // -> we were too fast?
                {
                    if ((dwWaitTime - _ticks_since_last_update) >  // -> some more security, to prevent
                        (60 * dwFrameRateTicks))                   //    wrong waiting times
                        _ticks_since_last_update = dwWaitTime;

                    while (_ticks_since_last_update < dwWaitTime)  // -> loop until we have reached the real psx time
                    {                                              //    (that's the additional limitation, yup)
                        curticks = timeGetTime();
                        _ticks_since_last_update = dwT + curticks - lastticks;
                    }
                } else  // we were still too slow ?!!?
                {
                    if (iAdditionalSkip <
                        MAXSKIP)  // -> well, somewhen we really have to stop skipping on very slow systems
                    {
                        iAdditionalSkip++;  // -> inc our watchdog var
                        dwLaceCnt = 0;      // -> reset lace count
                        lastticks = timeGetTime();
                        return;  // -> done, we will skip next frame to get more speed
                    }
                }
            }

            bInitCap = false;           // -> ok, we have inited the frameskip func
            iAdditionalSkip = 0;        // -> init additional skip
            bSkipNextFrame = false;     // -> we don't skip the next frame
            lastticks = timeGetTime();  // -> we store the start time of the next frame
            dwLaceCnt = 0;              // -> and we start to count the laces
            dwLastLace = 0;
            _ticks_since_last_update = 0;
            return;  // -> done, the next frame will get drawn
        }

        bSkipNextFrame = false;  // init the frame skip signal to 'no skipping' first

        curticks = timeGetTime();  // get the current time (we are now at the end of one drawn frame)
        _ticks_since_last_update = curticks - lastticks;

        dwLastLace = dwLaceCnt;                     // store curr count (frame limitation helper)
        dwWaitTime = dwLaceCnt * dwFrameRateTicks;  // calc the 'real psx lace time'

        if (_ticks_since_last_update > dwWaitTime)  // hey, we needed way too long for that frame...
        {
            if (UseFrameLimit)  // if limitation, we skip just next frame,
            {                   // and decide after, if we need to do more
                iNumSkips = 0;
            } else {
                iNumSkips = _ticks_since_last_update / dwWaitTime;  // -> calc number of frames to skip to catch up
                iNumSkips--;                                        // -> since we already skip next frame, one down
                if (iNumSkips > MAXSKIP) iNumSkips = MAXSKIP;       // -> well, somewhere we have to draw a line
            }
            bSkipNextFrame = true;  // -> signal for skipping the next frame
        } else                      // we were faster than real psx? fine :)
            if (UseFrameLimit)      // frame limit used? so we wait til the 'real psx time' has been reached
        {
            if (dwLaceCnt > MAXLACE)  // -> security check
                _ticks_since_last_update = dwWaitTime;

            while (_ticks_since_last_update < dwWaitTime)  // -> just do a waiting loop...
            {
                curticks = timeGetTime();
                _ticks_since_last_update = curticks - lastticks;
            }
        }

        lastticks = timeGetTime();  // ok, start time of the next frame
    }

    dwLaceCnt = 0;  // init lace counter
}

////////////////////////////////////////////////////////////////////////

void calcfps(void) {
    static unsigned long curticks, _ticks_since_last_update, lastticks;
    static long fps_cnt = 0;
    static unsigned long fps_tck = 1;
    static long fpsskip_cnt = 0;
    static unsigned long fpsskip_tck = 1;

    {
        curticks = timeGetTime();
        _ticks_since_last_update = curticks - lastticks;

        if (UseFrameSkip && !UseFrameLimit && _ticks_since_last_update)
            fps_skip = std::min(fps_skip, ((float)TIMEBASE / (float)_ticks_since_last_update + 1.0f));

        lastticks = curticks;
    }

    if (UseFrameSkip && UseFrameLimit) {
        fpsskip_tck += _ticks_since_last_update;

        if (++fpsskip_cnt == 2) {
            fps_skip = (float)2000 / (float)fpsskip_tck;
            fps_skip += 6.0f;
            fpsskip_cnt = 0;
            fpsskip_tck = 1;
        }
    }

    fps_tck += _ticks_since_last_update;

    if (++fps_cnt == 10) {
        fps_cur = (float)(TIMEBASE * 10) / (float)fps_tck;

        fps_cnt = 0;
        fps_tck = 1;

        if (UseFrameLimit && fps_cur > fFrameRateHz)  // optical adjust ;) avoids flickering fps display
            fps_cur = fFrameRateHz;
    }
}

void PCFrameCap(void) {
    static unsigned long curticks, lastticks, _ticks_since_last_update;
    static unsigned long TicksToWait = 0;
    bool Waiting = true;

    while (Waiting) {
        curticks = timeGetTime();
        _ticks_since_last_update = curticks - lastticks;
        if ((_ticks_since_last_update > TicksToWait) || (curticks < lastticks)) {
            Waiting = false;
            lastticks = curticks;
            TicksToWait = (TIMEBASE / (unsigned long)fFrameRateHz);
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCcalcfps(void) {
    static unsigned long curticks, _ticks_since_last_update, lastticks;
    static long fps_cnt = 0;
    static float fps_acc = 0;
    float CurrentFPS = 0;

    curticks = timeGetTime();
    _ticks_since_last_update = curticks - lastticks;
    if (_ticks_since_last_update)
        CurrentFPS = (float)TIMEBASE / (float)_ticks_since_last_update;
    else
        CurrentFPS = 0;
    lastticks = curticks;

    fps_acc += CurrentFPS;

    if (++fps_cnt == 10) {
        fps_cur = fps_acc / 10;
        fps_acc = 0;
        fps_cnt = 0;
    }

    fps_skip = CurrentFPS + 1.0f;
}

////////////////////////////////////////////////////////////////////////

void SetAutoFrameCap(void) {
    if (iFrameLimit == 1) {
        fFrameRateHz = fFrameRate;
        dwFrameRateTicks = (TIMEBASE / (unsigned long)fFrameRateHz);
        return;
    }

    if (dwActFixes & 32) {
        if (PSXDisplay.Interlaced)
            fFrameRateHz = PSXDisplay.PAL ? 50.0f : 60.0f;
        else
            fFrameRateHz = PSXDisplay.PAL ? 25.0f : 30.0f;
    } else {
        // fFrameRateHz = PSXDisplay.PAL?50.0f:59.94f;
        if (PSXDisplay.PAL) {
            if (lGPUstatusRet & GPUSTATUS_INTERLACED)
                fFrameRateHz = 33868800.0f / 677343.75f;  // 50.00238
            else
                fFrameRateHz = 33868800.0f / 680595.00f;  // 49.76351
        } else {
            if (lGPUstatusRet & GPUSTATUS_INTERLACED)
                fFrameRateHz = 33868800.0f / 565031.25f;  // 59.94146
            else
                fFrameRateHz = 33868800.0f / 566107.50f;  // 59.82750
        }
        dwFrameRateTicks = (TIMEBASE / (unsigned long)fFrameRateHz);
    }
}

////////////////////////////////////////////////////////////////////////

void SetFPSHandler(void) {}

////////////////////////////////////////////////////////////////////////

void InitFPS(void) {
    if (!fFrameRate) fFrameRate = 200.0f;

    if (fFrameRateHz == 0) {
        if (iFrameLimit == 2)
            fFrameRateHz = 59.94f;  // auto framerate? set some init val (no pal/ntsc known yet)
        else
            fFrameRateHz = fFrameRate;  // else set user framerate
    }

    dwFrameRateTicks = (TIMEBASE / (unsigned long)fFrameRateHz);
}

#endif
