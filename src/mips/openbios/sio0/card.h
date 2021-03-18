/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once

#include <stdlib.h>

int initCard(int padStarted);
int startCard();

void mcResetStatus();
int mcWaitForStatus();
int mcWaitForStatusAndReturnIndex();
void mcAllowNewCard();
int mcReadCardSector(int deviceId, int sector, uint8_t* buffer);

// internals
int mcReadHandler();
extern int g_mcOperation;
extern int g_mcPortFlipping;
extern uint8_t* g_mcUserBuffers[2];
extern int g_mcSector[2];
extern int g_mcDeviceId[2];
extern int g_mcActionInProgress;
extern int g_skipErrorOnNewCard;
extern uint8_t g_mcFlags[2];
extern int g_mcPortFlipping;
extern int g_mcLastPort;
extern int g_mcGotError;
extern int g_mcFastTrackActive;
