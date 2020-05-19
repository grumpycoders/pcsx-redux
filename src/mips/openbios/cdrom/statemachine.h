/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

#include "common/compiler/stdint.h"

int cdromSeekL(uint8_t * msf);
int cdromGetStatus(uint8_t *responsePtr);
int cdromRead(int count, void * buffer, uint32_t mode);
int cdromSetMode(uint32_t mode);
int cdromIOVerifier();
int cdromDMAVerifier();
void cdromIOHandler();
void cdromDMAHandler();
void getLastCDRomError(uint8_t * err1, uint8_t * err2);
int cdromInnerInit();
enum AutoAckType {
    AUTOACK_IO = 0,
    AUTOACK_DMA = 1,
};
int setCDRomIRQAutoAck(enum AutoAckType type, int value);
void enqueueCDRomHandlers();
void dequeueCDRomHandlers();
