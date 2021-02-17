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

#include <stdlib.h>

#include "common/compiler/stdint.h"

/* This one is a tough one. Technically, this should return a struct, that's
   using however the older gcc ABI. There's no way to reproduce the ABI
   with modern gcc as far as I know, but it's also likely the rest of
   the returned struct isn't actually used, so we might be lucky here
   in terms of API. As far as ABI is concerned however, inlined assembly
   code will solve the issue. */
int initPadHighLevel(uint32_t padType, uint32_t* buffer, int c, int d);
uint32_t readPadHighLevel();
int initPad(uint8_t* pad1Buffer, size_t pad1BufferSize, uint8_t* pad2Buffer, size_t pad2BufferSize);
int startPad();
void stopPad();

void patch_remove_ChgclrPAD();
void patch_disable_slotChangeOnAbort();
void patch_startPad();
void patch_stopPad();
void patch_send_pad();
void patch_setPadOutputData(uint8_t* pad1OutputBuffer, size_t pad1OutputSize, uint8_t* pad2OutputBuffer,
                            size_t pad2OutputSize);

extern uint32_t* g_userPadBuffer;
