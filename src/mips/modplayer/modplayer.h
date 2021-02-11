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

#include <stdint.h>

extern unsigned MOD_Channels;
extern unsigned MOD_SongLength;
extern const uint8_t* MOD_ModuleData;
extern unsigned MOD_CurrentOrder;
extern unsigned MOD_CurrentPattern;
extern unsigned MOD_CurrentRow;
extern unsigned MOD_Speed;
extern unsigned MOD_Tick;
extern unsigned MOD_BPM;
extern const uint8_t* MOD_RowPointer;
extern int MOD_ChangeRowNextTick;
extern unsigned MOD_NextRow;
extern int MOD_ChangeOrderNextTick;
extern unsigned MOD_NextOrder;
extern uint8_t MOD_PatternDelay;
extern unsigned MOD_LoopStart;
extern unsigned MOD_LoopCount;

struct MODFileFormat;

unsigned MOD_Check(const struct MODFileFormat* module);
unsigned MOD_Load(const struct MODFileFormat* module);
void MOD_Poll();
