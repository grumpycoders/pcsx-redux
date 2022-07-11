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

#include "common/psxlibc/handlers.h"

int sysEnqIntRP(int priority, struct HandlerInfo* handler);
struct HandlerInfo* sysDeqIntRP(int priority, struct HandlerInfo* handler);
int enqueueSyscallHandler(int priority);
int enqueueIrqHandler(int priority);
int enqueueRCntIrqs(int priority);
void setIrqAutoAck(uint32_t irq, int value);
int initTimer(uint32_t timer, uint16_t target, uint16_t flags);
int setTimerAutoAck(uint32_t timer, int value);
int getTimer(uint32_t timer);
int enableTimerIRQ(uint32_t timer);
int disableTimerIRQ(uint32_t timer);
int restartTimer(uint32_t timer);
