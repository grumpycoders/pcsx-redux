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

struct Registers {
    union {
        struct {
            uint32_t r0, at, v0, v1, a0, a1, a2, a3;
            uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
            uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
            uint32_t t8, t9, k0, k1, gp, sp, fp, ra;
        } n;
        uint32_t r[32];
    } GPR;
    uint32_t returnPC;
    uint32_t hi, lo;
    uint32_t SR;
    uint32_t Cause;
};

struct Thread {
    uint32_t flags, flags2;
    struct Registers registers;
    uint32_t unknown[9];
};

struct Process {
    struct Thread* thread;
};

int initThreads(int processCount, int threadCount);

int getFreeTCBslot();
int openThread(uint32_t pc, uint32_t sp, uint32_t gp);
int closeThread(int threadId);
int changeThread(int threadId);
