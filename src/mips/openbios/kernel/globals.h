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
#include "common/psxlibc/handlers.h"
#include "common/psxlibc/stdio.h"
#include "openbios/kernel/events.h"
#include "openbios/kernel/threads.h"

extern struct {
    uint32_t ramsize, unk1, unk2;
} __globals60;

extern struct {
    /* 100 */ struct HandlersStorage * handlersArray;
    /* 104 */ uint32_t handlersArraySize;
    /* 108 */ struct Thread ** blocks;
    /* 10c */ struct Thread * threads;
    /* 110 */ uint32_t xxx_04;
    /* 114 */ uint32_t xxx_05;
    /* 118 */ uint32_t xxx_06;
    /* 11c */ uint32_t xxx_07;
    /* 120 */ struct EventInfo * events;
    /* 124 */ uint32_t eventsSize;
    /* 128 */ uint32_t xxx_0a;
    /* 12c */ uint32_t xxx_0b;
    /* 130 */ uint32_t xxx_0c;
    /* 134 */ uint32_t xxx_0d;
    /* 138 */ uint32_t xxx_0e;
    /* 13c */ uint32_t xxx_0f;
    /* 140 */ struct File * files;
    /* 144 */ uint32_t filesSize;
    /* 148 */ uint32_t xxx_12;
    /* 14c */ uint32_t xxx_13;
    /* 150 */ struct Device * devices;
    /* 154 */ struct Device * devicesEnd;
    /* 158 */ uint32_t xxx_16;
    /* 15c */ uint32_t xxx_17;
    /* 160 */ uint32_t xxx_18;
    /* 164 */ uint32_t xxx_19;
    /* 168 */ uint32_t xxx_1a;
    /* 16c */ uint32_t xxx_1b;
    /* 170 */ uint32_t xxx_1c;
    /* 174 */ uint32_t xxx_1d;
    /* 178 */ uint32_t xxx_1e;
    /* 17c */ uint32_t xxx_1f;
} __globals;
