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

#include "shell/cdrom.h"

#include "common/hardware/cdrom.h"
#include "common/syscalls/syscalls.h"

static unsigned s_wait = 0;
static unsigned s_retries = 0;

static enum {
    CD_ERROR,
    CD_RESET,
    CD_INIT,
    CD_GETID,
    CD_SUCCESS_DATA,
    CD_SUCCESS_AUDIO,
} s_state;

static const char* c_stateMsg[] = {
    "CD_ERROR", "CD_RESET", "CD_INIT", "CD_GETID", "CD_SUCCESS_DATA", "CD_SUCCESS_AUDIO",
};

void initCD() {
    ramsyscall_printf("(TS) initCD()\n");
    CDROM_REG0 = 1;
    CDROM_REG3 = 0x1f;
    CDROM_REG0 = 1;
    CDROM_REG2 = 0x1f;
    CDROM_REG0 = 0;
    CDROM_REG1 = 10;
    s_state = CD_RESET;
}

int isCDError() { return s_state == CD_ERROR || s_retries >= 5; }
int isCDSuccess() { return s_state == CD_SUCCESS_DATA || s_state == CD_SUCCESS_AUDIO; };
int isCDAudio() { return s_state == CD_SUCCESS_AUDIO; };

static void dataReady() { ramsyscall_printf("(TS) cds::dataReady() - state: %s\n", c_stateMsg[s_state]); }
static void complete() {
    ramsyscall_printf("(TS) cds::complete() - state: %s\n", c_stateMsg[s_state]);
    switch (s_state) {
        case CD_RESET:
            s_state = CD_INIT;
            s_retries = 0;
            CDROM_REG0 = 0;
            CDROM_REG1 = 10;
            break;
        case CD_INIT:
            s_state = CD_GETID;
            s_retries = 0;
            CDROM_REG0 = 0;
            CDROM_REG1 = 26;
            break;
        case CD_GETID: {
            CDROM_REG0 = 0;
            uint8_t idResponse[8];
            for (unsigned i = 0; i < 8; i++) idResponse[i] = CDROM_REG1_UC;
            ramsyscall_printf("(TS) cds::complete: response: %02x %02x %02x %02x %02x %02x %02x %02x\n", idResponse[0],
                              idResponse[1], idResponse[2], idResponse[3], idResponse[4], idResponse[5], idResponse[6],
                              idResponse[7]);
            if ((idResponse[0] != 2) || (idResponse[1] != 0) || (idResponse[3] != 0)) {
                ramsyscall_printf("(TS) cds::complete: unexpected response to getID, trying again.\n");
                ramsyscall_printf("**** no recognizable CD inserted ****\n");
                s_retries++;
                s_wait = 1;
                break;
            }
            s_retries = 0;
            // todo
            break;
        }
    }
}
static void acknowledge() {
    CDROM_REG0 = 0;
    uint8_t stat = CDROM_REG1_UC;
    ramsyscall_printf("(TS) cds::acknowledge() - state: %s, status: %02x\n", c_stateMsg[s_state], stat);
}
static void end() {
    ramsyscall_printf("(TS) cds::end() - state: %s\n", c_stateMsg[s_state]);
    s_state = CD_ERROR;
}
static void discError() {
    ramsyscall_printf("(TS) cds::discError() - state: %s, retries: %i\n", c_stateMsg[s_state], s_retries);
    if (s_state == CD_GETID) {
        uint8_t idResponse[2];
        CDROM_REG0 = 0;
        for (unsigned i = 0; i < 2; i++) idResponse[i] = CDROM_REG1_UC;
        ramsyscall_printf("(TS) cds::discError: response: %02x %02x\n", idResponse[0], idResponse[1]);
        ramsyscall_printf("(TS) cds::discError: error during getID, trying again.\n");
        ramsyscall_printf("**** no recognizable CD inserted ****\n");
        // todo: check audio
        s_retries++;
        s_wait = 1;
        return;
    }
    ramsyscall_printf("(TS) cds::discError: restarting from scratch.\n");
    s_retries++;
    s_wait = 1;
    s_state = CD_RESET;
}

void checkCD(unsigned fps) {
    if (s_wait) {
        if (s_wait++ >= fps) {
            ramsyscall_printf("(TS) checkCD(), timeout expired.\n");
            s_wait = 0;
            switch (s_state) {
                case CD_RESET:
                case CD_INIT:
                    initCD();
                    break;
                case CD_GETID:
                    CDROM_REG0 = 0;
                    CDROM_REG1 = 26;
                    break;
            }
        }
        return;
    }
    CDROM_REG0 = 1;
    uint8_t cause = CDROM_REG3_UC;
    if (cause & 7) {
        CDROM_REG0 = 1;
        CDROM_REG3 = 7;
    }
    if (cause & 0x18) {
        CDROM_REG0 = 1;
        CDROM_REG3 = cause & 0x18;
    }
    switch (cause & 7) {
        case 1:
            dataReady();
            break;
        case 2:
            complete();
            break;
        case 3:
            acknowledge();
            break;
        case 4:
            end();
            break;
        case 5:
            discError();
            break;
    }
}
