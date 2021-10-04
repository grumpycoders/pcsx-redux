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
#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/syscalls/syscalls.h"
#include "common/util/util.h"

#define printf(...)

static void hexdump(const void* data_, unsigned size) {
    const uint8_t* data = (const uint8_t*)data_;
    char ascii[17];
    ascii[16] = 0;
    for (unsigned i = 0; i < size; i++) {
        if (i % 16 == 0) printf("%08x  |", i);
        printf("%02X ", data[i]);
        ascii[i % 16] = data[i] >= ' ' && data[i] <= '~' ? data[i] : '.';
        unsigned j = i + 1;
        if ((j % 8 == 0) || (j == size)) {
            printf(" ");
            if (j % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (j == size) {
                ascii[j % 16] = 0;
                if (j % 16 <= 8) printf(" ");
                for (j %= 16; j < 16; j++) printf("   ");
                printf("|  %s \n", ascii);
            }
        }
    }
}

static unsigned s_wait = 0;
static unsigned s_retries = 0;
static uint8_t s_sector[2048];

enum CdState {
    CD_ERROR,
    CD_RESET,
    CD_INIT,
    CD_GETTN,
    CD_GETID,
    CD_SETMODE,
    CD_SETLOC_TO_PVD,
    CD_READ_PVD,
    CD_READ_PVD_DMA,
    CD_READ_PVD_PAUSE,
    CD_SETLOC_TO_ROOT,
    CD_READ_ROOT,
    CD_READ_ROOT_DMA,
    CD_READ_ROOT_PAUSE,
    CD_SUCCESS_DATA,
    CD_SUCCESS_AUDIO,
};

static enum CdState s_state;

static const char* const c_stateMsg[] = {
    "CD_ERROR",         "CD_RESET",           "CD_INIT",           "CD_GETTN",
    "CD_GETID",         "CD_SETMODE",         "CD_SETLOC_TO_PVD",  "CD_READ_PVD",
    "CD_READ_PVD_DMA",  "CD_READ_PVD_PAUSE",  "CD_SETLOC_TO_ROOT", "CD_READ_ROOT",
    "CD_READ_ROOT_DMA", "CD_READ_ROOT_PAUSE", "CD_SUCCESS_DATA",   "CD_SUCCESS_AUDIO",
};

void initCD() {
    printf("(TS) initCD()\n");
    CDROM_REG0 = 1;
    CDROM_REG3 = 0x1f;
    CDROM_REG0 = 1;
    CDROM_REG2 = 0x1f;
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_INIT;
    s_state = CD_RESET;
}

int isCDError() { return s_state == CD_ERROR || s_retries >= 10; }
int isCDSuccess() { return s_state == CD_SUCCESS_DATA || s_state == CD_SUCCESS_AUDIO; };
int isCDAudio() { return s_state == CD_SUCCESS_AUDIO; };

static void startDmaOneSector() {
    SBUS_DEV5_CTRL = 0x20943;
    SBUS_COM_CTRL = 0x132c;
    CDROM_REG0 = 0;
    CDROM_REG0;
    CDROM_REG3 = 0;
    CDROM_REG3;
    CDROM_REG0 = 0;
    CDROM_REG3 = 0x80;
    uint32_t t = DICR;
    t &= 0xffffff;
    t |= 0x880000;
    DICR = t;
    DPCR |= 0x8000;
    DMA_CTRL[DMA_CDROM].MADR = (uintptr_t)s_sector;
    DMA_CTRL[DMA_CDROM].BCR = (2048 >> 2) | 0x10000;
    DMA_CTRL[DMA_CDROM].CHCR = 0x11000000;
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;
}

static void dataReady() {
    printf("(TS) cds::dataReady() - state: %s\n", c_stateMsg[s_state]);
    CDROM_REG0 = 0;
    uint8_t stat = CDROM_REG1_UC;
    switch (s_state) {
        case CD_READ_PVD: {
            printf("(TS) cds::read PVD successfully\n");
            startDmaOneSector();
            s_state = CD_READ_PVD_DMA;
            break;
        }
        case CD_READ_ROOT: {
            printf("(TS) cds::read root successfully\n");
            startDmaOneSector();
            s_state = CD_READ_ROOT_DMA;
            break;
        }
    }
}

static void complete() {
    CDROM_REG0 = 0;
    uint8_t stat = CDROM_REG1_UC;
    printf("(TS) cds::complete() - state: %s, status: %02x\n", c_stateMsg[s_state], stat);
    switch (s_state) {
        case CD_RESET:
            s_state = CD_INIT;
            s_retries = 0;
            CDROM_REG0 = 0;
            CDROM_REG1 = CDL_INIT;
            break;
        case CD_INIT:
            s_state = CD_GETTN;
            s_retries = 0;
            CDROM_REG0 = 0;
            CDROM_REG1 = CDL_GETTN;
            break;
        case CD_GETID: {
            CDROM_REG0 = 0;
            uint8_t idResponse[9] = {stat};
            for (unsigned i = 1; i < 8; i++) idResponse[i] = CDROM_REG1_UC;
            idResponse[8] = 0;
            printf("(TS) cds::complete: response: %02x %02x %02x %02x %02x %02x %02x %02x (%s)\n", idResponse[0],
                   idResponse[1], idResponse[2], idResponse[3], idResponse[4], idResponse[5], idResponse[6],
                   idResponse[7], &idResponse[4]);
            CDROM_REG0 = 0;
            CDROM_REG2 = 0;
            CDROM_REG1 = CDL_SETMODE;
            s_state = CD_SETMODE;
            break;
        }
        case CD_READ_PVD_PAUSE: {
            if (s_sector[1] != 'C' || s_sector[2] != 'D' || s_sector[3] != '0' || s_sector[4] != '0' ||
                s_sector[5] != '1' || s_sector[6] != 1) {
                printf(
                    "(TS) cds::complete: invalid PVD (%02x %02x %02x %02x %02x %02x %02x %02x). Restarting sequence.\n",
                    s_sector[0], s_sector[1], s_sector[2], s_sector[3], s_sector[4], s_sector[5], s_sector[6],
                    s_sector[7]);
                printf("**** invalid CD inserted - replace to continue ****\n");
                s_state = CD_RESET;
                s_wait = 1;
                break;
            }
            uint32_t lba = readUnaligned(s_sector, 158) + 150;
            unsigned minutes = lba / 4500;
            lba %= 4500;
            uint8_t msf[3] = {(minutes % 10) + (minutes / 10) * 0x10, ((lba / 75) % 10) + ((lba / 75) / 10) * 0x10,
                              ((lba % 75) % 10) + ((lba % 75) / 10) * 0x10};
            CDROM_REG0 = 0;
            CDROM_REG2 = msf[0];
            CDROM_REG2 = msf[1];
            CDROM_REG2 = msf[2];
            CDROM_REG1 = CDL_SETLOC;
            s_state = CD_SETLOC_TO_ROOT;
            break;
        }
        case CD_READ_ROOT_PAUSE: {
            printf("(TS) cds::complete: root sector read complete.\n");
            uint8_t* ptr = s_sector;
            int foundBoot = 0;
            while ((ptr < (s_sector + sizeof(s_sector))) && ptr[0] && !foundBoot) {
                uint8_t nameSize = ptr[32];
                if ((nameSize == 9) && (syscall_strncmp(ptr + 33, "PSX.EXE;1", 9) == 0)) foundBoot = 1;
                if ((nameSize == 12) && (syscall_strncmp(ptr + 33, "SYSTEM.CNF;1", 12) == 0)) foundBoot = 1;
                ptr += ptr[0];
            }

            if (!foundBoot) {
                printf("(TS) cds::complete: root sector invalid. Restarting sequence\n");
                printf("**** invalid CD inserted - replace to continue ****\n");
                s_state = CD_RESET;
                s_wait = 1;
            } else {
                s_state = CD_SUCCESS_DATA;
            }
        }
    }
}

static void acknowledge() {
    uint8_t stat = 0xff;
    enum CdState oldState = s_state;
    switch (s_state) {
        case CD_RESET:
        case CD_INIT:
            CDROM_REG0 = 0;
            stat = CDROM_REG1_UC;
            break;
        case CD_GETTN:
            CDROM_REG0 = 0;
            stat = CDROM_REG1_UC;
            CDROM_REG1;
            CDROM_REG1;
            s_state = CD_GETID;
            CDROM_REG0 = 0;
            CDROM_REG1 = CDL_GETID;
            break;
        case CD_SETMODE:
            CDROM_REG0 = 0;
            stat = CDROM_REG1_UC;
            CDROM_REG0 = 0;
            CDROM_REG2 = 0x00;
            CDROM_REG2 = 0x02;
            CDROM_REG2 = 0x16;
            CDROM_REG1 = CDL_SETLOC;
            s_state = CD_SETLOC_TO_PVD;
            break;
        case CD_SETLOC_TO_PVD:
            CDROM_REG0 = 0;
            stat = CDROM_REG1_UC;
            s_state = CD_READ_PVD;
            CDROM_REG0 = 0;
            CDROM_REG1 = CDL_READN;
            break;
        case CD_SETLOC_TO_ROOT:
            CDROM_REG0 = 0;
            stat = CDROM_REG1_UC;
            s_state = CD_READ_ROOT;
            CDROM_REG0 = 0;
            CDROM_REG1 = CDL_READN;
            break;
    }
    printf("(TS) cds::acknowledge() - state: %s, status: %02x\n", c_stateMsg[oldState], stat);
}

static void end() {
    printf("(TS) cds::end() - state: %s\n", c_stateMsg[s_state]);
    s_state = CD_ERROR;
}

static void discError() {
    printf("(TS) cds::discError() - state: %s, retries: %i\n", c_stateMsg[s_state], s_retries);
    uint8_t idResponse[2];
    CDROM_REG0 = 0;
    for (unsigned i = 0; i < 2; i++) idResponse[i] = CDROM_REG1_UC;
    printf("(TS) cds::discError: response: %02x %02x\n", idResponse[0], idResponse[1]);
    printf("(TS) cds::discError: error during %s, trying again.\n", c_stateMsg[s_state]);
    printf("**** no recognizable CD inserted ****\n");
    // todo: check audio
    if (s_retries++ == 20) {
        printf("(TS) cds::discError: restarting from scratch.\n");
        s_state = CD_RESET;
    }
    s_wait = 1;
}

void checkCD(unsigned fps) {
    switch (s_state) {
        case CD_READ_PVD_DMA: {
            if ((DMA_CTRL[DMA_CDROM].CHCR & 0x01000000) != 0) {
                printf("(TS) checkCD: PVD read DMA still pending.\n");
                break;
            }
            uint32_t dicr = DICR;
            dicr &= 0x00ffffff;
            dicr |= 0x88000000;
            DICR = dicr;
            printf("(TS) checkCD: PVD read DMA completed.\n");
            // hexdump(s_sector, 2048);
            s_state = CD_READ_PVD_PAUSE;
            break;
        }
        case CD_READ_ROOT_DMA: {
            if ((DMA_CTRL[DMA_CDROM].CHCR & 0x01000000) != 0) {
                printf("(TS) checkCD: root read DMA still pending.\n");
                break;
            }
            uint32_t dicr = DICR;
            dicr &= 0x00ffffff;
            dicr |= 0x88000000;
            DICR = dicr;
            printf("(TS) checkCD: root read DMA completed.\n");
            // hexdump(s_sector, 2048);
            s_state = CD_READ_ROOT_PAUSE;
            break;
        }
        case CD_SUCCESS_DATA:
            return;
    }
    if (s_wait) {
        if (fps != 0 && (s_wait++ >= fps)) {
            printf("(TS) checkCD(), timeout expired.\n");
            s_wait = 0;
            switch (s_state) {
                case CD_RESET:
                case CD_INIT:
                    initCD();
                    break;
                case CD_GETTN:
                    CDROM_REG0 = 0;
                    CDROM_REG1 = CDL_GETTN;
                    break;
                case CD_GETID:
                    CDROM_REG0 = 0;
                    CDROM_REG1 = CDL_GETID;
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
