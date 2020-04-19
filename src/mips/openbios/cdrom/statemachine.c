/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "common/hardware/cdrom.h"
#include "common/hardware/dma.h"
#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/events.h"
#include "openbios/cdrom/statemachine.h"

enum CDRomState {
    GETSTATUS            = 0x0001,
    SETMODE              = 0x000e,
    SEEKL                = 0x0015,
    SEEKP                = 0x0016,
    SEEKL_SETLOC         = 0x00f2,
    READN                = 0x00f6,
    READS                = 0x00fb,
    READ_SETMODE         = 0x00fe,
    INITIALIZING         = 0x0ccc,
    GOT_ERROR_AND_REINIT = 0x0ddd,
    PAUSING              = 0x0fff,
    IDLE                 = 0xffff,
};

static unsigned s_currentState;
static unsigned s_preemptedState;
static unsigned s_gotInt3;
static unsigned s_wordsToRead;
static uint8_t * s_getStatusResponsePtr;
static int s_sectorCounter;
static int s_dmaCounter;
static uint32_t * s_readBuffer;
static uint32_t s_mode;

int cdromSeekL(uint8_t * msf) {
    // unknown states
    if ((s_currentState == 0xe6) || (s_currentState == 0xeb)) {
        if (!s_gotInt3) return 0;
    } else {
        if (s_currentState != IDLE) return 0;
    }

    if (!(CDROM_REG0 & 0x10)) return 0;
    cdromUndeliverAllExceptAckAndDone();
    if ((s_currentState == 0xe6) || (s_currentState == 0xeb)) s_preemptedState = s_currentState;
    CDROM_REG0 = 0;
    CDROM_REG2 = msf[0];
    CDROM_REG2 = msf[1];
    CDROM_REG2 = msf[2];
    CDROM_REG1 = 2;
    s_currentState = SEEKL_SETLOC;
    return 1;
}

int cdromGetStatus(uint8_t *responsePtr) {
    if (s_currentState != IDLE) return 0;
    cdromUndeliverAll();
    CDROM_REG0 = 0;
    s_currentState = GETSTATUS;
    CDROM_REG1 = 1;
    s_getStatusResponsePtr = responsePtr;
    return 1;
}

int cdromRead(int count, void * buffer, uint32_t mode) {
    if ((s_currentState != IDLE) || (count <= 0)) return 0;

    cdromUndeliverAll();
    s_gotInt3 = 0;
    if ((mode & 0x10) == 0) {
        if ((mode & 0x20) == 0) {
            s_wordsToRead = 0x200;
        } else {
            s_wordsToRead = 0x249;
        }
    } else {
        s_wordsToRead = 0x249;
    }
    s_sectorCounter = count;
    s_dmaCounter = count;
    s_readBuffer = (uint32_t *) buffer;
    s_mode = mode;
    if ((CDROM_REG0 & 0x10) == 0) return 0;
    CDROM_REG0 = 0;
    CDROM_REG2 = mode;
    CDROM_REG1 = 14;
    return 1;
}

int cdromSetMode(uint32_t mode) {
    if (s_currentState != IDLE) return 0;
    cdromUndeliverAll();

    s_mode = mode;
    if ((CDROM_REG0 & 0x10) == 0) return 0;
    CDROM_REG0 = 0;
    CDROM_REG2 = mode;
    s_currentState = SETMODE;
    CDROM_REG1 = 14;
    return 1;
}

void setDMA(uint32_t *buffer, int amountOfWords) {
    uint32_t t = DICR;
    t &= 0xffffff;
    t |= 0x880000;
    DICR = t;

    DPCR |= 0x8000;
    DMA_CTRL[DMA_CDROM].MADR = (uintptr_t) buffer;
    DMA_CTRL[DMA_CDROM].BCR = amountOfWords | 0x10000;
    DMA_CTRL[DMA_CDROM].CHCR = 0x11000000;
}

static uint32_t * s_initialReadBuffer;

static void initiateDMA(void) {
    if (s_sectorCounter < 1) {
        if (s_sectorCounter == 0) {
            s_sectorCounter = -1;
        }
    }
    s_initialReadBuffer = s_readBuffer;
    CDROM_REG0 = 0;
    CDROM_REG3 = 0;
    CDROM_REG0 = 0;
    CDROM_REG3 = 0x80;
    SBUS_DEV5_CTRL = 0x20943;
    SBUS_COM_CTRL = 0x132c;
    s_sectorCounter--;
    setDMA(s_readBuffer, s_wordsToRead);
    s_readBuffer += s_wordsToRead;
    if (s_sectorCounter != 0) return;
    CDROM_REG0 = 0;
    CDROM_REG1 = 9;
    s_currentState = PAUSING;
}

// Not sure if this is really audio related,
// because it's technically dead code.
// Some of the code might in fact be culled away
// by the compiler.
uint8_t s_audioResp[8];
static void audioResponse(uint8_t status) {
    s_audioResp[0] = status;
    s_audioResp[1] = CDROM_REG1;
    s_audioResp[2] = CDROM_REG1;
    s_audioResp[3] = CDROM_REG1;
    s_audioResp[4] = CDROM_REG1;
    s_audioResp[5] = CDROM_REG1;
    s_audioResp[6] = CDROM_REG1;
    s_audioResp[7] = CDROM_REG1;
    syscall_deliverEvent(0xf0000003, 0x40);
}

static void dataReady() {
    uint8_t status = CDROM_REG1;
    switch (s_preemptedState) {
        case READN: case READS:
            initiateDMA();
            return;
        case 0xe6: case 0xeb:
            syscall_deliverEvent(0xf0000003, 0x40);
            return;
    }

    switch (s_currentState) {
        case READN: case READS:
            initiateDMA();
            break;
        case 0xe6: case 0xeb:
            syscall_deliverEvent(0xf0000003, 0x40);
            break;
        case 3: case 4:  case 5:
            audioResponse(status);
            break;
        default:
            syscall_deliverEvent(0xf0000003, 0x200);
            break;

    }
}

static uint8_t s_err1, s_err2;
static int s_gotInt5;

static void genericErrorState() {
    CDROM_REG0 = 0;
    CDROM_REG1 = 10;
    s_currentState = GOT_ERROR_AND_REINIT;
    s_preemptedState = IDLE;
    s_err1 = 1;
    s_err2 = 0x80;
    s_gotInt5 = 1;

}

static void setSessionResponse() {
    if (CDROM_REG0 & 0x10) {
        // request last track end state?
        s_currentState = 0xf14;
        CDROM_REG0 = 0;
        CDROM_REG2 = 0;
        CDROM_REG1 = 20;
    } else {
        genericErrorState();
    }
}

static int s_initializationComplete;
static uint8_t * s_idResponsePtr;

static void complete() {
    switch (s_currentState) {
        case 0x12: // setSession?
            setSessionResponse();
            break;
        case INITIALIZING:
            s_currentState = IDLE;
            s_initializationComplete = 1;
            break;
        case 8: // stop?
        case 9: // pause?
        case SEEKL:
        case SEEKP:
            switch (s_preemptedState) {
                case 0xe6: case 0xeb: case 3: case 4: case 5:
                    s_preemptedState = IDLE;
                    break;
            }
            s_currentState = IDLE;
            syscall_deliverEvent(0xf0000003, 0x0020);
            break;
        case 0x1a: { // getID?
            uint8_t * const ptr = s_idResponsePtr;
            ptr[0] = CDROM_REG1;
            ptr[1] = CDROM_REG1;
            ptr[2] = CDROM_REG1;
            ptr[3] = CDROM_REG1;
            s_currentState = IDLE;
            syscall_deliverEvent(0xf0000003, 0x0020);
            break;
        }
        case GOT_ERROR_AND_REINIT:
            s_gotInt5 = 0;
            s_currentState = IDLE;
            syscall_deliverEvent(0xf0000003, 0x8000);
            break;
        case IDLE:
            syscall_deliverEvent(0xf0000003, 0x0200);
            break;
        default:
            s_currentState = IDLE;
            syscall_deliverEvent(0xf0000003, 0x0020);
            break;
    }
}

static uint8_t * s_getLocResponsePtr;

static void getLocLAck() {
    uint8_t * const ptr = s_getLocResponsePtr;
    ptr[0] = CDROM_REG1;
    ptr[1] = CDROM_REG1;
    ptr[2] = CDROM_REG1;

    /* These are volatiles, so the compiler won't cull away these reads. */
    CDROM_REG1;
    CDROM_REG1;
    CDROM_REG1;
    CDROM_REG1;

    if (s_preemptedState == IDLE) {
        s_currentState = IDLE;
    } else {
        s_currentState = s_preemptedState;
        s_preemptedState = IDLE;
    }
    syscall_deliverEvent(0xf0000003, 0x0020);
}

static void getLocPAck() {
    s_currentState = s_preemptedState;

    /* These are volatiles, so the compiler won't cull away these reads. */
    CDROM_REG1;
    CDROM_REG1;
    CDROM_REG1;
    CDROM_REG1;

    uint8_t * const ptr = s_getLocResponsePtr;
    ptr[0] = CDROM_REG1;
    ptr[1] = CDROM_REG1;
    ptr[2] = CDROM_REG1;

    /* what ? somebody was too happy with the copy/paste here. */
    if (s_currentState == IDLE) {
        s_currentState = IDLE;
    } else {
        s_preemptedState = IDLE;
    }
    syscall_deliverEvent(0xf000000e, 0x0020);
}

static uint8_t * s_testAckPtr;

static void testAck(uint8_t status) {
    uint8_t * const ptr = s_testAckPtr;
    uint8_t count = ptr[1];
    ptr[0] = status;

    int i = 0;
    while (--count) {
        ptr[i++ + 2] = CDROM_REG1;
    }

    s_currentState = IDLE;
    syscall_deliverEvent(0xf0000003, 0x0020);
}

static void setModeAck() {
    s_currentState = IDLE;
    syscall_deliverEvent(0xf0000003, 0x0020);
}

static void acknowledge() {
    switch (s_currentState) {
        case 0x10:
            getLocLAck();
            return;
        case 0x11:
            getLocPAck();
            return;
    }

    uint8_t status = CDROM_REG1;
    switch (s_currentState) {
        case 0x19: /* test ? */
            testAck(status);
            break;
        case SETMODE:
            setModeAck();
            break;
        case 6: case 7: case 8:
            break;
        case 5:
            s_gotInt3 = 1;
            syscall_deliverEvent(0xf0000003, 0x0020);
            break;
        
    }
}

static void end() {
    if ((s_preemptedState == READN) || (s_preemptedState == READS) || (s_currentState == READN) || (s_currentState == READS)) {
        if (s_dmaCounter > 0) syscall_deliverEvent(0xf0000003, 0x0080);
        if ((s_currentState == READN) || (s_currentState == READS)) {
            s_currentState = IDLE;
        } else {
            s_preemptedState = IDLE;
        }
    }

    if ((s_currentState == 0xe6) || (s_currentState == 0xeb) || (s_preemptedState == 0xe6) || (s_preemptedState == 0xeb)) {
        if ((s_currentState == 0xe6) || (s_currentState == 0xeb)) {
            s_currentState = IDLE;
        } else {
            s_preemptedState = IDLE;
        }
    }

    switch (s_currentState) {
        case 3: case 4: case 5:
            syscall_deliverEvent(0xf0000003, 0x0080);
            s_currentState = IDLE;
            break;
        default:
            syscall_deliverEvent(0xf0000003, 0x0200);
            break;
    }
}

static uint8_t * s_getIDerrPtr;

static void discError() {
    s_err1 = CDROM_REG1;
    s_err2 = CDROM_REG1;
    switch (s_currentState) {
        case 0x1a: {
            uint8_t * const ptr = s_getIDerrPtr;
            ptr[0] = s_err1;
            ptr[1] = s_err2;
            ptr[2] = CDROM_REG1;
            ptr[3] = CDROM_REG1;
            s_preemptedState = IDLE;
            s_currentState = IDLE;
            syscall_deliverEvent(0xf0000003, 0x8000);
            break;
        }
        case INITIALIZING:
            s_initializationComplete = 2;
            break;
        default:
            if (!s_gotInt5) {
                s_gotInt5 = 1;
                s_preemptedState = IDLE;
                CDROM_REG0 = 0;
                CDROM_REG1 = 10;
                s_currentState = GOT_ERROR_AND_REINIT;
                break;
            } else {
                s_gotInt5 = 0;
                s_preemptedState = IDLE;
                s_currentState = IDLE;
                syscall_deliverEvent(0xf0000003, 0x8000);
            }
            break;
    }
}

static uint32_t s_lastIREG;
static uint8_t s_irqFlags;

// yeah, I don't know what's going on...
// they probably use this to force dummy write
// cycles to pause a bit, but that's a really
// weird way to do it.
static volatile uint32_t * const dummy = (volatile uint32_t * const) 0;

int cdromIOVerifier() {
    if ((IMASK & 4) == 0) return 0;
    s_lastIREG = IREG;
    if ((s_lastIREG & 4) == 0) return 0;

    CDROM_REG0 = 1;
    s_irqFlags = CDROM_REG3;
    if (s_irqFlags & 7) {
        CDROM_REG0 = 1;
        CDROM_REG3 = 7;
        *dummy = 0;
        *dummy = 0;
        *dummy = 0;
        *dummy = 0;
    }
    if (s_irqFlags & 0x18) {
        CDROM_REG0 = 1;
        CDROM_REG3 = s_irqFlags & 0x18;
        *dummy = 0;
        *dummy = 0;
        *dummy = 0;
        *dummy = 0;
    }
    switch (s_irqFlags & 7) {
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
    return 1;
}
