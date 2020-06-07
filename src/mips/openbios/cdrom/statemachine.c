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

#include "common/hardware/cdrom.h"
#include "common/hardware/dma.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/events.h"
#include "openbios/cdrom/statemachine.h"

// Portions of the state machines are missing, because they simply don't have
// any entry point in any of the BIOS' API. It looks very obvious that the
// state machine has a lot more steps, and one can infer a bit what's going on
// by looking at the response's code, but the end result here is that none of
// this code is reachable. It's very plausible that the missing entry points
// are in all the dummy calls in the A0 table between calls 0x70 and 0x90.
// The code here still tries to faithfully reproduce what the reverse
// engineering shows, but it's very likely the compiler will cull a lot of
// this code away, due to some static variables only being read, and never
// written to. Only the states with active entry points in the API are being
// represented by name in this enum. All others are numerical.

// There seems to be a strong correlation between the actual CDRom command
// and the state's value. Sometimes, with some upper flags to denominate what
// the state chain is about.
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

int __attribute__((section(".ramtext"))) cdromSeekL(uint8_t * msf) {
    // unknown states
    if ((s_currentState == 0xe6) || (s_currentState == 0xeb)) {
        if (!s_gotInt3) return 0;
    } else {
        if (s_currentState != IDLE) return 0;
    }

    if (!(CDROM_REG0 & 0x10)) return 0;
    cdromUndeliverAllExceptAckAndRdy();
    if ((s_currentState == 0xe6) || (s_currentState == 0xeb)) s_preemptedState = s_currentState;
    CDROM_REG0 = 0;
    CDROM_REG2 = msf[0];
    CDROM_REG2 = msf[1];
    CDROM_REG2 = msf[2];
    CDROM_REG1 = 2;
    s_currentState = SEEKL_SETLOC;
    return 1;
}

int __attribute__((section(".ramtext"))) cdromGetStatus(uint8_t *responsePtr) {
    if (s_currentState != IDLE) return 0;
    cdromUndeliverAll();
    CDROM_REG0 = 0;
    s_currentState = GETSTATUS;
    CDROM_REG1 = 1;
    s_getStatusResponsePtr = responsePtr;
    return 1;
}

int __attribute__((section(".ramtext"))) cdromRead(int count, void * buffer, uint32_t mode) {
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
        s_wordsToRead = 0x246;
    }
    s_sectorCounter = count;
    s_dmaCounter = count;
    s_readBuffer = (uint32_t *) buffer;
    s_mode = mode;
    if ((CDROM_REG0 & 0x10) == 0) return 0;
    s_currentState = READ_SETMODE;
    CDROM_REG0 = 0;
    CDROM_REG2 = mode;
    CDROM_REG1 = 14;
    return 1;
}

int __attribute__((section(".ramtext"))) cdromSetMode(uint32_t mode) {
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

static void __attribute__((section(".ramtext"))) setDMA(uint32_t *buffer, int amountOfWords) {
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

static void __attribute__((section(".ramtext"))) initiateDMA(void) {
    if (s_sectorCounter < 1) {
        if (s_sectorCounter == 0) {
            s_sectorCounter = -1;
        }
    }
    s_initialReadBuffer = s_readBuffer;
    CDROM_REG0 = 0;
    CDROM_REG0; // throw away
    CDROM_REG3 = 0;
    CDROM_REG3; // throw away
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
static void __attribute__((section(".ramtext"))) audioResponse(uint8_t status) {
    s_audioResp[0] = status;
    s_audioResp[1] = CDROM_REG1;
    s_audioResp[2] = CDROM_REG1;
    s_audioResp[3] = CDROM_REG1;
    s_audioResp[4] = CDROM_REG1;
    s_audioResp[5] = CDROM_REG1;
    s_audioResp[6] = CDROM_REG1;
    s_audioResp[7] = CDROM_REG1;
    syscall_deliverEvent(EVENT_CDROM, 0x40);
}

static void __attribute__((section(".ramtext"))) dataReady() {
    uint8_t status = CDROM_REG1;
    switch (s_preemptedState) {
        case READN: case READS:
            initiateDMA();
            return;
        case 0xe6: case 0xeb:
            syscall_deliverEvent(EVENT_CDROM, 0x40);
            return;
    }

    switch (s_currentState) {
        case READN: case READS:
            initiateDMA();
            break;
        case 0xe6: case 0xeb:
            syscall_deliverEvent(EVENT_CDROM, 0x40);
            break;
        case 3: case 4:  case 5:
            audioResponse(status);
            break;
        default:
            syscall_deliverEvent(EVENT_CDROM, 0x200);
            break;

    }
}

static uint8_t s_err1, s_err2;
static int s_gotInt5;

static void __attribute__((section(".ramtext"))) genericErrorState() {
    CDROM_REG0 = 0;
    CDROM_REG1 = 10;
    s_currentState = GOT_ERROR_AND_REINIT;
    s_preemptedState = IDLE;
    s_err1 = 1;
    s_err2 = 0x80;
    s_gotInt5 = 1;

}

static void __attribute__((section(".ramtext"))) setSessionResponse() {
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

// sigh... this is an anti-pattern, but a necessary one.
static volatile int s_initializationComplete;
static uint8_t * s_idResponsePtr;

static void __attribute__((section(".ramtext"))) complete() {
    CDROM_REG1; // throw away one read off the controller
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
            syscall_deliverEvent(EVENT_CDROM, 0x0020);
            break;
        case 0x1a: { // getID?
            uint8_t * const ptr = s_idResponsePtr;
            ptr[0] = CDROM_REG1;
            ptr[1] = CDROM_REG1;
            ptr[2] = CDROM_REG1;
            ptr[3] = CDROM_REG1;
            s_currentState = IDLE;
            syscall_deliverEvent(EVENT_CDROM, 0x0020);
            break;
        }
        case GOT_ERROR_AND_REINIT:
            s_gotInt5 = 0;
            s_currentState = IDLE;
            syscall_deliverEvent(EVENT_CDROM, 0x8000);
            break;
        case IDLE:
            syscall_deliverEvent(EVENT_CDROM, 0x0200);
            break;
        default:
            s_currentState = IDLE;
            syscall_deliverEvent(EVENT_CDROM, 0x0020);
            break;
    }
}

static uint8_t * s_getLocResponsePtr;

static void __attribute__((section(".ramtext"))) getLocLAck() {
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
    syscall_deliverEvent(EVENT_CDROM, 0x0020);
}

static void __attribute__((section(".ramtext"))) getLocPAck() {
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

static void __attribute__((section(".ramtext"))) testAck(uint8_t status) {
    uint8_t * const ptr = s_testAckPtr;
    uint8_t count = ptr[1];
    ptr[0] = status;

    int i = 0;
    while (--count) {
        ptr[i++ + 2] = CDROM_REG1;
    }

    s_currentState = IDLE;
    syscall_deliverEvent(EVENT_CDROM, 0x0020);
}

static void __attribute__((section(".ramtext"))) ack() {
    s_currentState = IDLE;
    syscall_deliverEvent(EVENT_CDROM, 0x0020);
}

static void __attribute__((section(".ramtext"))) getStatusAck(uint8_t status) {
    *s_getStatusResponsePtr = status;
    s_currentState = IDLE;
    syscall_deliverEvent(EVENT_CDROM, 0x0020);
}

static void __attribute__((section(".ramtext"))) demuteAck(void) {
    s_currentState = s_preemptedState;
    s_preemptedState = IDLE;
    syscall_deliverEvent(EVENT_CDROM, 0x0020);
}

static uint8_t * s_tracksInformationPtr;
static uint8_t s_getTDtrackNum;
static uint8_t s_numberOfTracks;

static void __attribute__((section(".ramtext"))) getTDack()  {
    uint8_t trackNum = s_getTDtrackNum;
    uint8_t * ptr = s_tracksInformationPtr + trackNum * 3;
    ptr[-3] = CDROM_REG1;
    ptr[-2] = CDROM_REG1;

    if (trackNum > s_numberOfTracks) {
        s_currentState = IDLE;
        syscall_deliverEvent(EVENT_CDROM, 0x0020);
        return;
    }

    if (!(CDROM_REG0 & 0x10)) {
        genericErrorState();
        return;
    }

    CDROM_REG0 = 0;
    s_getTDtrackNum++;
    CDROM_REG2 = (trackNum / 10) * 0x10 + trackNum % 10;
    s_currentState = 0x14;
    CDROM_REG1 = 0x14;
}

static uint8_t * s_getParamResultsPtr;

static void __attribute__((section(".ramtext"))) getParamAck() {
    *s_getParamResultsPtr = CDROM_REG1;
    CDROM_REG1;
    CDROM_REG1;
    CDROM_REG1;
    s_currentState = IDLE;
    syscall_deliverEvent(EVENT_CDROM, 0x0020);
}

static uint8_t s_firstTrack;

static void __attribute__((section(".ramtext"))) getTNack(void) {
    uint8_t v;

    uint8_t f = v = CDROM_REG1;
    s_firstTrack = (v / 0x10) * 10 + (v & 0xf);
    v = CDROM_REG1;
    s_numberOfTracks =  (v / 0x10) * 10 + (v & 0xf);

    if (!(CDROM_REG0 & 0x10)) {
        s_getTDtrackNum = s_firstTrack;
        genericErrorState();
        return;
    }

    CDROM_REG0 = 0;
    s_getTDtrackNum = s_firstTrack + 1;
    CDROM_REG2 = f;
    s_currentState = 0x14;
    CDROM_REG1 = 0x14;
}

static void __attribute__((section(".ramtext"))) unlockAck() {
    s_currentState = s_preemptedState;
    s_preemptedState = IDLE;
    syscall_deliverEvent(EVENT_CDROM, 0x0020);
}

static void __attribute__((section(".ramtext"))) issueSeekAfterSetLoc(int P) {
    s_currentState = SEEKP;
    if (!P) s_currentState = SEEKL;
    CDROM_REG0 = 0;
    CDROM_REG1 = s_currentState;
}

static void __attribute__((section(".ramtext"))) readSetModeResponse() {
    CDROM_REG0 = 0;
    if (!(s_mode & 0x100)) {
        if (s_currentState == READ_SETMODE) {
            s_currentState = READN;
        } else {
            s_currentState = 0xe6;
        }
        CDROM_REG1 = 6;
    } else {
        if (s_currentState == READ_SETMODE) {
            s_currentState = READS;
        } else {
            s_currentState = 0xeb;
        }
        CDROM_REG1 = 0x1b;
    }
}

static void __attribute__((section(".ramtext"))) chainGetTNack() {
    uint8_t * ptr = s_tracksInformationPtr;
    ptr[0] = CDROM_REG1;
    ptr[1] = CDROM_REG1;
    CDROM_REG0 = 0;
    CDROM_REG1 = 0x13;
    s_currentState = 0x13;
}

static void __attribute__((section(".ramtext"))) acknowledge() {
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
        case 0x19:
            testAck(status);
            break;
        case SETMODE:
        case 0x17:
            ack();
            break;
        case 3: case 4: case 5:
            s_gotInt3 = 1;
            syscall_deliverEvent(EVENT_CDROM, 0x0020);
            break;
        case GETSTATUS:
            getStatusAck(status);
            break;
        case 12:
            demuteAck();
            break;
        case 0x14:
            getTDack();
            break;
        case 15:
            getParamAck();
            break;
        case 0x13:
            getTNack();
            break;
        case 0x50:
            unlockAck();
            break;
        case READN: case READS:
        case 0xeb: case 0xe6:
            s_gotInt3 = 1;
            break;
        case 0xe2:
            issueSeekAfterSetLoc(1);
            break;
        case 0xee: case READ_SETMODE:
            readSetModeResponse();
            break;
        case 0xf2:
            issueSeekAfterSetLoc(0);
            break;
        case 0xf14:
            chainGetTNack();
            break;
        case IDLE:
            syscall_deliverEvent(EVENT_CDROM, 0x0200);
            break;
    }
}

static void __attribute__((section(".ramtext"))) end() {
    if ((s_preemptedState == READN) || (s_preemptedState == READS) || (s_currentState == READN) || (s_currentState == READS)) {
        if (s_dmaCounter > 0) syscall_deliverEvent(EVENT_CDROM, 0x0080);
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
            syscall_deliverEvent(EVENT_CDROM, 0x0080);
            s_currentState = IDLE;
            break;
        default:
            syscall_deliverEvent(EVENT_CDROM, 0x0200);
            break;
    }
}

static uint8_t * s_getIDerrPtr;

static void __attribute__((section(".ramtext"))) discError() {
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
            syscall_deliverEvent(EVENT_CDROM, 0x8000);
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
                syscall_deliverEvent(EVENT_CDROM, 0x8000);
            }
            break;
    }
}

static uint32_t s_lastIREG;
static uint8_t s_irqFlags;

// Most likely a poor man's flushWriteQueue,
// but messes up the NULL pointer data,
// so we need to keep it this way.
extern volatile uint32_t __vector_00;

int __attribute__((section(".ramtext"))) cdromIOVerifier() {
    if ((IMASK & IRQ_CDROM) == 0) return 0;
    s_lastIREG = IREG;
    if ((s_lastIREG & IRQ_CDROM) == 0) return 0;

    CDROM_REG0 = 1;
    s_irqFlags = CDROM_REG3;
    if (s_irqFlags & 7) {
        CDROM_REG0 = 1;
        CDROM_REG3 = 7;
        __vector_00 = 0;
        __vector_00 = 0;
        __vector_00 = 0;
        __vector_00 = 0;
    }
    if (s_irqFlags & 0x18) {
        CDROM_REG0 = 1;
        CDROM_REG3 = s_irqFlags & 0x18;
        __vector_00 = 0;
        __vector_00 = 0;
        __vector_00 = 0;
        __vector_00 = 0;
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

// This variable is always written to, never read...
// Probably a leftover from missing state machine entries.
static int s_dmaStuff;

int __attribute__((section(".ramtext"))) cdromDMAVerifier() {
    if (!(IMASK & IRQ_DMA)) return 0;
    if (!((s_lastIREG = IREG) & IRQ_DMA)) return 0;
    uint32_t dicr = DICR;
    dicr &= 0x00ffffff;
    dicr |= 0x88000000;
    DICR = dicr;
    if (!(--s_dmaCounter)) {
        syscall_deliverEvent(EVENT_CDROM, 0x0010);
    }
    s_dmaStuff = 0;
    return 1;
}

static int s_irqAutoAck[2];

void __attribute__((section(".ramtext"))) cdromIOHandler(int v) {
    if (!s_irqAutoAck[0]) return;
    IREG = ~IRQ_CDROM;
    syscall_returnFromException();
}

void __attribute__((section(".ramtext"))) cdromDMAHandler(int v) {
    if (!s_irqAutoAck[1]) return;
    IREG = ~IRQ_DMA;
    syscall_returnFromException();
}

void getLastCDRomError(uint8_t * err1, uint8_t * err2) {
    *err1 = s_err1;
    *err2 = s_err2;
}

void __attribute__((section(".ramtext"))) resetAllCDRomIRQs() {
    CDROM_REG0 = 1;
    CDROM_REG3 = 0x1f;
    for (int i = 0; i < 4; i++) __vector_00 = i;
}

void __attribute__((section(".ramtext"))) enableAllCDRomIRQs() {
    CDROM_REG0 = 1;
    CDROM_REG2 = 0x1f;
}

// Same as above, probably leftover state machine.
// Only beeing written to by cdromInnerInit, and then
// never read from or written to again.
static int s_stuff;

int __attribute__((section(".ramtext"))) cdromInnerInit() {
    s_initializationComplete = 0;
    s_gotInt5 = 0;
    s_stuff = 0;
    enterCriticalSection();
    IMASK &= ~IRQ_CDROM;
    IMASK &= ~IRQ_DMA;
    IREG &= ~IRQ_CDROM;
    IREG &= ~IRQ_DMA;
    s_irqAutoAck[1] = 1;
    s_irqAutoAck[0] = 1;
    DPCR = 0x9099;
    uint32_t dicr = DICR;
    dicr &= 0x00ffffff;
    dicr |= 0x88000000;
    DICR = dicr;
    s_preemptedState = IDLE;
    s_currentState = INITIALIZING;
    s_dmaStuff = 0;
    s_gotInt3 = 0;
    resetAllCDRomIRQs();
    enableAllCDRomIRQs();
    IREG &= ~IRQ_CDROM;
    IMASK |= IRQ_CDROM;
    IMASK |= IRQ_DMA;
    leaveCriticalSection();
    CDROM_REG0 = 0;
    CDROM_REG1 = 10;
    int wait = 30000;
    while (wait-- && s_initializationComplete != 2) {
        if (s_initializationComplete == 1) return 1;
    }
    return 0;
}

int setCDRomIRQAutoAck(enum AutoAckType type, int value) {
    int old = s_irqAutoAck[type];
    s_irqAutoAck[type] = value;
    return old;
}

static struct HandlerInfo s_cdromIOHandlerInfo;
static struct HandlerInfo s_cdromDMAHandlerInfo;

void enqueueCDRomHandlers() {
    s_cdromIOHandlerInfo.next = NULL;
    s_cdromIOHandlerInfo.handler = cdromIOHandler;
    s_cdromIOHandlerInfo.verifier = cdromIOVerifier;
    syscall_sysEnqIntRP(0, &s_cdromIOHandlerInfo);
    s_cdromDMAHandlerInfo.next = NULL;
    s_cdromDMAHandlerInfo.handler = cdromDMAHandler;
    s_cdromDMAHandlerInfo.verifier = cdromDMAVerifier;
    syscall_sysEnqIntRP(0, &s_cdromDMAHandlerInfo);
}

void dequeueCDRomHandlers() {
    syscall_sysDeqIntRP(0, &s_cdromIOHandlerInfo);
    syscall_sysDeqIntRP(0, &s_cdromDMAHandlerInfo);
}
