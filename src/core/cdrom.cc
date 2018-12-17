/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

/*
 * Handles all CD-ROM registers and functions.
 */

#include "core/cdrom.h"
#include "core/ppf.h"
#include "core/psxdma.h"

cdrStruct g_cdr;

/* CD-ROM magic numbers */
#define CdlSync 0
#define CdlNop 1
#define CdlSetloc 2
#define CdlPlay 3
#define CdlForward 4
#define CdlBackward 5
#define CdlReadN 6
#define CdlStandby 7
#define CdlStop 8
#define CdlPause 9
#define CdlInit 10       // 0xa
#define CdlMute 11       // 0xb
#define CdlDemute 12     // 0xc
#define CdlSetfilter 13  // 0xd
#define CdlSetmode 14    // 0xe
#define CdlGetmode 15    // 0xf
#define CdlGetlocL 16    // 0x10
#define CdlGetlocP 17    // 0x11
#define CdlReadT 18      // 0x12
#define CdlGetTN 19      // 0x13
#define CdlGetTD 20      // 0x14
#define CdlSeekL 21      // 0x15
#define CdlSeekP 22      // 0x16
#define CdlSetclock 23   // 0x17
#define CdlGetclock 24   // 0x18
#define CdlTest 25       // 0x19
#define CdlID 26         // 0x1a
#define CdlReadS 27      // 0x1b
#define CdlReset 28      // 0x1c
#define CdlGetQ 29       // 0x1d
#define CdlReadToc 30    // 0x1e

const char *CmdName[0x100] = {
    "CdlSync",     "CdlNop",     "CdlSetloc", "CdlPlay",  "CdlForward", "CdlBackward",  "CdlReadN",   "CdlStandby",
    "CdlStop",     "CdlPause",   "CdlInit",   "CdlMute",  "CdlDemute",  "CdlSetfilter", "CdlSetmode", "CdlGetmode",
    "CdlGetlocL",  "CdlGetlocP", "CdlReadT",  "CdlGetTN", "CdlGetTD",   "CdlSeekL",     "CdlSeekP",   "CdlSetclock",
    "CdlGetclock", "CdlTest",    "CdlID",     "CdlReadS", "CdlReset",   NULL,           "CDlReadToc", NULL};

unsigned char Test04[] = {0};
unsigned char Test05[] = {0};
unsigned char Test20[] = {0x98, 0x06, 0x10, 0xC3};
unsigned char Test22[] = {0x66, 0x6F, 0x72, 0x20, 0x45, 0x75, 0x72, 0x6F};
unsigned char Test23[] = {0x43, 0x58, 0x44, 0x32, 0x39, 0x34, 0x30, 0x51};

// g_cdr.Stat:
#define NoIntr 0
#define DataReady 1
#define Complete 2
#define Acknowledge 3
#define DataEnd 4
#define DiskError 5

/* Modes flags */
#define MODE_SPEED (1 << 7)      // 0x80
#define MODE_STRSND (1 << 6)     // 0x40 ADPCM on/off
#define MODE_SIZE_2340 (1 << 5)  // 0x20
#define MODE_SIZE_2328 (1 << 4)  // 0x10
#define MODE_SIZE_2048 (0 << 4)  // 0x00
#define MODE_SF (1 << 3)         // 0x08 channel on/off
#define MODE_REPORT (1 << 2)     // 0x04
#define MODE_AUTOPAUSE (1 << 1)  // 0x02
#define MODE_CDDA (1 << 0)       // 0x01

/* Status flags */
#define STATUS_PLAY (1 << 7)       // 0x80
#define STATUS_SEEK (1 << 6)       // 0x40
#define STATUS_READ (1 << 5)       // 0x20
#define STATUS_SHELLOPEN (1 << 4)  // 0x10
#define STATUS_UNKNOWN3 (1 << 3)   // 0x08
#define STATUS_UNKNOWN2 (1 << 2)   // 0x04
#define STATUS_ROTATING (1 << 1)   // 0x02
#define STATUS_ERROR (1 << 0)      // 0x01

/* Errors */
#define ERROR_NOTREADY (1 << 7)    // 0x80
#define ERROR_INVALIDCMD (1 << 6)  // 0x40
#define ERROR_INVALIDARG (1 << 5)  // 0x20

// 1x = 75 sectors per second
// PCSX::g_emulator.m_psxClockSpeed = 1 sec in the ps
// so (PCSX::g_emulator.m_psxClockSpeed / 75) = g_cdr read time (linuzappz)
#define cdReadTime (PCSX::g_emulator.m_psxClockSpeed / 75)

enum drive_state {
    DRIVESTATE_STANDBY = 0,
    DRIVESTATE_LID_OPEN,
    DRIVESTATE_RESCAN_CD,
    DRIVESTATE_PREPARE_CD,
    DRIVESTATE_STOPPED,
};

// for g_cdr.Seeked
enum seeked_state {
    SEEK_PENDING = 0,
    SEEK_DONE = 1,
};

static struct CdrStat cdr_stat;

unsigned int msf2sec(const uint8_t *msf);
void sec2msf(unsigned int s, uint8_t *msf);

// for that weird psemu API..
static unsigned int fsm2sec(const uint8_t *msf) { return ((msf[2] * 60 + msf[1]) * 75) + msf[0]; }

extern long CALLBACK ISOinit(void);
extern void CALLBACK SPUirq(void);
extern SPUregisterCallback SPU_registerCallback;

// A bit of a kludge, but it will get rid of the "macro redefined" warnings

#ifdef H_SPUirqAddr
#undef H_SPUirqAddr
#endif

#ifdef H_SPUaddr
#undef H_SPUaddr
#endif

#ifdef H_SPUctrl
#undef H_SPUctrl
#endif

#define H_SPUirqAddr 0x1f801da4
#define H_SPUaddr 0x1f801da6
#define H_SPUctrl 0x1f801daa
#define H_CDLeft 0x1f801db0
#define H_CDRight 0x1f801db2

// cdrInterrupt
#define CDR_INT(eCycle)                                      \
    {                                                        \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_CDR);              \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDR].cycle = eCycle;         \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDR].sCycle =        \
            PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle; \
    }

// cdrReadInterrupt
#define CDREAD_INT(eCycle)                                      \
    {                                                           \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_CDREAD);              \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDREAD].cycle = eCycle;         \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDREAD].sCycle =        \
            PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle; \
    }

// cdrDecodedBufferInterrupt
#define CDRDBUF_INT(eCycle)                                      \
    {                                                            \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_CDRDBUF);              \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRDBUF].cycle = eCycle;         \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRDBUF].sCycle =        \
            PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle; \
    }

// cdrLidSeekInterrupt
#define CDRLID_INT(eCycle)                                      \
    {                                                           \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_CDRLID);              \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRLID].cycle = eCycle;         \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRLID].sCycle =        \
            PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle; \
    }

// cdrPlayInterrupt
#define CDRMISC_INT(eCycle)                                      \
    {                                                            \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_CDRPLAY);              \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRPLAY].cycle = eCycle;         \
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRPLAY].sCycle =        \
            PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle; \
    }

#define StopReading()                                   \
    {                                                   \
        if (g_cdr.Reading) {                              \
            g_cdr.Reading = 0;                            \
            PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt &= ~(1 << PCSX::PSXINT_CDREAD); \
        }                                               \
        g_cdr.StatP &= ~(STATUS_READ | STATUS_SEEK);      \
    }

#define StopCdda()                        \
    {                                     \
        if (g_cdr.Play) {                   \
            if (!PCSX::g_emulator.config().Cdda) CDR_stop(); \
            g_cdr.StatP &= ~STATUS_PLAY;    \
            g_cdr.Play = false;             \
            g_cdr.FastForward = 0;          \
            g_cdr.FastBackward = 0;         \
            SPU_registerCallback(SPUirq); \
        }                                 \
    }

#define SetResultSize(size)  \
    {                        \
        g_cdr.ResultP = 0;     \
        g_cdr.ResultC = size;  \
        g_cdr.ResultReady = 1; \
    }

static void setIrq(void) {
    if (g_cdr.Stat & g_cdr.Reg2) psxHu32ref(0x1070) |= SWAP32((uint32_t)0x4);
}

static void adjustTransferIndex(void) {
    unsigned int bufSize = 0;

    switch (g_cdr.Mode & (MODE_SIZE_2340 | MODE_SIZE_2328)) {
        case MODE_SIZE_2340:
            bufSize = 2340;
            break;
        case MODE_SIZE_2328:
            bufSize = 12 + 2328;
            break;
        default:
        case MODE_SIZE_2048:
            bufSize = 12 + 2048;
            break;
    }

    if (g_cdr.transferIndex >= bufSize) g_cdr.transferIndex -= bufSize;
}

// FIXME: do this in SPU instead
void cdrDecodedBufferInterrupt() {
#if 0
	return;
#endif

    // ISO reader only
    if (CDR_init != ISOinit) return;

    // check dbuf IRQ still active
    if (g_cdr.Play == 0) return;
    if ((SPU_readRegister(H_SPUctrl) & 0x40) == 0) return;
    if ((SPU_readRegister(H_SPUirqAddr) * 8) >= 0x800) return;

    // turn off plugin SPU IRQ decoded buffer handling
    SPU_registerCallback(0);

    /*
    Vib Ribbon

    000-3FF = left CDDA
    400-7FF = right CDDA

    Assume IRQ every wrap
    */

    // signal CDDA data ready
    psxHu32ref(0x1070) |= SWAP32((uint32_t)0x200);

    // time for next full buffer
    // CDRDBUF_INT( PCSX::g_emulator.m_psxClockSpeed / 44100 * 0x200 );
    CDRDBUF_INT(PCSX::g_emulator.m_psxClockSpeed / 44100 * 0x100);
}

// timing used in this function was taken from tests on real hardware
// (yes it's slow, but you probably don't want to modify it)
void cdrLidSeekInterrupt() {
    switch (g_cdr.DriveState) {
        default:
        case DRIVESTATE_STANDBY:
            g_cdr.StatP &= ~STATUS_SEEK;

            if (CDR_getStatus(&cdr_stat) == -1) return;

            if (cdr_stat.Status & STATUS_SHELLOPEN) {
                StopCdda();
                g_cdr.DriveState = DRIVESTATE_LID_OPEN;
                CDRLID_INT(0x800);
            }
            break;

        case DRIVESTATE_LID_OPEN:
            if (CDR_getStatus(&cdr_stat) == -1) cdr_stat.Status &= ~STATUS_SHELLOPEN;

            // 02, 12, 10
            if (!(g_cdr.StatP & STATUS_SHELLOPEN)) {
                StopReading();
                g_cdr.StatP |= STATUS_SHELLOPEN;

                // could generate error irq here, but real hardware
                // only sometimes does that
                // (not done when lots of commands are sent?)

                CDRLID_INT(cdReadTime * 30);
                break;
            } else if (g_cdr.StatP & STATUS_ROTATING) {
                g_cdr.StatP &= ~STATUS_ROTATING;
            } else if (!(cdr_stat.Status & STATUS_SHELLOPEN)) {
                // closed now
                CheckCdrom();

                // g_cdr.StatP STATUS_SHELLOPEN is "sticky"
                // and is only cleared by CdlNop

                g_cdr.DriveState = DRIVESTATE_RESCAN_CD;
                CDRLID_INT(cdReadTime * 105);
                break;
            }

            // recheck for close
            CDRLID_INT(cdReadTime * 3);
            break;

        case DRIVESTATE_RESCAN_CD:
            g_cdr.StatP |= STATUS_ROTATING;
            g_cdr.DriveState = DRIVESTATE_PREPARE_CD;

            // this is very long on real hardware, over 6 seconds
            // make it a bit faster here...
            CDRLID_INT(cdReadTime * 150);
            break;

        case DRIVESTATE_PREPARE_CD:
            g_cdr.StatP |= STATUS_SEEK;

            g_cdr.DriveState = DRIVESTATE_STANDBY;
            CDRLID_INT(cdReadTime * 26);
            break;
    }
}

static void Find_CurTrack(const uint8_t *time) {
    int current, sect;

    current = msf2sec(time);

    for (g_cdr.CurTrack = 1; g_cdr.CurTrack < g_cdr.ResultTN[1]; g_cdr.CurTrack++) {
        CDR_getTD(g_cdr.CurTrack + 1, g_cdr.ResultTD);
        sect = fsm2sec(g_cdr.ResultTD);
        if (sect - current >= 150) break;
    }
    CDR_LOG("Find_CurTrack *** %02d %02d\n", g_cdr.CurTrack, current);
}

static void generate_subq(const uint8_t *time) {
    unsigned char start[3], next[3];
    unsigned int this_s, start_s, next_s, pregap;
    int relative_s;

    CDR_getTD(g_cdr.CurTrack, start);
    if (g_cdr.CurTrack + 1 <= g_cdr.ResultTN[1]) {
        pregap = 150;
        CDR_getTD(g_cdr.CurTrack + 1, next);
    } else {
        // last track - cd size
        pregap = 0;
        next[0] = g_cdr.SetSectorEnd[2];
        next[1] = g_cdr.SetSectorEnd[1];
        next[2] = g_cdr.SetSectorEnd[0];
    }

    this_s = msf2sec(time);
    start_s = fsm2sec(start);
    next_s = fsm2sec(next);

    g_cdr.TrackChanged = false;

    if (next_s - this_s < pregap) {
        g_cdr.TrackChanged = true;
        g_cdr.CurTrack++;
        start_s = next_s;
    }

    g_cdr.subq.Index = 1;

    relative_s = this_s - start_s;
    if (relative_s < 0) {
        g_cdr.subq.Index = 0;
        relative_s = -relative_s;
    }
    sec2msf(relative_s, g_cdr.subq.Relative);

    g_cdr.subq.Track = itob(g_cdr.CurTrack);
    g_cdr.subq.Relative[0] = itob(g_cdr.subq.Relative[0]);
    g_cdr.subq.Relative[1] = itob(g_cdr.subq.Relative[1]);
    g_cdr.subq.Relative[2] = itob(g_cdr.subq.Relative[2]);
    g_cdr.subq.Absolute[0] = itob(time[0]);
    g_cdr.subq.Absolute[1] = itob(time[1]);
    g_cdr.subq.Absolute[2] = itob(time[2]);
}

static void ReadTrack(const uint8_t *time) {
    unsigned char tmp[3];
    struct SubQ *subq;
    uint16_t crc;

    tmp[0] = itob(time[0]);
    tmp[1] = itob(time[1]);
    tmp[2] = itob(time[2]);

    if (memcmp(g_cdr.Prev, tmp, 3) == 0) return;

    CDR_LOG("ReadTrack *** %02x:%02x:%02x\n", tmp[0], tmp[1], tmp[2]);

    g_cdr.RErr = CDR_readTrack(tmp);
    memcpy(g_cdr.Prev, tmp, 3);

    subq = (struct SubQ *)CDR_getBufferSub();
    if (subq != NULL && g_cdr.CurTrack == 1) {
        crc = calcCrc((uint8_t *)subq + 12, 10);
        if (crc == (((uint16_t)subq->CRC[0] << 8) | subq->CRC[1])) {
            g_cdr.subq.Track = subq->TrackNumber;
            g_cdr.subq.Index = subq->IndexNumber;
            memcpy(g_cdr.subq.Relative, subq->TrackRelativeAddress, 3);
            memcpy(g_cdr.subq.Absolute, subq->AbsoluteAddress, 3);
        } else {
            CDR_LOG_IO("subq bad crc @%02x:%02x:%02x\n", tmp[0], tmp[1], tmp[2]);
        }
    } else {
        generate_subq(time);
    }

    CDR_LOG(" -> %02x,%02x %02x:%02x:%02x %02x:%02x:%02x\n", g_cdr.subq.Track, g_cdr.subq.Index, g_cdr.subq.Relative[0],
            g_cdr.subq.Relative[1], g_cdr.subq.Relative[2], g_cdr.subq.Absolute[0], g_cdr.subq.Absolute[1],
            g_cdr.subq.Absolute[2]);
}

static void AddIrqQueue(unsigned short irq, unsigned long ecycle) {
    if (g_cdr.Irq != 0) {
        if (irq == g_cdr.Irq || irq + 0x100 == g_cdr.Irq) {
            g_cdr.IrqRepeated = 1;
            CDR_INT(ecycle);
            return;
        }
        CDR_LOG_IO("cdr: override cmd %02x -> %02x\n", g_cdr.Irq, irq);
    }

    g_cdr.Irq = irq;
    g_cdr.eCycle = ecycle;

    CDR_INT(ecycle);
}

static void cdrPlayInterrupt_Autopause() {
    if ((g_cdr.Mode & MODE_AUTOPAUSE) && g_cdr.TrackChanged) {
        CDR_LOG("CDDA STOP\n");
        // Magic the Gathering
        // - looping territory cdda

        // ...?
        // g_cdr.ResultReady = 1;
        // g_cdr.Stat = DataReady;
        g_cdr.Stat = DataEnd;
        setIrq();

        StopCdda();
    } else if (g_cdr.Mode & MODE_REPORT) {
        g_cdr.Result[0] = g_cdr.StatP;
        g_cdr.Result[1] = g_cdr.subq.Track;
        g_cdr.Result[2] = g_cdr.subq.Index;

        if (g_cdr.subq.Absolute[2] & 0x10) {
            g_cdr.Result[3] = g_cdr.subq.Relative[0];
            g_cdr.Result[4] = g_cdr.subq.Relative[1] | 0x80;
            g_cdr.Result[5] = g_cdr.subq.Relative[2];
        } else {
            g_cdr.Result[3] = g_cdr.subq.Absolute[0];
            g_cdr.Result[4] = g_cdr.subq.Absolute[1];
            g_cdr.Result[5] = g_cdr.subq.Absolute[2];
        }

        g_cdr.Result[6] = 0;
        g_cdr.Result[7] = 0;

        // Rayman: Logo freeze (resultready + dataready)
        g_cdr.ResultReady = 1;
        g_cdr.Stat = DataReady;

        SetResultSize(8);
        setIrq();
    }
}

// also handles seek
void cdrPlayInterrupt() {
    if (g_cdr.Seeked == SEEK_PENDING) {
        if (g_cdr.Stat) {
            CDRMISC_INT(0x100);
            return;
        }
        SetResultSize(1);
        g_cdr.StatP |= STATUS_ROTATING;
        g_cdr.StatP &= ~STATUS_SEEK;
        g_cdr.Result[0] = g_cdr.StatP;
        g_cdr.Seeked = SEEK_DONE;
        if (g_cdr.Irq == 0) {
            g_cdr.Stat = Complete;
            setIrq();
        }

        if (g_cdr.SetlocPending) {
            memcpy(g_cdr.SetSectorPlay, g_cdr.SetSector, 4);
            g_cdr.SetlocPending = 0;
        }
        Find_CurTrack(g_cdr.SetSectorPlay);
        ReadTrack(g_cdr.SetSectorPlay);
        g_cdr.TrackChanged = false;
    }

    if (!g_cdr.Play) return;
    CDR_LOG("CDDA - %d:%d:%d\n", g_cdr.SetSectorPlay[0], g_cdr.SetSectorPlay[1], g_cdr.SetSectorPlay[2]);
    if (memcmp(g_cdr.SetSectorPlay, g_cdr.SetSectorEnd, 3) == 0) {
        StopCdda();
        g_cdr.TrackChanged = true;
    }

    if (!g_cdr.Irq && !g_cdr.Stat && (g_cdr.Mode & (MODE_AUTOPAUSE | MODE_REPORT))) cdrPlayInterrupt_Autopause();

    if (!g_cdr.Play) return;

    if (CDR_readCDDA && !g_cdr.Muted) {
        CDR_readCDDA(g_cdr.SetSectorPlay[0], g_cdr.SetSectorPlay[1], g_cdr.SetSectorPlay[2], g_cdr.Transfer);

        cdrAttenuate((int16_t *)g_cdr.Transfer, CD_FRAMESIZE_RAW / 4, 1);
        if (SPU_playCDDAchannel) SPU_playCDDAchannel((short *)g_cdr.Transfer, CD_FRAMESIZE_RAW);
    }

    g_cdr.SetSectorPlay[2]++;
    if (g_cdr.SetSectorPlay[2] == 75) {
        g_cdr.SetSectorPlay[2] = 0;
        g_cdr.SetSectorPlay[1]++;
        if (g_cdr.SetSectorPlay[1] == 60) {
            g_cdr.SetSectorPlay[1] = 0;
            g_cdr.SetSectorPlay[0]++;
        }
    }

    CDRMISC_INT(cdReadTime);

    // update for CdlGetlocP/autopause
    generate_subq(g_cdr.SetSectorPlay);
}

void cdrInterrupt() {
    uint16_t Irq = g_cdr.Irq;
    int no_busy_error = 0;
    int start_rotating = 0;
    int error = 0;
    int delay;

    // Reschedule IRQ
    if (g_cdr.Stat) {
        CDR_INT(0x100);
        return;
    }

    g_cdr.Ctrl &= ~0x80;

    // default response
    SetResultSize(1);
    g_cdr.Result[0] = g_cdr.StatP;
    g_cdr.Stat = Acknowledge;

    if (g_cdr.IrqRepeated) {
        g_cdr.IrqRepeated = 0;
        if (g_cdr.eCycle > PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle) {
            CDR_INT(g_cdr.eCycle);
            goto finish;
        }
    }

    g_cdr.Irq = 0;
    CDR_LOG("CDRINT %x %x %x %x\n", g_cdr.Seeked, g_cdr.Stat, Irq, g_cdr.IrqRepeated);
    switch (Irq) {
        case CdlSync:
            // TOOD: sometimes/always return error?
            break;

        case CdlNop:
            if (g_cdr.DriveState != DRIVESTATE_LID_OPEN) g_cdr.StatP &= ~STATUS_SHELLOPEN;
            no_busy_error = 1;
            break;

        case CdlSetloc:
            break;

        do_CdlPlay:
        case CdlPlay:
            StopCdda();
            if (g_cdr.Seeked == SEEK_PENDING) {
                // XXX: wrong, should seek instead..
                g_cdr.Seeked = SEEK_DONE;
            }
            if (g_cdr.SetlocPending) {
                memcpy(g_cdr.SetSectorPlay, g_cdr.SetSector, 4);
                g_cdr.SetlocPending = 0;
            }

            // BIOS CD Player
            // - Pause player, hit Track 01/02/../xx (Setloc issued!!)

            if (g_cdr.ParamC == 0 || g_cdr.Param[0] == 0) {
                CDR_LOG("PLAY Resume @ %d:%d:%d\n", g_cdr.SetSectorPlay[0], g_cdr.SetSectorPlay[1], g_cdr.SetSectorPlay[2]);
            } else {
                int track = btoi(g_cdr.Param[0]);

                if (track <= g_cdr.ResultTN[1]) g_cdr.CurTrack = track;

                CDR_LOG("PLAY track %d\n", g_cdr.CurTrack);

                if (CDR_getTD((uint8_t)g_cdr.CurTrack, g_cdr.ResultTD) != -1) {
                    g_cdr.SetSectorPlay[0] = g_cdr.ResultTD[2];
                    g_cdr.SetSectorPlay[1] = g_cdr.ResultTD[1];
                    g_cdr.SetSectorPlay[2] = g_cdr.ResultTD[0];
                }
            }

            /*
            Rayman: detect track changes
            - fixes logo freeze

            Twisted Metal 2: skip PREGAP + starting accurate SubQ
            - plays tracks without retry play

            Wild 9: skip PREGAP + starting accurate SubQ
            - plays tracks without retry play
            */
            Find_CurTrack(g_cdr.SetSectorPlay);
            ReadTrack(g_cdr.SetSectorPlay);
            g_cdr.TrackChanged = false;

            if (PCSX::g_emulator.config().Cdda != PCSX::Emulator::CDDA_DISABLED) CDR_play(g_cdr.SetSectorPlay);

            // Vib Ribbon: gameplay checks flag
            g_cdr.StatP &= ~STATUS_SEEK;
            g_cdr.Result[0] = g_cdr.StatP;

            g_cdr.StatP |= STATUS_PLAY;

            // BIOS player - set flag again
            g_cdr.Play = true;

            CDRMISC_INT(cdReadTime);
            start_rotating = 1;
            break;

        case CdlForward:
            // TODO: error 80 if stopped
            g_cdr.Stat = Complete;

            // GameShark CD Player: Calls 2x + Play 2x
            if (g_cdr.FastForward == 0)
                g_cdr.FastForward = 2;
            else
                g_cdr.FastForward++;

            g_cdr.FastBackward = 0;
            break;

        case CdlBackward:
            g_cdr.Stat = Complete;

            // GameShark CD Player: Calls 2x + Play 2x
            if (g_cdr.FastBackward == 0)
                g_cdr.FastBackward = 2;
            else
                g_cdr.FastBackward++;

            g_cdr.FastForward = 0;
            break;

        case CdlStandby:
            if (g_cdr.DriveState != DRIVESTATE_STOPPED) {
                error = ERROR_INVALIDARG;
                goto set_error;
            }
            AddIrqQueue(CdlStandby + 0x100, cdReadTime * 125 / 2);
            start_rotating = 1;
            break;

        case CdlStandby + 0x100:
            g_cdr.Stat = Complete;
            break;

        case CdlStop:
            if (g_cdr.Play) {
                // grab time for current track
                CDR_getTD((uint8_t)(g_cdr.CurTrack), g_cdr.ResultTD);

                g_cdr.SetSectorPlay[0] = g_cdr.ResultTD[2];
                g_cdr.SetSectorPlay[1] = g_cdr.ResultTD[1];
                g_cdr.SetSectorPlay[2] = g_cdr.ResultTD[0];
            }

            StopCdda();
            StopReading();

            delay = 0x800;
            if (g_cdr.DriveState == DRIVESTATE_STANDBY) delay = cdReadTime * 30 / 2;

            g_cdr.DriveState = DRIVESTATE_STOPPED;
            AddIrqQueue(CdlStop + 0x100, delay);
            break;

        case CdlStop + 0x100:
            g_cdr.StatP &= ~STATUS_ROTATING;
            g_cdr.Result[0] = g_cdr.StatP;
            g_cdr.Stat = Complete;
            break;

        case CdlPause:
            /*
            Gundam Battle Assault 2: much slower (*)
            - Fixes boot, gameplay

            Hokuto no Ken 2: slower
            - Fixes intro + subtitles

            InuYasha - Feudal Fairy Tale: slower
            - Fixes battles
            */
            AddIrqQueue(CdlPause + 0x100, cdReadTime * 3);
            g_cdr.Ctrl |= 0x80;
            break;

        case CdlPause + 0x100:
            g_cdr.StatP &= ~STATUS_READ;
            g_cdr.Result[0] = g_cdr.StatP;
            g_cdr.Stat = Complete;
            break;

        case CdlInit:
            AddIrqQueue(CdlInit + 0x100, cdReadTime * 6);
            no_busy_error = 1;
            start_rotating = 1;
            break;

        case CdlInit + 0x100:
            g_cdr.Stat = Complete;
            break;

        case CdlMute:
            g_cdr.Muted = true;
            break;

        case CdlDemute:
            g_cdr.Muted = false;
            break;

        case CdlSetfilter:
            g_cdr.File = g_cdr.Param[0];
            g_cdr.Channel = g_cdr.Param[1];
            break;

        case CdlSetmode:
            no_busy_error = 1;
            break;

        case CdlGetmode:
            SetResultSize(6);
            g_cdr.Result[1] = g_cdr.Mode;
            g_cdr.Result[2] = g_cdr.File;
            g_cdr.Result[3] = g_cdr.Channel;
            g_cdr.Result[4] = 0;
            g_cdr.Result[5] = 0;
            no_busy_error = 1;
            break;

        case CdlGetlocL:
            SetResultSize(8);
            memcpy(g_cdr.Result, g_cdr.Transfer, 8);
            break;

        case CdlGetlocP:
            SetResultSize(8);
            memcpy(&g_cdr.Result, &g_cdr.subq, 8);

            if (!g_cdr.Play && CheckSBI(g_cdr.Result + 5)) memset(g_cdr.Result + 2, 0, 6);
            if (!g_cdr.Play && !g_cdr.Reading) g_cdr.Result[1] = 0;  // HACK?
            break;

        case CdlReadT:  // SetSession?
            // really long
            AddIrqQueue(CdlReadT + 0x100, cdReadTime * 290 / 4);
            start_rotating = 1;
            break;

        case CdlReadT + 0x100:
            g_cdr.Stat = Complete;
            break;

        case CdlGetTN:
            SetResultSize(3);
            if (CDR_getTN(g_cdr.ResultTN) == -1) {
                g_cdr.Stat = DiskError;
                g_cdr.Result[0] |= STATUS_ERROR;
            } else {
                g_cdr.Stat = Acknowledge;
                g_cdr.Result[1] = itob(g_cdr.ResultTN[0]);
                g_cdr.Result[2] = itob(g_cdr.ResultTN[1]);
            }
            break;

        case CdlGetTD:
            g_cdr.Track = btoi(g_cdr.Param[0]);
            SetResultSize(4);
            if (CDR_getTD(g_cdr.Track, g_cdr.ResultTD) == -1) {
                g_cdr.Stat = DiskError;
                g_cdr.Result[0] |= STATUS_ERROR;
            } else {
                g_cdr.Stat = Acknowledge;
                g_cdr.Result[0] = g_cdr.StatP;
                g_cdr.Result[1] = itob(g_cdr.ResultTD[2]);
                g_cdr.Result[2] = itob(g_cdr.ResultTD[1]);
                g_cdr.Result[3] = itob(g_cdr.ResultTD[0]);
            }
            break;

        case CdlSeekL:
        case CdlSeekP:
            StopCdda();
            StopReading();
            g_cdr.StatP |= STATUS_SEEK;

            /*
            Crusaders of Might and Magic = 0.5x-4x
            - fix cutscene speech start

            Eggs of Steel = 2x-?
            - fix new game

            Medievil = ?-4x
            - fix cutscene speech

            Rockman X5 = 0.5-4x
            - fix capcom logo
            */
            CDRMISC_INT(g_cdr.Seeked == SEEK_DONE ? 0x800 : cdReadTime * 4);
            g_cdr.Seeked = SEEK_PENDING;
            start_rotating = 1;
            break;

        case CdlTest:
            switch (g_cdr.Param[0]) {
                case 0x20:  // System Controller ROM Version
                    SetResultSize(4);
                    memcpy(g_cdr.Result, Test20, 4);
                    break;
                case 0x22:
                    SetResultSize(8);
                    memcpy(g_cdr.Result, Test22, 4);
                    break;
                case 0x23:
                case 0x24:
                    SetResultSize(8);
                    memcpy(g_cdr.Result, Test23, 4);
                    break;
            }
            no_busy_error = 1;
            break;

        case CdlID:
            AddIrqQueue(CdlID + 0x100, 20480);
            break;

        case CdlID + 0x100:
            SetResultSize(8);
            g_cdr.Result[0] = g_cdr.StatP;
            g_cdr.Result[1] = 0;
            g_cdr.Result[2] = 0;
            g_cdr.Result[3] = 0;

            // 0x10 - audio | 0x40 - disk missing | 0x80 - unlicensed
            if (CDR_getStatus(&cdr_stat) == -1 || cdr_stat.Type == 0 || cdr_stat.Type == 0xff) {
                g_cdr.Result[1] = 0xc0;
            } else {
                if (cdr_stat.Type == 2) g_cdr.Result[1] |= 0x10;
                if (g_cdromId[0] == '\0') g_cdr.Result[1] |= 0x80;
            }
            g_cdr.Result[0] |= (g_cdr.Result[1] >> 4) & 0x08;

            strncpy((char *)&g_cdr.Result[4], "PCSX", 4);
            g_cdr.Stat = Complete;
            break;

        case CdlReset:
            // yes, it really sets STATUS_SHELLOPEN
            g_cdr.StatP |= STATUS_SHELLOPEN;
            g_cdr.DriveState = DRIVESTATE_RESCAN_CD;
            CDRLID_INT(20480);
            no_busy_error = 1;
            start_rotating = 1;
            break;

        case CdlGetQ:
            // TODO?
            CDR_LOG("got CdlGetQ\n");
            break;

        case CdlReadToc:
            AddIrqQueue(CdlReadToc + 0x100, cdReadTime * 180 / 4);
            no_busy_error = 1;
            start_rotating = 1;
            break;

        case CdlReadToc + 0x100:
            g_cdr.Stat = Complete;
            no_busy_error = 1;
            break;

        case CdlReadN:
        case CdlReadS:
            if (g_cdr.SetlocPending) {
                memcpy(g_cdr.SetSectorPlay, g_cdr.SetSector, 4);
                g_cdr.SetlocPending = 0;
            }
            Find_CurTrack(g_cdr.SetSectorPlay);

            if ((g_cdr.Mode & MODE_CDDA) && g_cdr.CurTrack > 1)
                // Read* acts as play for cdda tracks in cdda mode
                goto do_CdlPlay;

            g_cdr.Reading = 1;
            g_cdr.FirstSector = 1;

            // Fighting Force 2 - update subq time immediately
            // - fixes new game
            ReadTrack(g_cdr.SetSectorPlay);

            // Crusaders of Might and Magic - update getlocl now
            // - fixes cutscene speech
            {
                uint8_t *buf = CDR_getBuffer();
                if (buf != NULL) memcpy(g_cdr.Transfer, buf, 8);
            }

            /*
            Duke Nukem: Land of the Babes - seek then delay read for one frame
            - fixes cutscenes
            C-12 - Final Resistance - doesn't like seek
            */

            if (g_cdr.Seeked != SEEK_DONE) {
                g_cdr.StatP |= STATUS_SEEK;
                g_cdr.StatP &= ~STATUS_READ;

                // Crusaders of Might and Magic - use short time
                // - fix cutscene speech (startup)

                // ??? - use more accurate seek time later
                CDREAD_INT((g_cdr.Mode & 0x80) ? (cdReadTime) : cdReadTime * 2);
            } else {
                g_cdr.StatP |= STATUS_READ;
                g_cdr.StatP &= ~STATUS_SEEK;

                CDREAD_INT((g_cdr.Mode & 0x80) ? (cdReadTime) : cdReadTime * 2);
            }

            g_cdr.Result[0] = g_cdr.StatP;
            start_rotating = 1;
            break;

        default:
            CDR_LOG("Invalid command: %02x\n", Irq);
            error = ERROR_INVALIDCMD;
            // FALLTHROUGH

        set_error:
            SetResultSize(2);
            g_cdr.Result[0] = g_cdr.StatP | STATUS_ERROR;
            g_cdr.Result[1] = error;
            g_cdr.Stat = DiskError;
            break;
    }

    if (g_cdr.DriveState == DRIVESTATE_STOPPED && start_rotating) {
        g_cdr.DriveState = DRIVESTATE_STANDBY;
        g_cdr.StatP |= STATUS_ROTATING;
    }

    if (!no_busy_error) {
        switch (g_cdr.DriveState) {
            case DRIVESTATE_LID_OPEN:
            case DRIVESTATE_RESCAN_CD:
            case DRIVESTATE_PREPARE_CD:
                SetResultSize(2);
                g_cdr.Result[0] = g_cdr.StatP | STATUS_ERROR;
                g_cdr.Result[1] = ERROR_NOTREADY;
                g_cdr.Stat = DiskError;
                break;
        }
    }

finish:
    setIrq();
    g_cdr.ParamC = 0;

    {
        CDR_LOG_IO("CDR IRQ %d cmd %02x stat %02x: ", !!(g_cdr.Stat & g_cdr.Reg2), Irq, g_cdr.Stat);
        for (int i = 0; i < g_cdr.ResultC; i++) CDR_LOG_IO("%02x ", g_cdr.Result[i]);
        CDR_LOG_IO("\n");
    }
}

#define ssat32_to_16(v)     \
    do {                    \
        if (v < -32768)     \
            v = -32768;     \
        else if (v > 32767) \
            v = 32767;      \
    } while (0)

void cdrAttenuate(int16_t *buf, int samples, int stereo) {
    int i, l, r;
    int ll = g_cdr.AttenuatorLeftToLeft;
    int lr = g_cdr.AttenuatorLeftToRight;
    int rl = g_cdr.AttenuatorRightToLeft;
    int rr = g_cdr.AttenuatorRightToRight;

    if (lr == 0 && rl == 0 && 0x78 <= ll && ll <= 0x88 && 0x78 <= rr && rr <= 0x88) return;

    if (!stereo && ll == 0x40 && lr == 0x40 && rl == 0x40 && rr == 0x40) return;

    if (stereo) {
        for (i = 0; i < samples; i++) {
            l = buf[i * 2];
            r = buf[i * 2 + 1];
            l = (l * ll + r * rl) >> 7;
            r = (r * rr + l * lr) >> 7;
            ssat32_to_16(l);
            ssat32_to_16(r);
            buf[i * 2] = l;
            buf[i * 2 + 1] = r;
        }
    } else {
        for (i = 0; i < samples; i++) {
            l = buf[i];
            l = l * (ll + rl) >> 7;
            // r = r * (rr + lr) >> 7;
            ssat32_to_16(l);
            // ssat32_to_16(r);
            buf[i] = l;
        }
    }
}

void cdrReadInterrupt() {
    uint8_t *buf;

    if (!g_cdr.Reading) return;

    if (g_cdr.Irq || g_cdr.Stat) {
        CDREAD_INT(0x100);
        return;
    }

    if ((psxHu32ref(0x1070) & psxHu32ref(0x1074) & SWAP32((uint32_t)0x4)) && !g_cdr.ReadRescheduled) {
        // HACK: with PCSX::Emulator::BIAS 2, emulated CPU is often slower than real thing,
        // game may be unfinished with prev data read, so reschedule
        // (Brave Fencer Musashi)
        CDREAD_INT(cdReadTime / 2);
        g_cdr.ReadRescheduled = 1;
        return;
    }

    g_cdr.OCUP = 1;
    SetResultSize(1);
    g_cdr.StatP |= STATUS_READ | STATUS_ROTATING;
    g_cdr.StatP &= ~STATUS_SEEK;
    g_cdr.Result[0] = g_cdr.StatP;
    g_cdr.Seeked = SEEK_DONE;

    ReadTrack(g_cdr.SetSectorPlay);

    buf = CDR_getBuffer();
    if (buf == NULL) g_cdr.RErr = -1;

    if (g_cdr.RErr == -1) {
        CDR_LOG("cdrReadInterrupt() Log: err\n");
        memset(g_cdr.Transfer, 0, DATA_SIZE);
        g_cdr.Stat = DiskError;
        g_cdr.Result[0] |= STATUS_ERROR;
        CDREAD_INT((g_cdr.Mode & 0x80) ? (cdReadTime / 2) : cdReadTime);
        return;
    }

    memcpy(g_cdr.Transfer, buf, DATA_SIZE);
    CheckPPFCache(g_cdr.Transfer, g_cdr.Prev[0], g_cdr.Prev[1], g_cdr.Prev[2]);

    CDR_LOG("cdrReadInterrupt() Log: cdr.Transfer %x:%x:%x\n", g_cdr.Transfer[0], g_cdr.Transfer[1], g_cdr.Transfer[2]);

    if ((!g_cdr.Muted) && (g_cdr.Mode & MODE_STRSND) && (!PCSX::g_emulator.config().Xa) && (g_cdr.FirstSector != -1)) {  // CD-XA
        // Firemen 2: Multi-XA files - briefings, cutscenes
        if (g_cdr.FirstSector == 1 && (g_cdr.Mode & MODE_SF) == 0) {
            g_cdr.File = g_cdr.Transfer[4 + 0];
            g_cdr.Channel = g_cdr.Transfer[4 + 1];
        }

        if ((g_cdr.Transfer[4 + 2] & 0x4) && (g_cdr.Transfer[4 + 1] == g_cdr.Channel) && (g_cdr.Transfer[4 + 0] == g_cdr.File)) {
            int ret = xa_decode_sector(&g_cdr.Xa, g_cdr.Transfer + 4, g_cdr.FirstSector);
            if (!ret) {
                cdrAttenuate(g_cdr.Xa.pcm, g_cdr.Xa.nsamples, g_cdr.Xa.stereo);
                SPU_playADPCMchannel(&g_cdr.Xa);
                g_cdr.FirstSector = 0;
            } else
                g_cdr.FirstSector = -1;
        }
    }

    g_cdr.SetSectorPlay[2]++;
    if (g_cdr.SetSectorPlay[2] == 75) {
        g_cdr.SetSectorPlay[2] = 0;
        g_cdr.SetSectorPlay[1]++;
        if (g_cdr.SetSectorPlay[1] == 60) {
            g_cdr.SetSectorPlay[1] = 0;
            g_cdr.SetSectorPlay[0]++;
        }
    }

    g_cdr.Readed = 0;
    g_cdr.ReadRescheduled = 0;

    CDREAD_INT((g_cdr.Mode & MODE_SPEED) ? (cdReadTime / 2) : cdReadTime);

    /*
    Croc 2: $40 - only FORM1 (*)
    Judge Dredd: $C8 - only FORM1 (*)
    Sim Theme Park - no adpcm at all (zero)
    */

    if (!(g_cdr.Mode & MODE_STRSND) || !(g_cdr.Transfer[4 + 2] & 0x4)) {
        g_cdr.Stat = DataReady;
        setIrq();
    }

    // update for CdlGetlocP
    ReadTrack(g_cdr.SetSectorPlay);
}

/*
cdrRead0:
        bit 0,1 - mode
        bit 2 - unknown
        bit 3 - unknown
        bit 4 - unknown
        bit 5 - 1 result ready
        bit 6 - 1 dma ready
        bit 7 - 1 command being processed
*/

unsigned char cdrRead0(void) {
    if (g_cdr.ResultReady)
        g_cdr.Ctrl |= 0x20;
    else
        g_cdr.Ctrl &= ~0x20;

    if (g_cdr.OCUP) g_cdr.Ctrl |= 0x40;
    //  else
    //		g_cdr.Ctrl &= ~0x40;

    // What means the 0x10 and the 0x08 bits? I only saw it used by the bios
    g_cdr.Ctrl |= 0x18;

    CDR_LOG_IO("cdr r0: %02x\n", g_cdr.Ctrl);
    return psxHu8(0x1800) = g_cdr.Ctrl;
}

void cdrWrite0(unsigned char rt) {
    CDR_LOG_IO("cdr w0: %02x\n", rt);
    g_cdr.Ctrl = (rt & 3) | (g_cdr.Ctrl & ~3);
}

unsigned char cdrRead1(void) {
    if ((g_cdr.ResultP & 0xf) < g_cdr.ResultC)
        psxHu8(0x1801) = g_cdr.Result[g_cdr.ResultP & 0xf];
    else
        psxHu8(0x1801) = 0;
    g_cdr.ResultP++;
    if (g_cdr.ResultP == g_cdr.ResultC) g_cdr.ResultReady = 0;
    CDR_LOG_IO("cdr r1: %02x\n", psxHu8(0x1801));
    return psxHu8(0x1801);
}

void cdrWrite1(unsigned char rt) {
    uint8_t set_loc[3];
    int i;
    CDR_LOG_IO("cdr w1: %02x\n", rt);
    switch (g_cdr.Ctrl & 3) {
        case 0:
            break;
        case 3:
            g_cdr.AttenuatorRightToRightT = rt;
            return;
        default:
            return;
    }

    g_cdr.Cmd = rt;
    g_cdr.OCUP = 0;

    CDR_LOG_IO("CD1 write: %x (%s)", rt, CmdName[rt]);
    if (g_cdr.ParamC) {
        CDR_LOG_IO(" Param[%d] = {", g_cdr.ParamC);
        for (i = 0; i < g_cdr.ParamC; i++) CDR_LOG_IO(" %x,", g_cdr.Param[i]);
        CDR_LOG_IO("}\n");
    } else {
        CDR_LOG_IO("\n");
    }

    g_cdr.ResultReady = 0;
    g_cdr.Ctrl |= 0x80;
    // g_cdr.Stat = NoIntr;
    AddIrqQueue(g_cdr.Cmd, 0x800);

    switch (g_cdr.Cmd) {
        case CdlSetloc:
            for (i = 0; i < 3; i++) set_loc[i] = btoi(g_cdr.Param[i]);

            i = msf2sec(g_cdr.SetSectorPlay);
            i = abs(i - (int)msf2sec(set_loc));
            if (i > 16) g_cdr.Seeked = SEEK_PENDING;

            memcpy(g_cdr.SetSector, set_loc, 3);
            g_cdr.SetSector[3] = 0;
            g_cdr.SetlocPending = 1;
            break;

        case CdlReadN:
        case CdlReadS:
        case CdlPause:
            StopCdda();
            StopReading();
            break;

        case CdlReset:
        case CdlInit:
            g_cdr.Seeked = SEEK_DONE;
            StopCdda();
            StopReading();
            break;

        case CdlSetmode:
            CDR_LOG("cdrWrite1() Log: Setmode %x\n", g_cdr.Param[0]);
            g_cdr.Mode = g_cdr.Param[0];

            // Squaresoft on PlayStation 1998 Collector's CD Vol. 1
            // - fixes choppy movie sound
            if (g_cdr.Play && (g_cdr.Mode & MODE_CDDA) == 0) StopCdda();
            break;
    }
}

unsigned char cdrRead2(void) {
    unsigned char ret;

    if (g_cdr.Readed == 0) {
        ret = 0;
    } else {
        ret = g_cdr.Transfer[g_cdr.transferIndex];
        g_cdr.transferIndex++;
        adjustTransferIndex();
    }
    CDR_LOG_IO("cdr r2: %02x\n", ret);
    return ret;
}

void cdrWrite2(unsigned char rt) {
    CDR_LOG_IO("cdr w2: %02x\n", rt);
    switch (g_cdr.Ctrl & 3) {
        case 0:
            if (g_cdr.ParamC < 8)  // FIXME: size and wrapping
                g_cdr.Param[g_cdr.ParamC++] = rt;
            return;
        case 1:
            g_cdr.Reg2 = rt;
            setIrq();
            return;
        case 2:
            g_cdr.AttenuatorLeftToLeftT = rt;
            return;
        case 3:
            g_cdr.AttenuatorRightToLeftT = rt;
            return;
    }
}

unsigned char cdrRead3(void) {
    if (g_cdr.Ctrl & 0x1)
        psxHu8(0x1803) = g_cdr.Stat | 0xE0;
    else
        psxHu8(0x1803) = g_cdr.Reg2 | 0xE0;
    CDR_LOG_IO("cdr r3: %02x\n", psxHu8(0x1803));
    return psxHu8(0x1803);
}

void cdrWrite3(unsigned char rt) {
    CDR_LOG_IO("cdr w3: %02x\n", rt);
    switch (g_cdr.Ctrl & 3) {
        case 0:
            break;  // transfer
        case 1:
            g_cdr.Stat &= ~rt;

            if (rt & 0x40) g_cdr.ParamC = 0;
            return;
        case 2:
            g_cdr.AttenuatorLeftToRightT = rt;
            return;
        case 3:
            if (rt & 0x20) {
                memcpy(&g_cdr.AttenuatorLeftToLeft, &g_cdr.AttenuatorLeftToLeftT, 4);
                CDR_LOG_IO("CD-XA Volume: %02x %02x | %02x %02x\n", g_cdr.AttenuatorLeftToLeft, g_cdr.AttenuatorLeftToRight,
                           g_cdr.AttenuatorRightToLeft, g_cdr.AttenuatorRightToRight);
            }
            return;
    }

    if ((rt & 0x80) && g_cdr.Readed == 0) {
        g_cdr.Readed = 1;
        g_cdr.transferIndex = 0;

        switch (g_cdr.Mode & (MODE_SIZE_2340 | MODE_SIZE_2328)) {
            case MODE_SIZE_2328:
            case MODE_SIZE_2048:
                g_cdr.transferIndex += 12;
                break;

            case MODE_SIZE_2340:
                g_cdr.transferIndex += 0;
                break;

            default:
                break;
        }
    }
}

void psxDma3(uint32_t madr, uint32_t bcr, uint32_t chcr) {
    uint32_t cdsize;
    int i;
    uint8_t *ptr;

    CDR_LOG("psxDma3() Log: *** DMA 3 *** %x addr = %x size = %x\n", chcr, madr, bcr);

    switch (chcr) {
        case 0x11000000:
        case 0x11400100:
            if (g_cdr.Readed == 0) {
                CDR_LOG("psxDma3() Log: *** DMA 3 *** NOT READY\n");
                break;
            }

            cdsize = (bcr & 0xffff) * 4;

            // Ape Escape: bcr = 0001 / 0000
            // - fix boot
            if (cdsize == 0) {
                switch (g_cdr.Mode & (MODE_SIZE_2340 | MODE_SIZE_2328)) {
                    case MODE_SIZE_2340:
                        cdsize = 2340;
                        break;
                    case MODE_SIZE_2328:
                        cdsize = 2328;
                        break;
                    default:
                    case MODE_SIZE_2048:
                        cdsize = 2048;
                        break;
                }
            }

            ptr = (uint8_t *)PSXM(madr);
            if (ptr == NULL) {
                CDR_LOG("psxDma3() Log: *** DMA 3 *** NULL Pointer!\n");
                break;
            }

            /*
            GS CDX: Enhancement CD crash
            - Setloc 0:0:0
            - CdlPlay
            - Spams DMA3 and gets buffer overrun
            */
            for (i = 0; i < cdsize; ++i) {
                ptr[i] = g_cdr.Transfer[g_cdr.transferIndex];
                g_cdr.transferIndex++;
                adjustTransferIndex();
            }
            PCSX::g_emulator.m_psxCpu->Clear(madr, cdsize / 4);
            // burst vs normal
            if (chcr == 0x11400100) {
                CDRDMA_INT((cdsize / 4) / 4);
            } else if (chcr == 0x11000000) {
                CDRDMA_INT((cdsize / 4) * 1);
            }
            return;

        default:
            CDR_LOG("psxDma3() Log: Unknown cddma %x\n", chcr);
            break;
    }

    HW_DMA3_CHCR &= SWAP32(~0x01000000);
    DMA_INTERRUPT(3);
}

void cdrDmaInterrupt() {
    if (HW_DMA3_CHCR & SWAP32(0x01000000)) {
        HW_DMA3_CHCR &= SWAP32(~0x01000000);
        DMA_INTERRUPT(3);
    }
}

static void getCdInfo(void) {
    uint8_t tmp;

    CDR_getTN(g_cdr.ResultTN);
    CDR_getTD(0, g_cdr.SetSectorEnd);
    tmp = g_cdr.SetSectorEnd[0];
    g_cdr.SetSectorEnd[0] = g_cdr.SetSectorEnd[2];
    g_cdr.SetSectorEnd[2] = tmp;
}

void cdrReset() {
    memset(&g_cdr, 0, sizeof(g_cdr));
    g_cdr.CurTrack = 1;
    g_cdr.File = 1;
    g_cdr.Channel = 1;
    g_cdr.transferIndex = 0;
    g_cdr.Reg2 = 0x1f;
    g_cdr.Stat = NoIntr;
    g_cdr.DriveState = DRIVESTATE_STANDBY;
    g_cdr.StatP = STATUS_ROTATING;

    // BIOS player - default values
    g_cdr.AttenuatorLeftToLeft = 0x80;
    g_cdr.AttenuatorLeftToRight = 0x00;
    g_cdr.AttenuatorRightToLeft = 0x00;
    g_cdr.AttenuatorRightToRight = 0x80;

    getCdInfo();
}

int cdrFreeze(gzFile f, int Mode) {
    uint8_t tmpp[3];

    if (Mode == 0 && PCSX::g_emulator.config().Cdda != PCSX::Emulator::CDDA_DISABLED) CDR_stop();

    gzfreeze(&g_cdr, sizeof(g_cdr));

    if (Mode == 1) g_cdr.ParamP = g_cdr.ParamC;

    if (Mode == 0) {
        getCdInfo();

        // read right sub data
        memcpy(tmpp, g_cdr.Prev, 3);
        g_cdr.Prev[0]++;
        ReadTrack(tmpp);

        if (g_cdr.Play) {
            Find_CurTrack(g_cdr.SetSectorPlay);
            if (PCSX::g_emulator.config().Cdda != PCSX::Emulator::CDDA_DISABLED) CDR_play(g_cdr.SetSectorPlay);
        }
    }

    return 0;
}

void LidInterrupt() {
    getCdInfo();
    StopCdda();
    cdrLidSeekInterrupt();
}
