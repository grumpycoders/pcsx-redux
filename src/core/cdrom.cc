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

#include "spu/interface.h"

void SPUirq(void);

namespace {

class CDRomImpl : public PCSX::CDRom {
    /* CD-ROM magic numbers */
    enum {
        CdlSync = 0,
        CdlNop = 1,
        CdlSetloc = 2,
        CdlPlay = 3,
        CdlForward = 4,
        CdlBackward = 5,
        CdlReadN = 6,
        CdlStandby = 7,
        CdlStop = 8,
        CdlPause = 9,
        CdlInit = 10,
        CdlMute = 11,
        CdlDemute = 12,
        CdlSetfilter = 13,
        CdlSetmode = 14,
        CdlGetmode = 15,
        CdlGetlocL = 16,
        CdlGetlocP = 17,
        CdlReadT = 18,
        CdlGetTN = 19,
        CdlGetTD = 20,
        CdlSeekL = 21,
        CdlSeekP = 22,
        CdlSetclock = 23,
        CdlGetclock = 24,
        CdlTest = 25,
        CdlID = 26,
        CdlReadS = 27,
        CdlReset = 28,
        CdlGetQ = 29,
        CdlReadToc = 30,
    };

    static const inline char *CmdName[] = {
        "CdlSync",     "CdlNop",     "CdlSetloc", "CdlPlay",  "CdlForward", "CdlBackward",  "CdlReadN",   "CdlStandby",
        "CdlStop",     "CdlPause",   "CdlInit",   "CdlMute",  "CdlDemute",  "CdlSetfilter", "CdlSetmode", "CdlGetmode",
        "CdlGetlocL",  "CdlGetlocP", "CdlReadT",  "CdlGetTN", "CdlGetTD",   "CdlSeekL",     "CdlSeekP",   "CdlSetclock",
        "CdlGetclock", "CdlTest",    "CdlID",     "CdlReadS", "CdlReset",   "NULL",         "CDlReadToc", "NULL"};

    static const inline uint8_t Test04[] = {0};
    static const inline uint8_t Test05[] = {0};
    static const inline uint8_t Test20[] = {0x98, 0x06, 0x10, 0xC3};
    static const inline uint8_t Test22[] = {0x66, 0x6F, 0x72, 0x20, 0x45, 0x75, 0x72, 0x6F};
    static const inline uint8_t Test23[] = {0x43, 0x58, 0x44, 0x32, 0x39, 0x34, 0x30, 0x51};

    // m_Stat:
    enum {
        NoIntr = 0,
        DataReady = 1,
        Complete = 2,
        Acknowledge = 3,
        DataEnd = 4,
        DiskError = 5,
    };

    /* Modes flags */
    enum {
        MODE_SPEED = 1 << 7,      // 0x80
        MODE_STRSND = 1 << 6,     // 0x40 ADPCM on/off
        MODE_SIZE_2340 = 1 << 5,  // 0x20
        MODE_SIZE_2328 = 1 << 4,  // 0x10
        MODE_SIZE_2048 = 0 << 4,  // 0x00
        MODE_SF = 1 << 3,         // 0x08 channel on/off
        MODE_REPORT = 1 << 2,     // 0x04
        MODE_AUTOPAUSE = 1 << 1,  // 0x02
        MODE_CDDA = 1 << 0,       // 0x01
    };

    /* Status flags */
    enum {
        STATUS_PLAY = 1 << 7,       // 0x80
        STATUS_SEEK = 1 << 6,       // 0x40
        STATUS_READ = 1 << 5,       // 0x20
        STATUS_SHELLOPEN = 1 << 4,  // 0x10
        STATUS_UNKNOWN3 = 1 << 3,   // 0x08
        STATUS_UNKNOWN2 = 1 << 2,   // 0x04
        STATUS_ROTATING = 1 << 1,   // 0x02
        STATUS_ERROR = 1 << 0,      // 0x01
    };

    /* Errors */
    enum {
        ERROR_NOTREADY = 1 << 7,    // 0x80
        ERROR_INVALIDCMD = 1 << 6,  // 0x40
        ERROR_INVALIDARG = 1 << 5,  // 0x20
    };

// 1x = 75 sectors per second
// PCSX::g_emulator.m_psxClockSpeed = 1 sec in the ps
// so (PCSX::g_emulator.m_psxClockSpeed / 75) = m_cdr read time (linuzappz)
#define cdReadTime (PCSX::g_emulator.m_psxClockSpeed / 75)

    enum drive_state {
        DRIVESTATE_STANDBY = 0,
        DRIVESTATE_LID_OPEN,
        DRIVESTATE_RESCAN_CD,
        DRIVESTATE_PREPARE_CD,
        DRIVESTATE_STOPPED,
    };

    // for m_Seeked
    enum seeked_state {
        SEEK_PENDING = 0,
        SEEK_DONE = 1,
    };

    struct CdrStat cdr_stat;

    static constexpr unsigned int msf2sec(const uint8_t *msf) { return ((msf[0] * 60 + msf[1]) * 75) + msf[2]; }
    static constexpr void sec2msf(unsigned int s, uint8_t *msf) {
        msf[0] = s / 75 / 60;
        s = s - msf[0] * 75 * 60;
        msf[1] = s / 75;
        s = s - msf[1] * 75;
        msf[2] = s;
    }
    // for that weird psemu API..
    static constexpr unsigned int fsm2sec(const uint8_t *msf) { return ((msf[2] * 60 + msf[1]) * 75) + msf[0]; }

    static const uint32_t H_SPUirqAddr = 0x1f801da4;
    static const uint32_t H_SPUaddr = 0x1f801da6;
    static const uint32_t H_SPUctrl = 0x1f801daa;
    static const uint32_t H_CDLeft = 0x1f801db0;
    static const uint32_t H_CDRight = 0x1f801db2;

    // interrupt
    inline void CDR_INT(uint32_t eCycle) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_CDR);
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDR].cycle = eCycle;
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDR].sCycle =
            PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle;
    }

    // readInterrupt
    inline void CDREAD_INT(uint32_t eCycle) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_CDREAD);
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDREAD].cycle = eCycle;
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDREAD].sCycle =
            PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle;
    }

    // decodedBufferInterrupt
    inline void CDRDBUF_INT(uint32_t eCycle) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_CDRDBUF);
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRDBUF].cycle = eCycle;
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRDBUF].sCycle =
            PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle;
    }

    // lidSeekInterrupt
    inline void CDRLID_INT(uint32_t eCycle) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_CDRLID);
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRLID].cycle = eCycle;
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRLID].sCycle =
            PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle;
    }

    // playInterrupt
    inline void CDRMISC_INT(uint32_t eCycle) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_CDRPLAY);
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRPLAY].cycle = eCycle;
        PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_CDRPLAY].sCycle =
            PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle;
    }

    inline void StopReading() {
        if (m_Reading) {
            m_Reading = 0;
            PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt &= ~(1 << PCSX::PSXINT_CDREAD);
        }
        m_StatP &= ~(STATUS_READ | STATUS_SEEK);
    }

    inline void StopCdda() {
        if (m_Play) {
            if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingCDDA>() != PCSX::Emulator::CDDA_DISABLED)
                m_iso.stop();
            m_StatP &= ~STATUS_PLAY;
            m_Play = false;
            m_FastForward = 0;
            m_FastBackward = 0;
            PCSX::g_emulator.m_spu->registerCallback(SPUirq);
        }
    }

    inline void SetResultSize(uint8_t size) {
        m_ResultP = 0;
        m_ResultC = size;
        m_ResultReady = 1;
    }

    inline void setIrq(void) {
        if (m_Stat & m_Reg2) psxHu32ref(0x1070) |= SWAP_LE32((uint32_t)0x4);
    }

    void adjustTransferIndex(void) {
        size_t bufSize = 0;

        switch (m_Mode & (MODE_SIZE_2340 | MODE_SIZE_2328)) {
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

        if (m_transferIndex >= bufSize) m_transferIndex -= bufSize;
    }

    // FIXME: do this in SPU instead
    void decodedBufferInterrupt() final {
#if 0
    return;
#endif

        // check dbuf IRQ still active
        if (m_Play == 0) return;
        if ((PCSX::g_emulator.m_spu->readRegister(H_SPUctrl) & 0x40) == 0) return;
        if ((PCSX::g_emulator.m_spu->readRegister(H_SPUirqAddr) * 8) >= 0x800) return;

        // turn off plugin SPU IRQ decoded buffer handling
        PCSX::g_emulator.m_spu->registerCallback(0);

        /*
        Vib Ribbon

        000-3FF = left CDDA
        400-7FF = right CDDA

        Assume IRQ every wrap
        */

        // signal CDDA data ready
        psxHu32ref(0x1070) |= SWAP_LE32((uint32_t)0x200);

        // time for next full buffer
        // CDRDBUF_INT( PCSX::g_emulator.m_psxClockSpeed / 44100 * 0x200 );
        CDRDBUF_INT(PCSX::g_emulator.m_psxClockSpeed / 44100 * 0x100);
    }

    // timing used in this function was taken from tests on real hardware
    // (yes it's slow, but you probably don't want to modify it)
    void lidSeekInterrupt() final {
        switch (m_DriveState) {
            default:
            case DRIVESTATE_STANDBY:
                m_StatP &= ~STATUS_SEEK;

                if (!m_iso.getStatus(&cdr_stat)) return;

                if (cdr_stat.Status & STATUS_SHELLOPEN) {
                    StopCdda();
                    m_DriveState = DRIVESTATE_LID_OPEN;
                    CDRLID_INT(0x800);
                }
                break;

            case DRIVESTATE_LID_OPEN:
                if (!m_iso.getStatus(&cdr_stat)) cdr_stat.Status &= ~STATUS_SHELLOPEN;

                // 02, 12, 10
                if (!(m_StatP & STATUS_SHELLOPEN)) {
                    StopReading();
                    m_StatP |= STATUS_SHELLOPEN;

                    // could generate error irq here, but real hardware
                    // only sometimes does that
                    // (not done when lots of commands are sent?)

                    CDRLID_INT(cdReadTime * 30);
                    break;
                } else if (m_StatP & STATUS_ROTATING) {
                    m_StatP &= ~STATUS_ROTATING;
                } else if (!(cdr_stat.Status & STATUS_SHELLOPEN)) {
                    // closed now
                    CheckCdrom();

                    // m_StatP STATUS_SHELLOPEN is "sticky"
                    // and is only cleared by CdlNop

                    m_DriveState = DRIVESTATE_RESCAN_CD;
                    CDRLID_INT(cdReadTime * 105);
                    break;
                }

                // recheck for close
                CDRLID_INT(cdReadTime * 3);
                break;

            case DRIVESTATE_RESCAN_CD:
                m_StatP |= STATUS_ROTATING;
                m_DriveState = DRIVESTATE_PREPARE_CD;

                // this is very long on real hardware, over 6 seconds
                // make it a bit faster here...
                CDRLID_INT(cdReadTime * 150);
                break;

            case DRIVESTATE_PREPARE_CD:
                m_StatP |= STATUS_SEEK;

                m_DriveState = DRIVESTATE_STANDBY;
                CDRLID_INT(cdReadTime * 26);
                break;
        }
    }

    void Find_CurTrack(const uint8_t *time) {
        int current, sect;

        current = msf2sec(time);

        for (m_CurTrack = 1; m_CurTrack < m_ResultTN[1]; m_CurTrack++) {
            m_iso.getTD(m_CurTrack + 1, m_ResultTD);
            sect = fsm2sec(m_ResultTD);
            if (sect - current >= 150) break;
        }
        CDR_LOG("Find_CurTrack *** %02d %02d\n", m_CurTrack, current);
    }

    void generate_subq(const uint8_t *time) {
        unsigned char start[3], next[3];
        unsigned int this_s, start_s, next_s, pregap;
        int relative_s;

        m_iso.getTD(m_CurTrack, start);
        if (m_CurTrack + 1 <= m_ResultTN[1]) {
            pregap = 150;
            m_iso.getTD(m_CurTrack + 1, next);
        } else {
            // last track - cd size
            pregap = 0;
            next[0] = m_SetSectorEnd[2];
            next[1] = m_SetSectorEnd[1];
            next[2] = m_SetSectorEnd[0];
        }

        this_s = msf2sec(time);
        start_s = fsm2sec(start);
        next_s = fsm2sec(next);

        m_TrackChanged = false;

        if (next_s - this_s < pregap) {
            m_TrackChanged = true;
            m_CurTrack++;
            start_s = next_s;
        }

        m_subq.Index = 1;

        relative_s = this_s - start_s;
        if (relative_s < 0) {
            m_subq.Index = 0;
            relative_s = -relative_s;
        }
        sec2msf(relative_s, m_subq.Relative);

        m_subq.Track = itob(m_CurTrack);
        m_subq.Relative[0] = itob(m_subq.Relative[0]);
        m_subq.Relative[1] = itob(m_subq.Relative[1]);
        m_subq.Relative[2] = itob(m_subq.Relative[2]);
        m_subq.Absolute[0] = itob(time[0]);
        m_subq.Absolute[1] = itob(time[1]);
        m_subq.Absolute[2] = itob(time[2]);
    }

    void ReadTrack(const uint8_t *time) {
        unsigned char tmp[3];
        struct SubQ *subq;
        uint16_t crc;

        tmp[0] = itob(time[0]);
        tmp[1] = itob(time[1]);
        tmp[2] = itob(time[2]);

        if (memcmp(m_Prev, tmp, 3) == 0) return;

        CDR_LOG("ReadTrack *** %02x:%02x:%02x\n", tmp[0], tmp[1], tmp[2]);

        m_suceeded = m_iso.readTrack(tmp);
        memcpy(m_Prev, tmp, 3);

        subq = (struct SubQ *)m_iso.getBufferSub();
        if (subq != NULL && m_CurTrack == 1) {
            crc = calcCrc((uint8_t *)subq + 12, 10);
            if (crc == (((uint16_t)subq->CRC[0] << 8) | subq->CRC[1])) {
                m_subq.Track = subq->TrackNumber;
                m_subq.Index = subq->IndexNumber;
                memcpy(m_subq.Relative, subq->TrackRelativeAddress, 3);
                memcpy(m_subq.Absolute, subq->AbsoluteAddress, 3);
            } else {
                CDR_LOG_IO("subq bad crc @%02x:%02x:%02x\n", tmp[0], tmp[1], tmp[2]);
            }
        } else {
            generate_subq(time);
        }

        CDR_LOG(" -> %02x,%02x %02x:%02x:%02x %02x:%02x:%02x\n", m_subq.Track, m_subq.Index, m_subq.Relative[0],
                m_subq.Relative[1], m_subq.Relative[2], m_subq.Absolute[0], m_subq.Absolute[1], m_subq.Absolute[2]);
    }

    void AddIrqQueue(unsigned short irq, unsigned long ecycle) {
        if (m_Irq != 0) {
            if (irq == m_Irq || irq + 0x100 == m_Irq) {
                m_IrqRepeated = 1;
                CDR_INT(ecycle);
                return;
            }
            CDR_LOG_IO("cdr: override cmd %02x -> %02x\n", m_Irq, irq);
        }

        m_Irq = irq;
        m_eCycle = ecycle;

        CDR_INT(ecycle);
    }

    void cdrPlayInterrupt_Autopause() {
        if ((m_Mode & MODE_AUTOPAUSE) && m_TrackChanged) {
            CDR_LOG("CDDA STOP\n");
            // Magic the Gathering
            // - looping territory cdda

            // ...?
            // m_ResultReady = 1;
            // m_Stat = DataReady;
            m_Stat = DataEnd;
            setIrq();

            StopCdda();
        } else if (m_Mode & MODE_REPORT) {
            m_Result[0] = m_StatP;
            m_Result[1] = m_subq.Track;
            m_Result[2] = m_subq.Index;

            if (m_subq.Absolute[2] & 0x10) {
                m_Result[3] = m_subq.Relative[0];
                m_Result[4] = m_subq.Relative[1] | 0x80;
                m_Result[5] = m_subq.Relative[2];
            } else {
                m_Result[3] = m_subq.Absolute[0];
                m_Result[4] = m_subq.Absolute[1];
                m_Result[5] = m_subq.Absolute[2];
            }

            m_Result[6] = 0;
            m_Result[7] = 0;

            // Rayman: Logo freeze (resultready + dataready)
            m_ResultReady = 1;
            m_Stat = DataReady;

            SetResultSize(8);
            setIrq();
        }
    }

    // also handles seek
    void playInterrupt() final {
        if (m_Seeked == SEEK_PENDING) {
            if (m_Stat) {
                CDRMISC_INT(0x100);
                return;
            }
            SetResultSize(1);
            m_StatP |= STATUS_ROTATING;
            m_StatP &= ~STATUS_SEEK;
            m_Result[0] = m_StatP;
            m_Seeked = SEEK_DONE;
            if (m_Irq == 0) {
                m_Stat = Complete;
                setIrq();
            }

            if (m_SetlocPending) {
                memcpy(m_SetSectorPlay, m_SetSector, 4);
                m_SetlocPending = 0;
            }
            Find_CurTrack(m_SetSectorPlay);
            ReadTrack(m_SetSectorPlay);
            m_TrackChanged = false;
        }

        if (!m_Play) return;
        CDR_LOG("CDDA - %d:%d:%d\n", m_SetSectorPlay[0], m_SetSectorPlay[1], m_SetSectorPlay[2]);
        if (memcmp(m_SetSectorPlay, m_SetSectorEnd, 3) == 0) {
            StopCdda();
            m_TrackChanged = true;
        }

        if (!m_Irq && !m_Stat && (m_Mode & (MODE_AUTOPAUSE | MODE_REPORT))) cdrPlayInterrupt_Autopause();

        if (!m_Play) return;

        if (!m_Muted) {
            m_iso.readCDDA(m_SetSectorPlay[0], m_SetSectorPlay[1], m_SetSectorPlay[2], m_Transfer);

            attenuate((int16_t *)m_Transfer, CD_FRAMESIZE_RAW / 4, 1);
            PCSX::g_emulator.m_spu->playCDDAchannel((short *)m_Transfer, CD_FRAMESIZE_RAW);
        }

        m_SetSectorPlay[2]++;
        if (m_SetSectorPlay[2] == 75) {
            m_SetSectorPlay[2] = 0;
            m_SetSectorPlay[1]++;
            if (m_SetSectorPlay[1] == 60) {
                m_SetSectorPlay[1] = 0;
                m_SetSectorPlay[0]++;
            }
        }

        CDRMISC_INT(cdReadTime);

        // update for CdlGetlocP/autopause
        generate_subq(m_SetSectorPlay);
    }

    void interrupt() final {
        uint16_t Irq = m_Irq;
        int no_busy_error = 0;
        int start_rotating = 0;
        int error = 0;
        int delay;

        // Reschedule IRQ
        if (m_Stat) {
            CDR_INT(0x100);
            return;
        }

        m_Ctrl &= ~0x80;

        // default response
        SetResultSize(1);
        m_Result[0] = m_StatP;
        m_Stat = Acknowledge;

        if (m_IrqRepeated) {
            m_IrqRepeated = 0;
            if (m_eCycle > PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle) {
                CDR_INT(m_eCycle);
                goto finish;
            }
        }

        m_Irq = 0;
        CDR_LOG("CDRINT %x %x %x %x\n", m_Seeked, m_Stat, Irq, m_IrqRepeated);
        switch (Irq) {
            case CdlSync:
                // TOOD: sometimes/always return error?
                break;

            case CdlNop:
                if (m_DriveState != DRIVESTATE_LID_OPEN) m_StatP &= ~STATUS_SHELLOPEN;
                no_busy_error = 1;
                break;

            case CdlSetloc:
                break;

            do_CdlPlay:
            case CdlPlay:
                StopCdda();
                if (m_Seeked == SEEK_PENDING) {
                    // XXX: wrong, should seek instead..
                    m_Seeked = SEEK_DONE;
                }
                if (m_SetlocPending) {
                    memcpy(m_SetSectorPlay, m_SetSector, 4);
                    m_SetlocPending = 0;
                }

                // BIOS CD Player
                // - Pause player, hit Track 01/02/../xx (Setloc issued!!)

                if (m_ParamC == 0 || m_Param[0] == 0) {
                    CDR_LOG("PLAY Resume @ %d:%d:%d\n", m_SetSectorPlay[0], m_SetSectorPlay[1], m_SetSectorPlay[2]);
                } else {
                    int track = btoi(m_Param[0]);

                    if (track <= m_ResultTN[1]) m_CurTrack = track;

                    CDR_LOG("PLAY track %d\n", m_CurTrack);

                    if (m_iso.getTD((uint8_t)m_CurTrack, m_ResultTD)) {
                        m_SetSectorPlay[0] = m_ResultTD[2];
                        m_SetSectorPlay[1] = m_ResultTD[1];
                        m_SetSectorPlay[2] = m_ResultTD[0];
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
                Find_CurTrack(m_SetSectorPlay);
                ReadTrack(m_SetSectorPlay);
                m_TrackChanged = false;

                if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingCDDA>() != PCSX::Emulator::CDDA_DISABLED)
                    m_iso.play(m_SetSectorPlay);

                // Vib Ribbon: gameplay checks flag
                m_StatP &= ~STATUS_SEEK;
                m_Result[0] = m_StatP;

                m_StatP |= STATUS_PLAY;

                // BIOS player - set flag again
                m_Play = true;

                CDRMISC_INT(cdReadTime);
                start_rotating = 1;
                break;

            case CdlForward:
                // TODO: error 80 if stopped
                m_Stat = Complete;

                // GameShark CD Player: Calls 2x + Play 2x
                if (m_FastForward == 0)
                    m_FastForward = 2;
                else
                    m_FastForward++;

                m_FastBackward = 0;
                break;

            case CdlBackward:
                m_Stat = Complete;

                // GameShark CD Player: Calls 2x + Play 2x
                if (m_FastBackward == 0)
                    m_FastBackward = 2;
                else
                    m_FastBackward++;

                m_FastForward = 0;
                break;

            case CdlStandby:
                if (m_DriveState != DRIVESTATE_STOPPED) {
                    error = ERROR_INVALIDARG;
                    goto set_error;
                }
                AddIrqQueue(CdlStandby + 0x100, cdReadTime * 125 / 2);
                start_rotating = 1;
                break;

            case CdlStandby + 0x100:
                m_Stat = Complete;
                break;

            case CdlStop:
                if (m_Play) {
                    // grab time for current track
                    m_iso.getTD((uint8_t)(m_CurTrack), m_ResultTD);

                    m_SetSectorPlay[0] = m_ResultTD[2];
                    m_SetSectorPlay[1] = m_ResultTD[1];
                    m_SetSectorPlay[2] = m_ResultTD[0];
                }

                StopCdda();
                StopReading();

                delay = 0x800;
                if (m_DriveState == DRIVESTATE_STANDBY) delay = cdReadTime * 30 / 2;

                m_DriveState = DRIVESTATE_STOPPED;
                AddIrqQueue(CdlStop + 0x100, delay);
                break;

            case CdlStop + 0x100:
                m_StatP &= ~STATUS_ROTATING;
                m_Result[0] = m_StatP;
                m_Stat = Complete;
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
                m_Ctrl |= 0x80;
                break;

            case CdlPause + 0x100:
                m_StatP &= ~STATUS_READ;
                m_Result[0] = m_StatP;
                m_Stat = Complete;
                break;

            case CdlInit:
                AddIrqQueue(CdlInit + 0x100, cdReadTime * 6);
                no_busy_error = 1;
                start_rotating = 1;
                break;

            case CdlInit + 0x100:
                m_Stat = Complete;
                break;

            case CdlMute:
                m_Muted = true;
                break;

            case CdlDemute:
                m_Muted = false;
                break;

            case CdlSetfilter:
                m_File = m_Param[0];
                m_Channel = m_Param[1];
                break;

            case CdlSetmode:
                no_busy_error = 1;
                break;

            case CdlGetmode:
                SetResultSize(6);
                m_Result[1] = m_Mode;
                m_Result[2] = m_File;
                m_Result[3] = m_Channel;
                m_Result[4] = 0;
                m_Result[5] = 0;
                no_busy_error = 1;
                break;

            case CdlGetlocL:
                SetResultSize(8);
                memcpy(m_Result, m_Transfer, 8);
                break;

            case CdlGetlocP:
                SetResultSize(8);
                memcpy(&m_Result, &m_subq, 8);

                if (!m_Play && m_iso.CheckSBI(m_Result + 5)) memset(m_Result + 2, 0, 6);
                if (!m_Play && !m_Reading) m_Result[1] = 0;  // HACK?
                break;

            case CdlReadT:  // SetSession?
                // really long
                AddIrqQueue(CdlReadT + 0x100, cdReadTime * 290 / 4);
                start_rotating = 1;
                break;

            case CdlReadT + 0x100:
                m_Stat = Complete;
                break;

            case CdlGetTN:
                SetResultSize(3);
                if (!m_iso.getTN(m_ResultTN)) {
                    m_Stat = DiskError;
                    m_Result[0] |= STATUS_ERROR;
                } else {
                    m_Stat = Acknowledge;
                    m_Result[1] = itob(m_ResultTN[0]);
                    m_Result[2] = itob(m_ResultTN[1]);
                }
                break;

            case CdlGetTD:
                m_Track = btoi(m_Param[0]);
                SetResultSize(4);
                if (!m_iso.getTD(m_Track, m_ResultTD)) {
                    m_Stat = DiskError;
                    m_Result[0] |= STATUS_ERROR;
                } else {
                    m_Stat = Acknowledge;
                    m_Result[0] = m_StatP;
                    m_Result[1] = itob(m_ResultTD[2]);
                    m_Result[2] = itob(m_ResultTD[1]);
                    m_Result[3] = itob(m_ResultTD[0]);
                }
                break;

            case CdlSeekL:
            case CdlSeekP:
                StopCdda();
                StopReading();
                m_StatP |= STATUS_SEEK;

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
                CDRMISC_INT(m_Seeked == SEEK_DONE ? 0x800 : cdReadTime * 4);
                m_Seeked = SEEK_PENDING;
                start_rotating = 1;
                break;

            case CdlTest:
                switch (m_Param[0]) {
                    case 0x20:  // System Controller ROM Version
                        SetResultSize(4);
                        memcpy(m_Result, Test20, 4);
                        break;
                    case 0x22:
                        SetResultSize(8);
                        memcpy(m_Result, Test22, 4);
                        break;
                    case 0x23:
                    case 0x24:
                        SetResultSize(8);
                        memcpy(m_Result, Test23, 4);
                        break;
                }
                no_busy_error = 1;
                break;

            case CdlID:
                AddIrqQueue(CdlID + 0x100, 20480);
                break;

            case CdlID + 0x100:
                SetResultSize(8);
                m_Result[0] = m_StatP;
                m_Result[1] = 0;
                m_Result[2] = 0;
                m_Result[3] = 0;

                // 0x10 - audio | 0x40 - disk missing | 0x80 - unlicensed
                if (!m_iso.getStatus(&cdr_stat) || cdr_stat.Type == 0 || cdr_stat.Type == 0xff) {
                    m_Result[1] = 0xc0;
                } else {
                    if (cdr_stat.Type == 2) m_Result[1] |= 0x10;
                    if (PCSX::g_emulator.m_cdromId[0] == '\0') m_Result[1] |= 0x80;
                }
                m_Result[0] |= (m_Result[1] >> 4) & 0x08;

                strncpy((char *)&m_Result[4], "PCSX", 4);
                m_Stat = Complete;
                break;

            case CdlReset:
                // yes, it really sets STATUS_SHELLOPEN
                m_StatP |= STATUS_SHELLOPEN;
                m_DriveState = DRIVESTATE_RESCAN_CD;
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
                m_Stat = Complete;
                no_busy_error = 1;
                break;

            case CdlReadN:
            case CdlReadS:
                if (m_SetlocPending) {
                    memcpy(m_SetSectorPlay, m_SetSector, 4);
                    m_SetlocPending = 0;
                }
                Find_CurTrack(m_SetSectorPlay);

                if ((m_Mode & MODE_CDDA) && m_CurTrack > 1)
                    // Read* acts as play for cdda tracks in cdda mode
                    goto do_CdlPlay;

                m_Reading = 1;
                m_FirstSector = 1;

                // Fighting Force 2 - update m_subq time immediately
                // - fixes new game
                ReadTrack(m_SetSectorPlay);

                // Crusaders of Might and Magic - update getlocl now
                // - fixes cutscene speech
                {
                    uint8_t *buf = m_iso.getBuffer();
                    if (buf != NULL) memcpy(m_Transfer, buf, 8);
                }

                /*
                Duke Nukem: Land of the Babes - seek then delay read for one frame
                - fixes cutscenes
                C-12 - Final Resistance - doesn't like seek
                */

                if (m_Seeked != SEEK_DONE) {
                    m_StatP |= STATUS_SEEK;
                    m_StatP &= ~STATUS_READ;

                    // Crusaders of Might and Magic - use short time
                    // - fix cutscene speech (startup)

                    // ??? - use more accurate seek time later
                    CDREAD_INT((m_Mode & 0x80) ? (cdReadTime) : cdReadTime * 2);
                } else {
                    m_StatP |= STATUS_READ;
                    m_StatP &= ~STATUS_SEEK;

                    CDREAD_INT((m_Mode & 0x80) ? (cdReadTime) : cdReadTime * 2);
                }

                m_Result[0] = m_StatP;
                start_rotating = 1;
                break;

            default:
                CDR_LOG("Invalid command: %02x\n", Irq);
                error = ERROR_INVALIDCMD;
                // FALLTHROUGH

            set_error:
                SetResultSize(2);
                m_Result[0] = m_StatP | STATUS_ERROR;
                m_Result[1] = error;
                m_Stat = DiskError;
                break;
        }

        if (m_DriveState == DRIVESTATE_STOPPED && start_rotating) {
            m_DriveState = DRIVESTATE_STANDBY;
            m_StatP |= STATUS_ROTATING;
        }

        if (!no_busy_error) {
            switch (m_DriveState) {
                case DRIVESTATE_LID_OPEN:
                case DRIVESTATE_RESCAN_CD:
                case DRIVESTATE_PREPARE_CD:
                    SetResultSize(2);
                    m_Result[0] = m_StatP | STATUS_ERROR;
                    m_Result[1] = ERROR_NOTREADY;
                    m_Stat = DiskError;
                    break;
            }
        }

    finish:
        setIrq();
        m_ParamC = 0;

        {
            CDR_LOG_IO("CDR IRQ %d cmd %02x stat %02x: ", !!(m_Stat & m_Reg2), Irq, m_Stat);
            for (int i = 0; i < m_ResultC; i++) CDR_LOG_IO("%02x ", m_Result[i]);
            CDR_LOG_IO("\n");
        }
    }

    static constexpr inline int ssat32_to_16(int v) {
        if (v < -32768) {
            v = -32768;
        } else if (v > 32767) {
            v = 32767;
        }
        return v;
    }

    void attenuate(int16_t *buf, int samples, int stereo) final {
        int i, l, r;
        int ll = m_AttenuatorLeftToLeft;
        int lr = m_AttenuatorLeftToRight;
        int rl = m_AttenuatorRightToLeft;
        int rr = m_AttenuatorRightToRight;

        if (lr == 0 && rl == 0 && 0x78 <= ll && ll <= 0x88 && 0x78 <= rr && rr <= 0x88) return;

        if (!stereo && ll == 0x40 && lr == 0x40 && rl == 0x40 && rr == 0x40) return;

        if (stereo) {
            for (i = 0; i < samples; i++) {
                l = buf[i * 2];
                r = buf[i * 2 + 1];
                l = (l * ll + r * rl) >> 7;
                r = (r * rr + l * lr) >> 7;
                buf[i * 2] = ssat32_to_16(l);
                buf[i * 2 + 1] = ssat32_to_16(r);
            }
        } else {
            for (i = 0; i < samples; i++) {
                l = buf[i];
                l = l * (ll + rl) >> 7;
                buf[i] = ssat32_to_16(l);
            }
        }
    }

    void readInterrupt() final {
        uint8_t *buf;

        if (!m_Reading) return;

        if (m_Irq || m_Stat) {
            CDREAD_INT(0x100);
            return;
        }

        if ((psxHu32ref(0x1070) & psxHu32ref(0x1074) & SWAP_LE32((uint32_t)0x4)) && !m_ReadRescheduled) {
            // HACK: with PCSX::Emulator::BIAS 2, emulated CPU is often slower than real thing,
            // game may be unfinished with prev data read, so reschedule
            // (Brave Fencer Musashi)
            CDREAD_INT(cdReadTime / 2);
            m_ReadRescheduled = 1;
            return;
        }

        m_OCUP = 1;
        SetResultSize(1);
        m_StatP |= STATUS_READ | STATUS_ROTATING;
        m_StatP &= ~STATUS_SEEK;
        m_Result[0] = m_StatP;
        m_Seeked = SEEK_DONE;

        ReadTrack(m_SetSectorPlay);

        buf = m_iso.getBuffer();
        if (buf == NULL) m_suceeded = false;

        if (!m_suceeded) {
            CDR_LOG("readInterrupt() Log: err\n");
            memset(m_Transfer, 0, DATA_SIZE);
            m_Stat = DiskError;
            m_Result[0] |= STATUS_ERROR;
            CDREAD_INT((m_Mode & 0x80) ? (cdReadTime / 2) : cdReadTime);
            return;
        }

        memcpy(m_Transfer, buf, DATA_SIZE);
        m_ppf.CheckPPFCache(m_Transfer, m_Prev[0], m_Prev[1], m_Prev[2]);

        CDR_LOG("readInterrupt() Log: cdr.m_Transfer %x:%x:%x\n", m_Transfer[0], m_Transfer[1], m_Transfer[2]);

        if ((!m_Muted) && (m_Mode & MODE_STRSND) && (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingXa>()) &&
            (m_FirstSector != -1)) {  // CD-XA
            // Firemen 2: Multi-XA files - briefings, cutscenes
            if (m_FirstSector == 1 && (m_Mode & MODE_SF) == 0) {
                m_File = m_Transfer[4 + 0];
                m_Channel = m_Transfer[4 + 1];
            }

            if ((m_Transfer[4 + 2] & 0x4) && (m_Transfer[4 + 1] == m_Channel) && (m_Transfer[4 + 0] == m_File)) {
                int ret = xa_decode_sector(&m_Xa, m_Transfer + 4, m_FirstSector);
                if (!ret) {
                    attenuate(m_Xa.pcm, m_Xa.nsamples, m_Xa.stereo);
                    PCSX::g_emulator.m_spu->playADPCMchannel(&m_Xa);
                    m_FirstSector = 0;
                } else
                    m_FirstSector = -1;
            }
        }

        m_SetSectorPlay[2]++;
        if (m_SetSectorPlay[2] == 75) {
            m_SetSectorPlay[2] = 0;
            m_SetSectorPlay[1]++;
            if (m_SetSectorPlay[1] == 60) {
                m_SetSectorPlay[1] = 0;
                m_SetSectorPlay[0]++;
            }
        }

        m_Read = 0;
        m_ReadRescheduled = 0;

        CDREAD_INT((m_Mode & MODE_SPEED) ? (cdReadTime / 2) : cdReadTime);

        /*
        Croc 2: $40 - only FORM1 (*)
        Judge Dredd: $C8 - only FORM1 (*)
        Sim Theme Park - no adpcm at all (zero)
        */

        if (!(m_Mode & MODE_STRSND) || !(m_Transfer[4 + 2] & 0x4)) {
            m_Stat = DataReady;
            setIrq();
        }

        // update for CdlGetlocP
        ReadTrack(m_SetSectorPlay);
    }

    /*
    read0:
            bit 0,1 - mode
            bit 2 - unknown
            bit 3 - unknown
            bit 4 - unknown
            bit 5 - 1 result ready
            bit 6 - 1 dma ready
            bit 7 - 1 command being processed
    */

    uint8_t read0(void) final {
        if (m_ResultReady)
            m_Ctrl |= 0x20;
        else
            m_Ctrl &= ~0x20;

        if (m_OCUP) m_Ctrl |= 0x40;
        //  else
        //      m_Ctrl &= ~0x40;

        // What means the 0x10 and the 0x08 bits? I only saw it used by the bios
        m_Ctrl |= 0x18;

        CDR_LOG_IO("cdr r0: %02x\n", m_Ctrl);
        return psxHu8(0x1800) = m_Ctrl;
    }

    void write0(uint8_t rt) final {
        CDR_LOG_IO("cdr w0: %02x\n", rt);
        m_Ctrl = (rt & 3) | (m_Ctrl & ~3);
    }

    uint8_t read1(void) final {
        if ((m_ResultP & 0xf) < m_ResultC)
            psxHu8(0x1801) = m_Result[m_ResultP & 0xf];
        else
            psxHu8(0x1801) = 0;
        m_ResultP++;
        if (m_ResultP == m_ResultC) m_ResultReady = 0;
        CDR_LOG_IO("cdr r1: %02x\n", psxHu8(0x1801));
        return psxHu8(0x1801);
    }

    void write1(uint8_t rt) final {
        uint8_t set_loc[3];
        int i;
        CDR_LOG_IO("cdr w1: %02x\n", rt);
        switch (m_Ctrl & 3) {
            case 0:
                break;
            case 3:
                m_AttenuatorRightToRightT = rt;
                return;
            default:
                return;
        }

        m_Cmd = rt;
        m_OCUP = 0;

        CDR_LOG_IO("CD1 write: %x (%s)", rt, CmdName[rt]);
        if (m_ParamC) {
            CDR_LOG_IO(" Param[%d] = {", m_ParamC);
            for (i = 0; i < m_ParamC; i++) CDR_LOG_IO(" %x,", m_Param[i]);
            CDR_LOG_IO("}\n");
        } else {
            CDR_LOG_IO("\n");
        }

        m_ResultReady = 0;
        m_Ctrl |= 0x80;
        // m_Stat = NoIntr;
        AddIrqQueue(m_Cmd, 0x800);

        switch (m_Cmd) {
            case CdlSetloc:
                for (i = 0; i < 3; i++) set_loc[i] = btoi(m_Param[i]);

                i = msf2sec(m_SetSectorPlay);
                i = abs(i - (int)msf2sec(set_loc));
                if (i > 16) m_Seeked = SEEK_PENDING;

                memcpy(m_SetSector, set_loc, 3);
                m_SetSector[3] = 0;
                m_SetlocPending = 1;
                break;

            case CdlReadN:
            case CdlReadS:
            case CdlPause:
                StopCdda();
                StopReading();
                break;

            case CdlReset:
            case CdlInit:
                m_Seeked = SEEK_DONE;
                StopCdda();
                StopReading();
                break;

            case CdlSetmode:
                CDR_LOG("write1() Log: Setmode %x\n", m_Param[0]);
                m_Mode = m_Param[0];

                // Squaresoft on PlayStation 1998 Collector's CD Vol. 1
                // - fixes choppy movie sound
                if (m_Play && (m_Mode & MODE_CDDA) == 0) StopCdda();
                break;
        }
    }

    uint8_t read2(void) final {
        unsigned char ret;

        if (m_Read == 0) {
            ret = 0;
        } else {
            ret = m_Transfer[m_transferIndex];
            m_transferIndex++;
            adjustTransferIndex();
        }
        CDR_LOG_IO("cdr r2: %02x\n", ret);
        return ret;
    }

    void write2(uint8_t rt) final {
        CDR_LOG_IO("cdr w2: %02x\n", rt);
        switch (m_Ctrl & 3) {
            case 0:
                if (m_ParamC < 8)  // FIXME: size and wrapping
                    m_Param[m_ParamC++] = rt;
                return;
            case 1:
                m_Reg2 = rt;
                setIrq();
                return;
            case 2:
                m_AttenuatorLeftToLeftT = rt;
                return;
            case 3:
                m_AttenuatorRightToLeftT = rt;
                return;
        }
    }

    uint8_t read3(void) final {
        if (m_Ctrl & 0x1)
            psxHu8(0x1803) = m_Stat | 0xE0;
        else
            psxHu8(0x1803) = m_Reg2 | 0xE0;
        CDR_LOG_IO("cdr r3: %02x\n", psxHu8(0x1803));
        return psxHu8(0x1803);
    }

    void write3(uint8_t rt) final {
        CDR_LOG_IO("cdr w3: %02x\n", rt);
        switch (m_Ctrl & 3) {
            case 0:
                break;  // transfer
            case 1:
                m_Stat &= ~rt;

                if (rt & 0x40) m_ParamC = 0;
                return;
            case 2:
                m_AttenuatorLeftToRightT = rt;
                return;
            case 3:
                if (rt & 0x20) {
                    memcpy(&m_AttenuatorLeftToLeft, &m_AttenuatorLeftToLeftT, 4);
                    CDR_LOG_IO("CD-XA Volume: %02x %02x | %02x %02x\n", m_AttenuatorLeftToLeft, m_AttenuatorLeftToRight,
                               m_AttenuatorRightToLeft, m_AttenuatorRightToRight);
                }
                return;
        }

        if ((rt & 0x80) && m_Read == 0) {
            m_Read = 1;
            m_transferIndex = 0;

            switch (m_Mode & (MODE_SIZE_2340 | MODE_SIZE_2328)) {
                case MODE_SIZE_2328:
                case MODE_SIZE_2048:
                    m_transferIndex += 12;
                    break;

                case MODE_SIZE_2340:
                    m_transferIndex += 0;
                    break;

                default:
                    break;
            }
        }
    }

    void dma(uint32_t madr, uint32_t bcr, uint32_t chcr) final {
        uint32_t cdsize;
        unsigned i;
        uint8_t *ptr;

        CDR_LOG("dma() Log: *** DMA 3 *** %x addr = %x size = %x\n", chcr, madr, bcr);

        switch (chcr) {
            case 0x11000000:
            case 0x11400100:
                if (m_Read == 0) {
                    CDR_LOG("dma() Log: *** DMA 3 *** NOT READY\n");
                    break;
                }

                cdsize = (bcr & 0xffff) * 4;

                // Ape Escape: bcr = 0001 / 0000
                // - fix boot
                if (cdsize == 0) {
                    switch (m_Mode & (MODE_SIZE_2340 | MODE_SIZE_2328)) {
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
                    CDR_LOG("dma() Log: *** DMA 3 *** NULL Pointer!\n");
                    break;
                }

                /*
                GS CDX: Enhancement CD crash
                - Setloc 0:0:0
                - CdlPlay
                - Spams DMA3 and gets buffer overrun
                */
                for (i = 0; i < cdsize; ++i) {
                    ptr[i] = m_Transfer[m_transferIndex];
                    m_transferIndex++;
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
                CDR_LOG("dma() Log: Unknown cddma %x\n", chcr);
                break;
        }

        HW_DMA3_CHCR &= SWAP_LE32(~0x01000000);
        DMA_INTERRUPT(3);
    }

    void dmaInterrupt() final {
        if (HW_DMA3_CHCR & SWAP_LE32(0x01000000)) {
            HW_DMA3_CHCR &= SWAP_LE32(~0x01000000);
            DMA_INTERRUPT(3);
        }
    }

    void getCdInfo(void) {
        uint8_t tmp;

        m_iso.getTN(m_ResultTN);
        m_iso.getTD(0, m_SetSectorEnd);
        tmp = m_SetSectorEnd[0];
        m_SetSectorEnd[0] = m_SetSectorEnd[2];
        m_SetSectorEnd[2] = tmp;
    }

    void reset() final {
        m_OCUP = 0;
        m_Reg1Mode = 0;
        m_CmdProcess = 0;
        m_Ctrl = 0;

        memset(m_Transfer, 0, sizeof(m_Transfer));

        memset(m_Prev, 0, sizeof(m_Prev));
        memset(m_Param, 0, sizeof(m_Param));
        memset(m_Result, 0, sizeof(m_Result));

        m_ParamC = 0;
        m_ParamP = 0;
        m_ResultC = 0;
        m_ResultP = 0;
        m_ResultReady = 0;
        m_Cmd = 0;
        m_Read = 0;
        m_SetlocPending = 0;
        m_Reading = 0;

        memset(m_ResultTN, 0, sizeof(m_ResultTN));
        memset(m_ResultTD, 0, sizeof(m_ResultTD));
        memset(m_SetSectorPlay, 0, sizeof(m_SetSectorPlay));
        memset(m_SetSectorEnd, 0, sizeof(m_SetSectorEnd));
        memset(m_SetSector, 0, sizeof(m_SetSector));
        m_Track = 0;
        m_Play = false;
        m_Muted = false;
        m_Mode = 0;
        m_suceeded = true;
        m_FirstSector = 0;

        memset(&m_Xa, 0, sizeof(m_Xa));

        m_Irq = 0;
        m_IrqRepeated = 0;
        m_eCycle = 0;

        m_Seeked = 0;
        m_ReadRescheduled = 0;

        m_FastForward = 0;
        m_FastBackward = 0;

        m_AttenuatorLeftToLeftT = 0;
        m_AttenuatorLeftToRightT = 0;
        m_AttenuatorRightToRightT = 0;
        m_AttenuatorRightToLeftT = 0;

        m_subq.Index = 0;
        m_subq.Relative[0] = 0;
        m_subq.Relative[1] = 0;
        m_subq.Relative[2] = 0;
        m_subq.Absolute[0] = 0;
        m_subq.Absolute[1] = 0;
        m_subq.Absolute[2] = 0;
        m_TrackChanged = false;

        m_CurTrack = 1;
        m_File = 1;
        m_Channel = 1;
        m_transferIndex = 0;
        m_Reg2 = 0x1f;
        m_Stat = NoIntr;
        m_DriveState = DRIVESTATE_STANDBY;
        m_StatP = STATUS_ROTATING;

        // BIOS player - default values
        m_AttenuatorLeftToLeft = 0x80;
        m_AttenuatorLeftToRight = 0x00;
        m_AttenuatorRightToLeft = 0x00;
        m_AttenuatorRightToRight = 0x80;

        getCdInfo();
    }

    void load() final {
        getCdInfo();

        // read right sub data
        uint8_t tmpp[3];
        memcpy(tmpp, m_Prev, 3);
        m_Prev[0]++;
        ReadTrack(tmpp);

        if (m_Play) {
            Find_CurTrack(m_SetSectorPlay);
            if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingCDDA>() != PCSX::Emulator::CDDA_DISABLED)
                m_iso.play(m_SetSectorPlay);
        }
    }

    int freeze(gzFile f, int Mode) final {
        uint8_t tmpp[3];

        if (Mode == 0 && PCSX::g_emulator.settings.get<PCSX::Emulator::SettingCDDA>() != PCSX::Emulator::CDDA_DISABLED)
            m_iso.stop();

        // gzfreeze(&m_cdr, sizeof(m_cdr));

        if (Mode == 1) m_ParamP = m_ParamC;

        if (Mode == 0) {
            getCdInfo();

            // read right sub data
            memcpy(tmpp, m_Prev, 3);
            m_Prev[0]++;
            ReadTrack(tmpp);

            if (m_Play) {
                Find_CurTrack(m_SetSectorPlay);
                if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingCDDA>() != PCSX::Emulator::CDDA_DISABLED)
                    m_iso.play(m_SetSectorPlay);
            }
        }

        return 0;
    }

    void lidInterrupt() final {
        getCdInfo();
        StopCdda();
        lidSeekInterrupt();
    }
};

}  // namespace

PCSX::CDRom *PCSX::CDRom::factory() { return new CDRomImpl; }
