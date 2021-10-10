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

#include "core/cdriso.h"
#include "core/debug.h"
#include "core/ppf.h"
#include "core/psxdma.h"
#include "core/psxemulator.h"
#include "magic_enum/include/magic_enum.hpp"
#include "spu/interface.h"

namespace {

class CDRomImpl : public PCSX::CDRom {
    /* CD-ROM magic numbers */
    enum Commands {
        CdlSync = 0,
        CdlGetStat = 1,
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
        CdlGetparam = 15,
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

    static const inline uint8_t Test04[] = {0};
    static const inline uint8_t Test05[] = {0};
    static const inline uint8_t Test20[] = {0x98, 0x06, 0x10, 0xC3};
    static const inline uint8_t Test22[] = {0x66, 0x6F, 0x72, 0x20, 0x45, 0x75, 0x72, 0x6F};
    static const inline uint8_t Test23[] = {0x43, 0x58, 0x44, 0x32, 0x39, 0x34, 0x30, 0x51};
    static const unsigned irqReschedule = 0x100;

    // m_stat:
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
// PCSX::g_emulator->m_psxClockSpeed = 1 sec in the ps
// so (PCSX::g_emulator->m_psxClockSpeed / 75) = m_cdr read time (linuzappz)
#define cdReadTime (PCSX::g_emulator->m_psxClockSpeed / 75)

    enum drive_state {
        DRIVESTATE_STANDBY = 0,
        DRIVESTATE_LID_OPEN,
        DRIVESTATE_RESCAN_CD,
        DRIVESTATE_PREPARE_CD,
        DRIVESTATE_STOPPED,
    };

    // for m_seeked
    enum seeked_state {
        SEEK_PENDING = 0,
        SEEK_DONE = 1,
    };

    struct PCSX::CdrStat cdr_stat;

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
    static inline void scheduleCDIRQ(uint32_t eCycle) {
        PCSX::g_emulator->m_psxCpu->scheduleInterrupt(PCSX::PSXINT_CDR, eCycle);
    }

    // readInterrupt
    static inline void scheduleCDReadIRQ(uint32_t eCycle) {
        PCSX::g_emulator->m_psxCpu->scheduleInterrupt(PCSX::PSXINT_CDREAD, eCycle);
    }

    // decodedBufferInterrupt
    static inline void scheduleDecodeBufferIRQ(uint32_t eCycle) {
        PCSX::g_emulator->m_psxCpu->scheduleInterrupt(PCSX::PSXINT_CDRDBUF, eCycle);
    }

    // lidSeekInterrupt
    static inline void scheduleCDLidIRQ(uint32_t eCycle) {
        PCSX::g_emulator->m_psxCpu->scheduleInterrupt(PCSX::PSXINT_CDRLID, eCycle);
    }

    // playInterrupt
    static inline void scheduleCDPlayIRQ(uint32_t eCycle) {
        PCSX::g_emulator->m_psxCpu->scheduleInterrupt(PCSX::PSXINT_CDRPLAY, eCycle);
    }

    static inline void scheduleCDDMAIRQ(uint32_t eCycle) {
        PCSX::g_emulator->m_psxCpu->scheduleInterrupt(PCSX::PSXINT_CDRDMA, eCycle);
    }

    inline void StopReading() {
        if (m_reading) {
            m_reading = 0;
            PCSX::g_emulator->m_psxCpu->m_psxRegs.interrupt &= ~(1 << PCSX::PSXINT_CDREAD);
        }
        m_statP &= ~(STATUS_READ | STATUS_SEEK);
    }

    inline void StopCdda() {
        if (m_play) {
            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingCDDA>() != PCSX::Emulator::CDDA_DISABLED) {
                m_iso.stop();
            }
            m_statP &= ~STATUS_PLAY;
            m_play = false;
            m_fastForward = 0;
            m_fastBackward = 0;
            // PCSX::g_emulator->m_spu->registerCallback(SPUirq);
        }
    }

    inline void SetResultSize(uint8_t size) {
        m_resultP = 0;
        m_resultC = size;
        m_resultReady = 1;
    }

    inline void setIrq(void) {
        if (m_stat & m_reg2) psxHu32ref(0x1070) |= SWAP_LE32((uint32_t)0x4);
    }

    void adjustTransferIndex(void) {
        size_t bufSize = 0;

        switch (m_mode & (MODE_SIZE_2340 | MODE_SIZE_2328)) {
            case MODE_SIZE_2340:
                bufSize = 2340;
                break;
            case MODE_SIZE_2328:
                bufSize = 12 + 2328;
                break;
            case MODE_SIZE_2048:
            default:
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
        if (m_play == 0) return;
        if ((PCSX::g_emulator->m_spu->readRegister(H_SPUctrl) & 0x40) == 0) return;
        if ((PCSX::g_emulator->m_spu->readRegister(H_SPUirqAddr) * 8) >= 0x800) return;

        // turn off plugin SPU IRQ decoded buffer handling
        // PCSX::g_emulator->m_spu->registerCallback(0);

        /*
        Vib Ribbon

        000-3FF = left CDDA
        400-7FF = right CDDA

        Assume IRQ every wrap
        */

        // signal CDDA data ready
        psxHu32ref(0x1070) |= SWAP_LE32((uint32_t)0x200);

        // time for next full buffer
        // scheduleDecodeBufferIRQ( PCSX::g_emulator->m_psxClockSpeed / 44100 * 0x200 );
        scheduleDecodeBufferIRQ(PCSX::g_emulator->m_psxClockSpeed / 44100 * 0x100);
    }

    // timing used in this function was taken from tests on real hardware
    // (yes it's slow, but you probably don't want to modify it)
    void lidSeekInterrupt() final {
        switch (m_driveState) {
            default:
            case DRIVESTATE_STANDBY:
                m_statP &= ~STATUS_SEEK;

                if (!m_iso.getStatus(&cdr_stat)) return;

                if (cdr_stat.Status & STATUS_SHELLOPEN) {
                    StopCdda();
                    m_driveState = DRIVESTATE_LID_OPEN;
                    scheduleCDLidIRQ(8 * irqReschedule);
                }
                break;

            case DRIVESTATE_LID_OPEN:
                if (!m_iso.getStatus(&cdr_stat)) cdr_stat.Status &= ~STATUS_SHELLOPEN;

                // 02, 12, 10
                if (!(m_statP & STATUS_SHELLOPEN)) {
                    StopReading();
                    m_statP |= STATUS_SHELLOPEN;

                    // could generate error irq here, but real hardware
                    // only sometimes does that
                    // (not done when lots of commands are sent?)

                    scheduleCDLidIRQ(cdReadTime * 30);
                    break;
                } else if (m_statP & STATUS_ROTATING) {
                    m_statP &= ~STATUS_ROTATING;
                } else if (!(cdr_stat.Status & STATUS_SHELLOPEN)) {
                    // closed now
                    CheckCdrom();

                    // m_statP STATUS_SHELLOPEN is "sticky"
                    // and is only cleared by CdlGetStat

                    m_driveState = DRIVESTATE_RESCAN_CD;
                    scheduleCDLidIRQ(cdReadTime * 105);
                    break;
                }

                // recheck for close
                scheduleCDLidIRQ(cdReadTime * 3);
                break;

            case DRIVESTATE_RESCAN_CD:
                m_statP |= STATUS_ROTATING;
                m_driveState = DRIVESTATE_PREPARE_CD;

                // this is very long on real hardware, over 6 seconds
                // make it a bit faster here...
                scheduleCDLidIRQ(cdReadTime * 150);
                break;

            case DRIVESTATE_PREPARE_CD:
                m_statP |= STATUS_SEEK;

                m_driveState = DRIVESTATE_STANDBY;
                scheduleCDLidIRQ(cdReadTime * 26);
                break;
        }
    }

    void Find_CurTrack(const uint8_t *time) {
        int current, sect;

        current = msf2sec(time);

        for (m_curTrack = 1; m_curTrack < m_resultTN[1]; m_curTrack++) {
            m_iso.getTD(m_curTrack + 1, m_resultTD);
            sect = fsm2sec(m_resultTD);
            if (sect - current >= 150) break;
        }
        CDROM_LOG("Find_CurTrack *** %02d %02d\n", m_curTrack, current);
    }

    void generate_subq(const uint8_t *time) {
        unsigned char start[3], next[3];
        unsigned int this_s, start_s, next_s, pregap;
        int relative_s;

        m_iso.getTD(m_curTrack, start);
        if (m_curTrack + 1 <= m_resultTN[1]) {
            pregap = 150;
            m_iso.getTD(m_curTrack + 1, next);
        } else {
            // last track - cd size
            pregap = 0;
            next[0] = m_setSectorEnd[2];
            next[1] = m_setSectorEnd[1];
            next[2] = m_setSectorEnd[0];
        }

        this_s = msf2sec(time);
        start_s = fsm2sec(start);
        next_s = fsm2sec(next);

        m_trackChanged = false;

        if (next_s - this_s < pregap) {
            m_trackChanged = true;
            m_curTrack++;
            start_s = next_s;
        }

        m_subq.index = 1;

        relative_s = this_s - start_s;
        if (relative_s < 0) {
            m_subq.index = 0;
            relative_s = -relative_s;
        }
        sec2msf(relative_s, m_subq.relative);

        m_subq.track = itob(m_curTrack);
        m_subq.relative[0] = itob(m_subq.relative[0]);
        m_subq.relative[1] = itob(m_subq.relative[1]);
        m_subq.relative[2] = itob(m_subq.relative[2]);
        m_subq.absolute[0] = itob(time[0]);
        m_subq.absolute[1] = itob(time[1]);
        m_subq.absolute[2] = itob(time[2]);
    }

    void ReadTrack(const uint8_t *time) {
        unsigned char tmp[3];
        struct PCSX::SubQ *subq;
        uint16_t crc;

        tmp[0] = itob(time[0]);
        tmp[1] = itob(time[1]);
        tmp[2] = itob(time[2]);

        if (memcmp(m_prev, tmp, 3) == 0) return;

        CDROM_LOG("ReadTrack *** %02x:%02x:%02x\n", tmp[0], tmp[1], tmp[2]);

        m_suceeded = m_iso.readTrack(tmp);
        memcpy(m_prev, tmp, 3);

        subq = (struct PCSX::SubQ *)m_iso.getBufferSub();
        if (subq != NULL && m_curTrack == 1) {
            crc = calcCrc((uint8_t *)subq + 12, 10);
            if (crc == (((uint16_t)subq->CRC[0] << 8) | subq->CRC[1])) {
                m_subq.track = subq->TrackNumber;
                m_subq.index = subq->IndexNumber;
                memcpy(m_subq.relative, subq->TrackRelativeAddress, 3);
                memcpy(m_subq.absolute, subq->AbsoluteAddress, 3);
            } else {
                CDROM_IO_LOG("subq bad crc @%02x:%02x:%02x\n", tmp[0], tmp[1], tmp[2]);
            }
        } else {
            generate_subq(time);
        }

        CDROM_LOG(" -> %02x,%02x %02x:%02x:%02x %02x:%02x:%02x\n", m_subq.track, m_subq.index, m_subq.relative[0],
                  m_subq.relative[1], m_subq.relative[2], m_subq.absolute[0], m_subq.absolute[1], m_subq.absolute[2]);
    }

    void AddIrqQueue(unsigned short irq, unsigned long ecycle) {
        if (m_irq != 0) {
            if (irq == m_irq || irq + 0x100 == m_irq) {
                m_irqRepeated = 1;
                scheduleCDIRQ(ecycle);
                return;
            }
            CDROM_IO_LOG("cdr: override cmd %02x -> %02x\n", m_irq, irq);
        }

        m_irq = irq;
        m_eCycle = ecycle;

        scheduleCDIRQ(ecycle);
    }

    void cdrPlayInterrupt_Autopause() {
        if ((m_mode & MODE_AUTOPAUSE) && m_trackChanged) {
            CDROM_LOG("CDDA STOP\n");
            // Magic the Gathering
            // - looping territory cdda

            // ...?
            // m_resultReady = 1;
            // m_stat = DataReady;
            m_stat = DataEnd;
            setIrq();

            StopCdda();
        } else if (m_mode & MODE_REPORT) {
            m_result[0] = m_statP;
            m_result[1] = m_subq.track;
            m_result[2] = m_subq.index;

            if (m_subq.absolute[2] & 0x10) {
                m_result[3] = m_subq.relative[0];
                m_result[4] = m_subq.relative[1] | 0x80;
                m_result[5] = m_subq.relative[2];
            } else {
                m_result[3] = m_subq.absolute[0];
                m_result[4] = m_subq.absolute[1];
                m_result[5] = m_subq.absolute[2];
            }

            m_result[6] = 0;
            m_result[7] = 0;

            // Rayman: Logo freeze (resultready + dataready)
            m_resultReady = 1;
            m_stat = DataReady;

            SetResultSize(8);
            setIrq();
        }
    }

    // also handles seek
    void playInterrupt() final {
        if (m_seeked == SEEK_PENDING) {
            if (m_stat) {
                scheduleCDPlayIRQ(irqReschedule);
                return;
            }
            SetResultSize(1);
            m_statP |= STATUS_ROTATING;
            m_statP &= ~STATUS_SEEK;
            m_result[0] = m_statP;
            m_seeked = SEEK_DONE;
            if (m_irq == 0) {
                m_stat = Complete;
                m_suceeded = true;
                setIrq();
            }

            if (m_setlocPending) {
                memcpy(m_setSectorPlay, m_setSector, 4);
                m_setlocPending = 0;
                m_locationChanged = true;
            }
            Find_CurTrack(m_setSectorPlay);
            ReadTrack(m_setSectorPlay);
            m_trackChanged = false;
        }

        if (!m_play) return;
        CDROM_LOG("CDDA - %d:%d:%d\n", m_setSectorPlay[0], m_setSectorPlay[1], m_setSectorPlay[2]);
        if (memcmp(m_setSectorPlay, m_setSectorEnd, 3) == 0) {
            StopCdda();
            m_trackChanged = true;
        }

        if (!m_irq && !m_stat && (m_mode & (MODE_AUTOPAUSE | MODE_REPORT))) cdrPlayInterrupt_Autopause();

        if (!m_play) return;

        if (!m_muted) {
            m_iso.readCDDA(m_setSectorPlay[0], m_setSectorPlay[1], m_setSectorPlay[2], m_transfer);

            attenuate((int16_t *)m_transfer, CD_FRAMESIZE_RAW / 4, 1);
            PCSX::g_emulator->m_spu->playCDDAchannel((short *)m_transfer, CD_FRAMESIZE_RAW);
        }

        m_setSectorPlay[2]++;
        if (m_setSectorPlay[2] == 75) {
            m_setSectorPlay[2] = 0;
            m_setSectorPlay[1]++;
            if (m_setSectorPlay[1] == 60) {
                m_setSectorPlay[1] = 0;
                m_setSectorPlay[0]++;
            }
        }

        if (m_locationChanged) {
            scheduleCDPlayIRQ(cdReadTime * 30);
            m_locationChanged = false;
        } else {
            scheduleCDPlayIRQ(cdReadTime);
        }

        // update for CdlGetlocP/autopause
        generate_subq(m_setSectorPlay);
    }

    void interrupt() final {
        uint16_t irq = m_irq;
        int no_busy_error = 0;
        int start_rotating = 0;
        int error = 0;
        int delay;

        // Reschedule IRQ
        if (m_stat) {
            scheduleCDIRQ(irqReschedule);
            return;
        }

        m_ctrl &= ~0x80;

        // default response
        SetResultSize(1);
        m_result[0] = m_statP;
        m_stat = Acknowledge;

        if (m_irqRepeated) {
            m_irqRepeated = 0;
            if (m_eCycle > PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle) {
                scheduleCDIRQ(m_eCycle);
                goto finish;
            }
        }

        m_irq = 0;
        CDROM_IO_LOG("CDRINT %x %x %x %x\n", m_seeked, m_stat, irq, m_irqRepeated);
        if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                .get<PCSX::Emulator::DebugSettings::LoggingCDROM>()) {
            logCDROM(irq);
        }

        switch (irq) {
            case CdlGetStat:
                if (m_driveState != DRIVESTATE_LID_OPEN) m_statP &= ~STATUS_SHELLOPEN;
                no_busy_error = 1;
                break;

            case CdlSetloc:
                break;

            do_CdlPlay:
            case CdlPlay:
                StopCdda();
                if (m_seeked == SEEK_PENDING) {
                    // XXX: wrong, should seek instead..
                    m_seeked = SEEK_DONE;
                }
                if (m_setlocPending) {
                    memcpy(m_setSectorPlay, m_setSector, 4);
                    m_setlocPending = 0;
                    m_locationChanged = true;
                }

                // BIOS CD Player
                // - Pause player, hit Track 01/02/../xx (Setloc issued!!)

                if (m_paramC == 0 || m_param[0] == 0) {
                    CDROM_LOG("PLAY Resume @ %d:%d:%d\n", m_setSectorPlay[0], m_setSectorPlay[1], m_setSectorPlay[2]);
                } else {
                    int track = btoi(m_param[0]);

                    if (track <= m_resultTN[1]) m_curTrack = track;

                    CDROM_LOG("PLAY track %d\n", m_curTrack);

                    if (m_iso.getTD((uint8_t)m_curTrack, m_resultTD)) {
                        m_setSectorPlay[0] = m_resultTD[2];
                        m_setSectorPlay[1] = m_resultTD[1];
                        m_setSectorPlay[2] = m_resultTD[0];
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
                Find_CurTrack(m_setSectorPlay);
                ReadTrack(m_setSectorPlay);
                m_trackChanged = false;

                if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingCDDA>() != PCSX::Emulator::CDDA_DISABLED) {
                    m_iso.play(m_setSectorPlay);
                }

                // Vib Ribbon: gameplay checks flag
                m_statP &= ~STATUS_SEEK;
                m_result[0] = m_statP;

                m_statP |= STATUS_PLAY;

                // BIOS player - set flag again
                m_play = true;

                scheduleCDPlayIRQ(cdReadTime);
                start_rotating = 1;
                break;

            case CdlForward:
                // TODO: error 80 if stopped
                m_stat = Complete;
                m_suceeded = true;

                // GameShark CD Player: Calls 2x + Play 2x
                if (m_fastForward == 0) {
                    m_fastForward = 2;
                } else {
                    m_fastForward++;
                }

                m_fastBackward = 0;
                break;

            case CdlBackward:
                m_stat = Complete;
                m_suceeded = true;

                // GameShark CD Player: Calls 2x + Play 2x
                if (m_fastBackward == 0) {
                    m_fastBackward = 2;
                } else {
                    m_fastBackward++;
                }

                m_fastForward = 0;
                break;

            case CdlStandby:
                if (m_driveState != DRIVESTATE_STOPPED) {
                    error = ERROR_INVALIDARG;
                    goto set_error;
                }
                AddIrqQueue(CdlStandby + 0x100, cdReadTime * 125 / 2);
                start_rotating = 1;
                break;

            case CdlStandby + 0x100:
                m_stat = Complete;
                m_suceeded = true;
                break;

            case CdlStop:
                if (m_play) {
                    // grab time for current track
                    m_iso.getTD((uint8_t)(m_curTrack), m_resultTD);

                    m_setSectorPlay[0] = m_resultTD[2];
                    m_setSectorPlay[1] = m_resultTD[1];
                    m_setSectorPlay[2] = m_resultTD[0];
                }

                StopCdda();
                StopReading();

                delay = 0x800;
                if (m_driveState == DRIVESTATE_STANDBY) delay = cdReadTime * 30 / 2;

                m_driveState = DRIVESTATE_STOPPED;
                AddIrqQueue(CdlStop + 0x100, delay);
                break;

            case CdlStop + 0x100:
                m_statP &= ~STATUS_ROTATING;
                m_result[0] = m_statP;
                m_stat = Complete;
                m_suceeded = true;
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
                /*
                * Gameblabla -
                * The timings are based on hardware tests and were taken from Duckstation.
                * A couple of notes :
                * Gundam Battle Assault 2 in PAL mode (this includes the PAL release) needs a high enough delay
                * if not, the game will either crash after the FMV intro or upon starting a new game.
                * 
                */
                if (m_driveState == DRIVESTATE_STANDBY)
                {
                    /* Gameblabla -
                    * Dead or Alive needs this condition and a shorter delay otherwise : if you pause ingame, music will not resume. */
                    delay = 7000;
				}
				else
				{
                    delay = (((m_mode & MODE_SPEED) ? 2 : 1) * (1000000));
                    scheduleCDPlayIRQ((m_mode & MODE_SPEED) ? cdReadTime / 2 : cdReadTime);
				}
                AddIrqQueue(CdlPause + 0x100, delay);
                m_ctrl |= 0x80;
                break;

            case CdlPause + 0x100:
                m_statP &= ~STATUS_READ;
                m_result[0] = m_statP;
                m_stat = Complete;
                m_suceeded = true;
                break;

            case CdlInit:
                AddIrqQueue(CdlInit + 0x100, cdReadTime * 6);
                no_busy_error = 1;
                start_rotating = 1;
                break;

            case CdlInit + 0x100:
                m_stat = Complete;
                m_suceeded = true;
                break;

            case CdlMute:
                m_muted = true;
                break;

            case CdlDemute:
                m_muted = false;
                break;

            case CdlSetfilter:
                m_file = m_param[0];
                m_channel = m_param[1];
                break;

            case CdlSetmode:
                no_busy_error = 1;
                break;

            case CdlGetparam:
                SetResultSize(5);
                m_result[1] = m_mode;
                m_result[2] = 0;
                m_result[3] = m_file;
                m_result[4] = m_channel;
                no_busy_error = 1;
                break;

            case CdlGetlocL:
                SetResultSize(8);
                memcpy(m_result, m_transfer, 8);
                break;

            case CdlGetlocP:
                SetResultSize(8);
                memcpy(&m_result, &m_subq, 8);

                if (!m_play && m_iso.CheckSBI(m_result + 5)) memset(m_result + 2, 0, 6);
                if (!m_play && !m_reading) m_result[1] = 0;  // HACK?
                break;

            case CdlReadT:  // SetSession?
                // really long
                AddIrqQueue(CdlReadT + 0x100, cdReadTime * 290 / 4);
                start_rotating = 1;
                break;

            case CdlReadT + 0x100:
                m_stat = Complete;
                m_suceeded = true;
                break;

            case CdlGetTN:
                SetResultSize(3);
                if (!m_iso.getTN(m_resultTN)) {
                    m_stat = DiskError;
                    m_result[0] |= STATUS_ERROR;
                } else {
                    m_stat = Acknowledge;
                    m_result[1] = itob(m_resultTN[0]);
                    m_result[2] = itob(m_resultTN[1]);
                }
                break;

            case CdlGetTD:
                m_track = btoi(m_param[0]);
                SetResultSize(4);
                if (!m_iso.getTD(m_track, m_resultTD)) {
                    m_stat = DiskError;
                    m_result[0] |= STATUS_ERROR;
                } else {
                    m_stat = Acknowledge;
                    m_result[0] = m_statP;
                    m_result[1] = itob(m_resultTD[2]);
                    m_result[2] = itob(m_resultTD[1]);
                    m_result[3] = itob(m_resultTD[0]);
                }
                break;

            case CdlSeekL:
            case CdlSeekP:
                StopCdda();
                StopReading();
                m_statP |= STATUS_SEEK;

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
                scheduleCDPlayIRQ(m_seeked == SEEK_DONE ? 0x800 : cdReadTime * 4);
                m_seeked = SEEK_PENDING;
                start_rotating = 1;
                break;

            case CdlTest:
                switch (m_param[0]) {
                    case 0x20:  // System Controller ROM Version
                        SetResultSize(4);
                        memcpy(m_result, Test20, 4);
                        break;
                    case 0x22:
                        SetResultSize(8);
                        memcpy(m_result, Test22, 4);
                        break;
                    case 0x23:
                    case 0x24:
                        SetResultSize(8);
                        memcpy(m_result, Test23, 4);
                        break;
                }
                no_busy_error = 1;
                break;

            case CdlID:
                AddIrqQueue(CdlID + 0x100, 20480);
                break;

            case CdlID + 0x100:
                SetResultSize(8);
                m_result[0] = m_statP;
                m_result[1] = 0;
                m_result[2] = 0;
                m_result[3] = 0;

                // 0x10 - audio | 0x40 - disk missing | 0x80 - unlicensed
                if (!m_iso.getStatus(&cdr_stat) || cdr_stat.Type == 0 || cdr_stat.Type == 0xff) {
                    m_result[1] = 0xc0;
                } else {
                    if (cdr_stat.Type == 2) m_result[1] |= 0x10;
                    if (PCSX::g_emulator->m_cdromId[0] == '\0') m_result[1] |= 0x80;
                }
                m_result[0] |= (m_result[1] >> 4) & 0x08;

                strncpy((char *)&m_result[4], "PCSX", 4);
                m_stat = Complete;
                m_suceeded = true;
                break;

            case CdlReset:
                // yes, it really sets STATUS_SHELLOPEN
                m_statP |= STATUS_SHELLOPEN;
                m_driveState = DRIVESTATE_RESCAN_CD;
                scheduleCDLidIRQ(20480);
                no_busy_error = 1;
                start_rotating = 1;
                break;

            case CdlGetQ:
                // TODO?
                CDROM_LOG("got CdlGetQ\n");
                break;

            case CdlReadToc:
                AddIrqQueue(CdlReadToc + 0x100, cdReadTime * 180 / 4);
                no_busy_error = 1;
                start_rotating = 1;
                break;

            case CdlReadToc + 0x100:
                m_stat = Complete;
                m_suceeded = true;
                no_busy_error = 1;
                break;

            case CdlReadN:
            case CdlReadS:
                if (m_setlocPending) {
                    memcpy(m_setSectorPlay, m_setSector, 4);
                    m_setlocPending = 0;
                    m_locationChanged = true;
                }
                Find_CurTrack(m_setSectorPlay);

                if ((m_mode & MODE_CDDA) && m_curTrack > 1) {
                    // Read* acts as play for cdda tracks in cdda mode
                    goto do_CdlPlay;
                }

                m_reading = 1;
                m_firstSector = 1;

                // Fighting Force 2 - update m_subq time immediately
                // - fixes new game
                ReadTrack(m_setSectorPlay);

                // Crusaders of Might and Magic - update getlocl now
                // - fixes cutscene speech
                {
                    uint8_t *buf = m_iso.getBuffer();
                    if (buf != NULL) memcpy(m_transfer, buf, 8);
                }

                /*
                Duke Nukem: Land of the Babes - seek then delay read for one frame
                - fixes cutscenes
                C-12 - Final Resistance - doesn't like seek
                */

                // It LOOKS like this logic is wrong, therefore disabling it with `&& false` for now.
                //
                // For "PoPoLoCrois Monogatari II", the game logic will soft lock and will never issue GetLocP to detect
                // the end of its XA streams, as it seems to assume ReadS will not return a status byte with the SEEK
                // flag set. I think the reasonning is that since it's invalid to call GetLocP while seeking, the game
                // tries to protect itself against errors by preventing from issuing a GetLocP while it knows the
                // last status was "seek". But this makes the logic just softlock as it'll never get a notification
                // about the fact the drive is done seeking and the read actually started.
                //
                // In other words, this state machine here is probably wrong in assuming the response to ReadS/ReadN is
                // done right away. It's rather when it's done seeking, and the read has actually started. This probably
                // requires a bit more work to make sure seek delays are processed properly.
                //
                // Checked with a few games, this seems to work fine.
                if ((m_seeked != SEEK_DONE) && false) {
                    m_statP |= STATUS_SEEK;
                    m_statP &= ~STATUS_READ;

                    // Crusaders of Might and Magic - use short time
                    // - fix cutscene speech (startup)

                    // ??? - use more accurate seek time later
                    scheduleCDReadIRQ((m_mode & 0x80) ? (cdReadTime) : cdReadTime * 2);
                } else {
                    m_statP |= STATUS_READ;
                    m_statP &= ~STATUS_SEEK;

                    scheduleCDReadIRQ((m_mode & 0x80) ? (cdReadTime) : cdReadTime * 2);
                }

                m_result[0] = m_statP;
                start_rotating = 1;
                break;
            case CdlSync:
            default:
                CDROM_LOG("Invalid command: %02x\n", irq);
                error = ERROR_INVALIDCMD;
                // FALLTHROUGH

            set_error:
                SetResultSize(2);
                m_result[0] = m_statP | STATUS_ERROR;
                m_result[1] = error;
                m_stat = DiskError;
                break;
        }

        if (m_driveState == DRIVESTATE_STOPPED && start_rotating) {
            m_driveState = DRIVESTATE_STANDBY;
            m_statP |= STATUS_ROTATING;
        }

        if (!no_busy_error) {
            switch (m_driveState) {
                case DRIVESTATE_LID_OPEN:
                case DRIVESTATE_RESCAN_CD:
                case DRIVESTATE_PREPARE_CD:
                    SetResultSize(2);
                    m_result[0] = m_statP | STATUS_ERROR;
                    m_result[1] = ERROR_NOTREADY;
                    m_stat = DiskError;
                    break;
            }
        }

    finish:
        setIrq();
        m_paramC = 0;

        {
            CDROM_IO_LOG("CDR IRQ %d cmd %02x stat %02x: ", !!(m_stat & m_reg2), irq, m_stat);
            for (int i = 0; i < m_resultC; i++) CDROM_IO_LOG("%02x ", m_result[i]);
            CDROM_IO_LOG("\n");
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
        int ll = m_attenuatorLeftToLeft;
        int lr = m_attenuatorLeftToRight;
        int rl = m_attenuatorRightToLeft;
        int rr = m_attenuatorRightToRight;

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

        if (!m_reading) return;

        if (m_irq || m_stat) {
            scheduleCDReadIRQ(irqReschedule);
            return;
        }

        if ((psxHu32ref(0x1070) & psxHu32ref(0x1074) & SWAP_LE32((uint32_t)0x4)) && !m_readRescheduled) {
            // HACK: with PCSX::Emulator::BIAS 2, emulated CPU is often slower than real thing,
            // game may be unfinished with prev data read, so reschedule
            // (Brave Fencer Musashi)
            scheduleCDReadIRQ(cdReadTime / 2);
            m_readRescheduled = 1;
            return;
        }

        m_OCUP = 1;
        SetResultSize(1);
        m_statP |= STATUS_READ | STATUS_ROTATING;
        m_statP &= ~STATUS_SEEK;
        m_result[0] = m_statP;
        m_seeked = SEEK_DONE;

        ReadTrack(m_setSectorPlay);

        buf = m_iso.getBuffer();
        if (buf == NULL) m_suceeded = false;

        if (!m_suceeded) {
            CDROM_LOG("readInterrupt() Log: err\n");
            memset(m_transfer, 0, DATA_SIZE);
            m_stat = DiskError;
            m_result[0] |= STATUS_ERROR;
            scheduleCDReadIRQ((m_mode & 0x80) ? (cdReadTime / 2) : cdReadTime);
            return;
        }

        memcpy(m_transfer, buf, DATA_SIZE);
        m_ppf.CheckPPFCache(m_transfer, m_prev[0], m_prev[1], m_prev[2]);

        CDROM_LOG("readInterrupt() Log: cdr.m_transfer %x:%x:%x\n", m_transfer[0], m_transfer[1], m_transfer[2]);

        if ((!m_muted) && (m_mode & MODE_STRSND) && (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingXa>()) &&
            (m_firstSector != -1)) {  // CD-XA
            // Firemen 2: Multi-XA files - briefings, cutscenes
            if (m_firstSector == 1 && (m_mode & MODE_SF) == 0) {
                m_file = m_transfer[4 + 0];
                m_channel = m_transfer[4 + 1];
            }

            /* Gameblabla - Ignore sectors with channel 255.
             * This fixes the missing sound in Blue's Clues : Blue's Big Musical.
             * (Taxi 2 is also said to be affected by the same issue)
             * */
            if ((m_transfer[4 + 2] & 0x4) && (m_transfer[4 + 1] == m_channel) && (m_transfer[4 + 0] == m_file) &&
                m_channel != 255) {
                int ret = xa_decode_sector(&m_xa, m_transfer + 4, m_firstSector);
                if (!ret) {
                    attenuate(m_xa.pcm, m_xa.nsamples, m_xa.stereo);
                    PCSX::g_emulator->m_spu->playADPCMchannel(&m_xa);
                    m_firstSector = 0;
                } else {
                    m_firstSector = -1;
                }
            }
        }

        m_setSectorPlay[2]++;
        if (m_setSectorPlay[2] == 75) {
            m_setSectorPlay[2] = 0;
            m_setSectorPlay[1]++;
            if (m_setSectorPlay[1] == 60) {
                m_setSectorPlay[1] = 0;
                m_setSectorPlay[0]++;
            }
        }

        m_read = 0;
        m_readRescheduled = 0;

        uint32_t delay = (m_mode & MODE_SPEED) ? (cdReadTime / 2) : cdReadTime;
        if (m_locationChanged) {
            scheduleCDReadIRQ(delay * 30);
            m_locationChanged = false;
        } else {
            scheduleCDReadIRQ(delay);
        }

        /*
        Croc 2: $40 - only FORM1 (*)
        Judge Dredd: $C8 - only FORM1 (*)
        Sim Theme Park - no adpcm at all (zero)
        */

        if (!(m_mode & MODE_STRSND) || !(m_transfer[4 + 2] & 0x4)) {
            m_stat = DataReady;
            setIrq();
        }

        // update for CdlGetlocP
        ReadTrack(m_setSectorPlay);
    }

    /*
    read0:
            03 - bit 0,1 - mode
            04 - bit 2 - xa-adpcm fifo occupied
            08 - bit 3 - parameter fifo empty
            10 - bit 4 - parameter fifo safe to push to
            20 - bit 5 - 1 result ready
            40 - bit 6 - 1 dma ready
            80 - bit 7 - 1 command being processed
    */

    uint8_t read0(void) final {
        if (m_resultReady) {
            m_ctrl |= 0x20;
        } else {
            m_ctrl &= ~0x20;
        }

        if (m_OCUP) m_ctrl |= 0x40;
        //  else
        //      m_ctrl &= ~0x40;

        m_ctrl |= 0x18;

        CDROM_IO_LOG("cdr r0: %02x\n", m_ctrl);
        return psxHu8(0x1800) = m_ctrl;
    }

    void write0(uint8_t rt) final {
        CDROM_IO_LOG("cdr w0: %02x\n", rt);
        m_ctrl = (rt & 3) | (m_ctrl & ~3);
    }

    uint8_t read1(void) final {
        if ((m_resultP & 0xf) < m_resultC) {
            psxHu8(0x1801) = m_result[m_resultP & 0xf];
        } else {
            psxHu8(0x1801) = 0;
        }
        m_resultP++;
        if (m_resultP == m_resultC) m_resultReady = 0;
        CDROM_IO_LOG("cdr r1: %02x\n", psxHu8(0x1801));
        return psxHu8(0x1801);
    }

    void write1(uint8_t rt) final {
        uint8_t set_loc[3];
        int i;
        CDROM_IO_LOG("cdr w1: %02x\n", rt);
        switch (m_ctrl & 3) {
            case 0:
                break;
            case 3:
                m_attenuatorRightToRightT = rt;
                return;
            default:
                return;
        }

        m_cmd = rt;
        m_OCUP = 0;

        CDROM_IO_LOG("CD1 write: %x (%s)", rt, magic_enum::enum_names<Commands>()[rt]);
        if (m_paramC) {
            CDROM_IO_LOG(" Param[%d] = {", m_paramC);
            for (i = 0; i < m_paramC; i++) CDROM_IO_LOG(" %x,", m_param[i]);
            CDROM_IO_LOG("}\n");
        } else {
            CDROM_IO_LOG("\n");
        }

        m_resultReady = 0;
        m_ctrl |= 0x80;
        // m_stat = NoIntr;
        AddIrqQueue(m_cmd, 0x800);

        switch (m_cmd) {
            case CdlSetloc:
                CDROM_LOG("CDROM setloc command (%02X, %02X, %02X)\n", m_param[0], m_param[1], m_param[2]);
                // MM must be BCD, SS must be BCD and <0x60, FF must be BCD and <0x75
                if (((m_param[0] & 0x0F) > 0x09) || (m_param[0] > 0x99) || ((m_param[1] & 0x0F) > 0x09) || (m_param[1] >= 0x60) || ((m_param[2] & 0x0F) > 0x09) || (m_param[2] >= 0x75))
                {
                    CDROM_LOG("Invalid/out of range seek to %02X:%02X:%02X\n", m_param[0], m_param[1], m_param[2]);
                }
                else
                {
                    for (i = 0; i < 3; i++) set_loc[i] = btoi(m_param[i]);

                    i = msf2sec(m_setSectorPlay);
                    i = abs(i - (int)msf2sec(set_loc));
                    if (i > 16) m_seeked = SEEK_PENDING;

                    memcpy(m_setSector, set_loc, 3);
                    m_setSector[3] = 0;
                    m_setlocPending = 1;
                }
                break;

            case CdlReadN:
            case CdlReadS:
            case CdlPause:
                StopCdda();
                StopReading();
                break;

            case CdlReset:
            case CdlInit:
                m_seeked = SEEK_DONE;
                StopCdda();
                StopReading();
                break;

            case CdlSetmode:
                CDROM_LOG("write1() Log: Setmode %x\n", m_param[0]);
                if ((m_mode != MODE_STRSND) && (m_param[0] == MODE_STRSND)) {
                    xa_decode_reset(&m_xa);
                }
                m_mode = m_param[0];

                // Squaresoft on PlayStation 1998 Collector's CD Vol. 1
                // - fixes choppy movie sound
                if (m_play && (m_mode & MODE_CDDA) == 0) StopCdda();
                break;
        }
    }

    uint8_t read2(void) final {
        unsigned char ret;

        if (m_read == 0) {
            ret = 0;
        } else {
            ret = m_transfer[m_transferIndex];
            m_transferIndex++;
            adjustTransferIndex();
        }
        CDROM_IO_LOG("cdr r2: %02x\n", ret);
        return ret;
    }

    void write2(uint8_t rt) final {
        CDROM_IO_LOG("cdr w2: %02x\n", rt);
        switch (m_ctrl & 3) {
            case 0:
                if (m_paramC < 8) {  // FIXME: size and wrapping
                    m_param[m_paramC++] = rt;
                }
                return;
            case 1:
                m_reg2 = rt;
                setIrq();
                return;
            case 2:
                m_attenuatorLeftToLeftT = rt;
                return;
            case 3:
                m_attenuatorRightToLeftT = rt;
                return;
        }
    }

    uint8_t read3(void) final {
        if (m_ctrl & 0x1) {
            psxHu8(0x1803) = m_stat | 0xE0;
        } else {
            psxHu8(0x1803) = m_reg2 | 0xE0;
        }
        CDROM_IO_LOG("cdr r3: %02x\n", psxHu8(0x1803));
        return psxHu8(0x1803);
    }

    void write3(uint8_t rt) final {
        CDROM_IO_LOG("cdr w3: %02x\n", rt);
        switch (m_ctrl & 3) {
            case 0:
                break;  // transfer
            case 1:
                m_stat &= ~rt;

                if (rt & 0x40) m_paramC = 0;
                return;
            case 2:
                m_attenuatorLeftToRightT = rt;
                return;
            case 3:
                if (rt & 0x20) {
                    memcpy(&m_attenuatorLeftToLeft, &m_attenuatorLeftToLeftT, 4);
                    CDROM_IO_LOG("CD-XA Volume: %02x %02x | %02x %02x\n", m_attenuatorLeftToLeft,
                                 m_attenuatorLeftToRight, m_attenuatorRightToLeft, m_attenuatorRightToRight);
                }
                return;
        }

        if ((rt & 0x80) && m_read == 0) {
            m_read = 1;
            m_transferIndex = 0;

            switch (m_mode & (MODE_SIZE_2340 | MODE_SIZE_2328)) {
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

        CDROM_LOG("dma() Log: *** DMA 3 *** %x addr = %x size = %x\n", chcr, madr, bcr);

        switch (chcr) {
            case 0x11000000:
            case 0x11400100:
                if (m_read == 0) {
                    CDROM_LOG("dma() Log: *** DMA 3 *** NOT READY\n");
                    break;
                }

                cdsize = (bcr & 0xffff) * 4;

                // Ape Escape: bcr = 0001 / 0000
                // - fix boot
                if (cdsize == 0) {
                    switch (m_mode & (MODE_SIZE_2340 | MODE_SIZE_2328)) {
                        case MODE_SIZE_2340:
                            cdsize = 2340;
                            break;
                        case MODE_SIZE_2328:
                            cdsize = 2328;
                            break;
                        case MODE_SIZE_2048:
                        default:
                            cdsize = 2048;
                            break;
                    }
                }

                ptr = (uint8_t *)PSXM(madr);
                if (ptr == NULL) {
                    CDROM_LOG("dma() Log: *** DMA 3 *** NULL Pointer!\n");
                    break;
                }

                /*
                GS CDX: Enhancement CD crash
                - Setloc 0:0:0
                - CdlPlay
                - Spams DMA3 and gets buffer overrun
                */
                for (i = 0; i < cdsize; ++i) {
                    ptr[i] = m_transfer[m_transferIndex];
                    m_transferIndex++;
                    adjustTransferIndex();
                }
                if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                        .get<PCSX::Emulator::DebugSettings::Debug>()) {
                    PCSX::g_emulator->m_debug->checkDMAwrite(3, madr, cdsize);
                }
                PCSX::g_emulator->m_psxCpu->Clear(madr, cdsize / 4);
                // burst vs normal
                if (chcr == 0x11400100) {
                    scheduleCDDMAIRQ((cdsize / 4) / 4);
                } else if (chcr == 0x11000000) {
                    scheduleCDDMAIRQ((cdsize / 4) * 1);
                }
                return;

            default:
                CDROM_LOG("dma() Log: Unknown cddma %x\n", chcr);
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

        m_iso.getTN(m_resultTN);
        m_iso.getTD(0, m_setSectorEnd);
        tmp = m_setSectorEnd[0];
        m_setSectorEnd[0] = m_setSectorEnd[2];
        m_setSectorEnd[2] = tmp;
    }

    void reset() final {
        m_OCUP = 0;
        m_reg1Mode = 0;
        m_cmdProcess = 0;
        m_ctrl = 0;

        memset(m_transfer, 0, sizeof(m_transfer));

        memset(m_prev, 0, sizeof(m_prev));
        memset(m_param, 0, sizeof(m_param));
        memset(m_result, 0, sizeof(m_result));

        m_paramC = 0;
        m_paramP = 0;
        m_resultC = 0;
        m_resultP = 0;
        m_resultReady = 0;
        m_cmd = 0;
        m_read = 0;
        m_setlocPending = 0;
        m_locationChanged = false;
        m_reading = 0;

        memset(m_resultTN, 0, sizeof(m_resultTN));
        memset(m_resultTD, 0, sizeof(m_resultTD));
        memset(m_setSectorPlay, 0, sizeof(m_setSectorPlay));
        memset(m_setSectorEnd, 0, sizeof(m_setSectorEnd));
        memset(m_setSector, 0, sizeof(m_setSector));
        m_track = 0;
        m_play = false;
        m_muted = false;
        m_mode = 0;
        m_suceeded = true;
        m_firstSector = 0;

        memset(&m_xa, 0, sizeof(m_xa));

        m_irq = 0;
        m_irqRepeated = 0;
        m_eCycle = 0;

        m_seeked = 0;
        m_readRescheduled = 0;

        m_fastForward = 0;
        m_fastBackward = 0;

        m_attenuatorLeftToLeftT = 0;
        m_attenuatorLeftToRightT = 0;
        m_attenuatorRightToRightT = 0;
        m_attenuatorRightToLeftT = 0;

        m_subq.index = 0;
        m_subq.relative[0] = 0;
        m_subq.relative[1] = 0;
        m_subq.relative[2] = 0;
        m_subq.absolute[0] = 0;
        m_subq.absolute[1] = 0;
        m_subq.absolute[2] = 0;
        m_trackChanged = false;

        m_curTrack = 1;
        m_file = 1;
        m_channel = 1;
        m_transferIndex = 0;
        m_reg2 = 0x1f;
        m_stat = NoIntr;
        m_driveState = DRIVESTATE_STANDBY;
        m_statP = STATUS_ROTATING;

        // BIOS player - default values
        m_attenuatorLeftToLeft = 0x80;
        m_attenuatorLeftToRight = 0x00;
        m_attenuatorRightToLeft = 0x00;
        m_attenuatorRightToRight = 0x80;

        getCdInfo();
    }

    void load() final {
        getCdInfo();

        // read right sub data
        uint8_t tmpp[3];
        memcpy(tmpp, m_prev, 3);
        m_prev[0]++;
        ReadTrack(tmpp);

        if (m_play) {
            Find_CurTrack(m_setSectorPlay);
            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingCDDA>() != PCSX::Emulator::CDDA_DISABLED) {
                m_iso.play(m_setSectorPlay);
            }
        }
    }

    int freeze(gzFile f, int Mode) final {
        uint8_t tmpp[3];

        if (Mode == 0 &&
            PCSX::g_emulator->settings.get<PCSX::Emulator::SettingCDDA>() != PCSX::Emulator::CDDA_DISABLED) {
            m_iso.stop();
        }

        // gzfreeze(&m_cdr, sizeof(m_cdr));

        if (Mode == 1) m_paramP = m_paramC;

        if (Mode == 0) {
            getCdInfo();

            // read right sub data
            memcpy(tmpp, m_prev, 3);
            m_prev[0]++;
            ReadTrack(tmpp);

            if (m_play) {
                Find_CurTrack(m_setSectorPlay);
                if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingCDDA>() != PCSX::Emulator::CDDA_DISABLED) {
                    m_iso.play(m_setSectorPlay);
                }
            }
        }

        return 0;
    }

    void lidInterrupt() final {
        getCdInfo();
        StopCdda();
        lidSeekInterrupt();
    }

    void logCDROM(int command) {
        const auto delayedString = (command & 0x100) ? "[Delayed]" : "";  // log if this is a delayed CD-ROM IRQ

        switch (command & 0xff) {
            // TODO: decode more commands
            case CdlTest:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "[CDROM]%s Command: CdlTest %02x\n", delayedString,
                                    m_param[0]);
                break;
            default:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "[CDROM]%s Command: %s\n", delayedString,
                                    magic_enum::enum_names<Commands>()[command & 0xff]);
                break;
        }
    }
};

}  // namespace

PCSX::CDRom *PCSX::CDRom::factory() { return new CDRomImpl; }
