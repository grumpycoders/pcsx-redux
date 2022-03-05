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
 * Functions for PSX hardware control.
 */

#include "core/psxhw.h"

#include <stdint.h>

#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/logger.h"
#include "core/mdec.h"
#include "core/psxemulator.h"
#include "spu/interface.h"

// Vampire Hunter D hack

static inline void setIrq(uint32_t irq) { psxHu32ref(0x1070) |= SWAP_LEu32(irq); }

static constexpr bool between(uint32_t val, uint32_t beg, uint32_t end) {
    return (beg > end) ? false : (val >= beg && val <= end - 3);
}

static constexpr bool addressInRegisterSpace(uint32_t address) {
    uint32_t _add = address & 0x1fffffff;

    return (between(_add, 0x1f801000, 0x1f801023) ||               // MEMCTRL
            between(_add, 0x1f801060, 0x1f801063) ||               // RAM_SIZE
            between(_add, 0x1f801070, 0x1f801077) ||               // IRQCTRL
            between(_add & 0xffffff0f, 0x1f801000, 0x1f801003) ||  // DMAx.ADDR
            between(_add & 0xffffff0f, 0x1f801008, 0x1f80100f) ||  // DMAx.CTRL/MIRR
            between(_add, 0x1f8010f0, 0x1f8010f7) ||               // DMA.DPCR/DICR
            between(_add, 0x1f801100, 0x1f80110b) ||               // Timer 0
            between(_add, 0x1f801110, 0x1f80111b) ||               // Timer 1
            between(_add, 0x1f801120, 0x1f80112b));                // Timer 2
}

void PCSX::HW::psxHwReset() {
    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingSpuIrq>()) setIrq(0x200);

    memset(PCSX::g_emulator->m_psxMem->g_psxH, 0, 0x10000);

    PCSX::g_emulator->m_mdec->mdecInit();  // initialize mdec decoder
    PCSX::g_emulator->m_cdrom->reset();
    PCSX::g_emulator->m_psxCounters->psxRcntInit();
    PCSX::g_emulator->m_spu->resetCaptureBuffer();
}

uint8_t PCSX::HW::psxHwRead8(uint32_t add) {
    unsigned char hard;

    switch (add & 0x1fffffff) {
        case 0x1f801040:
            hard = PCSX::g_emulator->m_sio->sioRead8();
            break;
        case 0x1f801050:  // rx/tx data register
            hard = PCSX::g_emulator->m_sio1->readData8();
            SIO1_LOG("SIO1.DATA read8 %x; ret = %x\n", add & 0xf, hard);
            break;
        case 0x1f801054:  // stat register
            hard = PCSX::g_emulator->m_sio1->readStat8();
            // Log command below is overly spammy
            //SIO1_LOG("SIO1.STAT read8 %x; ret = %x\n", add & 0xf, hard);
            break;
        case 0x1f801058:  // mode register
            hard = PCSX::g_emulator->m_sio1->readMode8();
            SIO1_LOG("SIO1.MODE read8 %x; ret = %x\n", add & 0xf, hard);
            break;
        case 0x1f80105a: // control register
            hard = PCSX::g_emulator->m_sio1->readCtrl8();
            SIO1_LOG("SIO1.CTRL read8 %x; ret = %x\n", add & 0xf, hard);
            break;
        case 0x1f80105e: // baudrate register
            hard = PCSX::g_emulator->m_sio1->readBaud8();
            SIO1_LOG("SIO1.BAUD read8 %x; ret = %x\n", add & 0xf, hard);
            break;
        case 0x1f801800:
            hard = PCSX::g_emulator->m_cdrom->read0();
            break;
        case 0x1f801801:
            hard = PCSX::g_emulator->m_cdrom->read1();
            break;
        case 0x1f801802:
            hard = PCSX::g_emulator->m_cdrom->read2();
            break;
        case 0x1f801803:
            hard = PCSX::g_emulator->m_cdrom->read3();
            break;
        case 0x1f802040:
            hard = 2;
            break;
        case 0x1f802080:
            hard = 0x50;
            break;
        case 0x1f802081:
            hard = 0x43;
            break;
        case 0x1f802082:
            hard = 0x53;
            break;
        case 0x1f802083:
            hard = 0x58;
            break;
        default:
            hard = psxHu8(add);
            PSXHW_LOG("*Unknown 8bit read at address %x\n", add);
            return hard;
    }

    PSXHW_LOG("*Known 8bit read at address %x value %x\n", add, hard);
    return hard;
}

uint16_t PCSX::HW::psxHwRead16(uint32_t add) {
    unsigned short hard;

    switch (add & 0x1fffffff) {
        case 0x1f801070:
            PSXHW_LOG("IREG 16bit read %x\n", psxHu16(0x1070));
            return psxHu16(0x1070);
        case 0x1f801074:
            PSXHW_LOG("IMASK 16bit read %x\n", psxHu16(0x1074));
            return psxHu16(0x1074);
        case 0x1f801040:
            hard = PCSX::g_emulator->m_sio->sioRead8();
            hard |= PCSX::g_emulator->m_sio->sioRead8() << 8;
            SIO0_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f801044:
            hard = PCSX::g_emulator->m_sio->readStatus16();
            SIO0_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f801048:
            hard = PCSX::g_emulator->m_sio->readMode16();
            SIO0_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f80104a:
            hard = PCSX::g_emulator->m_sio->readCtrl16();
            SIO0_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f80104e:
            hard = PCSX::g_emulator->m_sio->readBaud16();
            SIO0_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f801050:  // rx/tx data register
            hard = PCSX::g_emulator->m_sio1->readData16();
            SIO1_LOG("SIO1.DATA read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f801054:  // stat register
            hard = PCSX::g_emulator->m_sio1->readStat16();
            // Log command below is overly spammy
            //SIO1_LOG("SIO1.STAT read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f801058:  // mode register
            hard = PCSX::g_emulator->m_sio1->readMode16();
            SIO1_LOG("SIO1.MODE read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f80105a:  // control register
            hard = PCSX::g_emulator->m_sio1->readCtrl16();
            SIO1_LOG("SIO1.CTRL read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f80105e:  // baudrate register
            hard = PCSX::g_emulator->m_sio1->readBaud16();
            SIO1_LOG("SIO1.BAUD read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        /* Fixes Armored Core misdetecting the Link cable being detected.
         * We want to turn that thing off and force it to do local multiplayer instead.
         * Thanks Sony for the fix, they fixed it in their PS Classic fork.
         */
        /* Stat's value set in SIO1/m_sio1, Armored Core local multiplayer is working.
        case 0x1f801054:
            return 0x80;
        */

        case 0x1f801100:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRcount(0);
            PSXHW_LOG("T0 count read16: %x\n", hard);
            return hard;
        case 0x1f801104:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRmode(0);
            PSXHW_LOG("T0 mode read16: %x\n", hard);
            return hard;
        case 0x1f801108:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRtarget(0);
            PSXHW_LOG("T0 target read16: %x\n", hard);
            return hard;
        case 0x1f801110:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRcount(1);
            PSXHW_LOG("T1 count read16: %x\n", hard);
            return hard;
        case 0x1f801114:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRmode(1);
            PSXHW_LOG("T1 mode read16: %x\n", hard);
            return hard;
        case 0x1f801118:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRtarget(1);
            PSXHW_LOG("T1 target read16: %x\n", hard);
            return hard;
        case 0x1f801120:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRcount(2);
            PSXHW_LOG("T2 count read16: %x\n", hard);
            return hard;
        case 0x1f801124:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRmode(2);
            PSXHW_LOG("T2 mode read16: %x\n", hard);
            return hard;
        case 0x1f801128:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRtarget(2);
            PSXHW_LOG("T2 target read16: %x\n", hard);
            return hard;

            // case 0x1f802030: hard =   //int_2000????
            // case 0x1f802040: hard =//dip switches...??

        case 0x1f802080:
            hard = 0x4350;
            break;
        case 0x1f802082:
            hard = 0x5853;
            break;

        default:
            if (add >= 0x1f801c00 && add < 0x1f801e00) {
                hard = PCSX::g_emulator->m_spu->readRegister(add);
            } else {
                hard = psxHu16(add);
                PSXHW_LOG("*Unknown 16bit read at address %x\n", add);
            }
            return hard;
    }

    PSXHW_LOG("*Known 16bit read at address %x value %x\n", add, hard);
    return hard;
}

uint32_t PCSX::HW::psxHwRead32(uint32_t add) {
    uint32_t hard;

    switch (add & 0x1fffffff) {
        case 0x1f801040:
            hard = PCSX::g_emulator->m_sio->sioRead8();
            hard |= PCSX::g_emulator->m_sio->sioRead8() << 8;
            hard |= PCSX::g_emulator->m_sio->sioRead8() << 16;
            hard |= PCSX::g_emulator->m_sio->sioRead8() << 24;
            SIO0_LOG("sio read32 ;ret = %x\n", hard);
            return hard;
        case 0x1f801050:  // rx/tx data register
            hard = PCSX::g_emulator->m_sio1->readData32();
            SIO1_LOG("SIO1.DATA read32 ;ret = %x\n", hard);
            return hard;
        case 0x1f801054:  // stat register
            hard = PCSX::g_emulator->m_sio1->readStat32();
            // Log command below is overly spammy
            //SIO1_LOG("SIO1.STAT read32 ;ret = %x\n", hard);
            return hard;
        case 0x1f801060:
            PSXHW_LOG("RAM size read %x\n", psxHu32(0x1060));
            return psxHu32(0x1060);
        case 0x1f801070:
            PSXHW_LOG("IREG 32bit read %x\n", psxHu32(0x1070));
            return psxHu32(0x1070);
        case 0x1f801074:
            PSXHW_LOG("IMASK 32bit read %x\n", psxHu32(0x1074));
            return psxHu32(0x1074);
        case 0x1f801810:
            hard = PCSX::g_emulator->m_gpu->readData();
            PSXHW_LOG("GPU DATA 32bit read %x\n", hard);
            return hard;
        case 0x1f801814:
            hard = PCSX::g_emulator->m_gpu->gpuReadStatus();
            PSXHW_LOG("GPU STATUS 32bit read %x\n", hard);
            return hard;

        case 0x1f801820:
            hard = PCSX::g_emulator->m_mdec->mdecRead0();
            break;
        case 0x1f801824:
            hard = PCSX::g_emulator->m_mdec->mdecRead1();
            break;
        case 0x1f8010a0:
            PSXHW_LOG("DMA2 MADR 32bit read %x\n", psxHu32(0x10a0));
            return SWAP_LEu32(HW_DMA2_MADR);
        case 0x1f8010a4:
            PSXHW_LOG("DMA2 BCR 32bit read %x\n", psxHu32(0x10a4));
            return SWAP_LEu32(HW_DMA2_BCR);
        case 0x1f8010a8:
            PSXHW_LOG("DMA2 CHCR 32bit read %x\n", psxHu32(0x10a8));
            return SWAP_LEu32(HW_DMA2_CHCR);
        case 0x1f8010b0:
            PSXHW_LOG("DMA3 MADR 32bit read %x\n", psxHu32(0x10b0));
            return SWAP_LEu32(HW_DMA3_MADR);
        case 0x1f8010b4:
            PSXHW_LOG("DMA3 BCR 32bit read %x\n", psxHu32(0x10b4));
            return SWAP_LEu32(HW_DMA3_BCR);
        case 0x1f8010b8:
            PSXHW_LOG("DMA3 CHCR 32bit read %x\n", psxHu32(0x10b8));
            return SWAP_LEu32(HW_DMA3_CHCR);
        case 0x1f8010f0:
            PSXHW_LOG("DMA PCR 32bit read %x\n", HW_DMA_PCR);
            return SWAP_LEu32(HW_DMA_PCR);  // DMA control register
        case 0x1f8010f4:
            PSXHW_LOG("DMA ICR 32bit read %x\n", HW_DMA_ICR);
            return SWAP_LEu32(HW_DMA_ICR);  // DMA interrupt register (enable/ack)
        // time for rootcounters :)
        case 0x1f801100:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRcount(0);
            PSXHW_LOG("T0 count read32: %x\n", hard);
            return hard;
        case 0x1f801104:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRmode(0);
            PSXHW_LOG("T0 mode read32: %x\n", hard);
            return hard;
        case 0x1f801108:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRtarget(0);
            PSXHW_LOG("T0 target read32: %x\n", hard);
            return hard;
        case 0x1f801110:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRcount(1);
            PSXHW_LOG("T1 count read32: %x\n", hard);
            return hard;
        case 0x1f801114:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRmode(1);
            PSXHW_LOG("T1 mode read32: %x\n", hard);
            return hard;
        case 0x1f801118:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRtarget(1);
            PSXHW_LOG("T1 target read32: %x\n", hard);
            return hard;
        case 0x1f801120:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRcount(2);
            PSXHW_LOG("T2 count read32: %x\n", hard);
            return hard;
        case 0x1f801124:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRmode(2);
            PSXHW_LOG("T2 mode read32: %x\n", hard);
            return hard;
        case 0x1f801128:
            hard = PCSX::g_emulator->m_psxCounters->psxRcntRtarget(2);
            PSXHW_LOG("T2 target read32: %x\n", hard);
            return hard;
        case 0x1f801014:
            hard = psxHu32(add);
            PSXHW_LOG("SPU delay [0x1014] read32: %8.8lx\n", hard);
            return hard;
        case 0x1f802080:
            hard = 0x58534350;
            break;

        default:
            hard = psxHu32(add);
            PSXHW_LOG("*Unknown 32bit read at address %x (0x%8.8lx)\n", add, hard);
            return hard;
    }
    PSXHW_LOG("*Known 32bit read at address %x\n", add);
    return hard;
}

void PCSX::HW::psxHwWrite8(uint32_t add, uint32_t rawvalue) {
    uint8_t value = (uint8_t)rawvalue;

    switch (add & 0x1fffffff) {
        case 0x1f801040:
            PCSX::g_emulator->m_sio->write8(value);
            break;
        case 0x1f801050:    // rx/tx data register
            PCSX::g_emulator->m_sio1->writeData8(value);
            SIO1_LOG("SIO1.DATA write8 %x; ret = %x\n", add & 0xf, value);
            break;
        case 0x1f801054:    // stat register
            PCSX::g_emulator->m_sio1->writeStat8(value);
            SIO1_LOG("SIO1.STAT write8 %x; ret = %x\n", add & 0xf, value);
            break;
        case 0x1f801058:  // mode register
            PCSX::g_emulator->m_sio1->writeMode8(value);
            SIO1_LOG("SIO1.MODE write8 %x; ret = %x\n", add & 0xf, value);
            break;
        case 0x1f80105a:  // control register
            PCSX::g_emulator->m_sio1->writeCtrl8(value);
            SIO1_LOG("SIO1.CTRL write8 %x; ret = %x\n", add & 0xf, value);
            break;
        case 0x1f80105e:  // baudrate register
            PCSX::g_emulator->m_sio1->writeBaud8(value);
            SIO1_LOG("SIO1.Baud write8 %x; ret = %x\n", add & 0xf, value);
            break;
        case 0x1f801800:
            PCSX::g_emulator->m_cdrom->write0(value);
            break;
        case 0x1f801801:
            PCSX::g_emulator->m_cdrom->write1(value);
            break;
        case 0x1f801802:
            PCSX::g_emulator->m_cdrom->write2(value);
            break;
        case 0x1f801803:
            PCSX::g_emulator->m_cdrom->write3(value);
            break;
        case 0x1f802041:
            PCSX::g_system->log(LogClass::HARDWARE, "BIOS Trace1: 0x%02x\n", value);
            break;
        case 0x1f802042:
            PCSX::g_system->log(LogClass::HARDWARE, "BIOS Trace2: 0x%02x\n", value);
            break;
        case 0x1f802080:
            PCSX::g_system->biosPutc(value);
            break;
        case 0x1f802081:
            PCSX::g_system->pause();
            break;

        default:
            if (addressInRegisterSpace(add)) {
                psxHu32ref(add) = rawvalue;
                PSXHW_LOG("*Unknown 8bit(actually 32bit) write at address %x value %x\n", add, rawvalue);
            } else {
                psxHu8ref(add) = value;
                PSXHW_LOG("*Unknown 8bit write at address %x value %x\n", add, value);
            }
            return;
    }
    if (addressInRegisterSpace(add)) {
        psxHu32ref(add) = value;
        PSXHW_LOG("*Known 8bit(actually 32bit) write at address %x value %x\n", add, rawvalue);
    } else {
        psxHu8ref(add) = value;
        PSXHW_LOG("*Known 8bit write at address %x value %x\n", add, value);
    }
}

void PCSX::HW::psxHwWrite16(uint32_t add, uint32_t rawvalue) {
    uint16_t value = (uint16_t)rawvalue;

    switch (add & 0x1fffffff) {
        case 0x1f801040:
            PCSX::g_emulator->m_sio->write8((unsigned char)value);
            PCSX::g_emulator->m_sio->write8((unsigned char)(value >> 8));
            SIO0_LOG("sio write16 %x, %x\n", add & 0xf, value);
            break;
        case 0x1f801044:
            PCSX::g_emulator->m_sio->writeStatus16(value);
            SIO0_LOG("sio write16 %x, %x\n", add & 0xf, value);
            break;
        case 0x1f801048:
            PCSX::g_emulator->m_sio->writeMode16(value);
            SIO0_LOG("sio write16 %x, %x\n", add & 0xf, value);
            break;
        case 0x1f80104a:  // control register
            PCSX::g_emulator->m_sio->writeCtrl16(value);
            SIO0_LOG("sio write16 %x, %x\n", add & 0xf, value);
            break;
        case 0x1f80104e:  // baudrate register
            PCSX::g_emulator->m_sio->writeBaud16(value);
            SIO0_LOG("sio write16 %x, %x\n", add & 0xf, value);
            break;
        case 0x1f801050: // rx/tx data register
            PCSX::g_emulator->m_sio1->writeData16(value);
            SIO1_LOG("SIO1.DATA write16 %x, %x\n", add & 0xf, value);
            break;
        case 0x1f801054: // stat register
            PCSX::g_emulator->m_sio1->writeStat16(value);
            SIO1_LOG("SIO1.STAT write16 %x, %x\n", add & 0xf, value);
            break;
        case 0x1f801058: // mode register
            PCSX::g_emulator->m_sio1->writeMode16(value);
            SIO1_LOG("SIO1.MODE write16 %x, %x\n", add & 0xf, value);
            break;
        case 0x1f80105a: // control register
            PCSX::g_emulator->m_sio1->writeCtrl16(value);
            SIO1_LOG("SIO1.CTRL write16 %x, %x\n", add & 0xf, value);
            break;
        case 0x1f80105e: // baudrate register
            PCSX::g_emulator->m_sio1->writeBaud16(value);
            SIO1_LOG("SIO1.BAUD write16 %x, %x\n", add & 0xf, value);
            break;
        case 0x1f801070:
            PSXHW_LOG("IREG 16bit(actually 32bit) write %x\n", rawvalue);
            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingSpuIrq>())
                psxHu16ref(0x1070) |= SWAP_LEu16(0x200);
            psxHu32ref(0x1070) &= SWAP_LEu32(rawvalue);
            return;

        case 0x1f801074:
            PSXHW_LOG("IMASK 16bit write %x\n", value);
            break;

        case 0x1f801100:
            PSXHW_LOG("COUNTER 0 COUNT 16bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWcount(0, value);
            break;
        case 0x1f801104:
            PSXHW_LOG("COUNTER 0 MODE 16bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWmode(0, value);
            break;
        case 0x1f801108:
            PSXHW_LOG("COUNTER 0 TARGET 16bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWtarget(0, value);
            break;

        case 0x1f801110:
            PSXHW_LOG("COUNTER 1 COUNT 16bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWcount(1, value);
            break;
        case 0x1f801114:
            PSXHW_LOG("COUNTER 1 MODE 16bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWmode(1, value);
            break;
        case 0x1f801118:
            PSXHW_LOG("COUNTER 1 TARGET 16bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWtarget(1, value);
            break;

        case 0x1f801120:
            PSXHW_LOG("COUNTER 2 COUNT 16bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWcount(2, value);
            break;
        case 0x1f801124:
            PSXHW_LOG("COUNTER 2 MODE 16bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWmode(2, value);
            break;
        case 0x1f801128:
            PSXHW_LOG("COUNTER 2 TARGET 16bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWtarget(2, value);
            break;
        case 0x1f802082:
            PCSX::g_system->testQuit((int16_t)value);
            break;

        default:
            if (add >= 0x1f801c00 && add < 0x1f801e00) {
                PCSX::g_emulator->m_spu->writeRegister(add, value);
                break;
            }

            if (addressInRegisterSpace(add)) {
                psxHu32ref(add) = SWAP_LEu32(rawvalue);
                PSXHW_LOG("*Unknown 16bit(actually 32bit) write at address %x value %x\n", add, rawvalue);
            } else {
                psxHu16ref(add) = SWAP_LEu16(value);
                PSXHW_LOG("*Unknown 16bit write at address %x value %x\n", add, value);
                return;
            }
    }
    if (addressInRegisterSpace(add)) {
        psxHu32ref(add) = SWAP_LEu32(rawvalue);
        PSXHW_LOG("*Known 16bit(actually 32bit) write at address %x value %x\n", add, rawvalue);
    } else {
        psxHu16ref(add) = SWAP_LEu16(value);
        PSXHW_LOG("*Known 16bit write at address %x value %x\n", add, value);
    }
}

inline void PCSX::HW::psxDma0(uint32_t madr, uint32_t bcr, uint32_t chcr) {
    PSXDMA_LOG("*** DMA0 MDEC *** %x addr = %x size = %x\n", chcr, madr, bcr);
    PCSX::g_emulator->m_mdec->psxDma0(madr, bcr, chcr);
}

inline void PCSX::HW::psxDma1(uint32_t madr, uint32_t bcr, uint32_t chcr) {
    PSXDMA_LOG("*** DMA1 MDEC *** %x addr = %x size = %x\n", chcr, madr, bcr);
    PCSX::g_emulator->m_mdec->psxDma1(madr, bcr, chcr);
}

inline void PCSX::HW::psxDma2(uint32_t madr, uint32_t bcr, uint32_t chcr) {
    PCSX::g_emulator->m_gpu->dma(madr, bcr, chcr);
}

inline void PCSX::HW::psxDma3(uint32_t madr, uint32_t bcr, uint32_t chcr) {
    PSXDMA_LOG("*** DMA3 CDROM *** %x addr = %x size = %x\n", chcr, madr, bcr);
    PCSX::g_emulator->m_cdrom->dma(madr, bcr, chcr);
}

#define DmaExec(n)                                                           \
    {                                                                        \
        HW_DMA##n##_CHCR = SWAP_LEu32(value);                                \
                                                                             \
        if (value & 0x01000000 && SWAP_LEu32(HW_DMA_PCR) & (8 << (n * 4))) { \
            uint32_t madr = SWAP_LEu32(HW_DMA##n##_MADR);                    \
            uint32_t bcr = SWAP_LEu32(HW_DMA##n##_BCR);                      \
            uint32_t chcr = value;                                           \
            psxDma##n(madr, bcr, chcr);                                      \
        }                                                                    \
    }

void PCSX::HW::psxHwWrite32(uint32_t add, uint32_t value) {
    switch (add & 0x1fffffff) {
        case 0x1f801040:
            PCSX::g_emulator->m_sio->write8((unsigned char)value);
            PCSX::g_emulator->m_sio->write8((unsigned char)((value & 0xff) >> 8));
            PCSX::g_emulator->m_sio->write8((unsigned char)((value & 0xff) >> 16));
            PCSX::g_emulator->m_sio->write8((unsigned char)((value & 0xff) >> 24));
            SIO0_LOG("sio write32 %x\n", value);
            break;
        case 0x1f801050:
            PCSX::g_emulator->m_sio1->writeData32(value);
            SIO1_LOG("SIO1.DATA write32 %x\n", value);
            break;
        case 0x1f801054:
            PCSX::g_emulator->m_sio1->writeStat32(value);
            SIO1_LOG("SIO1.STAT write32 %x\n", value);
            break;
        case 0x1f801060:
            PSXHW_LOG("RAM size write %x\n", value);
            psxHu32ref(add) = SWAP_LEu32(value);
            g_emulator->m_psxMem->setLuts();
            break;  // Ram size
        case 0x1f801070:
            PSXHW_LOG("IREG 32bit write %x\n", value);
            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingSpuIrq>()) setIrq(0x200);
            psxHu32ref(0x1070) &= SWAP_LEu32(value);
            return;
        case 0x1f801074:
            PSXHW_LOG("IMASK 32bit write %x\n", value);
            psxHu32ref(0x1074) = SWAP_LEu32(value);
            break;
        case 0x1f801080:
            PSXHW_LOG("DMA0 MADR 32bit write %x\n", value);
            HW_DMA0_MADR = SWAP_LEu32(value);
            break;  // DMA0 madr
        case 0x1f801084:
            PSXHW_LOG("DMA0 BCR 32bit write %x\n", value);
            HW_DMA0_BCR = SWAP_LEu32(value);
            break;  // DMA0 bcr
        case 0x1f801088:
            PSXHW_LOG("DMA0 CHCR 32bit write %x\n", value);
            DmaExec(0);  // DMA0 chcr (MDEC in DMA)
            break;
        case 0x1f801090:
            PSXHW_LOG("DMA1 MADR 32bit write %x\n", value);
            HW_DMA1_MADR = SWAP_LEu32(value);
            break;  // DMA1 madr
        case 0x1f801094:
            PSXHW_LOG("DMA1 BCR 32bit write %x\n", value);
            HW_DMA1_BCR = SWAP_LEu32(value);
            break;  // DMA1 bcr
        case 0x1f801098:
            PSXHW_LOG("DMA1 CHCR 32bit write %x\n", value);
            DmaExec(1);  // DMA1 chcr (MDEC out DMA)
            break;
        case 0x1f8010a0:
            PSXHW_LOG("DMA2 MADR 32bit write %x\n", value);
            HW_DMA2_MADR = SWAP_LEu32(value);
            break;  // DMA2 madr
        case 0x1f8010a4:
            PSXHW_LOG("DMA2 BCR 32bit write %x\n", value);
            HW_DMA2_BCR = SWAP_LEu32(value);
            break;  // DMA2 bcr
        case 0x1f8010a8:
            PSXHW_LOG("DMA2 CHCR 32bit write %x\n", value);
            /* A hack that makes Vampire Hunter D title screen visible,
             * but makes Tomb Raider II water effect to stay opaque
             * Root cause for this problem is that when DMA2 is issued
             * it is incompletele and still beign built by the game.
             * Maybe it is ready when some signal comes in or within given delay?
             */
            if (s_dmaGpuListHackEn && value == 0x00000401 && HW_DMA2_BCR == 0x0) {
                psxDma2(SWAP_LEu32(HW_DMA2_MADR), SWAP_LEu32(HW_DMA2_BCR), SWAP_LEu32(value));
                break;
            }
            DmaExec(2);  // DMA2 chcr (GPU DMA)
            if (PCSX::g_emulator->config().HackFix && HW_DMA2_CHCR == 0x1000401) s_dmaGpuListHackEn = true;
            break;
        case 0x1f8010b0:
            PSXHW_LOG("DMA3 MADR 32bit write %x\n", value);
            HW_DMA3_MADR = SWAP_LEu32(value);
            break;  // DMA3 madr
        case 0x1f8010b4:
            PSXHW_LOG("DMA3 BCR 32bit write %x\n", value);
            HW_DMA3_BCR = SWAP_LEu32(value);
            break;  // DMA3 bcr
        case 0x1f8010b8:
            PSXHW_LOG("DMA3 CHCR 32bit write %x\n", value);
            DmaExec(3);  // DMA3 chcr (CDROM DMA)
            break;
        case 0x1f8010c0:
            PSXHW_LOG("DMA4 MADR 32bit write %x\n", value);
            HW_DMA4_MADR = SWAP_LEu32(value);
            break;  // DMA4 madr
        case 0x1f8010c4:
            PSXHW_LOG("DMA4 BCR 32bit write %x\n", value);
            HW_DMA4_BCR = SWAP_LEu32(value);
            break;  // DMA4 bcr
        case 0x1f8010c8:
            PSXHW_LOG("DMA4 CHCR 32bit write %x\n", value);
            DmaExec(4);  // DMA4 chcr (SPU DMA)
            break;

#if 0
        case 0x1f8010d0: break; //DMA5write_madr();
        case 0x1f8010d4: break; //DMA5write_bcr();
        case 0x1f8010d8: break; //DMA5write_chcr(); // Not needed
#endif
        case 0x1f8010e0:
            PSXHW_LOG("DMA6 MADR 32bit write %x\n", value);
            HW_DMA6_MADR = SWAP_LEu32(value);
            break;  // DMA6 bcr
        case 0x1f8010e4:
            PSXHW_LOG("DMA6 BCR 32bit write %x\n", value);
            HW_DMA6_BCR = SWAP_LEu32(value);
            break;  // DMA6 bcr
        case 0x1f8010e8:
            PSXHW_LOG("DMA6 CHCR 32bit write %x\n", value);
            DmaExec(6);  // DMA6 chcr (OT clear)
            break;
        case 0x1f8010f0:
            PSXHW_LOG("DMA PCR 32bit write %x\n", value);
            HW_DMA_PCR = SWAP_LEu32(value);
            break;
        case 0x1f8010f4:
            PSXHW_LOG("DMA ICR 32bit write %x\n", value);
            {
                uint32_t tmp = (~value) & SWAP_LEu32(HW_DMA_ICR);
                HW_DMA_ICR = SWAP_LEu32(((tmp ^ value) & 0xffffff) ^ tmp);
                return;
            }
        case 0x1f801014:
            PSXHW_LOG("SPU delay [0x1014] write32: %8.8lx\n", value);
            psxHu32ref(add) = SWAP_LEu32(value);
            break;
        case 0x1f801810:
            PSXHW_LOG("GPU DATA 32bit write %x (CMD/MSB %x)\n", value, value >> 24);
            // 0x1F means irq request, so fulfill it here because plugin can't and won't
            // Probably no need to send this to plugin in first place...
            // MML/Tronbonne is known to use this.
            // TODO FIFO is not implemented properly so commands are not exact
            // and thus we rely on hack that counter/cdrom irqs are enabled at same time
            if (PCSX::g_emulator->config().HackFix && SWAP_LEu32(value) == 0x1f00000 && (psxHu32ref(0x1070) & 0x44)) {
                setIrq(0x01);
            }
            PCSX::g_emulator->m_gpu->writeData(value);
            break;
        case 0x1f801814:
            PSXHW_LOG("GPU STATUS 32bit write %x\n", value);
            if (value & 0x8000000) s_dmaGpuListHackEn = false;
            PCSX::g_emulator->m_gpu->writeStatus(value);
            break;

        case 0x1f801820:
            PCSX::g_emulator->m_mdec->mdecWrite0(value);
            break;
        case 0x1f801824:
            PCSX::g_emulator->m_mdec->mdecWrite1(value);
            break;
        case 0x1f801100:
            PSXHW_LOG("COUNTER 0 COUNT 32bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWcount(0, value & 0xffff);
            break;
        case 0x1f801104:
            PSXHW_LOG("COUNTER 0 MODE 32bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWmode(0, value);
            break;
        case 0x1f801108:
            PSXHW_LOG("COUNTER 0 TARGET 32bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWtarget(0, value & 0xffff);
            break;  //  HW_DMA_ICR&= SWAP_LE32((~value)&0xff000000);
        case 0x1f801110:
            PSXHW_LOG("COUNTER 1 COUNT 32bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWcount(1, value & 0xffff);
            break;
        case 0x1f801114:
            PSXHW_LOG("COUNTER 1 MODE 32bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWmode(1, value);
            break;
        case 0x1f801118:
            PSXHW_LOG("COUNTER 1 TARGET 32bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWtarget(1, value & 0xffff);
            break;
        case 0x1f801120:
            PSXHW_LOG("COUNTER 2 COUNT 32bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWcount(2, value & 0xffff);
            break;
        case 0x1f801124:
            PSXHW_LOG("COUNTER 2 MODE 32bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWmode(2, value);
            break;
        case 0x1f801128:
            PSXHW_LOG("COUNTER 2 TARGET 32bit write %x\n", value);
            PCSX::g_emulator->m_psxCounters->psxRcntWtarget(2, value & 0xffff);
            break;
        case 0x1f802084:
            g_system->message("%s", PSXM(value));
            break;
        default:
            // Dukes of Hazard 2 - car engine noise
            if (add >= 0x1f801c00 && add < 0x1f801e00) {
                PCSX::g_emulator->m_spu->writeRegister(add, value & 0xffff);
                add += 2;
                value >>= 16;

                if (add >= 0x1f801c00 && add < 0x1f801e00) PCSX::g_emulator->m_spu->writeRegister(add, value & 0xffff);
                break;
            }

            psxHu32ref(add) = SWAP_LEu32(value);
            PSXHW_LOG("*Unknown 32bit write at address %x value %x\n", add, value);
            return;
    }
    psxHu32ref(add) = SWAP_LEu32(value);
    PSXHW_LOG("*Known 32bit write at address %x value %x\n", add, value);
}

int PCSX::HW::psxHwFreeze(gzFile f, int Mode) { return 0; }
