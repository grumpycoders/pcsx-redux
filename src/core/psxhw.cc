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
#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/mdec.h"
#include "spu/interface.h"

// Vampire Hunter D hack

static inline void setIrq(uint32_t irq) { psxHu32ref(0x1070) |= SWAP_LEu32(irq); }

void PCSX::HW::psxHwReset() {
    if (PCSX::g_emulator.config().SioIrq) psxHu32ref(0x1070) |= SWAP_LE32(0x80);
    if (PCSX::g_emulator.config().SpuIrq) psxHu32ref(0x1070) |= SWAP_LE32(0x200);

    memset(PCSX::g_emulator.m_psxMem->g_psxH, 0, 0x10000);

    PCSX::g_emulator.m_mdec->mdecInit();  // initialize mdec decoder
    PCSX::g_emulator.m_cdrom->reset();
    PCSX::g_emulator.m_psxCounters->psxRcntInit();
}

uint8_t PCSX::HW::psxHwRead8(uint32_t add) {
    unsigned char hard;

    switch (add) {
        case 0x1f801040:
            hard = PCSX::g_emulator.m_sio->sioRead8();
            break;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            hard = SIO1_readData8();
            break;
#endif
        case 0x1f801800:
            hard = PCSX::g_emulator.m_cdrom->read0();
            break;
        case 0x1f801801:
            hard = PCSX::g_emulator.m_cdrom->read1();
            break;
        case 0x1f801802:
            hard = PCSX::g_emulator.m_cdrom->read2();
            break;
        case 0x1f801803:
            hard = PCSX::g_emulator.m_cdrom->read3();
            break;
        default:
            hard = psxHu8(add);
            PSXHW_LOG("*Unkwnown 8bit read at address %x\n", add);
            return hard;
    }

    PSXHW_LOG("*Known 8bit read at address %x value %x\n", add, hard);
    return hard;
}

uint16_t PCSX::HW::psxHwRead16(uint32_t add) {
    unsigned short hard;

    switch (add) {
        case 0x1f801070:
            PSXHW_LOG("IREG 16bit read %x\n", psxHu16(0x1070));
            return psxHu16(0x1070);
        case 0x1f801074:
            PSXHW_LOG("IMASK 16bit read %x\n", psxHu16(0x1074));
            return psxHu16(0x1074);
        case 0x1f801040:
            hard = PCSX::g_emulator.m_sio->sioRead8();
            hard |= PCSX::g_emulator.m_sio->sioRead8() << 8;
            PAD_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f801044:
            hard = PCSX::g_emulator.m_sio->sioReadStat16();
            PAD_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f801048:
            hard = PCSX::g_emulator.m_sio->sioReadMode16();
            PAD_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f80104a:
            hard = PCSX::g_emulator.m_sio->sioReadCtrl16();
            PAD_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f80104e:
            hard = PCSX::g_emulator.m_sio->sioReadBaud16();
            PAD_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            hard = SIO1_readData16();
            SIO1_LOG("sio1 read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f801054:
            hard = SIO1_readStat16();
            SIO1_LOG("sio1 read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f801058:
            hard = SIO1_readMode16();
            SIO1_LOG("sio1 read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f80105a:
            hard = SIO1_readCtrl16();
            SIO1_LOG("sio1 read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
        case 0x1f80105e:
            hard = SIO1_readBaud16();
            SIO1_LOG("sio1 read16 %x; ret = %x\n", add & 0xf, hard);
            return hard;
#endif
        case 0x1f801100:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRcount(0);
            PSXHW_LOG("T0 count read16: %x\n", hard);
            return hard;
        case 0x1f801104:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRmode(0);
            PSXHW_LOG("T0 mode read16: %x\n", hard);
            return hard;
        case 0x1f801108:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRtarget(0);
            PSXHW_LOG("T0 target read16: %x\n", hard);
            return hard;
        case 0x1f801110:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRcount(1);
            PSXHW_LOG("T1 count read16: %x\n", hard);
            return hard;
        case 0x1f801114:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRmode(1);
            PSXHW_LOG("T1 mode read16: %x\n", hard);
            return hard;
        case 0x1f801118:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRtarget(1);
            PSXHW_LOG("T1 target read16: %x\n", hard);
            return hard;
        case 0x1f801120:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRcount(2);
            PSXHW_LOG("T2 count read16: %x\n", hard);
            return hard;
        case 0x1f801124:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRmode(2);
            PSXHW_LOG("T2 mode read16: %x\n", hard);
            return hard;
        case 0x1f801128:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRtarget(2);
            PSXHW_LOG("T2 target read16: %x\n", hard);
            return hard;

            // case 0x1f802030: hard =   //int_2000????
            // case 0x1f802040: hard =//dip switches...??

        default:
            if (add >= 0x1f801c00 && add < 0x1f801e00) {
                hard = PCSX::g_emulator.m_spu->readRegister(add);
            } else {
                hard = psxHu16(add);
                PSXHW_LOG("*Unkwnown 16bit read at address %x\n", add);
            }
            return hard;
    }

    PSXHW_LOG("*Known 16bit read at address %x value %x\n", add, hard);
    return hard;
}

uint32_t PCSX::HW::psxHwRead32(uint32_t add) {
    uint32_t hard;

    switch (add) {
        case 0x1f801040:
            hard = PCSX::g_emulator.m_sio->sioRead8();
            hard |= PCSX::g_emulator.m_sio->sioRead8() << 8;
            hard |= PCSX::g_emulator.m_sio->sioRead8() << 16;
            hard |= PCSX::g_emulator.m_sio->sioRead8() << 24;
            PAD_LOG("sio read32 ;ret = %x\n", hard);
            return hard;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            hard = SIO1_readData32();
            SIO1_LOG("sio1 read32 ;ret = %x\n", hard);
            return hard;
#endif
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
            hard = PCSX::g_emulator.m_gpu->readData();
            PSXHW_LOG("GPU DATA 32bit read %x\n", hard);
            return hard;
        case 0x1f801814:
            hard = PCSX::g_emulator.m_gpu->gpuReadStatus();
            PSXHW_LOG("GPU STATUS 32bit read %x\n", hard);
            return hard;

        case 0x1f801820:
            hard = PCSX::g_emulator.m_mdec->mdecRead0();
            break;
        case 0x1f801824:
            hard = PCSX::g_emulator.m_mdec->mdecRead1();
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
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRcount(0);
            PSXHW_LOG("T0 count read32: %x\n", hard);
            return hard;
        case 0x1f801104:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRmode(0);
            PSXHW_LOG("T0 mode read32: %x\n", hard);
            return hard;
        case 0x1f801108:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRtarget(0);
            PSXHW_LOG("T0 target read32: %x\n", hard);
            return hard;
        case 0x1f801110:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRcount(1);
            PSXHW_LOG("T1 count read32: %x\n", hard);
            return hard;
        case 0x1f801114:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRmode(1);
            PSXHW_LOG("T1 mode read32: %x\n", hard);
            return hard;
        case 0x1f801118:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRtarget(1);
            PSXHW_LOG("T1 target read32: %x\n", hard);
            return hard;
        case 0x1f801120:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRcount(2);
            PSXHW_LOG("T2 count read32: %x\n", hard);
            return hard;
        case 0x1f801124:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRmode(2);
            PSXHW_LOG("T2 mode read32: %x\n", hard);
            return hard;
        case 0x1f801128:
            hard = PCSX::g_emulator.m_psxCounters->psxRcntRtarget(2);
            PSXHW_LOG("T2 target read32: %x\n", hard);
            return hard;
        case 0x1f801014:
            hard = psxHu32(add);
            PSXHW_LOG("SPU delay [0x1014] read32: %8.8lx\n", hard);
            return hard;

        default:
            hard = psxHu32(add);
            PSXHW_LOG("*Unknown 32bit read at address %x (0x%8.8lx)\n", add, hard);
            return hard;
    }
    PSXHW_LOG("*Known 32bit read at address %x\n", add);
    return hard;
}

void PCSX::HW::psxHwWrite8(uint32_t add, uint8_t value) {
    switch (add) {
        case 0x1f801040:
            PCSX::g_emulator.m_sio->sioWrite8(value);
            break;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            SIO1_writeData8(value);
            break;
#endif
        case 0x1f801800:
            PCSX::g_emulator.m_cdrom->write0(value);
            break;
        case 0x1f801801:
            PCSX::g_emulator.m_cdrom->write1(value);
            break;
        case 0x1f801802:
            PCSX::g_emulator.m_cdrom->write2(value);
            break;
        case 0x1f801803:
            PCSX::g_emulator.m_cdrom->write3(value);
            break;

        default:
            psxHu8ref(add) = value;
            PSXHW_LOG("*Unknown 8bit write at address %x value %x\n", add, value);
            return;
    }
    psxHu8ref(add) = value;
    PSXHW_LOG("*Known 8bit write at address %x value %x\n", add, value);
}

void PCSX::HW::psxHwWrite16(uint32_t add, uint16_t value) {
    switch (add) {
        case 0x1f801040:
            PCSX::g_emulator.m_sio->sioWrite8((unsigned char)value);
            PCSX::g_emulator.m_sio->sioWrite8((unsigned char)(value >> 8));
            PAD_LOG("sio write16 %x, %x\n", add & 0xf, value);
            return;
        case 0x1f801044:
            PCSX::g_emulator.m_sio->sioWriteStat16(value);
            PAD_LOG("sio write16 %x, %x\n", add & 0xf, value);
            return;
        case 0x1f801048:
            PCSX::g_emulator.m_sio->sioWriteMode16(value);
            PAD_LOG("sio write16 %x, %x\n", add & 0xf, value);
            return;
        case 0x1f80104a:  // control register
            PCSX::g_emulator.m_sio->sioWriteCtrl16(value);
            PAD_LOG("sio write16 %x, %x\n", add & 0xf, value);
            return;
        case 0x1f80104e:  // baudrate register
            PCSX::g_emulator.m_sio->sioWriteBaud16(value);
            PAD_LOG("sio write16 %x, %x\n", add & 0xf, value);
            return;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            SIO1_writeData16(value);
            SIO1_LOG("sio1 write16 %x, %x\n", add & 0xf, value);
            return;
        case 0x1f801054:
            SIO1_writeStat16(value);
            SIO1_LOG("sio1 write16 %x, %x\n", add & 0xf, value);
            return;
        case 0x1f801058:
            SIO1_writeMode16(value);
            SIO1_LOG("sio1 write16 %x, %x\n", add & 0xf, value);
            return;
        case 0x1f80105a:
            SIO1_writeCtrl16(value);
            SIO1_LOG("sio1 write16 %x, %x\n", add & 0xf, value);
            return;
        case 0x1f80105e:
            SIO1_writeBaud16(value);
            SIO1_LOG("sio1 write16 %x, %x\n", add & 0xf, value);
            return;
#endif
        case 0x1f801070:
            PSXHW_LOG("IREG 16bit write %x\n", value);
            if (PCSX::g_emulator.config().SioIrq) psxHu16ref(0x1070) |= SWAP_LEu16(0x80);
            if (PCSX::g_emulator.config().SpuIrq) psxHu16ref(0x1070) |= SWAP_LEu16(0x200);
            psxHu16ref(0x1070) &= SWAP_LEu16(value);
            return;

        case 0x1f801074:
            PSXHW_LOG("IMASK 16bit write %x\n", value);
            psxHu16ref(0x1074) = SWAP_LEu16(value);
            return;

        case 0x1f801100:
            PSXHW_LOG("COUNTER 0 COUNT 16bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWcount(0, value);
            return;
        case 0x1f801104:
            PSXHW_LOG("COUNTER 0 MODE 16bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWmode(0, value);
            return;
        case 0x1f801108:
            PSXHW_LOG("COUNTER 0 TARGET 16bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWtarget(0, value);
            return;

        case 0x1f801110:
            PSXHW_LOG("COUNTER 1 COUNT 16bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWcount(1, value);
            return;
        case 0x1f801114:
            PSXHW_LOG("COUNTER 1 MODE 16bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWmode(1, value);
            return;
        case 0x1f801118:
            PSXHW_LOG("COUNTER 1 TARGET 16bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWtarget(1, value);
            return;

        case 0x1f801120:
            PSXHW_LOG("COUNTER 2 COUNT 16bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWcount(2, value);
            return;
        case 0x1f801124:
            PSXHW_LOG("COUNTER 2 MODE 16bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWmode(2, value);
            return;
        case 0x1f801128:
            PSXHW_LOG("COUNTER 2 TARGET 16bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWtarget(2, value);
            return;

        default:
            if (add >= 0x1f801c00 && add < 0x1f801e00) {
                PCSX::g_emulator.m_spu->writeRegister(add, value);
                return;
            }

            psxHu16ref(add) = SWAP_LEu16(value);
            PSXHW_LOG("*Unknown 16bit write at address %x value %x\n", add, value);
            return;
    }
    psxHu16ref(add) = SWAP_LEu16(value);
    PSXHW_LOG("*Known 16bit write at address %x value %x\n", add, value);
}

inline void PCSX::HW::psxDma0(uint32_t madr, uint32_t bcr, uint32_t chcr) {
    PCSX::g_emulator.m_mdec->psxDma0(madr, bcr, chcr);
}

inline void PCSX::HW::psxDma1(uint32_t madr, uint32_t bcr, uint32_t chcr) {
    PCSX::g_emulator.m_mdec->psxDma1(madr, bcr, chcr);
}

inline void PCSX::HW::psxDma2(uint32_t madr, uint32_t bcr, uint32_t chcr) {
    PCSX::g_emulator.m_gpu->dma(madr, bcr, chcr);
}

inline void PCSX::HW::psxDma3(uint32_t madr, uint32_t bcr, uint32_t chcr) {
    PCSX::g_emulator.m_cdrom->dma(madr, bcr, chcr);
}

#define DmaExec(n)                                                                                              \
    {                                                                                                           \
        HW_DMA##n##_CHCR = SWAP_LEu32(value);                                                                   \
                                                                                                                \
        if (SWAP_LEu32(HW_DMA##n##_CHCR) & 0x01000000 && SWAP_LEu32(HW_DMA_PCR) & (8 << (n * 4))) {             \
            psxDma##n(SWAP_LEu32(HW_DMA##n##_MADR), SWAP_LEu32(HW_DMA##n##_BCR), SWAP_LEu32(HW_DMA##n##_CHCR)); \
        }                                                                                                       \
    }

void PCSX::HW::psxHwWrite32(uint32_t add, uint32_t value) {
    switch (add) {
        case 0x1f801040:
            PCSX::g_emulator.m_sio->sioWrite8((unsigned char)value);
            PCSX::g_emulator.m_sio->sioWrite8((unsigned char)((value & 0xff) >> 8));
            PCSX::g_emulator.m_sio->sioWrite8((unsigned char)((value & 0xff) >> 16));
            PCSX::g_emulator.m_sio->sioWrite8((unsigned char)((value & 0xff) >> 24));
            PAD_LOG("sio write32 %x\n", value);
            return;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            SIO1_writeData32(value);
            SIO1_LOG("sio1 write32 %x\n", value);
            return;
#endif
        case 0x1f801060:
            PSXHW_LOG("RAM size write %x\n", value);
            psxHu32ref(add) = SWAP_LEu32(value);
            return;  // Ram size
        case 0x1f801070:
            PSXHW_LOG("IREG 32bit write %x\n", value);
            if (PCSX::g_emulator.config().SioIrq) psxHu32ref(0x1070) |= SWAP_LEu32(0x80);
            if (PCSX::g_emulator.config().SpuIrq) psxHu32ref(0x1070) |= SWAP_LEu32(0x200);
            psxHu32ref(0x1070) &= SWAP_LEu32(value);
            return;
        case 0x1f801074:
            PSXHW_LOG("IMASK 32bit write %x\n", value);
            psxHu32ref(0x1074) = SWAP_LEu32(value);
            return;
        case 0x1f801080:
            PSXHW_LOG("DMA0 MADR 32bit write %x\n", value);
            HW_DMA0_MADR = SWAP_LEu32(value);
            return;  // DMA0 madr
        case 0x1f801084:
            PSXHW_LOG("DMA0 BCR 32bit write %x\n", value);
            HW_DMA0_BCR = SWAP_LEu32(value);
            return;  // DMA0 bcr
        case 0x1f801088:
            PSXHW_LOG("DMA0 CHCR 32bit write %x\n", value);
            DmaExec(0);  // DMA0 chcr (MDEC in DMA)
            return;
        case 0x1f801090:
            PSXHW_LOG("DMA1 MADR 32bit write %x\n", value);
            HW_DMA1_MADR = SWAP_LEu32(value);
            return;  // DMA1 madr
        case 0x1f801094:
            PSXHW_LOG("DMA1 BCR 32bit write %x\n", value);
            HW_DMA1_BCR = SWAP_LEu32(value);
            return;  // DMA1 bcr
        case 0x1f801098:
            PSXHW_LOG("DMA1 CHCR 32bit write %x\n", value);
            DmaExec(1);  // DMA1 chcr (MDEC out DMA)
            return;
        case 0x1f8010a0:
            PSXHW_LOG("DMA2 MADR 32bit write %x\n", value);
            HW_DMA2_MADR = SWAP_LEu32(value);
            return;  // DMA2 madr
        case 0x1f8010a4:
            PSXHW_LOG("DMA2 BCR 32bit write %x\n", value);
            HW_DMA2_BCR = SWAP_LEu32(value);
            return;  // DMA2 bcr
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
                return;
            }
            DmaExec(2);  // DMA2 chcr (GPU DMA)
            if (PCSX::g_emulator.config().HackFix && HW_DMA2_CHCR == 0x1000401) s_dmaGpuListHackEn = true;
            return;
        case 0x1f8010b0:
            PSXHW_LOG("DMA3 MADR 32bit write %x\n", value);
            HW_DMA3_MADR = SWAP_LEu32(value);
            return;  // DMA3 madr
        case 0x1f8010b4:
            PSXHW_LOG("DMA3 BCR 32bit write %x\n", value);
            HW_DMA3_BCR = SWAP_LEu32(value);
            return;  // DMA3 bcr
        case 0x1f8010b8:
            PSXHW_LOG("DMA3 CHCR 32bit write %x\n", value);
            DmaExec(3);  // DMA3 chcr (CDROM DMA)
            return;
        case 0x1f8010c0:
            PSXHW_LOG("DMA4 MADR 32bit write %x\n", value);
            HW_DMA4_MADR = SWAP_LEu32(value);
            return;  // DMA4 madr
        case 0x1f8010c4:
            PSXHW_LOG("DMA4 BCR 32bit write %x\n", value);
            HW_DMA4_BCR = SWAP_LEu32(value);
            return;  // DMA4 bcr
        case 0x1f8010c8:
            PSXHW_LOG("DMA4 CHCR 32bit write %x\n", value);
            DmaExec(4);  // DMA4 chcr (SPU DMA)
            return;

#if 0
        case 0x1f8010d0: break; //DMA5write_madr();
        case 0x1f8010d4: break; //DMA5write_bcr();
        case 0x1f8010d8: break; //DMA5write_chcr(); // Not needed
#endif
        case 0x1f8010e0:
            PSXHW_LOG("DMA6 MADR 32bit write %x\n", value);
            HW_DMA6_MADR = SWAP_LEu32(value);
            return;  // DMA6 bcr
        case 0x1f8010e4:
            PSXHW_LOG("DMA6 BCR 32bit write %x\n", value);
            HW_DMA6_BCR = SWAP_LEu32(value);
            return;  // DMA6 bcr
        case 0x1f8010e8:
            PSXHW_LOG("DMA6 CHCR 32bit write %x\n", value);
            DmaExec(6);  // DMA6 chcr (OT clear)
            return;
        case 0x1f8010f0:
            PSXHW_LOG("DMA PCR 32bit write %x\n", value);
            HW_DMA_PCR = SWAP_LEu32(value);
            return;
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
            return;
        case 0x1f801810:
            PSXHW_LOG("GPU DATA 32bit write %x (CMD/MSB %x)\n", value, value >> 24);
            // 0x1F means irq request, so fulfill it here because plugin can't and won't
            // Probably no need to send this to plugin in first place...
            // MML/Tronbonne is known to use this.
            // TODO FIFO is not implemented properly so commands are not exact
            // and thus we rely on hack that counter/cdrom irqs are enabled at same time
            if (PCSX::g_emulator.config().HackFix && SWAP_LEu32(value) == 0x1f00000 && (psxHu32ref(0x1070) & 0x44)) {
                setIrq(0x01);
            }
            PCSX::g_emulator.m_gpu->writeData(value);
            return;
        case 0x1f801814:
            PSXHW_LOG("GPU STATUS 32bit write %x\n", value);
            if (value & 0x8000000) s_dmaGpuListHackEn = false;
            PCSX::g_emulator.m_gpu->writeStatus(value);
            return;

        case 0x1f801820:
            PCSX::g_emulator.m_mdec->mdecWrite0(value);
            break;
        case 0x1f801824:
            PCSX::g_emulator.m_mdec->mdecWrite1(value);
            break;
        case 0x1f801100:
            PSXHW_LOG("COUNTER 0 COUNT 32bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWcount(0, value & 0xffff);
            return;
        case 0x1f801104:
            PSXHW_LOG("COUNTER 0 MODE 32bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWmode(0, value);
            return;
        case 0x1f801108:
            PSXHW_LOG("COUNTER 0 TARGET 32bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWtarget(0, value & 0xffff);
            return;  //  HW_DMA_ICR&= SWAP_LE32((~value)&0xff000000);
        case 0x1f801110:
            PSXHW_LOG("COUNTER 1 COUNT 32bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWcount(1, value & 0xffff);
            return;
        case 0x1f801114:
            PSXHW_LOG("COUNTER 1 MODE 32bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWmode(1, value);
            return;
        case 0x1f801118:
            PSXHW_LOG("COUNTER 1 TARGET 32bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWtarget(1, value & 0xffff);
            return;
        case 0x1f801120:
            PSXHW_LOG("COUNTER 2 COUNT 32bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWcount(2, value & 0xffff);
            return;
        case 0x1f801124:
            PSXHW_LOG("COUNTER 2 MODE 32bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWmode(2, value);
            return;
        case 0x1f801128:
            PSXHW_LOG("COUNTER 2 TARGET 32bit write %x\n", value);
            PCSX::g_emulator.m_psxCounters->psxRcntWtarget(2, value & 0xffff);
            return;
        default:
            // Dukes of Hazard 2 - car engine noise
            if (add >= 0x1f801c00 && add < 0x1f801e00) {
                PCSX::g_emulator.m_spu->writeRegister(add, value & 0xffff);
                add += 2;
                value >>= 16;

                if (add >= 0x1f801c00 && add < 0x1f801e00) PCSX::g_emulator.m_spu->writeRegister(add, value & 0xffff);
                return;
            }

            psxHu32ref(add) = SWAP_LEu32(value);
            PSXHW_LOG("*Unknown 32bit write at address %x value %x\n", add, value);
            return;
    }
    psxHu32ref(add) = SWAP_LEu32(value);
    PSXHW_LOG("*Known 32bit write at address %x value %x\n", add, value);
}

int PCSX::HW::psxHwFreeze(gzFile f, int Mode) { return 0; }
