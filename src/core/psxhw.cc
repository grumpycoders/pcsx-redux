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

#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/mdec.h"
#include "core/psxhw.h"

// Vampire Hunter D hack
bool g_dmaGpuListHackEn = false;

static inline void setIrq(uint32_t irq) { psxHu32ref(0x1070) |= SWAPu32(irq); }

void psxHwReset() {
    if (g_config.SioIrq) psxHu32ref(0x1070) |= SWAP32(0x80);
    if (g_config.SpuIrq) psxHu32ref(0x1070) |= SWAP32(0x200);

    memset(g_psxH, 0, 0x10000);

    mdecInit();  // initialize mdec decoder
    cdrReset();
    psxRcntInit();
}

uint8_t psxHwRead8(uint32_t add) {
    unsigned char hard;

    switch (add) {
        case 0x1f801040:
            hard = sioRead8();
            break;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            hard = SIO1_readData8();
            break;
#endif
        case 0x1f801800:
            hard = cdrRead0();
            break;
        case 0x1f801801:
            hard = cdrRead1();
            break;
        case 0x1f801802:
            hard = cdrRead2();
            break;
        case 0x1f801803:
            hard = cdrRead3();
            break;
        default:
            hard = psxHu8(add);
#ifdef PSXHW_LOG
            PSXHW_LOG("*Unkwnown 8bit read at address %x\n", add);
#endif
            return hard;
    }

#ifdef PSXHW_LOG
    PSXHW_LOG("*Known 8bit read at address %x value %x\n", add, hard);
#endif
    return hard;
}

uint16_t psxHwRead16(uint32_t add) {
    unsigned short hard;

    switch (add) {
#ifdef PSXHW_LOG
        case 0x1f801070:
            PSXHW_LOG("IREG 16bit read %x\n", psxHu16(0x1070));
            return psxHu16(0x1070);
#endif
#ifdef PSXHW_LOG
        case 0x1f801074:
            PSXHW_LOG("IMASK 16bit read %x\n", psxHu16(0x1074));
            return psxHu16(0x1074);
#endif

        case 0x1f801040:
            hard = sioRead8();
            hard |= sioRead8() << 8;
#ifdef PAD_LOG
            PAD_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
#endif
            return hard;
        case 0x1f801044:
            hard = sioReadStat16();
#ifdef PAD_LOG
            PAD_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
#endif
            return hard;
        case 0x1f801048:
            hard = sioReadMode16();
#ifdef PAD_LOG
            PAD_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
#endif
            return hard;
        case 0x1f80104a:
            hard = sioReadCtrl16();
#ifdef PAD_LOG
            PAD_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
#endif
            return hard;
        case 0x1f80104e:
            hard = sioReadBaud16();
#ifdef PAD_LOG
            PAD_LOG("sio read16 %x; ret = %x\n", add & 0xf, hard);
#endif
            return hard;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            hard = SIO1_readData16();
#ifdef SIO1_LOG
            SIO1_LOG("sio1 read16 %x; ret = %x\n", add & 0xf, hard);
#endif
            return hard;
        case 0x1f801054:
            hard = SIO1_readStat16();
#ifdef SIO1_LOG
            SIO1_LOG("sio1 read16 %x; ret = %x\n", add & 0xf, hard);
#endif
            return hard;
        case 0x1f801058:
            hard = SIO1_readMode16();
#ifdef SIO1_LOG
            SIO1_LOG("sio1 read16 %x; ret = %x\n", add & 0xf, hard);
#endif
            return hard;
        case 0x1f80105a:
            hard = SIO1_readCtrl16();
#ifdef SIO1_LOG
            SIO1_LOG("sio1 read16 %x; ret = %x\n", add & 0xf, hard);
#endif
            return hard;
        case 0x1f80105e:
            hard = SIO1_readBaud16();
#ifdef SIO1_LOG
            SIO1_LOG("sio1 read16 %x; ret = %x\n", add & 0xf, hard);
#endif
            return hard;
#endif
        case 0x1f801100:
            hard = psxRcntRcount(0);
#ifdef PSXHW_LOG
            PSXHW_LOG("T0 count read16: %x\n", hard);
#endif
            return hard;
        case 0x1f801104:
            hard = psxRcntRmode(0);
#ifdef PSXHW_LOG
            PSXHW_LOG("T0 mode read16: %x\n", hard);
#endif
            return hard;
        case 0x1f801108:
            hard = psxRcntRtarget(0);
#ifdef PSXHW_LOG
            PSXHW_LOG("T0 target read16: %x\n", hard);
#endif
            return hard;
        case 0x1f801110:
            hard = psxRcntRcount(1);
#ifdef PSXHW_LOG
            PSXHW_LOG("T1 count read16: %x\n", hard);
#endif
            return hard;
        case 0x1f801114:
            hard = psxRcntRmode(1);
#ifdef PSXHW_LOG
            PSXHW_LOG("T1 mode read16: %x\n", hard);
#endif
            return hard;
        case 0x1f801118:
            hard = psxRcntRtarget(1);
#ifdef PSXHW_LOG
            PSXHW_LOG("T1 target read16: %x\n", hard);
#endif
            return hard;
        case 0x1f801120:
            hard = psxRcntRcount(2);
#ifdef PSXHW_LOG
            PSXHW_LOG("T2 count read16: %x\n", hard);
#endif
            return hard;
        case 0x1f801124:
            hard = psxRcntRmode(2);
#ifdef PSXHW_LOG
            PSXHW_LOG("T2 mode read16: %x\n", hard);
#endif
            return hard;
        case 0x1f801128:
            hard = psxRcntRtarget(2);
#ifdef PSXHW_LOG
            PSXHW_LOG("T2 target read16: %x\n", hard);
#endif
            return hard;

            // case 0x1f802030: hard =   //int_2000????
            // case 0x1f802040: hard =//dip switches...??

        default:
            if (add >= 0x1f801c00 && add < 0x1f801e00) {
                hard = SPU_readRegister(add);
            } else {
                hard = psxHu16(add);
#ifdef PSXHW_LOG
                PSXHW_LOG("*Unkwnown 16bit read at address %x\n", add);
#endif
            }
            return hard;
    }

#ifdef PSXHW_LOG
    PSXHW_LOG("*Known 16bit read at address %x value %x\n", add, hard);
#endif
    return hard;
}

uint32_t psxHwRead32(uint32_t add) {
    uint32_t hard;

    switch (add) {
        case 0x1f801040:
            hard = sioRead8();
            hard |= sioRead8() << 8;
            hard |= sioRead8() << 16;
            hard |= sioRead8() << 24;
#ifdef PAD_LOG
            PAD_LOG("sio read32 ;ret = %x\n", hard);
#endif
            return hard;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            hard = SIO1_readData32();
#ifdef SIO1_LOG
            SIO1_LOG("sio1 read32 ;ret = %x\n", hard);
#endif
            return hard;
#endif
#ifdef PSXHW_LOG
        case 0x1f801060:
            PSXHW_LOG("RAM size read %x\n", psxHu32(0x1060));
            return psxHu32(0x1060);
#endif
#ifdef PSXHW_LOG
        case 0x1f801070:
            PSXHW_LOG("IREG 32bit read %x\n", psxHu32(0x1070));
            return psxHu32(0x1070);
#endif
#ifdef PSXHW_LOG
        case 0x1f801074:
            PSXHW_LOG("IMASK 32bit read %x\n", psxHu32(0x1074));
            return psxHu32(0x1074);
#endif

        case 0x1f801810:
            hard = GPU_readData();
#ifdef PSXHW_LOG
            PSXHW_LOG("GPU DATA 32bit read %x\n", hard);
#endif
            return hard;
        case 0x1f801814:
            hard = gpuReadStatus();
#ifdef PSXHW_LOG
            PSXHW_LOG("GPU STATUS 32bit read %x\n", hard);
#endif
            return hard;

        case 0x1f801820:
            hard = mdecRead0();
            break;
        case 0x1f801824:
            hard = mdecRead1();
            break;

#ifdef PSXHW_LOG
        case 0x1f8010a0:
            PSXHW_LOG("DMA2 MADR 32bit read %x\n", psxHu32(0x10a0));
            return SWAPu32(HW_DMA2_MADR);
        case 0x1f8010a4:
            PSXHW_LOG("DMA2 BCR 32bit read %x\n", psxHu32(0x10a4));
            return SWAPu32(HW_DMA2_BCR);
        case 0x1f8010a8:
            PSXHW_LOG("DMA2 CHCR 32bit read %x\n", psxHu32(0x10a8));
            return SWAPu32(HW_DMA2_CHCR);
#endif

#ifdef PSXHW_LOG
        case 0x1f8010b0:
            PSXHW_LOG("DMA3 MADR 32bit read %x\n", psxHu32(0x10b0));
            return SWAPu32(HW_DMA3_MADR);
        case 0x1f8010b4:
            PSXHW_LOG("DMA3 BCR 32bit read %x\n", psxHu32(0x10b4));
            return SWAPu32(HW_DMA3_BCR);
        case 0x1f8010b8:
            PSXHW_LOG("DMA3 CHCR 32bit read %x\n", psxHu32(0x10b8));
            return SWAPu32(HW_DMA3_CHCR);
#endif

#ifdef PSXHW_LOG
        case 0x1f8010f0:
            PSXHW_LOG("DMA PCR 32bit read %x\n", HW_DMA_PCR);
            return SWAPu32(HW_DMA_PCR);  // DMA control register
        case 0x1f8010f4:
            PSXHW_LOG("DMA ICR 32bit read %x\n", HW_DMA_ICR);
            return SWAPu32(HW_DMA_ICR);  // DMA interrupt register (enable/ack)
#endif

        // time for rootcounters :)
        case 0x1f801100:
            hard = psxRcntRcount(0);
#ifdef PSXHW_LOG
            PSXHW_LOG("T0 count read32: %x\n", hard);
#endif
            return hard;
        case 0x1f801104:
            hard = psxRcntRmode(0);
#ifdef PSXHW_LOG
            PSXHW_LOG("T0 mode read32: %x\n", hard);
#endif
            return hard;
        case 0x1f801108:
            hard = psxRcntRtarget(0);
#ifdef PSXHW_LOG
            PSXHW_LOG("T0 target read32: %x\n", hard);
#endif
            return hard;
        case 0x1f801110:
            hard = psxRcntRcount(1);
#ifdef PSXHW_LOG
            PSXHW_LOG("T1 count read32: %x\n", hard);
#endif
            return hard;
        case 0x1f801114:
            hard = psxRcntRmode(1);
#ifdef PSXHW_LOG
            PSXHW_LOG("T1 mode read32: %x\n", hard);
#endif
            return hard;
        case 0x1f801118:
            hard = psxRcntRtarget(1);
#ifdef PSXHW_LOG
            PSXHW_LOG("T1 target read32: %x\n", hard);
#endif
            return hard;
        case 0x1f801120:
            hard = psxRcntRcount(2);
#ifdef PSXHW_LOG
            PSXHW_LOG("T2 count read32: %x\n", hard);
#endif
            return hard;
        case 0x1f801124:
            hard = psxRcntRmode(2);
#ifdef PSXHW_LOG
            PSXHW_LOG("T2 mode read32: %x\n", hard);
#endif
            return hard;
        case 0x1f801128:
            hard = psxRcntRtarget(2);
#ifdef PSXHW_LOG
            PSXHW_LOG("T2 target read32: %x\n", hard);
#endif
            return hard;
        case 0x1f801014:
            hard = psxHu32(add);
#ifdef PSXHW_LOG
            PSXHW_LOG("SPU delay [0x1014] read32: %8.8lx\n", hard);
#endif
            return hard;

        default:
            hard = psxHu32(add);
#ifdef PSXHW_LOG
            PSXHW_LOG("*Unknown 32bit read at address %x (0x%8.8lx)\n", add, hard);
#endif
            return hard;
    }
#ifdef PSXHW_LOG
    PSXHW_LOG("*Known 32bit read at address %x\n", add);
#endif
    return hard;
}

void psxHwWrite8(uint32_t add, uint8_t value) {
    switch (add) {
        case 0x1f801040:
            sioWrite8(value);
            break;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            SIO1_writeData8(value);
            break;
#endif
        case 0x1f801800:
            cdrWrite0(value);
            break;
        case 0x1f801801:
            cdrWrite1(value);
            break;
        case 0x1f801802:
            cdrWrite2(value);
            break;
        case 0x1f801803:
            cdrWrite3(value);
            break;

        default:
            psxHu8ref(add) = value;
#ifdef PSXHW_LOG
            PSXHW_LOG("*Unknown 8bit write at address %x value %x\n", add, value);
#endif
            return;
    }
    psxHu8ref(add) = value;
#ifdef PSXHW_LOG
    PSXHW_LOG("*Known 8bit write at address %x value %x\n", add, value);
#endif
}

void psxHwWrite16(uint32_t add, uint16_t value) {
    switch (add) {
        case 0x1f801040:
            sioWrite8((unsigned char)value);
            sioWrite8((unsigned char)(value >> 8));
#ifdef PAD_LOG
            PAD_LOG("sio write16 %x, %x\n", add & 0xf, value);
#endif
            return;
        case 0x1f801044:
            sioWriteStat16(value);
#ifdef PAD_LOG
            PAD_LOG("sio write16 %x, %x\n", add & 0xf, value);
#endif
            return;
        case 0x1f801048:
            sioWriteMode16(value);
#ifdef PAD_LOG
            PAD_LOG("sio write16 %x, %x\n", add & 0xf, value);
#endif
            return;
        case 0x1f80104a:  // control register
            sioWriteCtrl16(value);
#ifdef PAD_LOG
            PAD_LOG("sio write16 %x, %x\n", add & 0xf, value);
#endif
            return;
        case 0x1f80104e:  // baudrate register
            sioWriteBaud16(value);
#ifdef PAD_LOG
            PAD_LOG("sio write16 %x, %x\n", add & 0xf, value);
#endif
            return;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            SIO1_writeData16(value);
#ifdef SIO1_LOG
            SIO1_LOG("sio1 write16 %x, %x\n", add & 0xf, value);
#endif
            return;
        case 0x1f801054:
            SIO1_writeStat16(value);
#ifdef SIO1_LOG
            SIO1_LOG("sio1 write16 %x, %x\n", add & 0xf, value);
#endif
            return;
        case 0x1f801058:
            SIO1_writeMode16(value);
#ifdef SIO1_LOG
            SIO1_LOG("sio1 write16 %x, %x\n", add & 0xf, value);
#endif
            return;
        case 0x1f80105a:
            SIO1_writeCtrl16(value);
#ifdef SIO1_LOG
            SIO1_LOG("sio1 write16 %x, %x\n", add & 0xf, value);
#endif
            return;
        case 0x1f80105e:
            SIO1_writeBaud16(value);
#ifdef SIO1_LOG
            SIO1_LOG("sio1 write16 %x, %x\n", add & 0xf, value);
#endif
            return;
#endif
        case 0x1f801070:
#ifdef PSXHW_LOG
            PSXHW_LOG("IREG 16bit write %x\n", value);
#endif
            if (g_config.SioIrq) psxHu16ref(0x1070) |= SWAPu16(0x80);
            if (g_config.SpuIrq) psxHu16ref(0x1070) |= SWAPu16(0x200);
            psxHu16ref(0x1070) &= SWAPu16(value);
            return;

        case 0x1f801074:
#ifdef PSXHW_LOG
            PSXHW_LOG("IMASK 16bit write %x\n", value);
#endif
            psxHu16ref(0x1074) = SWAPu16(value);
            return;

        case 0x1f801100:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 0 COUNT 16bit write %x\n", value);
#endif
            psxRcntWcount(0, value);
            return;
        case 0x1f801104:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 0 MODE 16bit write %x\n", value);
#endif
            psxRcntWmode(0, value);
            return;
        case 0x1f801108:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 0 TARGET 16bit write %x\n", value);
#endif
            psxRcntWtarget(0, value);
            return;

        case 0x1f801110:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 1 COUNT 16bit write %x\n", value);
#endif
            psxRcntWcount(1, value);
            return;
        case 0x1f801114:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 1 MODE 16bit write %x\n", value);
#endif
            psxRcntWmode(1, value);
            return;
        case 0x1f801118:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 1 TARGET 16bit write %x\n", value);
#endif
            psxRcntWtarget(1, value);
            return;

        case 0x1f801120:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 2 COUNT 16bit write %x\n", value);
#endif
            psxRcntWcount(2, value);
            return;
        case 0x1f801124:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 2 MODE 16bit write %x\n", value);
#endif
            psxRcntWmode(2, value);
            return;
        case 0x1f801128:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 2 TARGET 16bit write %x\n", value);
#endif
            psxRcntWtarget(2, value);
            return;

        default:
            if (add >= 0x1f801c00 && add < 0x1f801e00) {
                SPU_writeRegister(add, value);
                return;
            }

            psxHu16ref(add) = SWAPu16(value);
#ifdef PSXHW_LOG
            PSXHW_LOG("*Unknown 16bit write at address %x value %x\n", add, value);
#endif
            return;
    }
    psxHu16ref(add) = SWAPu16(value);
#ifdef PSXHW_LOG
    PSXHW_LOG("*Known 16bit write at address %x value %x\n", add, value);
#endif
}

#define DmaExec(n)                                                                                     \
    {                                                                                                  \
        HW_DMA##n##_CHCR = SWAPu32(value);                                                             \
                                                                                                       \
        if (SWAPu32(HW_DMA##n##_CHCR) & 0x01000000 && SWAPu32(HW_DMA_PCR) & (8 << (n * 4))) {          \
            psxDma##n(SWAPu32(HW_DMA##n##_MADR), SWAPu32(HW_DMA##n##_BCR), SWAPu32(HW_DMA##n##_CHCR)); \
        }                                                                                              \
    }

void psxHwWrite32(uint32_t add, uint32_t value) {
    switch (add) {
        case 0x1f801040:
            sioWrite8((unsigned char)value);
            sioWrite8((unsigned char)((value & 0xff) >> 8));
            sioWrite8((unsigned char)((value & 0xff) >> 16));
            sioWrite8((unsigned char)((value & 0xff) >> 24));
#ifdef PAD_LOG
            PAD_LOG("sio write32 %x\n", value);
#endif
            return;
#ifdef ENABLE_SIO1API
        case 0x1f801050:
            SIO1_writeData32(value);
#ifdef SIO1_LOG
            SIO1_LOG("sio1 write32 %x\n", value);
#endif
            return;
#endif
#ifdef PSXHW_LOG
        case 0x1f801060:
            PSXHW_LOG("RAM size write %x\n", value);
            psxHu32ref(add) = SWAPu32(value);
            return;  // Ram size
#endif

        case 0x1f801070:
#ifdef PSXHW_LOG
            PSXHW_LOG("IREG 32bit write %x\n", value);
#endif
            if (g_config.SioIrq) psxHu32ref(0x1070) |= SWAPu32(0x80);
            if (g_config.SpuIrq) psxHu32ref(0x1070) |= SWAPu32(0x200);
            psxHu32ref(0x1070) &= SWAPu32(value);
            return;
        case 0x1f801074:
#ifdef PSXHW_LOG
            PSXHW_LOG("IMASK 32bit write %x\n", value);
#endif
            psxHu32ref(0x1074) = SWAPu32(value);
            return;

#ifdef PSXHW_LOG
        case 0x1f801080:
            PSXHW_LOG("DMA0 MADR 32bit write %x\n", value);
            HW_DMA0_MADR = SWAPu32(value);
            return;  // DMA0 madr
        case 0x1f801084:
            PSXHW_LOG("DMA0 BCR 32bit write %x\n", value);
            HW_DMA0_BCR = SWAPu32(value);
            return;  // DMA0 bcr
#endif
        case 0x1f801088:
#ifdef PSXHW_LOG
            PSXHW_LOG("DMA0 CHCR 32bit write %x\n", value);
#endif
            DmaExec(0);  // DMA0 chcr (MDEC in DMA)
            return;

#ifdef PSXHW_LOG
        case 0x1f801090:
            PSXHW_LOG("DMA1 MADR 32bit write %x\n", value);
            HW_DMA1_MADR = SWAPu32(value);
            return;  // DMA1 madr
        case 0x1f801094:
            PSXHW_LOG("DMA1 BCR 32bit write %x\n", value);
            HW_DMA1_BCR = SWAPu32(value);
            return;  // DMA1 bcr
#endif
        case 0x1f801098:
#ifdef PSXHW_LOG
            PSXHW_LOG("DMA1 CHCR 32bit write %x\n", value);
#endif
            DmaExec(1);  // DMA1 chcr (MDEC out DMA)
            return;

#ifdef PSXHW_LOG
        case 0x1f8010a0:
            PSXHW_LOG("DMA2 MADR 32bit write %x\n", value);
            HW_DMA2_MADR = SWAPu32(value);
            return;  // DMA2 madr
        case 0x1f8010a4:
            PSXHW_LOG("DMA2 BCR 32bit write %x\n", value);
            HW_DMA2_BCR = SWAPu32(value);
            return;  // DMA2 bcr
#endif
        case 0x1f8010a8:
#ifdef PSXHW_LOG
            PSXHW_LOG("DMA2 CHCR 32bit write %x\n", value);
#endif
            /* A hack that makes Vampire Hunter D title screen visible,
             * but makes Tomb Raider II water effect to stay opaque
             * Root cause for this problem is that when DMA2 is issued
             * it is incompletele and still beign built by the game.
             * Maybe it is ready when some signal comes in or within given delay?
             */
            if (g_dmaGpuListHackEn && value == 0x00000401 && HW_DMA2_BCR == 0x0) {
                psxDma2(SWAPu32(HW_DMA2_MADR), SWAPu32(HW_DMA2_BCR), SWAPu32(value));
                return;
            }
            DmaExec(2);  // DMA2 chcr (GPU DMA)
            if (g_config.HackFix && HW_DMA2_CHCR == 0x1000401) g_dmaGpuListHackEn = true;
            return;

#ifdef PSXHW_LOG
        case 0x1f8010b0:
            PSXHW_LOG("DMA3 MADR 32bit write %x\n", value);
            HW_DMA3_MADR = SWAPu32(value);
            return;  // DMA3 madr
        case 0x1f8010b4:
            PSXHW_LOG("DMA3 BCR 32bit write %x\n", value);
            HW_DMA3_BCR = SWAPu32(value);
            return;  // DMA3 bcr
#endif
        case 0x1f8010b8:
#ifdef PSXHW_LOG
            PSXHW_LOG("DMA3 CHCR 32bit write %x\n", value);
#endif
            DmaExec(3);  // DMA3 chcr (CDROM DMA)

            return;

#ifdef PSXHW_LOG
        case 0x1f8010c0:
            PSXHW_LOG("DMA4 MADR 32bit write %x\n", value);
            HW_DMA4_MADR = SWAPu32(value);
            return;  // DMA4 madr
        case 0x1f8010c4:
            PSXHW_LOG("DMA4 BCR 32bit write %x\n", value);
            HW_DMA4_BCR = SWAPu32(value);
            return;  // DMA4 bcr
#endif
        case 0x1f8010c8:
#ifdef PSXHW_LOG
            PSXHW_LOG("DMA4 CHCR 32bit write %x\n", value);
#endif
            DmaExec(4);  // DMA4 chcr (SPU DMA)
            return;

#if 0
		case 0x1f8010d0: break; //DMA5write_madr();
		case 0x1f8010d4: break; //DMA5write_bcr();
		case 0x1f8010d8: break; //DMA5write_chcr(); // Not needed
#endif

#ifdef PSXHW_LOG
        case 0x1f8010e0:
            PSXHW_LOG("DMA6 MADR 32bit write %x\n", value);
            HW_DMA6_MADR = SWAPu32(value);
            return;  // DMA6 bcr
        case 0x1f8010e4:
            PSXHW_LOG("DMA6 BCR 32bit write %x\n", value);
            HW_DMA6_BCR = SWAPu32(value);
            return;  // DMA6 bcr
#endif
        case 0x1f8010e8:
#ifdef PSXHW_LOG
            PSXHW_LOG("DMA6 CHCR 32bit write %x\n", value);
#endif
            DmaExec(6);  // DMA6 chcr (OT clear)
            return;

#ifdef PSXHW_LOG
        case 0x1f8010f0:
            PSXHW_LOG("DMA PCR 32bit write %x\n", value);
            HW_DMA_PCR = SWAPu32(value);
            return;
#endif

        case 0x1f8010f4:
#ifdef PSXHW_LOG
            PSXHW_LOG("DMA ICR 32bit write %x\n", value);
#endif
            {
                uint32_t tmp = (~value) & SWAPu32(HW_DMA_ICR);
                HW_DMA_ICR = SWAPu32(((tmp ^ value) & 0xffffff) ^ tmp);
                return;
            }

        case 0x1f801014:
#ifdef PSXHW_LOG
            PSXHW_LOG("SPU delay [0x1014] write32: %8.8lx\n", value);
#endif
            psxHu32ref(add) = SWAPu32(value);
            return;
        case 0x1f801810:
#ifdef PSXHW_LOG
            PSXHW_LOG("GPU DATA 32bit write %x (CMD/MSB %x)\n", value, value >> 24);
#endif
            // 0x1F means irq request, so fulfill it here because plugin can't and won't
            // Probably no need to send this to plugin in first place...
            // MML/Tronbonne is known to use this.
            // TODO FIFO is not implemented properly so commands are not exact
            // and thus we rely on hack that counter/cdrom irqs are enabled at same time
            if (g_config.HackFix && SWAPu32(value) == 0x1f00000 && (psxHu32ref(0x1070) & 0x44)) {
                setIrq(0x01);
            }
            GPU_writeData(value);
            return;
        case 0x1f801814:
#ifdef PSXHW_LOG
            PSXHW_LOG("GPU STATUS 32bit write %x\n", value);
#endif
            if (value & 0x8000000) g_dmaGpuListHackEn = false;
            GPU_writeStatus(value);
            return;

        case 0x1f801820:
            mdecWrite0(value);
            break;
        case 0x1f801824:
            mdecWrite1(value);
            break;

        case 0x1f801100:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 0 COUNT 32bit write %x\n", value);
#endif
            psxRcntWcount(0, value & 0xffff);
            return;
        case 0x1f801104:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 0 MODE 32bit write %x\n", value);
#endif
            psxRcntWmode(0, value);
            return;
        case 0x1f801108:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 0 TARGET 32bit write %x\n", value);
#endif
            psxRcntWtarget(0, value & 0xffff);
            return;  //  HW_DMA_ICR&= SWAP32((~value)&0xff000000);

        case 0x1f801110:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 1 COUNT 32bit write %x\n", value);
#endif
            psxRcntWcount(1, value & 0xffff);
            return;
        case 0x1f801114:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 1 MODE 32bit write %x\n", value);
#endif
            psxRcntWmode(1, value);
            return;
        case 0x1f801118:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 1 TARGET 32bit write %x\n", value);
#endif
            psxRcntWtarget(1, value & 0xffff);
            return;

        case 0x1f801120:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 2 COUNT 32bit write %x\n", value);
#endif
            psxRcntWcount(2, value & 0xffff);
            return;
        case 0x1f801124:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 2 MODE 32bit write %x\n", value);
#endif
            psxRcntWmode(2, value);
            return;
        case 0x1f801128:
#ifdef PSXHW_LOG
            PSXHW_LOG("COUNTER 2 TARGET 32bit write %x\n", value);
#endif
            psxRcntWtarget(2, value & 0xffff);
            return;

        default:
            // Dukes of Hazard 2 - car engine noise
            if (add >= 0x1f801c00 && add < 0x1f801e00) {
                SPU_writeRegister(add, value & 0xffff);
                add += 2;
                value >>= 16;

                if (add >= 0x1f801c00 && add < 0x1f801e00) SPU_writeRegister(add, value & 0xffff);
                return;
            }

            psxHu32ref(add) = SWAPu32(value);
#ifdef PSXHW_LOG
            PSXHW_LOG("*Unknown 32bit write at address %x value %x\n", add, value);
#endif
            return;
    }
    psxHu32ref(add) = SWAPu32(value);
#ifdef PSXHW_LOG
    PSXHW_LOG("*Known 32bit write at address %x value %x\n", add, value);
#endif
}

int psxHwFreeze(gzFile f, int Mode) { return 0; }
