/***************************************************************************
                          freeze.c  -  description
                             -------------------
    begin                : Wed May 15 2002
    copyright            : (C) 2002 by Pete Bernert
    email                : BlackDove@addcom.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version. See also the license.txt file for *
 *   additional informations.                                              *
 *                                                                         *
 ***************************************************************************/

//*************************************************************************//
// History of changes:
//
// 2004/09/18 - Pete
// - corrected LDChen ADSRX values after save state loading
//
// 2003/03/20 - Pete
// - fix to prevent the new interpolations from crashing when loading a save state
//
// 2003/01/06 - Pete
// - small changes for version 1.3 adsr save state loading
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include "stdafx.h"

#define _IN_FREEZE

#include "spu/externals.h"
#include "spu/interface.h"
#include "spu/registers.h"

////////////////////////////////////////////////////////////////////////
// freeze structs
////////////////////////////////////////////////////////////////////////

typedef struct {
    unsigned short spuIrq;
    unsigned long pSpuIrq;
    unsigned long dummy0;
    unsigned long dummy1;
    unsigned long dummy2;
    unsigned long dummy3;

    PCSX::SPU::SPUCHAN s_chan[PCSX::SPU::impl::MAXCHAN];

} SPUOSSFreeze_t;

////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// SPUFREEZE: called by main emu on savestate load/save
////////////////////////////////////////////////////////////////////////

long PCSX::SPU::impl::freeze(uint32_t ulFreezeMode, SPUFreeze_t *pF) {
    int i;
    SPUOSSFreeze_t *pFO;

    if (!pF) return 0;  // first check

    if (ulFreezeMode)  // info or save?
    {                  //--------------------------------------------------//
        if (ulFreezeMode == 1) memset(pF, 0, sizeof(SPUFreeze_t) + sizeof(SPUOSSFreeze_t));

        strcpy(pF->PluginName, "PBOSS");
        pF->PluginVersion = 5;
        pF->Size = sizeof(SPUFreeze_t) + sizeof(SPUOSSFreeze_t);

        if (ulFreezeMode == 2)
            return 1;   // info mode? ok, bye
                        // save mode:
        RemoveThread();  // stop timer

        memcpy(pF->SPURam, spuMem, 0x80000);  // copy common infos
        memcpy(pF->SPUPorts, regArea, 0x200);

        if (xapGlobal && XAPlay != XAFeed)  // some xa
        {
            pF->xa = *xapGlobal;
        } else
            memset(&pF->xa, 0, sizeof(xa_decode_t));  // or clean xa

        pFO = (SPUOSSFreeze_t *)(pF + 1);  // store special stuff

        pFO->spuIrq = spuIrq;
        if (pSpuIrq) pFO->pSpuIrq = (unsigned long)pSpuIrq - (unsigned long)spuMemC;

        for (i = 0; i < MAXCHAN; i++) {
            memcpy((void *)&pFO->s_chan[i], (void *)&s_chan[i], sizeof(SPUCHAN));
            if (pFO->s_chan[i].pStart) pFO->s_chan[i].pStart -= (unsigned long)spuMemC;
            if (pFO->s_chan[i].pCurr) pFO->s_chan[i].pCurr -= (unsigned long)spuMemC;
            if (pFO->s_chan[i].pLoop) pFO->s_chan[i].pLoop -= (unsigned long)spuMemC;
        }

        SetupThread();  // sound processing on again

        return 1;
        //--------------------------------------------------//
    }

    if (ulFreezeMode != 0) return 0;  // bad mode? bye

    RemoveThread();  // we stop processing while doing the save!

    memcpy(spuMem, pF->SPURam, 0x80000);  // get ram
    memcpy(regArea, pF->SPUPorts, 0x200);

    if (pF->xa.nsamples <= 4032)  // start xa again
        playADPCMchannel(&pF->xa);

    xapGlobal = 0;

    if (!strcmp(pF->PluginName, "PBOSS") && pF->PluginVersion == 5)
        LoadStateV5(pF);
    else
        LoadStateUnknown(pF);

    // repair some globals
    for (i = 0; i <= 62; i += 2) writeRegister(H_Reverb + i, regArea[(H_Reverb + i - 0xc00) >> 1]);
    writeRegister(H_SPUReverbAddr, regArea[(H_SPUReverbAddr - 0xc00) >> 1]);
    writeRegister(H_SPUrvolL, regArea[(H_SPUrvolL - 0xc00) >> 1]);
    writeRegister(H_SPUrvolR, regArea[(H_SPUrvolR - 0xc00) >> 1]);

    writeRegister(H_SPUctrl, (unsigned short)(regArea[(H_SPUctrl - 0xc00) >> 1] | 0x4000));
    writeRegister(H_SPUstat, regArea[(H_SPUstat - 0xc00) >> 1]);
    writeRegister(H_CDLeft, regArea[(H_CDLeft - 0xc00) >> 1]);
    writeRegister(H_CDRight, regArea[(H_CDRight - 0xc00) >> 1]);

    // fix to prevent new interpolations from crashing
    for (i = 0; i < MAXCHAN; i++) s_chan[i].SB[28] = 0;

    // repair LDChen's ADSR changes
    for (i = 0; i < 24; i++) {
        writeRegister(0x1f801c00 + (i << 4) + 0xc8, regArea[(i << 3) + 0x64]);
        writeRegister(0x1f801c00 + (i << 4) + 0xca, regArea[(i << 3) + 0x65]);
    }

    SetupThread();  // start sound processing again

    return 1;
}

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::LoadStateV5(SPUFreeze_t *pF) {
    int i;
    SPUOSSFreeze_t *pFO;

    pFO = (SPUOSSFreeze_t *)(pF + 1);

    spuIrq = pFO->spuIrq;
    if (pFO->pSpuIrq)
        pSpuIrq = pFO->pSpuIrq + spuMemC;
    else
        pSpuIrq = 0;

    for (i = 0; i < MAXCHAN; i++) {
        memcpy((void *)&s_chan[i], (void *)&pFO->s_chan[i], sizeof(SPUCHAN));

        s_chan[i].pStart += (unsigned long)spuMemC;
        s_chan[i].pCurr += (unsigned long)spuMemC;
        s_chan[i].pLoop += (unsigned long)spuMemC;
        s_chan[i].iMute = false;
        s_chan[i].iIrqDone = 0;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::LoadStateUnknown(SPUFreeze_t *pF) {
    int i;

    for (i = 0; i < MAXCHAN; i++) {
        s_chan[i].bOn = 0;
        s_chan[i].bNew = 0;
        s_chan[i].bStop = 0;
        s_chan[i].ADSR.lVolume = 0;
        s_chan[i].pLoop = spuMemC;
        s_chan[i].pStart = spuMemC;
        s_chan[i].pLoop = spuMemC;
        s_chan[i].iMute = false;
        s_chan[i].iIrqDone = 0;
    }

    dwNewChannel = 0;
    pSpuIrq = 0;

    for (i = 0; i < 0xc0; i++) {
        writeRegister(0x1f801c00 + i * 2, regArea[i]);
    }
}

////////////////////////////////////////////////////////////////////////
