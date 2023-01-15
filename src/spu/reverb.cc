/***************************************************************************
                          reverb.c  -  description
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
// 2003/01/19 - Pete
// - added Neill's reverb (see at the end of file)
//
// 2002/12/26 - Pete
// - adjusted reverb handling
//
// 2002/08/14 - Pete
// - added extra reverb
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include "spu/externals.h"
#include "spu/interface.h"

////////////////////////////////////////////////////////////////////////
// SET REVERB
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::SetREVERB(unsigned short val) {
    switch (val) {
        case 0x0000:
            iReverbOff = -1;
            break;  // off
        case 0x007D:
            iReverbOff = 32;
            iReverbNum = 2;
            iReverbRepeat = 128;
            break;  // ok room

        case 0x0033:
            iReverbOff = 32;
            iReverbNum = 2;
            iReverbRepeat = 64;
            break;  // studio small
        case 0x00B1:
            iReverbOff = 48;
            iReverbNum = 2;
            iReverbRepeat = 96;
            break;  // ok studio medium
        case 0x00E3:
            iReverbOff = 64;
            iReverbNum = 2;
            iReverbRepeat = 128;
            break;  // ok studio large ok

        case 0x01A5:
            iReverbOff = 128;
            iReverbNum = 4;
            iReverbRepeat = 32;
            break;  // ok hall
        case 0x033D:
            iReverbOff = 256;
            iReverbNum = 4;
            iReverbRepeat = 64;
            break;  // space echo
        case 0x0001:
            iReverbOff = 184;
            iReverbNum = 3;
            iReverbRepeat = 128;
            break;  // echo/delay
        case 0x0017:
            iReverbOff = 128;
            iReverbNum = 2;
            iReverbRepeat = 128;
            break;  // half echo
        default:
            iReverbOff = 32;
            iReverbNum = 1;
            iReverbRepeat = 0;
            break;
    }
}

////////////////////////////////////////////////////////////////////////
// START REVERB
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::StartREVERB(SPUCHAN *pChannel) {
    if (pChannel->data.get<Chan::Reverb>().value && (spuCtrl & 0x80))  // reverb possible?
    {
        if (settings.get<Reverb>() == 2 || settings.get<Reverb>() == 3) {
            pChannel->data.get<Chan::RVBActive>().value = true;
        } else if (settings.get<Reverb>() == 1 && iReverbOff > 0)  // -> fake reverb used?
        {
            pChannel->data.get<Chan::RVBActive>().value = true;  // -> activate it
            pChannel->data.get<Chan::RVBOffset>().value = iReverbOff * NSSIZE;
            pChannel->data.get<Chan::RVBRepeat>().value = iReverbRepeat * NSSIZE;
            pChannel->data.get<Chan::RVBNum>().value = iReverbNum;
        }
    } else
        pChannel->data.get<Chan::RVBActive>().value = false;  // else -> no reverb
}

////////////////////////////////////////////////////////////////////////
// HELPER FOR NEILL'S REVERB: re-inits our reverb mixing buf
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::InitREVERB() {
    if (settings.get<Reverb>() == 2 || settings.get<Reverb>() == 3) {
        memset(sRVBStart, 0, NSSIZE * 2 * 4);
    }
}

////////////////////////////////////////////////////////////////////////
// STORE REVERB
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::StoreREVERB(SPUCHAN *pChannel, int ns) {
    if (settings.get<Reverb>() == 0)
        return;
    else if (settings.get<Reverb>() == 2 ||
             settings.get<Reverb>() == 3)  // -------------------------------- // Neil's reverb
    {
        const int iRxl =
            (pChannel->data.get<Chan::sval>().value * pChannel->data.get<Chan::LeftVolume>().value) / 0x4000;
        const int iRxr =
            (pChannel->data.get<Chan::sval>().value * pChannel->data.get<Chan::RightVolume>().value) / 0x4000;

        ns <<= 1;

        *(sRVBStart + ns) += iRxl;  // -> we mix all active reverb channels into an extra buffer
        *(sRVBStart + ns + 1) += iRxr;
    } else  // --------------------------------------------- // Pete's easy fake reverb
    {
        int *pN;
        int iRn, iRr = 0;

        // we use the half channel volume (/0x8000) for the first reverb effects, quarter for next and so on

        int iRxl = (pChannel->data.get<Chan::sval>().value * pChannel->data.get<Chan::LeftVolume>().value) / 0x8000;
        int iRxr = (pChannel->data.get<Chan::sval>().value * pChannel->data.get<Chan::RightVolume>().value) / 0x8000;

        for (iRn = 1; iRn <= pChannel->data.get<Chan::RVBNum>().value;
             iRn++, iRr += pChannel->data.get<Chan::RVBRepeat>().value, iRxl /= 2, iRxr /= 2) {
            pN = sRVBPlay + ((pChannel->data.get<Chan::RVBOffset>().value + iRr + ns) << 1);
            if (pN >= sRVBEnd) pN = sRVBStart + (pN - sRVBEnd);

            (*pN) += iRxl;
            pN++;
            (*pN) += iRxr;
        }
    }
}

////////////////////////////////////////////////////////////////////////

inline int PCSX::SPU::impl::g_buffer(int iOff)  // get_buffer content helper: takes care about wraps
{
    short *p = (short *)spuMem;
    iOff = (iOff * 4) + rvb.CurrAddr;
    while (iOff > 0x3FFFF) iOff = rvb.StartAddr + (iOff - 0x40000);
    while (iOff < rvb.StartAddr) iOff = 0x3ffff - (rvb.StartAddr - iOff);
    return (int)*(p + iOff);
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::s_bufferdrhell(int iOff,
                                            int iVal)  // set_buffer content helper: takes care about wraps and clipping
{
    short *p = (short *)spuMem;
    iOff = (iOff) + rvb.CurrAddr;
    while (iOff > 0x3FFFF) iOff = rvb.StartAddr + (iOff - 0x40000);
    while (iOff < rvb.StartAddr) iOff = 0x3ffff - (rvb.StartAddr - iOff);
    if (iVal < -32768L) iVal = -32768L;
    if (iVal > 32767L) iVal = 32767L;
    *(p + iOff) = (short)iVal;
}

inline int PCSX::SPU::impl::g_bufferdrhell(int iOff)  // get_buffer content helper: takes care about wraps
{
    short *p = (short *)spuMem;
    iOff = (iOff) + rvb.CurrAddr;
    while (iOff > 0x3FFFF) iOff = rvb.StartAddr + (iOff - 0x40000);
    while (iOff < rvb.StartAddr) iOff = 0x3ffff - (rvb.StartAddr - iOff);
    return (int)*(p + iOff);
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::s_buffer(int iOff,
                                      int iVal)  // set_buffer content helper: takes care about wraps and clipping
{
    short *p = (short *)spuMem;
    iOff = (iOff * 4) + rvb.CurrAddr;
    while (iOff > 0x3FFFF) iOff = rvb.StartAddr + (iOff - 0x40000);
    while (iOff < rvb.StartAddr) iOff = 0x3ffff - (rvb.StartAddr - iOff);
    if (iVal < -32768L) iVal = -32768L;
    if (iVal > 32767L) iVal = 32767L;
    *(p + iOff) = (short)iVal;
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::s_buffer1(
    int iOff, int iVal)  // set_buffer (+1 sample) content helper: takes care about wraps and clipping
{
    short *p = (short *)spuMem;
    iOff = (iOff * 4) + rvb.CurrAddr + 1;
    while (iOff > 0x3FFFF) iOff = rvb.StartAddr + (iOff - 0x40000);
    while (iOff < rvb.StartAddr) iOff = 0x3ffff - (rvb.StartAddr - iOff);
    if (iVal < -32768L) iVal = -32768L;
    if (iVal > 32767L) iVal = 32767L;
    *(p + iOff) = (short)iVal;
}

////////////////////////////////////////////////////////////////////////
int PCSX::SPU::impl::DrHellReverb(int ns) {
    static int iCnt = 0;  // this func will be called with 44.1 khz

    if (!rvb.StartAddr)  // reverb is off
    {
        rvb.iLastRVBLeft = rvb.iLastRVBRight = rvb.iRVBLeft = rvb.iRVBRight = 0;
        return 0;
    }

    iCnt++;

    if (iCnt & 1)  // we work on every second left value: downsample to 22 khz
    {
        if (spuCtrl & ControlFlags::ReverbMasterEnable)  // -> reverb on? oki
        {
            /*
             * PlayStation Reverberation Algorithm (C) Dr. Hell, 2005
             * Strictly speaking, the timing of left and right processing is shifted by one sampling time,
             * each run every 2 sampling times
             */
            int32_t z1_Lsame = reverb_regs.mLSAME - 1;
            int32_t z1_Rsame = reverb_regs.mRSAME - 1;
            int32_t z1_Ldiff = reverb_regs.mLDIFF - 1;
            int32_t z1_Rdiff = reverb_regs.mRDIFF - 1;
            int32_t zm_Lapf1 = reverb_regs.mLSAME - reverb_regs.dAPF1;
            int32_t zm_Rapf1 = reverb_regs.mRSAME - reverb_regs.dAPF1;
            int32_t zm_Lapf2 = reverb_regs.mLAPF2 - reverb_regs.dAPF2;
            int32_t zm_Rapf2 = reverb_regs.mRAPF2 - reverb_regs.dAPF2;

            /*
             * LoadFromLowPassFilter is a 35 or 39 tap FIR filter
             * Even if the outermost coefficient is 0, the result is the same, so it is not possible to determine
             * whether it is 35 or 39.
             */
            const int INPUT_SAMPLE_L = *(sRVBStart + (ns << 1));
            const int INPUT_SAMPLE_R = *(sRVBStart + (ns << 1) + 1);

            int L_in = (INPUT_SAMPLE_L * reverb_regs.vLIN);
            int R_in = (INPUT_SAMPLE_R * reverb_regs.vRIN);

            /*
             * Left -> Wall -> Left Reflection
             */
            int32_t L_temp = g_bufferdrhell(reverb_regs.dLSAME);
            int32_t R_temp = g_bufferdrhell(reverb_regs.dRSAME);
            int32_t L_same = L_in + ((reverb_regs.vWALL * L_temp) / 32768L);
            int32_t R_same = R_in + ((reverb_regs.vWALL * R_temp) / 32768L);
            L_temp = g_bufferdrhell(z1_Lsame);
            R_temp = g_bufferdrhell(z1_Rsame);
            L_same = L_temp + ((reverb_regs.vIIR * (L_same - L_temp)) / 32768L);
            R_same = R_temp + ((reverb_regs.vIIR * (R_same - R_temp)) / 32768L);

            /*
             * Left -> Wall -> Right Reflection
             */
            L_temp = g_bufferdrhell(reverb_regs.dRDIFF);
            R_temp = g_bufferdrhell(reverb_regs.dLDIFF);
            int32_t L_diff = L_in + ((reverb_regs.vWALL * L_temp) / 32768L);
            int32_t R_diff = R_in + ((reverb_regs.vWALL * R_temp) / 32768L);
            L_temp = g_bufferdrhell(z1_Ldiff);
            R_temp = g_bufferdrhell(z1_Rdiff);
            L_diff = L_temp + ((reverb_regs.vIIR * (L_diff - L_temp)) / 32768L);
            R_diff = R_temp + ((reverb_regs.vIIR * (R_diff - R_temp)) / 32768L);

            /*
             * Early Echo (Comb Filter)
             */
            L_in = ((reverb_regs.vCOMB1 * g_bufferdrhell(reverb_regs.mLCOMB1)) / 32768L) +
                   ((reverb_regs.vCOMB2 * g_bufferdrhell(reverb_regs.mLCOMB2)) / 32768L) +
                   ((reverb_regs.vCOMB3 * g_bufferdrhell(reverb_regs.mLCOMB3)) / 32768L) +
                   ((reverb_regs.vCOMB4 * g_bufferdrhell(reverb_regs.mLCOMB4)) / 32768L);
            R_in = ((reverb_regs.vCOMB1 * g_bufferdrhell(reverb_regs.mRCOMB1)) / 32768L) +
                   ((reverb_regs.vCOMB2 * g_bufferdrhell(reverb_regs.mRCOMB2)) / 32768L) +
                   ((reverb_regs.vCOMB3 * g_bufferdrhell(reverb_regs.mRCOMB3)) / 32768L) +
                   ((reverb_regs.vCOMB4 * g_bufferdrhell(reverb_regs.mRCOMB4)) / 32768L);

            /*
             * Late Reverb (Two All Pass Filters)
             */
            L_temp = g_bufferdrhell(zm_Lapf1);
            R_temp = g_bufferdrhell(zm_Rapf1);
            int32_t L_apf1 = L_in - reverb_regs.vAPF1 * L_temp;
            int32_t R_apf1 = R_in - reverb_regs.vAPF1 * R_temp;
            L_in = L_temp + reverb_regs.vAPF1 * L_apf1;
            R_in = R_temp + reverb_regs.vAPF1 * R_apf1;
            L_temp = g_bufferdrhell(zm_Lapf2);
            R_temp = g_bufferdrhell(zm_Rapf2);
            int32_t L_apf2 = L_in - reverb_regs.vAPF2 * L_temp;
            int32_t R_apf2 = R_in - reverb_regs.vAPF2 * R_temp;
            L_in = L_temp + reverb_regs.vAPF2 * L_apf2;
            R_in = R_temp + reverb_regs.vAPF2 * R_apf2;

            /*
             * Output
             */
            // SetOutputL(L_in);
            // SetOutputR(R_in);

            /*
             * Write Buffer
             */
            s_bufferdrhell(reverb_regs.mLSAME, L_same);
            s_bufferdrhell(reverb_regs.mRSAME, R_same);
            s_bufferdrhell(reverb_regs.mLDIFF, L_diff);
            s_bufferdrhell(reverb_regs.mRDIFF, R_diff);
            s_bufferdrhell(reverb_regs.mLAPF1, L_apf1);
            s_bufferdrhell(reverb_regs.mRAPF1, R_apf1);
            s_bufferdrhell(reverb_regs.mLAPF2, L_apf2);
            s_bufferdrhell(reverb_regs.mRAPF2, R_apf2);

            /*
             * Update Circular Buffer
             */
            // UpdateReverbWork();

            rvb.iLastRVBLeft = rvb.iRVBLeft;
            rvb.iLastRVBRight = rvb.iRVBRight;

            rvb.iRVBLeft = (g_bufferdrhell(reverb_regs.mLAPF1) + g_bufferdrhell(reverb_regs.mLAPF2)) / 3;
            rvb.iRVBRight = (g_bufferdrhell(reverb_regs.mRAPF1) + g_bufferdrhell(reverb_regs.mRAPF2)) / 3;

            rvb.iRVBLeft = (rvb.iRVBLeft * rvb.VolLeft) / 0x4000;
            rvb.iRVBRight = (rvb.iRVBRight * rvb.VolRight) / 0x4000;

            rvb.CurrAddr++;
            if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;

            return rvb.iLastRVBLeft + (rvb.iRVBLeft - rvb.iLastRVBLeft) / 2;
        } else  // -> reverb off
        {
            rvb.iLastRVBLeft = rvb.iLastRVBRight = rvb.iRVBLeft = rvb.iRVBRight = 0;
        }

        rvb.CurrAddr++;
        if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;
    }

    return rvb.iLastRVBLeft;
}

int PCSX::SPU::impl::AnotherReverbTest(int ns) {
    if (settings.get<Reverb>() == 0) return 0;

    static int iCnt = 0;  // this func will be called with 44.1 khz

    if (!rvb.StartAddr)  // reverb is off
    {
        rvb.iLastRVBLeft = rvb.iLastRVBRight = rvb.iRVBLeft = rvb.iRVBRight = 0;
        return 0;
    }

    iCnt++;

    if (iCnt & 1)  // we work on every second left value: downsample to 22 khz
    {
        if (spuCtrl & ControlFlags::ReverbMasterEnable)  // -> reverb on? oki
        {
            const int INPUT_SAMPLE_L = *(sRVBStart + (ns << 1));
            const int INPUT_SAMPLE_R = *(sRVBStart + (ns << 1) + 1);
            int LeftInput = *(sRVBStart + (ns << 1));
            int RightInput = *(sRVBStart + (ns << 1) + 1);

            int32_t mAPF1 = rvb.FB_SRC_A * 4;
            int32_t mAPF2 = rvb.FB_SRC_B * 4;
            double gIIR = rvb.IIR_ALPHA / 32768.0;
            double gCOMB1 = rvb.ACC_COEF_A / 32768.0;
            double gCOMB2 = rvb.ACC_COEF_B / 32768.0;
            double gCOMB3 = rvb.ACC_COEF_C / 32768.0;
            double gCOMB4 = rvb.ACC_COEF_D / 32768.0;
            double gWALL = rvb.IIR_COEF / 32768.0;
            double gAPF1 = rvb.FB_ALPHA / 32768.0;
            double gAPF2 = rvb.FB_X / 32768.0;
            int32_t z0_Lsame = rvb.IIR_DEST_A0 * 4;
            int32_t z0_Rsame = rvb.IIR_DEST_A1 * 4;
            int32_t m1_Lcomb = rvb.ACC_SRC_A0 * 4;
            int32_t m1_Rcomb = rvb.ACC_SRC_A1 * 4;
            int32_t m2_Lcomb = rvb.ACC_SRC_B0 * 4;
            int32_t m2_Rcomb = rvb.ACC_SRC_B1 * 4;
            int32_t zm_Lsame = rvb.IIR_SRC_A0 * 4;
            int32_t zm_Rsame = rvb.IIR_SRC_A1 * 4;
            int32_t z0_Ldiff = rvb.IIR_DEST_B0 * 4;
            int32_t z0_Rdiff = rvb.IIR_DEST_B1 * 4;
            int32_t m3_Lcomb = rvb.ACC_SRC_C0 * 4;
            int32_t m3_Rcomb = rvb.ACC_SRC_C1 * 4;
            int32_t m4_Lcomb = rvb.ACC_SRC_D0 * 4;
            int32_t m4_Rcomb = rvb.ACC_SRC_D1 * 4;
            int32_t zm_Ldiff = rvb.IIR_SRC_B1 * 4;
            int32_t zm_Rdiff = rvb.IIR_SRC_B0 * 4;
            int32_t z0_Lapf1 = rvb.MIX_DEST_A0 * 4;
            int32_t z0_Rapf1 = rvb.MIX_DEST_A1 * 4;
            int32_t z0_Lapf2 = rvb.MIX_DEST_B0 * 4;
            int32_t z0_Rapf2 = rvb.MIX_DEST_B1 * 4;
            double gLIN = rvb.IN_COEF_L / 32768.0;
            double gRIN = rvb.IN_COEF_R / 32768.0;
            int32_t z1_Lsame = z0_Lsame - 1;
            int32_t z1_Rsame = z0_Rsame - 1;
            int32_t z1_Ldiff = z0_Ldiff - 1;
            int32_t z1_Rdiff = z0_Rdiff - 1;
            int32_t zm_Lapf1 = z0_Lapf1 - mAPF1;
            int32_t zm_Rapf1 = z0_Rapf1 - mAPF1;
            int32_t zm_Lapf2 = z0_Lapf2 - mAPF2;
            int32_t zm_Rapf2 = z0_Rapf2 - mAPF2;

            // ___Input from Mixer (Input volume multiplied with incoming data)_____________
            int L_in = rvb.IN_COEF_L * LeftInput;   // from any channels that have Reverb enabled
            int R_in = rvb.IN_COEF_R * RightInput;  // from any channels that have Reverb enabled

            /*
             * Left -> Wall -> Left Reflection
             */
            int32_t L_temp = g_bufferdrhell(zm_Lsame);
            int32_t R_temp = g_bufferdrhell(zm_Rsame);
            int32_t L_same = L_in + (gWALL * L_temp);
            int32_t R_same = R_in + (gWALL * R_temp);
            L_temp = g_bufferdrhell(z1_Lsame);
            R_temp = g_bufferdrhell(z1_Rsame);
            L_same = L_temp + gIIR * (L_same - L_temp);
            R_same = R_temp + gIIR * (R_same - R_temp);

            /*
             * Left -> Wall -> Right Reflection
             */
            L_temp = g_bufferdrhell(zm_Rdiff);
            R_temp = g_bufferdrhell(zm_Ldiff);
            int32_t L_diff = L_in + gWALL * L_temp;
            int32_t R_diff = R_in + gWALL * R_temp;
            L_temp = g_bufferdrhell(z1_Ldiff);
            R_temp = g_bufferdrhell(z1_Rdiff);
            L_diff = L_temp + gIIR * (L_diff - L_temp);
            R_diff = R_temp + gIIR * (R_diff - R_temp);

            /*
             * Early Echo (Comb Filter)
             */
            L_in = gCOMB1 * g_bufferdrhell(m1_Lcomb) + gCOMB2 * g_bufferdrhell(m2_Lcomb) +
                   gCOMB3 * g_bufferdrhell(m3_Lcomb) + gCOMB4 * g_bufferdrhell(m4_Lcomb);
            R_in = gCOMB1 * g_bufferdrhell(m1_Rcomb) + gCOMB2 * g_bufferdrhell(m2_Rcomb) +
                   gCOMB3 * g_bufferdrhell(m3_Rcomb) + gCOMB4 * g_bufferdrhell(m4_Rcomb);

            /*
             * Late Reverb (Two All Pass Filters)
             */
            L_temp = g_bufferdrhell(zm_Lapf1);
            R_temp = g_bufferdrhell(zm_Rapf1);
            int32_t L_apf1 = L_in - gAPF1 * L_temp;
            int32_t R_apf1 = R_in - gAPF1 * R_temp;
            L_in = L_temp + gAPF1 * L_apf1;
            R_in = R_temp + gAPF1 * R_apf1;
            L_temp = g_bufferdrhell(zm_Lapf2);
            R_temp = g_bufferdrhell(zm_Rapf2);
            int32_t L_apf2 = L_in - gAPF2 * L_temp;
            int32_t R_apf2 = R_in - gAPF2 * R_temp;
            L_in = L_temp + gAPF2 * L_apf2;
            R_in = R_temp + gAPF2 * R_apf2;

            /*
             * Output
             */
            // SetOutputL(L_in);
            // SetOutputR(R_in);

            int ACC0, ACC1, FB_A0, FB_A1, FB_B0, FB_B1;

            const int IIR_INPUT_A0 =
                (g_buffer(rvb.IIR_SRC_A0) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_L * rvb.IN_COEF_L) / 32768L;
            const int IIR_INPUT_A1 =
                (g_buffer(rvb.IIR_SRC_A1) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_R * rvb.IN_COEF_R) / 32768L;
            const int IIR_INPUT_B0 =
                (g_buffer(rvb.IIR_SRC_B0) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_L * rvb.IN_COEF_L) / 32768L;
            const int IIR_INPUT_B1 =
                (g_buffer(rvb.IIR_SRC_B1) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_R * rvb.IN_COEF_R) / 32768L;

            const int IIR_A0 = (IIR_INPUT_A0 * rvb.IIR_ALPHA) / 32768L +
                               (g_buffer(rvb.IIR_DEST_A0) * (32768L - rvb.IIR_ALPHA)) / 32768L;
            const int IIR_A1 = (IIR_INPUT_A1 * rvb.IIR_ALPHA) / 32768L +
                               (g_buffer(rvb.IIR_DEST_A1) * (32768L - rvb.IIR_ALPHA)) / 32768L;
            const int IIR_B0 = (IIR_INPUT_B0 * rvb.IIR_ALPHA) / 32768L +
                               (g_buffer(rvb.IIR_DEST_B0) * (32768L - rvb.IIR_ALPHA)) / 32768L;
            const int IIR_B1 = (IIR_INPUT_B1 * rvb.IIR_ALPHA) / 32768L +
                               (g_buffer(rvb.IIR_DEST_B1) * (32768L - rvb.IIR_ALPHA)) / 32768L;

            ACC0 = (g_buffer(rvb.ACC_SRC_A0) * rvb.ACC_COEF_A) / 32768L +
                   (g_buffer(rvb.ACC_SRC_B0) * rvb.ACC_COEF_B) / 32768L +
                   (g_buffer(rvb.ACC_SRC_C0) * rvb.ACC_COEF_C) / 32768L +
                   (g_buffer(rvb.ACC_SRC_D0) * rvb.ACC_COEF_D) / 32768L;
            ACC1 = (g_buffer(rvb.ACC_SRC_A1) * rvb.ACC_COEF_A) / 32768L +
                   (g_buffer(rvb.ACC_SRC_B1) * rvb.ACC_COEF_B) / 32768L +
                   (g_buffer(rvb.ACC_SRC_C1) * rvb.ACC_COEF_C) / 32768L +
                   (g_buffer(rvb.ACC_SRC_D1) * rvb.ACC_COEF_D) / 32768L;

            FB_A0 = g_buffer(rvb.MIX_DEST_A0 - rvb.FB_SRC_A);
            FB_A1 = g_buffer(rvb.MIX_DEST_A1 - rvb.FB_SRC_A);
            FB_B0 = g_buffer(rvb.MIX_DEST_B0 - rvb.FB_SRC_B);
            FB_B1 = g_buffer(rvb.MIX_DEST_B1 - rvb.FB_SRC_B);

            // s_buffer1(rvb.IIR_DEST_A0, IIR_A0);
            // s_buffer1(rvb.IIR_DEST_A1, IIR_A1);
            // s_buffer1(rvb.IIR_DEST_B0, IIR_B0);
            // s_buffer1(rvb.IIR_DEST_B1, IIR_B1);
            //  s_buffer(rvb.MIX_DEST_A0, ACC0 - (FB_A0 * rvb.FB_ALPHA) / 32768L);
            //  s_buffer(rvb.MIX_DEST_A1, ACC1 - (FB_A1 * rvb.FB_ALPHA) / 32768L);

            // s_buffer(rvb.MIX_DEST_B0, (rvb.FB_ALPHA * ACC0) / 32768L -
            //                               (FB_A0 * (int)(rvb.FB_ALPHA ^ 0xFFFF8000)) / 32768L -
            //                               (FB_B0 * rvb.FB_X) / 32768L);
            // s_buffer(rvb.MIX_DEST_B1, (rvb.FB_ALPHA * ACC1) / 32768L -
            //                               (FB_A1 * (int)(rvb.FB_ALPHA ^ 0xFFFF8000)) / 32768L -
            //                               (FB_B1 * rvb.FB_X) / 32768L);

            /*
             * Write Buffer
             */
            // s_buffer1(rvb.IIR_DEST_A0, IIR_A0);
            s_bufferdrhell(z0_Lsame, L_same / 32768L);

            // s_buffer1(rvb.IIR_DEST_A1, IIR_A1);
            s_bufferdrhell(z0_Rsame, R_same / 32768L);

            // s_buffer1(rvb.IIR_DEST_B0, IIR_B0);
            s_bufferdrhell(z0_Ldiff, L_diff / 32768L);

            // s_buffer1(rvb.IIR_DEST_B1, IIR_B1);
            s_bufferdrhell(z0_Rdiff, R_diff / 32768L);

            s_bufferdrhell(z0_Lapf1, L_apf1);
            s_bufferdrhell(z0_Rapf1, R_apf1);
            s_bufferdrhell(z0_Lapf2, L_apf2);
            s_bufferdrhell(z0_Rapf2, R_apf2);

            rvb.iLastRVBLeft = rvb.iRVBLeft;
            rvb.iLastRVBRight = rvb.iRVBRight;

            rvb.iRVBLeft = (g_buffer(rvb.MIX_DEST_A0) + g_buffer(rvb.MIX_DEST_B0)) / 3;
            rvb.iRVBRight = (g_buffer(rvb.MIX_DEST_A1) + g_buffer(rvb.MIX_DEST_B1)) / 3;

            rvb.iRVBLeft = (rvb.iRVBLeft * rvb.VolLeft) / 0x4000;
            rvb.iRVBRight = (rvb.iRVBRight * rvb.VolRight) / 0x4000;

            rvb.CurrAddr++;
            if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;

            return rvb.iLastRVBLeft + (rvb.iRVBLeft - rvb.iLastRVBLeft) / 2;
        } else  // -> reverb off
        {
            rvb.iLastRVBLeft = rvb.iLastRVBRight = rvb.iRVBLeft = rvb.iRVBRight = 0;
        }

        rvb.CurrAddr++;
        if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;
    }

    return rvb.iLastRVBLeft;
}

int PCSX::SPU::impl::NoCashReverb(int ns) {
    static int iCnt = 0;  // this func will be called with 44.1 khz

    if (!rvb.StartAddr)  // reverb is off
    {
        rvb.iLastRVBLeft = rvb.iLastRVBRight = rvb.iRVBLeft = rvb.iRVBRight = 0;
        return 0;
    }

    iCnt++;

    if (iCnt & 1)  // we work on every second left value: downsample to 22 khz
    {
        if (spuCtrl & ControlFlags::ReverbMasterEnable)  // -> reverb on? oki
        {
            const int INPUT_SAMPLE_L = *(sRVBStart + (ns << 1));
            const int INPUT_SAMPLE_R = *(sRVBStart + (ns << 1) + 1);

            int L_in = (INPUT_SAMPLE_L * reverb_regs.vLIN);
            int R_in = (INPUT_SAMPLE_R * reverb_regs.vRIN);

            int32_t Lout;
            int32_t Rout;

            int32_t mLSAME = g_bufferdrhell(reverb_regs.mLSAME);
            int32_t mLSAME2 = g_bufferdrhell(reverb_regs.mLSAME - 2);
            int32_t notmlsame = g_buffer(rvb.IIR_DEST_A0);

            if (notmlsame || mLSAME || mLSAME2) {
                notmlsame = notmlsame + 0;
            }

            int32_t mRSAME = g_bufferdrhell(reverb_regs.mRSAME);
            int32_t mRSAME2 = g_bufferdrhell(reverb_regs.mRSAME - 2);

            int32_t mLDIFF = g_bufferdrhell(reverb_regs.mLDIFF);
            int32_t mLDIFF2 = g_bufferdrhell(reverb_regs.mLDIFF - 2);

            int32_t mRDIFF = g_bufferdrhell(reverb_regs.mRDIFF);
            int32_t mRDIFF2 = g_bufferdrhell(reverb_regs.mRDIFF - 2);

            int32_t dLSAME = g_bufferdrhell(reverb_regs.dLSAME);
            int32_t dRSAME = g_bufferdrhell(reverb_regs.dRSAME);

            int32_t dLDIFF = g_bufferdrhell(reverb_regs.dLDIFF);
            int32_t dRDIFF = g_bufferdrhell(reverb_regs.dRDIFF);

            int32_t mLCOMB1 = g_bufferdrhell(reverb_regs.mLCOMB1);
            int32_t mRCOMB1 = g_bufferdrhell(reverb_regs.mRCOMB1);
            int32_t mLCOMB2 = g_bufferdrhell(reverb_regs.mLCOMB2);
            int32_t mRCOMB2 = g_bufferdrhell(reverb_regs.mRCOMB2);
            int32_t mLCOMB3 = g_bufferdrhell(reverb_regs.mLCOMB3);
            int32_t mRCOMB3 = g_bufferdrhell(reverb_regs.mRCOMB3);
            int32_t mLCOMB4 = g_bufferdrhell(reverb_regs.mLCOMB4);
            int32_t mRCOMB4 = g_bufferdrhell(reverb_regs.mRCOMB4);

            int32_t APFL1 = g_bufferdrhell(reverb_regs.mLAPF1 - reverb_regs.dAPF1);
            int32_t APFR1 = g_bufferdrhell(reverb_regs.mRAPF1 - reverb_regs.dAPF1);
            int32_t APFL2 = g_bufferdrhell(reverb_regs.mLAPF2 - reverb_regs.dAPF2);
            int32_t APFR2 = g_bufferdrhell(reverb_regs.mRAPF2 - reverb_regs.dAPF2);

            // Same Side Reflection(left - to - left and right - to - right)

            // L-to-L
            s_bufferdrhell(reverb_regs.mLSAME,
                           (L_in + dLSAME * reverb_regs.vWALL - mLSAME2) * reverb_regs.vIIR + mLSAME2);

            // R-to-R
            s_bufferdrhell(reverb_regs.mRSAME,
                           (R_in + dRSAME * reverb_regs.vWALL - mRSAME2) * reverb_regs.vIIR + mRSAME2);

            // Different Side Reflection(left - to - right and right - to - left)
            s_bufferdrhell(reverb_regs.mLDIFF,
                           (L_in + dRDIFF * reverb_regs.vWALL - mLDIFF2) * reverb_regs.vIIR + mLDIFF2);
            s_bufferdrhell(reverb_regs.mRDIFF,
                           (R_in + dLDIFF * reverb_regs.vWALL - mRDIFF2) * reverb_regs.vIIR + mRDIFF2);

            // Early Echo (Comb Filter, with input from buffer)
            Lout = reverb_regs.vCOMB1 * mLCOMB1 + reverb_regs.vCOMB2 * mLCOMB2 + reverb_regs.vCOMB3 * mLCOMB3 +
                   reverb_regs.vCOMB4 * mLCOMB4;

            Rout = reverb_regs.vCOMB1 * mRCOMB1 + reverb_regs.vCOMB2 * mRCOMB2 + reverb_regs.vCOMB3 * mRCOMB3 +
                   reverb_regs.vCOMB4 * mRCOMB4;

            // Late Reverb APF1 (All Pass Filter 1, with input from COMB)________________
            Lout = Lout - reverb_regs.vAPF1 * APFL1;
            s_bufferdrhell(reverb_regs.mLAPF1, Lout);
            Lout = Lout * reverb_regs.vAPF1 + APFL1;

            Rout = Rout - reverb_regs.vAPF1 * APFR1;
            s_bufferdrhell(reverb_regs.mRAPF1, Rout);
            Rout = Rout * reverb_regs.vAPF1 + APFR2;

            // Late Reverb APF2 (All Pass Filter 2, with input from APF1)
            Lout = Lout - reverb_regs.vAPF2 * APFL2;
            s_bufferdrhell(reverb_regs.mLAPF2, Lout);
            Lout = Lout * reverb_regs.vAPF2 + APFL2;

            Rout = Rout - reverb_regs.vAPF2 * APFR2;
            s_bufferdrhell(reverb_regs.mRAPF2, Rout);
            Rout = Rout * reverb_regs.vAPF2 + APFR2;

            rvb.iLastRVBLeft = rvb.iRVBLeft;
            rvb.iLastRVBRight = rvb.iRVBRight;

            rvb.iRVBLeft = (g_bufferdrhell(reverb_regs.mLAPF1) + g_bufferdrhell(reverb_regs.mLAPF2)) / 3;
            rvb.iRVBRight = (g_bufferdrhell(reverb_regs.mRAPF1) + g_bufferdrhell(reverb_regs.mRAPF2)) / 3;

            rvb.iRVBLeft = (Lout)*rvb.VolLeft;
            rvb.iRVBRight = (Rout)*rvb.VolRight;

            rvb.CurrAddr++;
            if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;

            return rvb.iLastRVBLeft + (rvb.iRVBLeft - rvb.iLastRVBLeft) / 2;
        } else  // -> reverb off
        {
            rvb.iLastRVBLeft = rvb.iLastRVBRight = rvb.iRVBLeft = rvb.iRVBRight = 0;
        }

        rvb.CurrAddr++;
        if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;
    }

    return rvb.iLastRVBLeft;
}

////////////////////////////////////////////////////////////////////////
int PCSX::SPU::impl::MixREVERBLeft(int ns) {
    if (settings.get<Reverb>() == 0)
        return 0;
    else if (settings.get<Reverb>() == 2) {
        static int iCnt = 0;  // this func will be called with 44.1 khz

        if (!rvb.StartAddr)  // reverb is off
        {
            rvb.iLastRVBLeft = rvb.iLastRVBRight = rvb.iRVBLeft = rvb.iRVBRight = 0;
            return 0;
        }

        iCnt++;

        if (iCnt & 1)  // we work on every second left value: downsample to 22 khz
        {
            if (spuCtrl & ControlFlags::ReverbMasterEnable)  // -> reverb on? oki
            {
                int ACC0, ACC1, FB_A0, FB_A1, FB_B0, FB_B1;

                const int INPUT_SAMPLE_L = *(sRVBStart + (ns << 1));
                const int INPUT_SAMPLE_R = *(sRVBStart + (ns << 1) + 1);

                const int IIR_INPUT_A0 =
                    (g_buffer(rvb.IIR_SRC_A0) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_L * rvb.IN_COEF_L) / 32768L;
                const int IIR_INPUT_A1 =
                    (g_buffer(rvb.IIR_SRC_A1) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_R * rvb.IN_COEF_R) / 32768L;
                const int IIR_INPUT_B0 =
                    (g_buffer(rvb.IIR_SRC_B0) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_L * rvb.IN_COEF_L) / 32768L;
                const int IIR_INPUT_B1 =
                    (g_buffer(rvb.IIR_SRC_B1) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_R * rvb.IN_COEF_R) / 32768L;

                const int IIR_A0 = (IIR_INPUT_A0 * rvb.IIR_ALPHA) / 32768L +
                                   (g_buffer(rvb.IIR_DEST_A0) * (32768L - rvb.IIR_ALPHA)) / 32768L;
                const int IIR_A1 = (IIR_INPUT_A1 * rvb.IIR_ALPHA) / 32768L +
                                   (g_buffer(rvb.IIR_DEST_A1) * (32768L - rvb.IIR_ALPHA)) / 32768L;
                const int IIR_B0 = (IIR_INPUT_B0 * rvb.IIR_ALPHA) / 32768L +
                                   (g_buffer(rvb.IIR_DEST_B0) * (32768L - rvb.IIR_ALPHA)) / 32768L;
                const int IIR_B1 = (IIR_INPUT_B1 * rvb.IIR_ALPHA) / 32768L +
                                   (g_buffer(rvb.IIR_DEST_B1) * (32768L - rvb.IIR_ALPHA)) / 32768L;

                s_buffer1(rvb.IIR_DEST_A0, IIR_A0);
                s_buffer1(rvb.IIR_DEST_A1, IIR_A1);
                s_buffer1(rvb.IIR_DEST_B0, IIR_B0);
                s_buffer1(rvb.IIR_DEST_B1, IIR_B1);

                ACC0 = (g_buffer(rvb.ACC_SRC_A0) * rvb.ACC_COEF_A) / 32768L +
                       (g_buffer(rvb.ACC_SRC_B0) * rvb.ACC_COEF_B) / 32768L +
                       (g_buffer(rvb.ACC_SRC_C0) * rvb.ACC_COEF_C) / 32768L +
                       (g_buffer(rvb.ACC_SRC_D0) * rvb.ACC_COEF_D) / 32768L;
                ACC1 = (g_buffer(rvb.ACC_SRC_A1) * rvb.ACC_COEF_A) / 32768L +
                       (g_buffer(rvb.ACC_SRC_B1) * rvb.ACC_COEF_B) / 32768L +
                       (g_buffer(rvb.ACC_SRC_C1) * rvb.ACC_COEF_C) / 32768L +
                       (g_buffer(rvb.ACC_SRC_D1) * rvb.ACC_COEF_D) / 32768L;

                FB_A0 = g_buffer(rvb.MIX_DEST_A0 - rvb.FB_SRC_A);
                FB_A1 = g_buffer(rvb.MIX_DEST_A1 - rvb.FB_SRC_A);
                FB_B0 = g_buffer(rvb.MIX_DEST_B0 - rvb.FB_SRC_B);
                FB_B1 = g_buffer(rvb.MIX_DEST_B1 - rvb.FB_SRC_B);

                s_buffer(rvb.MIX_DEST_A0, ACC0 - (FB_A0 * rvb.FB_ALPHA) / 32768L);
                s_buffer(rvb.MIX_DEST_A1, ACC1 - (FB_A1 * rvb.FB_ALPHA) / 32768L);

                s_buffer(rvb.MIX_DEST_B0, (rvb.FB_ALPHA * ACC0) / 32768L -
                                              (FB_A0 * (int)(rvb.FB_ALPHA ^ 0xFFFF8000)) / 32768L -
                                              (FB_B0 * rvb.FB_X) / 32768L);
                s_buffer(rvb.MIX_DEST_B1, (rvb.FB_ALPHA * ACC1) / 32768L -
                                              (FB_A1 * (int)(rvb.FB_ALPHA ^ 0xFFFF8000)) / 32768L -
                                              (FB_B1 * rvb.FB_X) / 32768L);

                rvb.iLastRVBLeft = rvb.iRVBLeft;
                rvb.iLastRVBRight = rvb.iRVBRight;

                rvb.iRVBLeft = (g_buffer(rvb.MIX_DEST_A0) + g_buffer(rvb.MIX_DEST_B0)) / 3;
                rvb.iRVBRight = (g_buffer(rvb.MIX_DEST_A1) + g_buffer(rvb.MIX_DEST_B1)) / 3;

                rvb.iRVBLeft = (rvb.iRVBLeft * rvb.VolLeft) / 0x4000;
                rvb.iRVBRight = (rvb.iRVBRight * rvb.VolRight) / 0x4000;

                rvb.CurrAddr++;
                if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;

                return rvb.iLastRVBLeft + (rvb.iRVBLeft - rvb.iLastRVBLeft) / 2;
            } else  // -> reverb off
            {
                rvb.iLastRVBLeft = rvb.iLastRVBRight = rvb.iRVBLeft = rvb.iRVBRight = 0;
            }

            rvb.CurrAddr++;
            if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;
        }

        return rvb.iLastRVBLeft;
    } else if (settings.get<Reverb>() == 3) {
        // return DrHellReverb(ns);
        //  return NoCashReverb(ns);
        return AnotherReverbTest(ns);
    } else  // easy fake reverb:
    {
        const int iRV = *sRVBPlay;                      // -> simply take the reverb mix buf value
        *sRVBPlay++ = 0;                                // -> init it after
        if (sRVBPlay >= sRVBEnd) sRVBPlay = sRVBStart;  // -> and take care about wrap arounds
        return iRV;                                     // -> return reverb mix buf val
    }
}

////////////////////////////////////////////////////////////////////////

int PCSX::SPU::impl::MixREVERBRight() {
    if (settings.get<Reverb>() == 0)
        return 0;
    else if (settings.get<Reverb>() == 2 || settings.get<Reverb>() == 3)  // Neill's reverb:
    {
        int i = rvb.iLastRVBRight + (rvb.iRVBRight - rvb.iLastRVBRight) / 2;
        rvb.iLastRVBRight = rvb.iRVBRight;
        return i;  // -> just return the last right reverb val (little bit scaled by the previous right val)
    } else         // easy fake reverb:
    {
        const int iRV = *sRVBPlay;                      // -> simply take the reverb mix buf value
        *sRVBPlay++ = 0;                                // -> init it after
        if (sRVBPlay >= sRVBEnd) sRVBPlay = sRVBStart;  // -> and take care about wrap arounds
        return iRV;                                     // -> return reverb mix buf val
    }
}

////////////////////////////////////////////////////////////////////////

/*
-----------------------------------------------------------------------------
PSX reverb hardware notes
by Neill Corlett
-----------------------------------------------------------------------------

Yadda yadda disclaimer yadda probably not perfect yadda well it's okay anyway
yadda yadda.

-----------------------------------------------------------------------------

Basics
------

- The reverb buffer is 22khz 16-bit mono PCM.
- It starts at the reverb address given by 1DA2, extends to
  the end of sound RAM, and wraps back to the 1DA2 address.

Setting the address at 1DA2 resets the current reverb work address.

This work address ALWAYS increments every 1/22050 sec., regardless of
whether reverb is enabled (bit 7 of 1DAA set).

And the contents of the reverb buffer ALWAYS play, scaled by the
"reverberation depth left/right" volumes (1D84/1D86).
(which, by the way, appear to be scaled so 3FFF=approx. 1.0, 4000=-1.0)

-----------------------------------------------------------------------------

Register names
--------------

These are probably not their real names.
These are probably not even correct names.
We will use them anyway, because we can.

1DC0: FB_SRC_A       (offset)
1DC2: FB_SRC_B       (offset)
1DC4: IIR_ALPHA      (coef.)
1DC6: ACC_COEF_A     (coef.)
1DC8: ACC_COEF_B     (coef.)
1DCA: ACC_COEF_C     (coef.)
1DCC: ACC_COEF_D     (coef.)
1DCE: IIR_COEF       (coef.)
1DD0: FB_ALPHA       (coef.)
1DD2: FB_X           (coef.)
1DD4: IIR_DEST_A0    (offset)
1DD6: IIR_DEST_A1    (offset)
1DD8: ACC_SRC_A0     (offset)
1DDA: ACC_SRC_A1     (offset)
1DDC: ACC_SRC_B0     (offset)
1DDE: ACC_SRC_B1     (offset)
1DE0: IIR_SRC_A0     (offset)
1DE2: IIR_SRC_A1     (offset)
1DE4: IIR_DEST_B0    (offset)
1DE6: IIR_DEST_B1    (offset)
1DE8: ACC_SRC_C0     (offset)
1DEA: ACC_SRC_C1     (offset)
1DEC: ACC_SRC_D0     (offset)
1DEE: ACC_SRC_D1     (offset)
1DF0: IIR_SRC_B1     (offset)
1DF2: IIR_SRC_B0     (offset)
1DF4: MIX_DEST_A0    (offset)
1DF6: MIX_DEST_A1    (offset)
1DF8: MIX_DEST_B0    (offset)
1DFA: MIX_DEST_B1    (offset)
1DFC: IN_COEF_L      (coef.)
1DFE: IN_COEF_R      (coef.)

The coefficients are signed fractional values.
-32768 would be -1.0
 32768 would be  1.0 (if it were possible... the highest is of course 32767)

The offsets are (byte/8) offsets into the reverb buffer.
i.e. you multiply them by 8, you get byte offsets.
You can also think of them as (samples/4) offsets.
They appear to be signed.  They can be negative.
None of the documented presets make them negative, though.

Yes, 1DF0 and 1DF2 appear to be backwards.  Not a typo.

-----------------------------------------------------------------------------

What it does
------------

We take all reverb sources:
- regular channels that have the reverb bit on
- cd and external sources, if their reverb bits are on
and mix them into one stereo 44100hz signal.

Lowpass/downsample that to 22050hz.  The PSX uses a proper bandlimiting
algorithm here, but I haven't figured out the hysterically exact specifics.
I use an 8-tap filter with these coefficients, which are nice but probably
not the real ones:

0.037828187894
0.157538631280
0.321159685278
0.449322115345
0.449322115345
0.321159685278
0.157538631280
0.037828187894

So we have two input samples (INPUT_SAMPLE_L, INPUT_SAMPLE_R) every 22050hz.

* IN MY EMULATION, I divide these by 2 to make it clip less.
  (and of course the L/R output coefficients are adjusted to compensate)
  The real thing appears to not do this.

At every 22050hz tick:
- If the reverb bit is enabled (bit 7 of 1DAA), execute the reverb
  steady-state algorithm described below
- AFTERWARDS, retrieve the "wet out" L and R samples from the reverb buffer
  (This part may not be exactly right and I guessed at the coefs. TODO: check later.)
  L is: 0.333 * (buffer[MIX_DEST_A0] + buffer[MIX_DEST_B0])
  R is: 0.333 * (buffer[MIX_DEST_A1] + buffer[MIX_DEST_B1])
- Advance the current buffer position by 1 sample

The wet out L and R are then upsampled to 44100hz and played at the
"reverberation depth left/right" (1D84/1D86) volume, independent of the main
volume.

-----------------------------------------------------------------------------

Reverb steady-state
-------------------

The reverb steady-state algorithm is fairly clever, and of course by
"clever" I mean "batshit insane".

buffer[x] is relative to the current buffer position, not the beginning of
the buffer.  Note that all buffer offsets must wrap around so they're
contained within the reverb work area.

Clipping is performed at the end... maybe also sooner, but definitely at
the end.

IIR_INPUT_A0 = buffer[IIR_SRC_A0] * IIR_COEF + INPUT_SAMPLE_L * IN_COEF_L;
IIR_INPUT_A1 = buffer[IIR_SRC_A1] * IIR_COEF + INPUT_SAMPLE_R * IN_COEF_R;
IIR_INPUT_B0 = buffer[IIR_SRC_B0] * IIR_COEF + INPUT_SAMPLE_L * IN_COEF_L;
IIR_INPUT_B1 = buffer[IIR_SRC_B1] * IIR_COEF + INPUT_SAMPLE_R * IN_COEF_R;

IIR_A0 = IIR_INPUT_A0 * IIR_ALPHA + buffer[IIR_DEST_A0] * (1.0 - IIR_ALPHA);
IIR_A1 = IIR_INPUT_A1 * IIR_ALPHA + buffer[IIR_DEST_A1] * (1.0 - IIR_ALPHA);
IIR_B0 = IIR_INPUT_B0 * IIR_ALPHA + buffer[IIR_DEST_B0] * (1.0 - IIR_ALPHA);
IIR_B1 = IIR_INPUT_B1 * IIR_ALPHA + buffer[IIR_DEST_B1] * (1.0 - IIR_ALPHA);

buffer[IIR_DEST_A0 + 1sample] = IIR_A0;
buffer[IIR_DEST_A1 + 1sample] = IIR_A1;
buffer[IIR_DEST_B0 + 1sample] = IIR_B0;
buffer[IIR_DEST_B1 + 1sample] = IIR_B1;

ACC0 = buffer[ACC_SRC_A0] * ACC_COEF_A +
       buffer[ACC_SRC_B0] * ACC_COEF_B +
       buffer[ACC_SRC_C0] * ACC_COEF_C +
       buffer[ACC_SRC_D0] * ACC_COEF_D;
ACC1 = buffer[ACC_SRC_A1] * ACC_COEF_A +
       buffer[ACC_SRC_B1] * ACC_COEF_B +
       buffer[ACC_SRC_C1] * ACC_COEF_C +
       buffer[ACC_SRC_D1] * ACC_COEF_D;

FB_A0 = buffer[MIX_DEST_A0 - FB_SRC_A];
FB_A1 = buffer[MIX_DEST_A1 - FB_SRC_A];
FB_B0 = buffer[MIX_DEST_B0 - FB_SRC_B];
FB_B1 = buffer[MIX_DEST_B1 - FB_SRC_B];

buffer[MIX_DEST_A0] = ACC0 - FB_A0 * FB_ALPHA;
buffer[MIX_DEST_A1] = ACC1 - FB_A1 * FB_ALPHA;
buffer[MIX_DEST_B0] = (FB_ALPHA * ACC0) - FB_A0 * (FB_ALPHA^0x8000) - FB_B0 * FB_X;
buffer[MIX_DEST_B1] = (FB_ALPHA * ACC1) - FB_A1 * (FB_ALPHA^0x8000) - FB_B1 * FB_X;

-----------------------------------------------------------------------------
*/
