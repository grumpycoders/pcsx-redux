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
 * XA audio decoding functions (Kazzuya).
 */

#include "core/decode_xa.h"

//#define FIXED

#define NOT(_X_) (!(_X_))
#define XACLAMP(_X_, _MI_, _MA_)    \
    {                               \
        if (_X_ < _MI_) _X_ = _MI_; \
        if (_X_ > _MA_) _X_ = _MA_; \
    }

#define SH 4
#define SHC 10

//============================================
//===  ADPCM DECODING ROUTINES
//============================================

#ifndef FIXED
static const double s_K0[4] = {0.0, 0.9375, 1.796875, 1.53125};

static const double s_K1[4] = {0.0, 0.0, -0.8125, -0.859375};
#else
static const int s_K0[4] = {0.0 * (1 << SHC), 0.9375 * (1 << SHC), 1.796875 * (1 << SHC), 1.53125 * (1 << SHC)};

static const int s_K1[4] = {0.0 * (1 << SHC), 0.0 * (1 << SHC), -0.8125 * (1 << SHC), -0.859375 * (1 << SHC)};
#endif

#define BLKSIZ 28 /* block size (32 - 4 nibbles) */

//===========================================
static void ADPCM_InitDecode(ADPCM_Decode_t *decp) {
    decp->y0 = 0;
    decp->y1 = 0;
}

//===========================================
#ifndef FIXED
#define IK0(fid) ((int)((-s_K0[fid]) * (1 << SHC)))
#define IK1(fid) ((int)((-s_K1[fid]) * (1 << SHC)))
#else
#define IK0(fid) (-s_K0[fid])
#define IK1(fid) (-s_K1[fid])
#endif

static inline void ADPCM_DecodeBlock16(ADPCM_Decode_t *decp, uint8_t filter_range, const void *vblockp, short *destp,
                                       int inc) {
    int i;
    int range, filterid;
    int32_t fy0, fy1;
    const uint16_t *blockp;

    blockp = (const unsigned short *)vblockp;
    filterid = (filter_range >> 4) & 0x0f;
    range = (filter_range >> 0) & 0x0f;

    fy0 = decp->y0;
    fy1 = decp->y1;

    for (i = BLKSIZ / 4; i; --i) {
        int32_t y;
        int32_t x0, x1, x2, x3;

        y = *blockp++;
        x3 = (short)(y & 0xf000) >> range;
        x3 <<= SH;
        x2 = (short)((y << 4) & 0xf000) >> range;
        x2 <<= SH;
        x1 = (short)((y << 8) & 0xf000) >> range;
        x1 <<= SH;
        x0 = (short)((y << 12) & 0xf000) >> range;
        x0 <<= SH;

        x0 -= (IK0(filterid) * fy0 + (IK1(filterid) * fy1)) >> SHC;
        fy1 = fy0;
        fy0 = x0;
        x1 -= (IK0(filterid) * fy0 + (IK1(filterid) * fy1)) >> SHC;
        fy1 = fy0;
        fy0 = x1;
        x2 -= (IK0(filterid) * fy0 + (IK1(filterid) * fy1)) >> SHC;
        fy1 = fy0;
        fy0 = x2;
        x3 -= (IK0(filterid) * fy0 + (IK1(filterid) * fy1)) >> SHC;
        fy1 = fy0;
        fy0 = x3;

        XACLAMP(x0, -32768 << SH, 32767 << SH);
        *destp = x0 >> SH;
        destp += inc;
        XACLAMP(x1, -32768 << SH, 32767 << SH);
        *destp = x1 >> SH;
        destp += inc;
        XACLAMP(x2, -32768 << SH, 32767 << SH);
        *destp = x2 >> SH;
        destp += inc;
        XACLAMP(x3, -32768 << SH, 32767 << SH);
        *destp = x3 >> SH;
        destp += inc;
    }
    decp->y0 = fy0;
    decp->y1 = fy1;
}

static const int s_headtable[4] = {0, 2, 8, 10};

//===========================================
static void xa_decode_data(xa_decode_t *xdp, unsigned char *srcp) {
    const uint8_t *sound_groupsp;
    const uint8_t *sound_datap, *sound_datap2;
    int i, j, k, nbits;
    uint16_t data[4096], *datap;
    short *destp;

    destp = xdp->pcm;
    nbits = xdp->nbits == 4 ? 4 : 2;

    if (xdp->stereo) {                                    // stereo
        if ((xdp->nbits == 8) && (xdp->freq == 37800)) {  // level A
            for (j = 0; j < 18; j++) {
                sound_groupsp = srcp + j * 128;    // sound groups header
                sound_datap = sound_groupsp + 16;  // sound data just after the header

                for (i = 0; i < nbits; i++) {
                    datap = data;
                    sound_datap2 = sound_datap + i;

                    for (k = 0; k < 14; k++, sound_datap2 += 8) {
                        *(datap++) = (uint16_t)sound_datap2[0] | (uint16_t)(sound_datap2[4] << 8);
                    }

                    ADPCM_DecodeBlock16(&xdp->left, sound_groupsp[s_headtable[i] + 0], data, destp + 0, 2);

                    datap = data;
                    sound_datap2 = sound_datap + i;
                    for (k = 0; k < 14; k++, sound_datap2 += 8) {
                        *(datap++) = (uint16_t)sound_datap2[0] | (uint16_t)(sound_datap2[4] << 8);
                    }
                    ADPCM_DecodeBlock16(&xdp->right, sound_groupsp[s_headtable[i] + 1], data, destp + 1, 2);

                    destp += 28 * 2;
                }
            }
        } else {  // level B/C
            for (j = 0; j < 18; j++) {
                sound_groupsp = srcp + j * 128;    // sound groups header
                sound_datap = sound_groupsp + 16;  // sound data just after the header

                for (i = 0; i < nbits; i++) {
                    datap = data;
                    sound_datap2 = sound_datap + i;

                    for (k = 0; k < 7; k++, sound_datap2 += 16) {
                        *(datap++) = (uint16_t)(sound_datap2[0] & 0x0f) | ((uint16_t)(sound_datap2[4] & 0x0f) << 4) |
                                     ((uint16_t)(sound_datap2[8] & 0x0f) << 8) |
                                     ((uint16_t)(sound_datap2[12] & 0x0f) << 12);
                    }
                    ADPCM_DecodeBlock16(&xdp->left, sound_groupsp[s_headtable[i] + 0], data, destp + 0, 2);

                    datap = data;
                    sound_datap2 = sound_datap + i;
                    for (k = 0; k < 7; k++, sound_datap2 += 16) {
                        *(datap++) = (uint16_t)(sound_datap2[0] >> 4) | ((uint16_t)(sound_datap2[4] >> 4) << 4) |
                                     ((uint16_t)(sound_datap2[8] >> 4) << 8) |
                                     ((uint16_t)(sound_datap2[12] >> 4) << 12);
                    }
                    ADPCM_DecodeBlock16(&xdp->right, sound_groupsp[s_headtable[i] + 1], data, destp + 1, 2);

                    destp += 28 * 2;
                }
            }
        }
    } else {                                              // mono
        if ((xdp->nbits == 8) && (xdp->freq == 37800)) {  // level A
            for (j = 0; j < 18; j++) {
                sound_groupsp = srcp + j * 128;    // sound groups header
                sound_datap = sound_groupsp + 16;  // sound data just after the header

                for (i = 0; i < nbits; i++) {
                    datap = data;
                    sound_datap2 = sound_datap + i;
                    for (k = 0; k < 14; k++, sound_datap2 += 8) {
                        *(datap++) = (uint16_t)sound_datap2[0] | (uint16_t)(sound_datap2[4] << 8);
                    }
                    ADPCM_DecodeBlock16(&xdp->left, sound_groupsp[s_headtable[i] + 0], data, destp, 1);

                    destp += 28;

                    datap = data;
                    sound_datap2 = sound_datap + i;
                    for (k = 0; k < 14; k++, sound_datap2 += 8) {
                        *(datap++) = (uint16_t)sound_datap2[0] | (uint16_t)(sound_datap2[4] << 8);
                    }
                    ADPCM_DecodeBlock16(&xdp->left, sound_groupsp[s_headtable[i] + 1], data, destp, 1);

                    destp += 28;
                }
            }
        } else {  // level B/C
            for (j = 0; j < 18; j++) {
                sound_groupsp = srcp + j * 128;    // sound groups header
                sound_datap = sound_groupsp + 16;  // sound data just after the header

                for (i = 0; i < nbits; i++) {
                    datap = data;
                    sound_datap2 = sound_datap + i;
                    for (k = 0; k < 7; k++, sound_datap2 += 16) {
                        *(datap++) = (uint16_t)(sound_datap2[0] & 0x0f) | ((uint16_t)(sound_datap2[4] & 0x0f) << 4) |
                                     ((uint16_t)(sound_datap2[8] & 0x0f) << 8) |
                                     ((uint16_t)(sound_datap2[12] & 0x0f) << 12);
                    }
                    ADPCM_DecodeBlock16(&xdp->left, sound_groupsp[s_headtable[i] + 0], data, destp, 1);

                    destp += 28;

                    datap = data;
                    sound_datap2 = sound_datap + i;
                    for (k = 0; k < 7; k++, sound_datap2 += 16) {
                        *(datap++) = (uint16_t)(sound_datap2[0] >> 4) | ((uint16_t)(sound_datap2[4] >> 4) << 4) |
                                     ((uint16_t)(sound_datap2[8] >> 4) << 8) |
                                     ((uint16_t)(sound_datap2[12] >> 4) << 12);
                    }
                    ADPCM_DecodeBlock16(&xdp->left, sound_groupsp[s_headtable[i] + 1], data, destp, 1);

                    destp += 28;
                }
            }
        }
    }
}

//============================================
//===  XA SPECIFIC ROUTINES
//============================================
typedef struct {
    uint8_t filenum;
    uint8_t channum;
    uint8_t submode;
    uint8_t coding;

    uint8_t filenum2;
    uint8_t channum2;
    uint8_t submode2;
    uint8_t coding2;
} xa_subheader_t;

#define SUB_SUB_EOF (1 << 7)      // end of file
#define SUB_SUB_RT (1 << 6)       // real-time sector
#define SUB_SUB_FORM (1 << 5)     // 0 form1  1 form2
#define SUB_SUB_TRIGGER (1 << 4)  // used for interrupt
#define SUB_SUB_DATA (1 << 3)     // contains data
#define SUB_SUB_AUDIO (1 << 2)    // contains audio
#define SUB_SUB_VIDEO (1 << 1)    // contains video
#define SUB_SUB_EOR (1 << 0)      // end of record

#define AUDIO_CODING_GET_STEREO(_X_) ((_X_)&3)
#define AUDIO_CODING_GET_FREQ(_X_) (((_X_) >> 2) & 3)
#define AUDIO_CODING_GET_BPS(_X_) (((_X_) >> 4) & 3)
#define AUDIO_CODING_GET_EMPHASIS(_X_) (((_X_) >> 6) & 1)

#define SUB_UNKNOWN 0
#define SUB_VIDEO 1
#define SUB_AUDIO 2

//============================================
static int parse_xa_audio_sector(xa_decode_t *xdp, xa_subheader_t *subheadp, unsigned char *sectorp,
                                 int is_first_sector) {
    if (is_first_sector) {
        int freq;
        int nbits;
        int stereo;
        switch (AUDIO_CODING_GET_FREQ(subheadp->coding)) {
            case 0:
                freq = 37800;
                break;
            case 1:
                freq = 18900;
                break;
            default:
                freq = 0;
                break;
        }
        switch (AUDIO_CODING_GET_BPS(subheadp->coding)) {
            case 0:
                nbits = 4;
                break;
            case 1:
                nbits = 8;
                break;
            default:
                nbits = 0;
                break;
        }
        switch (AUDIO_CODING_GET_STEREO(subheadp->coding)) {
            case 0:
                stereo = 0;
                break;
            case 1:
                stereo = 1;
                break;
            default:
                stereo = 0;
                break;
        }

        if (freq == 0) return -1;

        if ((xdp->freq != freq) || (xdp->nbits != nbits) || (xdp->stereo != stereo)) {
            xdp->freq = freq;
            xdp->nbits = nbits;
            xdp->stereo = stereo;
            ADPCM_InitDecode(&xdp->left);
            ADPCM_InitDecode(&xdp->right);

            xdp->nsamples = 18 * 28 * 8;
            if (xdp->stereo == 1) xdp->nsamples /= 2;
        }
    }
    xa_decode_data(xdp, sectorp);

    return 0;
}

//================================================================
//=== THIS IS WHAT YOU HAVE TO CALL
//=== xdp              - structure were all important data are returned
//=== sectorp          - data in input
//=== pcmp             - data in output
//=== is_first_sector  - 1 if it's the 1st sector of the stream
//===                  - 0 for any other successive sector
//=== return -1 if error
//================================================================
int32_t xa_decode_sector(xa_decode_t *xdp, unsigned char *sectorp, int is_first_sector) {
    if (parse_xa_audio_sector(xdp, (xa_subheader_t *)sectorp, sectorp + sizeof(xa_subheader_t), is_first_sector))
        return -1;

    return 0;
}

void xa_decode_reset(xa_decode_t *xdp) {
    ADPCM_InitDecode(&xdp->left);
    ADPCM_InitDecode(&xdp->right);
}

/* EXAMPLE:
"nsamples" is the number of 16 bit samples
every sample is 2 bytes in mono and 4 bytes in stereo

xa_decode_t xa;

        sectorp = read_first_sector();
        xa_decode_sector( &xa, sectorp, 1 );
        play_wave( xa.pcm, xa.freq, xa.nsamples );

        while ( --n_sectors )
        {
                sectorp = read_next_sector();
                xa_decode_sector( &xa, sectorp, 0 );
                play_wave( xa.pcm, xa.freq, xa.nsamples );
        }
*/
