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

//===========================================
static void ADPCM_InitDecode(ADPCM_Decode_t *decp) {
    decp->y0 = 0;
    decp->y1 = 0;
}

//===========================================
// A sector holds 18 sound groups of 128 bytes: 16 header bytes, then 28 words
// of 4 bytes. 4-bit audio has 8 blocks per group (block b is nibble b of each
// word), 8-bit audio has 4 (block b is byte b of each word). The parameters of
// block b are header byte 4 + b. Stereo puts the left channel in the even
// blocks and the right channel in the odd ones.
static const int s_filterPos[4] = {0, 60, 115, 98};
static const int s_filterNeg[4] = {0, 0, -52, -55};

static void decodeBlock(ADPCM_Decode_t *state, const uint8_t *group, int block, bool eightBits, short *dest,
                        int stride) {
    const uint8_t param = group[4 + block];
    const int filter = (param >> 4) & 3;
    int range = param & 0x0f;
    if (range > 12) range = 9;
    const uint8_t *data = group + 16;
    int32_t y0 = state->y0, y1 = state->y1;
    for (int n = 0; n < 28; n++) {
        int16_t t;
        if (eightBits) {
            t = int16_t(data[n * 4 + block] << 8);
        } else {
            t = int16_t(((data[n * 4 + block / 2] >> ((block & 1) * 4)) & 0x0f) << 12);
        }
        int32_t sample = (t >> range) + ((y0 * s_filterPos[filter] + y1 * s_filterNeg[filter] + 32) >> 6);
        if (sample < -32768) sample = -32768;
        if (sample > 32767) sample = 32767;
        y1 = y0;
        y0 = sample;
        *dest = sample;
        dest += stride;
    }
    state->y0 = y0;
    state->y1 = y1;
}

static void xa_decode_data(xa_decode_t *xdp, unsigned char *srcp) {
    const bool eightBits = xdp->nbits == 8;
    const int blocks = eightBits ? 4 : 8;
    short *dest = xdp->pcm;
    for (int g = 0; g < 18; g++) {
        const uint8_t *group = srcp + g * 128;
        if (xdp->stereo) {
            for (int b = 0; b < blocks; b += 2) {
                decodeBlock(&xdp->left, group, b, eightBits, dest, 2);
                decodeBlock(&xdp->right, group, b + 1, eightBits, dest + 1, 2);
                dest += 28 * 2;
            }
        } else {
            for (int b = 0; b < blocks; b++) {
                decodeBlock(&xdp->left, group, b, eightBits, dest, 1);
                dest += 28;
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

#define AUDIO_CODING_GET_STEREO(_X_) ((_X_) & 3)
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

            // 18 groups of 28 samples per block; stereo pairs two blocks per frame.
            xdp->nsamples = 18 * 28 * (nbits == 8 ? 4 : 8);
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
