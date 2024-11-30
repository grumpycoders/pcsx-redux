/***************************************************************************
 *   Copyright (C) 2016 by iCatButler                                      *
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

/**************************************************************************
 *  pgxp_value.h
 *  PGXP - Parallel/Precision Geometry Xform Pipeline
 *
 *  Created on: 07 Jun 2016
 *      Author: iCatButler
 ***************************************************************************/

#ifndef _PGXP_VALUE_H_
#define _PGXP_VALUE_H_

#include "core/psxemulator.h"

typedef union {
#if defined(__BIGENDIAN__)
    struct {
        uint8_t h3, h2, h, l;
    } b;
    struct {
        int8_t h3, h2, h, l;
    } sb;
    struct {
        uint16_t h, l;
    } w;
    struct {
        int16_t h, l;
    } sw;
#else
    struct {
        uint8_t l, h, h2, h3;
    } b;
    struct {
        uint16_t l, h;
    } w;
    struct {
        int8_t l, h, h2, h3;
    } sb;
    struct {
        int16_t l, h;
    } sw;
#endif
    uint32_t d;
    int32_t sd;
} psx_value;

typedef struct PGXP_value_Tag {
    float x;
    float y;
    float z;
    union {
        unsigned int flags;
        unsigned char compFlags[4];
        unsigned short halfFlags[2];
    };
    unsigned int count;
    unsigned int value;

    unsigned short gFlags;
    unsigned char lFlags;
    unsigned char hFlags;
} PGXP_value;

typedef enum {
    UNINITIALISED = 0,
    INVALID_PSX_VALUE = 1,
    INVALID_ADDRESS = 2,
    INVALID_BITWISE_OP = 3,
    DIVIDE_BY_ZERO = 4,
    INVALID_8BIT_LOAD = 5,
    INVALID_8BIT_STORE = 6
} PGXP_error_states;

typedef enum { VALID_HALF = (1 << 0) } PGXP_half_flags;

// typedef enum
//{
// #define NONE 0
#define ALL 0xFFFFFFFF
#define VALID 1
#define VALID_0 (VALID << 0)
#define VALID_1 (VALID << 8)
#define VALID_2 (VALID << 16)
#define VALID_3 (VALID << 24)
#define VALID_01 (VALID_0 | VALID_1)
#define VALID_012 (VALID_0 | VALID_1 | VALID_2)
#define VALID_ALL (VALID_0 | VALID_1 | VALID_2 | VALID_3)
#define INV_VALID_ALL (ALL ^ VALID_ALL)
//} PGXP_value_flags;

static const PGXP_value PGXP_value_invalid_address = {0.f, 0.f, 0.f, 0, 0, 0, INVALID_ADDRESS, 0, 0};
static const PGXP_value PGXP_value_zero = {0.f, 0.f, 0.f, 0, 0, VALID_ALL, 0, 0, 0};

void SetValue(PGXP_value *pV, uint32_t psxV);
void MakeValid(PGXP_value *pV, uint32_t psxV);
void Validate(PGXP_value *pV, uint32_t psxV);
void MaskValidate(PGXP_value *pV, uint32_t psxV, uint32_t mask, uint32_t validMask);
uint32_t ValueToTolerance(PGXP_value *pV, uint32_t psxV, float tolerance);

double f16Sign(double in);
double f16Unsign(double in);
double fu16Trunc(double in);
double f16Overflow(double in);

typedef union {
    struct {
        int16_t x;
        int16_t y;
    };
    struct {
        uint16_t ux;
        uint16_t uy;
    };
    uint32_t word;
} low_value;

#endif  //_PGX_VALUE_H_
