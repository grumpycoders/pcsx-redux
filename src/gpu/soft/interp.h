/*
 * This file is part of the Advance project.
 *
 * Copyright (C) 2003 Andrea Mazzoleni
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 *
 * In addition, as a special exception, Andrea Mazzoleni
 * gives permission to link the code of this program with
 * the MAME library (or with modified versions of MAME that use the
 * same license as MAME), and distribute linked combinations including
 * the two.  You must obey the GNU General Public License in all
 * respects for all of the code used other than MAME.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 */

#ifndef __INTERP_H
#define __INTERP_H

/***************************************************************************/
/* Basic types */

/***************************************************************************/
/* interpolation */

static unsigned interp_mask[2];
static unsigned interp_bits_per_pixel;

#define INTERP_16_MASK_1(v) (v & interp_mask[0])
#define INTERP_16_MASK_2(v) (v & interp_mask[1])

static __inline unsigned short interp_16_521(unsigned short p1, unsigned short p2, unsigned short p3)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*5 + INTERP_16_MASK_1(p2)*2 + INTERP_16_MASK_1(p3)*1) / 8)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*5 + INTERP_16_MASK_2(p2)*2 + INTERP_16_MASK_2(p3)*1) / 8);
}

static __inline unsigned short interp_16_332(unsigned short p1, unsigned short p2, unsigned short p3)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*3 + INTERP_16_MASK_1(p2)*3 + INTERP_16_MASK_1(p3)*2) / 8)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*3 + INTERP_16_MASK_2(p2)*3 + INTERP_16_MASK_2(p3)*2) / 8);
}

static __inline unsigned short interp_16_611(unsigned short p1, unsigned short p2, unsigned short p3)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*6 + INTERP_16_MASK_1(p2) + INTERP_16_MASK_1(p3)) / 8)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*6 + INTERP_16_MASK_2(p2) + INTERP_16_MASK_2(p3)) / 8);
}

static __inline unsigned short interp_16_71(unsigned short p1, unsigned short p2)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*7 + INTERP_16_MASK_1(p2)) / 8)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*7 + INTERP_16_MASK_2(p2)) / 8);
}

static __inline unsigned short interp_16_211(unsigned short p1, unsigned short p2, unsigned short p3)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*2 + INTERP_16_MASK_1(p2) + INTERP_16_MASK_1(p3)) / 4)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*2 + INTERP_16_MASK_2(p2) + INTERP_16_MASK_2(p3)) / 4);
}

static __inline unsigned short interp_16_772(unsigned short p1, unsigned short p2, unsigned short p3)
{
  return INTERP_16_MASK_1(((INTERP_16_MASK_1(p1) + INTERP_16_MASK_1(p2))*7 + INTERP_16_MASK_1(p3)*2) / 16)
    | INTERP_16_MASK_2(((INTERP_16_MASK_2(p1) + INTERP_16_MASK_2(p2))*7 + INTERP_16_MASK_2(p3)*2) / 16);
}

static __inline unsigned short interp_16_11(unsigned short p1, unsigned short p2)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1) + INTERP_16_MASK_1(p2)) / 2)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1) + INTERP_16_MASK_2(p2)) / 2);
}

static __inline unsigned short interp_16_31(unsigned short p1, unsigned short p2)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*3 + INTERP_16_MASK_1(p2)) / 4)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*3 + INTERP_16_MASK_2(p2)) / 4);
}

static __inline unsigned short interp_16_1411(unsigned short p1, unsigned short p2, unsigned short p3)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*14 + INTERP_16_MASK_1(p2) + INTERP_16_MASK_1(p3)) / 16)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*14 + INTERP_16_MASK_2(p2) + INTERP_16_MASK_2(p3)) / 16);
}

static __inline unsigned short interp_16_431(unsigned short p1, unsigned short p2, unsigned short p3)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*4 + INTERP_16_MASK_1(p2)*3 + INTERP_16_MASK_1(p3)) / 8)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*4 + INTERP_16_MASK_2(p2)*3 + INTERP_16_MASK_2(p3)) / 8);
}

static __inline unsigned short interp_16_53(unsigned short p1, unsigned short p2)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*5 + INTERP_16_MASK_1(p2)*3) / 8)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*5 + INTERP_16_MASK_2(p2)*3) / 8);
}

static __inline unsigned short interp_16_151(unsigned short p1, unsigned short p2)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*15 + INTERP_16_MASK_1(p2)) / 16)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*15 + INTERP_16_MASK_2(p2)) / 16);
}

static __inline unsigned short interp_16_97(unsigned short p1, unsigned short p2)
{
  return INTERP_16_MASK_1((INTERP_16_MASK_1(p1)*9 + INTERP_16_MASK_1(p2)*7) / 16)
    | INTERP_16_MASK_2((INTERP_16_MASK_2(p1)*9 + INTERP_16_MASK_2(p2)*7) / 16);
}

#define INTERP_32_MASK_1(v) (v & 0xFF00FF)
#define INTERP_32_MASK_2(v) (v & 0x00FF00)

static __inline unsigned int  interp_32_521(unsigned int  p1, unsigned int  p2, unsigned int  p3)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*5 + INTERP_32_MASK_1(p2)*2 + INTERP_32_MASK_1(p3)*1) / 8)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*5 + INTERP_32_MASK_2(p2)*2 + INTERP_32_MASK_2(p3)*1) / 8);
}

static __inline unsigned int  interp_32_332(unsigned int  p1, unsigned int  p2, unsigned int  p3)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*3 + INTERP_32_MASK_1(p2)*3 + INTERP_32_MASK_1(p3)*2) / 8)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*3 + INTERP_32_MASK_2(p2)*3 + INTERP_32_MASK_2(p3)*2) / 8);
}

static __inline unsigned int  interp_32_211(unsigned int  p1, unsigned int  p2, unsigned int  p3)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*2 + INTERP_32_MASK_1(p2) + INTERP_32_MASK_1(p3)) / 4)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*2 + INTERP_32_MASK_2(p2) + INTERP_32_MASK_2(p3)) / 4);
}

static __inline unsigned int  interp_32_611(unsigned int  p1, unsigned int  p2, unsigned int  p3)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*6 + INTERP_32_MASK_1(p2) + INTERP_32_MASK_1(p3)) / 8)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*6 + INTERP_32_MASK_2(p2) + INTERP_32_MASK_2(p3)) / 8);
}

static __inline unsigned int  interp_32_71(unsigned int  p1, unsigned int  p2)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*7 + INTERP_32_MASK_1(p2)) / 8)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*7 + INTERP_32_MASK_2(p2)) / 8);
}

static __inline unsigned int  interp_32_772(unsigned int  p1, unsigned int  p2, unsigned int  p3)
{
  return INTERP_32_MASK_1(((INTERP_32_MASK_1(p1) + INTERP_32_MASK_1(p2))*7 + INTERP_32_MASK_1(p3)*2) / 16)
    | INTERP_32_MASK_2(((INTERP_32_MASK_2(p1) + INTERP_32_MASK_2(p2))*7 + INTERP_32_MASK_2(p3)*2) / 16);
}

static __inline unsigned int  interp_32_11(unsigned int  p1, unsigned int  p2)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1) + INTERP_32_MASK_1(p2)) / 2)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1) + INTERP_32_MASK_2(p2)) / 2);
}

static __inline unsigned int  interp_32_31(unsigned int  p1, unsigned int  p2)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*3 + INTERP_32_MASK_1(p2)) / 4)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*3 + INTERP_32_MASK_2(p2)) / 4);
}

static __inline unsigned int  interp_32_1411(unsigned int  p1, unsigned int  p2, unsigned int  p3)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*14 + INTERP_32_MASK_1(p2) + INTERP_32_MASK_1(p3)) / 16)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*14 + INTERP_32_MASK_2(p2) + INTERP_32_MASK_2(p3)) / 16);
}

static __inline unsigned int  interp_32_431(unsigned int  p1, unsigned int  p2, unsigned int  p3)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*4 + INTERP_32_MASK_1(p2)*3 + INTERP_32_MASK_1(p3)) / 8)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*4 + INTERP_32_MASK_2(p2)*3 + INTERP_32_MASK_2(p3)) / 8);
}

static __inline unsigned int  interp_32_53(unsigned int  p1, unsigned int  p2)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*5 + INTERP_32_MASK_1(p2)*3) / 8)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*5 + INTERP_32_MASK_2(p2)*3) / 8);
}

static __inline unsigned int  interp_32_151(unsigned int  p1, unsigned int  p2)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*15 + INTERP_32_MASK_1(p2)) / 16)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*15 + INTERP_32_MASK_2(p2)) / 16);
}

static __inline unsigned int  interp_32_97(unsigned int  p1, unsigned int  p2)
{
  return INTERP_32_MASK_1((INTERP_32_MASK_1(p1)*9 + INTERP_32_MASK_1(p2)*7) / 16)
    | INTERP_32_MASK_2((INTERP_32_MASK_2(p1)*9 + INTERP_32_MASK_2(p2)*7) / 16);
}

/***************************************************************************/
/* diff */

#define INTERP_Y_LIMIT (0x30*4)
#define INTERP_U_LIMIT (0x07*4)
#define INTERP_V_LIMIT (0x06*8)

__inline static int interp_16_diff(unsigned short p1, unsigned short p2)
{
  int r, g, b;
  int y, u, v;

  if (p1 == p2)
    return 0;

  if (interp_bits_per_pixel == 16) {
    b = (int)((p1 & 0x1F) - (p2 & 0x1F)) << 3;
    g = (int)((p1 & 0x7E0) - (p2 & 0x7E0)) >> 3;
    r = (int)((p1 & 0xF800) - (p2 & 0xF800)) >> 8;
  } else {
    b = (int)((p1 & 0x1F) - (p2 & 0x1F)) << 3;
    g = (int)((p1 & 0x3E0) - (p2 & 0x3E0)) >> 2;
    r = (int)((p1 & 0x7C00) - (p2 & 0x7C00)) >> 7;
  }

  y = r + g + b;
  u = r - b;
  v = -r + 2*g - b;

  if (y < -INTERP_Y_LIMIT || y > INTERP_Y_LIMIT)
    return 1;

  if (u < -INTERP_U_LIMIT || u > INTERP_U_LIMIT)
    return 1;

  if (v < -INTERP_V_LIMIT || v > INTERP_V_LIMIT)
    return 1;

  return 0;
}

__inline static int interp_32_diff(unsigned int  p1, unsigned int  p2)
{
  int r, g, b;
  int y, u, v;

  if ((p1 & 0xF8F8F8) == (p2 & 0xF8F8F8))
    return 0;

  b = (int)((p1 & 0xFF) - (p2 & 0xFF));
  g = (int)((p1 & 0xFF00) - (p2 & 0xFF00)) >> 8;
  r = (int)((p1 & 0xFF0000) - (p2 & 0xFF0000)) >> 16;

  y = r + g + b;
  u = r - b;
  v = -r + 2*g - b;

  if (y < -INTERP_Y_LIMIT || y > INTERP_Y_LIMIT)
    return 1;

  if (u < -INTERP_U_LIMIT || u > INTERP_U_LIMIT)
    return 1;

  if (v < -INTERP_V_LIMIT || v > INTERP_V_LIMIT)
    return 1;

  return 0;
}

__inline static void interp_set(unsigned bits_per_pixel)
{
  interp_bits_per_pixel = bits_per_pixel;

  switch (bits_per_pixel) {
  case 15 :
    interp_mask[0] = 0x7C1F;
    interp_mask[1] = 0x03E0;
    break;
  case 16 :
    interp_mask[0] = 0xF81F;
    interp_mask[1] = 0x07E0;
    break;
  case 32 :
    interp_mask[0] = 0xFF00FF;
    interp_mask[1] = 0x00FF00;
    break;
  }
}

#endif
