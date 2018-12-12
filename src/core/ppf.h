/*  PPF Patch Support for PCSX-Reloaded
 *  Copyright (c) 2009, Wei Mingzhi <whistler_wmz@users.sf.net>.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __PPF_H__
#define __PPF_H__

#ifdef __cplusplus
extern "C" {
#endif

void BuildPPFCache();
void FreePPFCache();
void CheckPPFCache(unsigned char *pB, unsigned char m, unsigned char s, unsigned char f);

int LoadSBI(const char *filename);
boolean CheckSBI(const u8 *time);
void UnloadSBI(void);

#ifdef __cplusplus
}
#endif
#endif
