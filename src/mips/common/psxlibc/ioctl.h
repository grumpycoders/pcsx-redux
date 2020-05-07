/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#pragma once

#define MAKEIOCTL(c, s) ((c << 8 | s))

#define PSXFIOCNBLOCK MAKEIOCTL('f', 1)
#define PSXFIOCSCAN   MAKEIOCTL('f', 2)

#define PSXTIOCRAW    MAKEIOCTL('t', 1)
#define PSXTIOCFLUSH  MAKEIOCTL('t', 2)
#define PSXTIOCREOPEN MAKEIOCTL('t', 3)
#define PSXTIOCBAUD   MAKEIOCTL('t', 4)
#define PSXTIOCEXIT   MAKEIOCTL('t', 5)
#define PSXTIOCDTR    MAKEIOCTL('t', 6)
#define PSXTIOCRTS    MAKEIOCTL('t', 7)
#define PSXTIOCLEN    MAKEIOCTL('t', 8)
#define PSXTIOCPARITY MAKEIOCTL('t', 9)
#define PSXTIOSTATUS  MAKEIOCTL('t', 10)
#define PSXTIOERRRST  MAKEIOCTL('t', 11)
#define PSXTIOEXIST   MAKEIOCTL('t', 12)
#define PSXTIORLEN    MAKEIOCTL('t', 13)

#define PSXDIOFORMAT  MAKEIOCTL('d', 1)
