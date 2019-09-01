/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

    .section .text, "ax", @progbits
    .set noreorder

    .align 2
    .global readCOP0Status
    .type readCOP0Status, @function
readCOP0Status:
    mfc0  $v0, $12
    nop
    jr    $ra
    nop

    .align 2
    .global writeCOP0Status
    .type writeCOP0Status, @function
writeCOP0Status:
    mtc0  $a0, $12
    nop
    jr    $ra
    nop
