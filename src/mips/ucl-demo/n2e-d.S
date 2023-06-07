//   Copyright (C) 2023 PCSX-Redux authors
//
//   This program is free software; you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation; either version 2 of the License, or
//   (at your option) any later version.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this program; if not, write to the
//   Free Software Foundation, Inc.,
//   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

// This is from my old ps2-packer, which I wrote from scratch eons ago.

.set noreorder
.global n2e_decompress
.ent n2e_decompress

#ifdef ARGS_IN_S
#define source     $s0
#define dest       $s1
#else
#define source     $a0
#define dest       $a1
#endif
#define bb         $t0
#define last_m_off $t2
#define m_off      $t3
#define m_len      $t4
#define m_pos      $t5
#define ff0000     $t6
#define saved_ra   $t9

n2e_decompress:
    // a0/s0 = source
    // a1/s1 = destination
    
    // t0 = bitbucket (bb)
    // t1 = temp... (memmove)
    // t2 = last_m_off
    // t3 = m_off
    // t4 = m_len
    // t5 = m_pos
    // t6 = 0xff0000

    // t9 = saved_ra

    move	saved_ra, $ra
    
    move	bb, $0
    li		last_m_off, 1
    lui 	ff0000, 0xff
    
main_loop:					// for (;;)

        bal	getbit                   	// while (getbit(bb))
        nop
        beqz	    $v0, m_off_loop
    	li	    m_off, 1			// m_off = 1 (doing it there, in the unused delay slot) */
            lbu		    $t1, 0(source)	// dst[olen++] = src[ilen++]
    	    addiu	    source, 1
    	    sb		    $t1, 0(dest)
        b		main_loop
    	    addiu	    dest, 1

m_off_loop:
	    bal		    getbit		// + getbi...
	    sll		    m_off, 1		// m_off = m_off * 2...
	    bal		    getbit		// if (getbit(bb)...
	    addu	    m_off, $v0		// ..t(bb)
	    bnez	    $v0, exit_m_off_loop	// ... break  (and m_off-- as a side effect)
	    addiu	    m_off, -1		// m_off = (m_off-1)..
	    bal		    getbit		// + getbi...
	    sll		    m_off, 1		// ..*2
	b		m_off_loop              // for(;;)
	    addu	    m_off, $v0          // ..t(bb)

exit_m_off_loop:
	addiu	    m_off, -1			// if (!(--m_off)) ...
	bnez	    m_off, m_off_diff_2
	nop
	    bal	        getbit                  // m_len = getbit(bb)
	    move	m_off, last_m_off       // m_off = last_m_off
	b	    exit_if_moff_eq_2
	    move	m_len, $v0

m_off_diff_2:                                   // else
            addiu	m_off, -1               // (m_off-1) (m_off was already sub by 2)
            lbu		$t1, 0(source)          // src[ilen++]
            sll		m_off, 8                // *256
            addiu	source, 1
            addu	m_off, $t1              // m_off = ...
            addiu	$t1, m_off, 1           // if (m_off == -1) (that is, t1 == 0)
            bnez	$t1, 1f
		nop
		jr	    saved_ra            // break; (that is, return)
1:          andi	m_len, $t1, 1           // mlen = (m_off ^ 1) & 1 (that is, (m_off + 1) & 1)
            srl		m_off, 1                // m_off >>= 1
            addiu	m_off, 1                // ++m_off
            move	last_m_off, m_off       // last_m_off = m_off
	    
	    // endif

exit_if_moff_eq_2:

        bal	    getbit			// prefetch next bit, can be used twice
        nop
        beqz	    m_len, else_1               // if (m_len)
        nop
        b	    exit_if
            addiu	m_len, $v0, 3           // m_len = 3 + getbit(bb) (I add 2 everywhere, for later)
else_1:
            bnez	$v0, else_2_reversed    // else if (getbit(bb)) (second time the prefetched bit can be used)
            nop                                 // else...
    
	    addiu	m_len, 1                // m_len++
while_m_len:
                bal	    getbit              // + getbit(bb)
                sll	    m_len, 1            // m_len * 2
            bal		getbit                  // preparing the condition
                addu	    m_len, $v0          // m_len = ...
            beqz	$v0, while_m_len        // while(!getbit(bb))
            nop
        b	    exit_if
            addiu	m_len, 5                // m_len += 5 (+2 from the original code)

else_2_reversed:
            bal	        getbit                  // m_len = 5 + getbit(bb) (still + 2 from the original code)
            nop
            addiu	m_len, $v0, 5
	
	// endif

exit_if:
        sltiu	    $t1, m_off, 0x501           // original code does m_len += (m_off > 0x500)
        subu	    m_len, $t1                  // we do m_len -= (m_off < 0x501) (to use sltiu)
	                                        // which get one of the +1 from before
    
        subu	    m_pos, dest, m_off          // m_pos = dest + olen - m_off
    
						// Here, the original code does dst[olen++] = *m_pos++
						// we roll it back in the loop, by adding +1 before to m_len.
copy_loop:
            lbu	        $t1, 0(m_pos)           // dst[olen++] = *m_pos++
            addiu	m_pos, 1
            sb		$t1, 0(dest)
            nop                                 // stupid 5900 loop bug...
        addiu	    m_len, -1
        bnez	    m_len, copy_loop
            addiu	dest, 1
    
    b		main_loop
    nop
    
.end n2e_decompress


  // a0 = source
  // t0 = bitbucket
  // v0 = returned bit
  // t1 = safely erased

.ent getbit
getbit:
    and		$t1, bb, ff0000
    bnez	$t1, bb_okay
    nop

    lbu		$t1, 0(source)
    addiu	source, 1
    or		bb, $t1, ff0000

bb_okay:
    srl		$v0, bb, 7
    sll		bb, 1
    jr		$ra
    andi	$v0, 1
.end getbit
