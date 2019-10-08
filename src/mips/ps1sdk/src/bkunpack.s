; ByteKiller decrunch code for PSX by Silpheed of Hitmen

; BK_Decrunch
; a0 - src
; a1 - dest


BK_Decrunch     move t9, ra
                move t0, a0            
                lw t2, (a0)    
                move t1, a1            
                lw t3, 4(a0)
                addu t2,t2,t1    
                addu t0,t0,t3        
                subiu t0,t0,4        
                lw t3, (t0)            
                
BK_mainloop     jal BK_getnextbit
                nop
                
                beq zero,v0,BK_part2    
                nop
                                        
                jal BK_readbits            
                li a0, 2                
                
                slti t4, v0, 2
                beq zero,t4,BK_skip1
                nop
                                        
                addiu a0,v0,9
                jal BK_dodupl            
                addiu a1,v0,2
                
                b BK_endloop
                nop
                        
BK_skip1        subiu t4,v0,3
                bne zero,t4,BK_skip2        
                nop
                                        
                li a0, 8
                jal BK_dojmp            
                li a1, 8                        
                
                b BK_endloop
                nop
                
BK_skip2        jal BK_readbits            
                li a0, 8
                
                move a1,v0
                jal BK_dodupl            
                li a0, 12
                
                b BK_endloop
                nop
BK_part2                                
                jal BK_getnextbit
                nop
                                
                beq zero,v0,BK_skip3
                nop

                li a0, 8
                jal BK_dodupl            
                li a1, 1
                
                b BK_endloop
                nop
                
BK_skip3        li a0, 3
                jal BK_dojmp            
                move a1, zero

BK_endloop      bne t2,t1,BK_mainloop    
                nop                
                
                jr ra
                move ra, t9


BK_getnextbit   andi v0,t3,1            
                srl t3,t3,1                
                bne zero,t3,BK_gnbend
                nop
                                        
                subiu t0,t0,4            
                lw t3, (t0)                
                nop
                andi v0,t3,1            
                srl t3,t3,1                
                lui t5, $8000
                or t3,t3,t5
                
BK_gnbend       jr ra
                nop


BK_readbits     move v1, zero            
                move t8,ra
BK_rbloop       beq zero,a0,BK_rbend    
                nop
                
                subiu a0,a0,1            
                
                jal BK_getnextbit
                sll v1,v1,1                
                or v1,v1,v0                
                
                b BK_rbloop
                nop
                
BK_rbend        move v0,v1
                jr ra
                move ra,t8
                

BK_dojmp        move t7, ra
                jal BK_readbits
                nop
                
                addu t4,v0,a1
                addiu t4,t4,1            

BK_djloop       beq zero,t4,BK_djend
                nop
        
                subiu t4,t4,1            
        
                li a0, 8
                jal BK_readbits
                subiu t2,t2,1            
                
                sb v0, (t2)                
                nop
                
                b BK_djloop
                nop
                
BK_djend        jr ra
                move ra, t7


BK_dodupl       move t7, ra
                jal BK_readbits        
                addiu a1,a1,1            
                
BK_ddloop       beq zero,a1,BK_ddend
                nop
                
                subiu a1,a1,1            
                
                subiu t2,t2,1            
                addu t4,t2,v0    
                lb t4, (t4)
                nop
                sb t4, (t2)
                nop

                b BK_ddloop
                nop

BK_ddend        jr ra
                move ra, t7

        
