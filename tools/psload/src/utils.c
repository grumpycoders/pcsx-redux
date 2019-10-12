#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>

#include "pcserial.h"
#include "utils.h"

uint32_t __verbosity_flags = (VERBOSITY_FLAG_WARN | VERBOSITY_FLAG_INFO | VERBOSITY_FLAG_ERROR | VERBOSITY_FLAG_DEBUG);
uint32_t __verbosity_level = VERBOSITY_INFO;
/*
int psl_sync(void)
{
    uint8_t d = '-';
    
    do
    {
        if(psl_putb('P') != 0) return -1;
        if(psl_putb('S') != 0) return -2;
        if(psl_getb(&d) <= 0) return -3;
    } while(d != '+');
}
*/
