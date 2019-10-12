#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>

#include "pcserial.h"
#include "utils.h"

static SerialConfig cfg =
{
    baud: 57600,
    chlen: CHLEN_8,
    parity: PARITY_NONE,
    sbits: STOPBITS_1,
    sw_handshake: 0,
    hw_handshake: 0,
    line_ends: LINE_ENDS_LF
};

static volatile int term = 0;

void handle_sigint(int sig)
{
    printf("Caught signal %d\n", sig);
    term = 1;
}

void printUsage(const char *arg0)
{
    fprintf(stderr, "usage: %s SERIALPORT CMD ...params...\n",arg0);
    fprintf(stderr, "commands:\n");
    fprintf(stderr, "\trun FILE\t- xfer FILE to target and exec\n");
    fprintf(stderr, "\n");
}

int main(int argc, char *argv[])
{
    char *_defDevPath = "/dev/ttyUSB0";
    char *devPath = _defDevPath;
    uint8_t ch;
    int i;
    int rv = 0;
    
    if(argc < 2)
    {
        printUsage(argv[0]);
        exit(1);
    }
    
    devPath = argv[1];
    i = 2;

    if(__verbosity_level >= VERBOSITY_INFO)
        print_serial_config(&cfg);

    signal(SIGINT, handle_sigint);

    if(serial_open(&cfg, devPath) != 0)
    {
        rv = 1;
        goto _end;
    }
    
    if(strcasecmp(argv[i], "run") == 0)
    {
        eprintf("FIXME!!!! run not supported\n");
        rv = 1;
        goto _end;
    }
    
    while(!term)
    {
        if((rv = serial_getb(&cfg, &ch)) < 0)
        {
            // should only happen if there was an error
            rv = 1;
            break;
        }

        if(rv != 0)
        {
            // data was read
            cons_putchar(&cfg, ch);
            continue;
        }
        
        // note: device may have been disconnected
    }
    
//~ _finish:
    serial_close(&cfg);

_end:        
    return rv;
}
