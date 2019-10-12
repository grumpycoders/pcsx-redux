#include <stdlib.h>
#include <string.h>
#include "pcserial.h"
#include "utils.h"

#define inited(__cfg) (((__cfg)->_devPath) != NULL)

void millisleep(int ms)
{
    if (ms>0)
    {
      struct timeval tv;
      tv.tv_sec=0;
      tv.tv_usec=ms*1000;
      select(0, 0, 0, 0, &tv);
    }
}

int serial_open(SerialConfig *cfg, const char *devPath)
{
    cfg->_fd = -1;
    cfg->_devPath = NULL;
    
    cfg->_fd = open(devPath, O_RDWR | O_NDELAY);
    if(cfg->_fd < 0)
    {
        eprintf("failed to open serial port \"%s\"\n", devPath);
        return -1;
    }

    cfg->_in_fp = stdin;
    cfg->_out_fp = stdout;
    cfg->_err_fp = stderr;
    
    // flushing is to be done after opening. This prevents first read and write to be spam'ish.
    tcflush(cfg->_fd, TCIOFLUSH);

    int n = fcntl(cfg->_fd, F_GETFL, 0);
    fcntl(cfg->_fd, F_SETFL, n & ~O_NDELAY);

    // save the current termios config
    if(tcgetattr(cfg->_fd, &cfg->_old_tio)!=0)
    {
        eprintf("tcgetattr() 2 failed\n");
        close(cfg->_fd);
        return -1;
    }
 
    cfg->_prev_ch = -1;
    
    // NOTE: the string for _devPath is allocated here!  It should be free'd with free(cfg->_devPath)
    cfg->_devPath = strdup(devPath);

    if(serial_config(cfg) != 0)
    {
        serial_close(cfg);
        return -1;
    }
    
    return 0;
}

/** This function features some code from minicom 2.0.0, src/sysdep1.c */
int serial_config(SerialConfig *cfg)
{
    if(!inited(cfg)) return -1;

    struct termios newtio;

    if(tcgetattr(cfg->_fd, &newtio) != 0)
    {
        eprintf("tcgetattr failed\n");
        return -1;
    }

    speed_t _baud=0;
    switch (cfg->baud)
    {
#ifdef B0
    case      0: _baud=B0;     break;
#endif
   
#ifdef B50
    case     50: _baud=B50;    break;
#endif
#ifdef B75
    case     75: _baud=B75;    break;
#endif
#ifdef B110
    case    110: _baud=B110;   break;
#endif
#ifdef B134
    case    134: _baud=B134;   break;
#endif
#ifdef B150
    case    150: _baud=B150;   break;
#endif
#ifdef B200
    case    200: _baud=B200;   break;
#endif
#ifdef B300
    case    300: _baud=B300;   break;
#endif
#ifdef B600
    case    600: _baud=B600;   break;
#endif
#ifdef B1200
    case   1200: _baud=B1200;  break;
#endif
#ifdef B1800
    case   1800: _baud=B1800;  break;
#endif
#ifdef B2400
    case   2400: _baud=B2400;  break;
#endif
#ifdef B4800
    case   4800: _baud=B4800;  break;
#endif
#ifdef B7200
    case   7200: _baud=B7200;  break;
#endif
#ifdef B9600
    case   9600: _baud=B9600;  break;
#endif
#ifdef B14400
    case  14400: _baud=B14400; break;
#endif
#ifdef B19200
    case  19200: _baud=B19200; break;
#endif
#ifdef B28800
    case  28800: _baud=B28800; break;
#endif
#ifdef B38400
    case  38400: _baud=B38400; break;
#endif
#ifdef B57600
    case  57600: _baud=B57600; break;
#endif
#ifdef B76800
    case  76800: _baud=B76800; break;
#endif
#ifdef B115200
    case 115200: _baud=B115200; break;
#endif
#ifdef B128000
    case 128000: _baud=B128000; break;
#endif
#ifdef B230400
    case 230400: _baud=B230400; break;
#endif
#ifdef B460800
    case 460800: _baud=B460800; break;
#endif
#ifdef B576000
    case 576000: _baud=B576000; break;
#endif
#ifdef B921600
    case 921600: _baud=B921600; break;
#endif
    default:
//   case 256000:
//      _baud=B256000;
      break;
    }

    cfsetospeed(&newtio, (speed_t)_baud);
    cfsetispeed(&newtio, (speed_t)_baud);

    newtio.c_cflag &= (~CSIZE);
    switch (cfg->chlen)
    {
        case CHLEN_5:
            newtio.c_cflag |= CS5;
            break;
        case CHLEN_6:
            newtio.c_cflag |= CS6;
            break;
        case CHLEN_7:
            newtio.c_cflag |= CS7;
            break;
        case CHLEN_8:
        default:
            newtio.c_cflag |= CS8;
            break;
    }

    newtio.c_cflag |= CLOCAL | CREAD;

    //parity
      
    newtio.c_cflag &= ~(PARENB | PARODD);
    if(cfg->parity != PARITY_NONE) newtio.c_cflag |= PARENB | ((cfg->parity == PARITY_ODD) ? PARODD : 0);
   
    //hardware handshake
/*   if (cfg->hw_handshake)
      newtio.c_cflag |= CRTSCTS;
    else
      newtio.c_cflag &= ~CRTSCTS;*/

    newtio.c_cflag &= ~CRTSCTS;

    newtio.c_cflag &= ~CSTOPB;

    if(cfg->sbits==STOPBITS_2)
    {
        newtio.c_cflag |= CSTOPB;
    }

//   newtio.c_iflag=IGNPAR | IGNBRK;
    newtio.c_iflag=IGNBRK;
//   newtio.c_iflag=IGNPAR;

    //software handshake
    if (cfg->sw_handshake)
    {
        newtio.c_iflag |= IXON | IXOFF;
    }
    else
    {
        newtio.c_iflag &= ~(IXON|IXOFF|IXANY);
    }

    newtio.c_lflag=0;
    newtio.c_oflag=0;

    newtio.c_cc[VTIME]=1;
    newtio.c_cc[VMIN]=60;

//   tcflush(cfg->_fd, TCIFLUSH);
    if(tcsetattr(cfg->_fd, TCSANOW, &newtio)!=0)
    {
        eprintf("tcsetattr() 1 failed\n");
        return -1;
    }

    int mcs=0;
    ioctl(cfg->_fd, TIOCMGET, &mcs);
    mcs |= TIOCM_RTS;
    ioctl(cfg->_fd, TIOCMSET, &mcs);

    if (tcgetattr(cfg->_fd, &newtio)!=0)
    {
        eprintf("tcgetattr() 4 failed\n");
        return -1;
    }

    newtio.c_cflag &= ~CRTSCTS;
    if(cfg->hw_handshake)
    {
        newtio.c_cflag |= CRTSCTS;
    }

    if(tcsetattr(cfg->_fd, TCSANOW, &newtio)!=0)
    {
        eprintf("tcsetattr() 2 failed\n");
        return -1;
    }
    
    cfg->_line_ends = cfg->line_ends;
    if(cfg->_line_ends == LINE_ENDS_AUTO)
#ifdef _OS_IS_WINDOWS
        cfg->_line_ends = LINE_ENDS_CRLF;
#else
        cfg->_line_ends = LINE_ENDS_LF;
#endif

    return 0;
}

int serial_putb(SerialConfig *cfg, uint8_t c, uint32_t delay)
{
    if(!inited(cfg)) return -1;

    int res = write(cfg->_fd, &c, 1);
    if (res<1)
    {
        eprintf("write returned %d, errno: %d\n", res, errno);
        return -1;
    }

    if(delay != 0) millisleep(delay);

    return 0;
}

int serial_getb(SerialConfig *cfg, uint8_t *c)
{
    if(!inited(cfg)) return -1;

    int res = read(cfg->_fd, &c, 1);
    if(res < 0)
    {
        eprintf("read returned %d, errno: %d\n", res, errno);
        return -1;
    }

    return res;
}

int serial_close(SerialConfig *cfg)
{
    if(!inited(cfg)) return -1;

    if(cfg->_fd >= 0)
    {
        tcsetattr(cfg->_fd, TCSANOW, &cfg->_old_tio);
        close(cfg->_fd);
        cfg->_fd = -1;
    }
    
    if(cfg->_in_fp != NULL)
    {
        if(cfg->_in_fp != stdin) { fclose(cfg->_in_fp); }
        cfg->_in_fp = NULL;
    }

    if(cfg->_out_fp!= NULL)
    {
        if(cfg->_out_fp != stdout) { fclose(cfg->_out_fp); }
        cfg->_out_fp = NULL;
    }

    if(cfg->_err_fp != NULL)
    {
        if(cfg->_err_fp != stderr) { fclose(cfg->_err_fp); }
        cfg->_err_fp = NULL;
    }
    
    if(cfg->_devPath)
    {
        free(cfg->_devPath);
        cfg->_devPath = NULL;
    }
    
    return 0;
}

void print_serial_config(SerialConfig *cfg)
{
    if(cfg->_devPath)
        printf("dev:\t\t%s\n", cfg->_devPath);
    printf("baud:\t\t%d\n", cfg->baud);
    printf("chlen:\t\t%d\n", ((cfg->chlen == CHLEN_5) ? 5 : 
        (((cfg->chlen == CHLEN_5) ? 6 : 
        ((cfg->chlen == CHLEN_5) ? 7 : 8)))));
    printf("parity:\t\t%s\n", ((cfg->parity == PARITY_NONE) ? "None" : 
        ((cfg->parity == PARITY_EVEN) ? "Even" : "Odd")));
    printf("sbits:\t\t%s\n", ((cfg->sbits == STOPBITS_2) ? "1" : 
        (((cfg->sbits == STOPBITS_1) ? "1" : 
        ((cfg->sbits == STOPBITS_1_5) ? "1.5" :
        "0")))));
    printf("SW hshake:\t%c\n", cfg->sw_handshake ? 'Y' : 'N');
    printf("HW hshake:\t%c\n", cfg->hw_handshake ? 'Y' : 'N');
}

int cons_putchar(SerialConfig *cfg, uint8_t ch)
{
    if(!inited(cfg)) return -1;
    
    if(cfg->_line_ends != LINE_ENDS_DEF)
    {
        if(ch == '\x0A')
        {
            if(cfg->_line_ends == LINE_ENDS_CRLF)
            {
                if((cfg->_prev_ch == -1) || (cfg->_prev_ch != '\x0D'))
                {
                    fputc('\x0D', cfg->_out_fp);
                }
            }
        }
        else if(ch == '\x0D')
        {
            if(cfg->_line_ends == LINE_ENDS_LF)
            {
                // if line endings are set to only LF, ignore any CR chars
                return 0;
            }
        }
    }
    
    fputc(ch, cfg->_out_fp);
    cfg->_prev_ch = ch;

    return 0;
}
