#ifndef _XMODEM_H
#define _XMODEM_H

#include "sys/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_XM_SEND_RETRY 10

#define XM_SOH 1
#define XM_STX 2
#define XM_EOT 4
#define XM_ACK 6
#define XM_NAK 21
#define XM_CAN 24

typedef int (*PeekFunc)(uint8_t* ch, int timeout);
typedef int (*PokeFunc)(uint8_t ch, int timeout);

int xmodem_recv(PeekFunc peek, PokeFunc poke, int use_crc16, void* dest, int max, int timeout);
int xmodem_send(PeekFunc peek, PokeFunc poke, int use_1k, void* src, int len, int timeout);

#ifdef __cplusplus
}
#endif

#endif /* _XMODEM_H */
