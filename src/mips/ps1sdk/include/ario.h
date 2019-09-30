/* 
 * File:   ario.h
 * Author: aric
 *
 * Created on February 10, 2009, 1:13 AM
 */

#ifndef _ARIO_H
#define	_ARIO_H

#ifdef	__cplusplus
extern "C" {
#endif

/* prototypes */

int ar12_peek(uint8_t *ch, int timeout);
int ar12_poke(uint8_t ch, int timeout);
int ar12_reset(void);

int ar3_peek(uint8_t *ch, int timeout);
int ar3_poke(uint8_t ch, int timeout);
int ar3_reset(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _ARIO_H */

