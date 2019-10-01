/*
 * File:   serialio.h
 * Author: asmblur
 *
 * Created on February 10, 2009, 1:13 AM
 * Reversed on September 2, 2019
 */

#ifndef _SERIALIO_H
#define _SERIALIO_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions:
 *
 * DTE(Data Terminal Equiptment): a PC/PS/etc(Not a modem)
 * DCE(Data Communications Equiptment): a modem
 *
 * RTS-CTS flow control:
 * RTS/RTR: Request To Send/Ready To Receive, assert to indicate readiness to receive data
 * CTS: Clear To Send, input from RTR of other.
 *
 * DTR: Data Terminal Ready, assert to indicate readiness to communicate
 * DSR: Data Set Ready, input from DTR of other
 *
 *
 *
 *
 */

// bits for STATUS
// SIO Interrupt Pending
#define SIO_STAT_IRQ 0x0200
#define SIO_STAT_CTS 0x0100
#define SIO_STAT_DSR 0x0080
#define SIO_STAT_SYNC_DET 0x0040
#define SIO_STAT_FRAME_ERR 0x0020
#define SIO_STAT_RX_OVRN_ERR 0x0010
#define SIO_STAT_PARITY_ERR 0x0008
#define SIO_STAT_TX_EMPTY 0x0004
#define SIO_STAT_RX_RDY 0x0002
#define SIO_STAT_TX_RDY 0x0001
#define SIO_STAT_MASK (0x03FF)

// bits for CONTROL

// enable DSR interrupts.
#define SIO_CTRL_DSRI_EN 0x1000
// enable RXD interrupts.
#define SIO_CTRL_RXI_EN 0x0800
// enable TXD interrupts.
#define SIO_CTRL_TXI_EN 0x0400
#define SIO_CTRL_BUF8 0x0300
#define SIO_CTRL_BUF4 0x0200
#define SIO_CTRL_BUF2 0x0100
#define SIO_CTRL_BUF1 0x0000
// why is there nothing for bit 7? CTRL_BUFx is bits 9-10
#define SIO_CTRL_RESET_INT 0x0040
// enable RTS driver(inverted)
#define SIO_CTRL_RTS_EN 0x0020
#define SIO_CTRL_RTR_EN 0x0020
#define SIO_CTRL_RESET_ERR 0x0010
#define SIO_CTRL_BRK 0x0008
// enable RXD
#define SIO_CTRL_RX_EN 0x0004
// enable DTR driver(inverted)
#define SIO_CTRL_DTR_EN 0x0002
// enable TXD
#define SIO_CTRL_TX_EN 0x0001
#define SIO_CTRL_MASK (0x1FFF)

/*
 *  SIO1
 *  Pins go from left to right
 *
 * NOTE: All pins except for RXD, TXD, GND and 3V3 are inverted.
 *
 *  Pin         Name    Dir             Notes
 * -----        -----   ---             ----------
 *   1          RXD             I               Receive Data
 *   2          3V3                             3.3V output
 *   3          DSR             I               Data Set Ready
 *       4              TXD             O               Transmit Data
 *       5              CTS             O               Clear To Send
 *   6          DTR     I               Data Terminal Ready
 *       7              GND                             Ground
 *   8          RTS             O               Request To Send
 */

// Bits for MODE

// MODE: Stop Bits
// bits 6-7
#define SIO_MODE_SB_1 0x0040
#define SIO_MODE_SB_1_5 0x0080
#define SIO_MODE_SB_2 0x00C0

// MODE: Parity
// bits 4-5
#define SIO_MODE_P_NONE 0x0000
#define SIO_MODE_P_ODD 0x0010
#define SIO_MODE_P_EVEN 0x0030

// MODE: Character Length(Bits Per Character)
// bits 2-3
#define SIO_MODE_CHLEN_5 0x0000
#define SIO_MODE_CHLEN_6 0x0004
#define SIO_MODE_CHLEN_7 0x0008
#define SIO_MODE_CHLEN_8 0x000C

// MODE: Baud Rate multiplier(??)
// NOTE: supposedly these 2 bits should always be "10"(2)..
// bits 0-1
#define SIO_MODE_BR_1 0x0001
#define SIO_MODE_BR_16 0x0002
#define SIO_MODE_BR_64 0x0003

#define SIO_MODE_MASK 0x00FF

/* prototypes */

int sio_peek8(uint32_t timeout);
uint32_t sio_peek32(uint32_t timeout);
uint16_t sio_peek16(uint32_t timeout);

int sio_poke8(uint8_t data, uint32_t timeout);
int sio_poke16(uint16_t data, uint32_t timeout);
int sio_poke32(uint32_t data, uint32_t timeout);

void sio_reset(void);
void sio_clear_error(void);
void sio_reset_driver(void);
void init_sio(uint32_t baud);

//~ void sio_init(int port_no, int baud);

//~ int sio_reset(int port_no);
//~ int sio_reset_fifos(int port_no);

//~ int sio_set_baud(int port_no, int baud);

//~ int sio_get_byte(int port_no);
//~ int sio_put_byte(int port_no, uint8_t data, uint32_t timeout);

//~ uint8_t sio_peek_data(int port_no);
//~ void sio_poke_data(int port_no, uint8_t data);

//~ uint16_t sio_peek_status(int port_no);
//~ void sio_poke_status(int port_no, uint16_t status);

//~ uint16_t sio_peek_mode(int port_no);
//~ void sio_poke_mode(int port_no, uint16_t mode);

//~ uint16_t sio_peek_ctrl(int port_no);
//~ void sio_poke_ctrl(int port_no, uint16_t ctrl);

//~ uint16_t sio_peek_baud(int port_no);
//~ void sio_poke_baud(int port_no, uint16_t baud);

// TTY stuff(uses SIO1)
int sio_putchar(char ch);

#ifdef __cplusplus
}
#endif

#endif /* _SERIALIO_H */
