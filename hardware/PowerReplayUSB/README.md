# PowerReplayUSB

An FT232H mod for the Power Replay cart. The board solders onto the castellations where the cart's missing comms buffer would go. [PowerReplayUSBC](../PowerReplayUSBC) is the same board with a USB-C connector.

## Ordering

The `GerberFiles` directory and the two CSV files are ready for JLCPCB's assembly service.

- `GATES` is a 74LVC02 (C548044). The SN74AHC02PWR it replaces is close to out of stock at LCSC. The 7402 is powered from the cart's 5V rail, and LVC parts are rated up to 5.5V, so any TSSOP-14 74LVC02 fits.
- The schematic says 93LC76B for the EEPROM. The BOM's C190271 is a 93LC56B, the part FTDI's datasheet names.
- The FT232HQ (C82158) is often low in stock. Check it before ordering.

## Registers

The FT232H only answers when A2=0 and A4=0, anywhere in 0x1f060000-0x1f07ffff, and only 0x1f060008 decodes writes. Use these addresses:

- data: `0x1f060008`
- status: `0x1f060009`, bit 0 set when a byte can be read, bit 1 set when a byte can be written. Bits 4-7 follow the next byte in the receive FIFO, so mask the status to bits 0 and 1.

The stock EXP1 settings work. A read delay of 0 does not.

The FT232H is powered from the USB port only, so the console side reads an undriven bus when no computer is plugged in.
