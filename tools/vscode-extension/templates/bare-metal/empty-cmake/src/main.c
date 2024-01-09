/*
 * This program is going to just print "Hello world!" in an infinite loop; since
 * we don't have the luxury of a terminal or even anything resembling a "text
 * mode" on the GPU, we'll use the PS1's serial port instead.
 *
 * The serial port can be found on the back of the console on all models except
 * the PSone, and can be connected to a PC with an appropriately modified link
 * cable. Internally it is connected to the secondary serial interface, known as
 * SIO1 (as opposed to SIO0 which is wired to the controller and memory card
 * ports). SIO1 is controlled through I/O registers, which we're going to
 * manipulate to get it to output our message.
 */

#include "ps1/registers.h"

static void printCharacter(char ch) {
	// Wait until the serial interface is ready to send a new byte, then write
	// it to the data register.
	// NOTE: the serial interface checks for an external signal (CTS) and will
	// *not* send any data until it is asserted. To avoid blocking forever if
	// CTS is not asserted, we have to check for it manually and abort if
	// necessary.
	while (
		(SIO_STAT(1) & (SIO_STAT_TX_NOT_FULL | SIO_STAT_CTS)) == SIO_STAT_CTS
	)
		__asm__ volatile("");

	if (SIO_STAT(1) & SIO_STAT_CTS)
		SIO_DATA(1) = ch;
}

int main(int argc, const char **argv) {
	// Reset the serial interface and initialize it to output data at 115200bps,
	// 8 data bits, 1 stop bit and no parity.
	SIO_CTRL(1) = SIO_CTRL_RESET;

	SIO_MODE(1) = SIO_MODE_BAUD_DIV16 | SIO_MODE_DATA_8 | SIO_MODE_STOP_1;
	SIO_BAUD(1) = (F_CPU / 16) / 115200;
	SIO_CTRL(1) = SIO_CTRL_TX_ENABLE | SIO_CTRL_RX_ENABLE | SIO_CTRL_RTS;

	// Output "Hello world!" in a loop, one character at a time.
	for (;;) {
		const char *str = "Hello world!\n";

		for (; *str; str++)
			printCharacter(*str);
	}

	// We're not actually going to return. Unless a loader was used to launch
	// the program, returning from main() would crash the console as there would
	// be nothing to return to.
	return 0;
}
