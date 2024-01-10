/*
 * This program is going to just print "Hello world!" in an infinite loop, using
 * the printf() function provided by the PS1 kernel. By default the output of
 * this function is not routed anywhere, however an appropriate executable
 * loader can be used on real hardware to redirect it to the serial port on the
 * back of the console or to another interface. Additionally, most emulators can
 * log calls to printf() and display the output in their log window.
 *
 * For a variant of this project that prints directly to the PS1's serial port
 * instead of using the kernel, see:
 *     https://github.com/spicyjpeg/ps1-bare-metal/blob/main/src/00_helloWorld/main.c
 */

#define BIOS_API_TABLE ((void **) 0x80000200)

int main(int argc, const char **argv) {
	int (*kernelPrintf)(const char *, ...) =
		(int (*)(const char *, ...)) BIOS_API_TABLE[0x3f];

	for (;;)
		kernelPrintf("Hello world!\n");

	// We're not actually going to return. Unless a loader was used to launch
	// the program, returning from main() would crash the console as there would
	// be nothing to return to.
	return 0;
}
