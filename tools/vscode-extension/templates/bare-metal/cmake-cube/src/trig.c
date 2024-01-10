/*
 * This is a fast lookup-table-less implementation of fixed-point sine and
 * cosine, based on the isin_S4 implementation from:
 *     https://www.coranac.com/2009/07/sines
 */

#include "trig.h"

#define A (1 << 12)
#define B 19900
#define	C 3516

int isin(int x) {
	int c = x << (30 - ISIN_SHIFT);
	x    -= 1 << ISIN_SHIFT;

	x <<= 31 - ISIN_SHIFT;
	x >>= 31 - ISIN_SHIFT;
	x  *= x;
	x >>= 2 * ISIN_SHIFT - 14;

	int y = B - (x * C >> 14);
	y     = A - (x * y >> 16);

	return (c >= 0) ? y : (-y);
}

int isin2(int x) {
	int c = x << (30 - ISIN2_SHIFT);
	x    -= 1 << ISIN2_SHIFT;

	x <<= 31 - ISIN2_SHIFT;
	x >>= 31 - ISIN2_SHIFT;
	x  *= x;
	x >>= 2 * ISIN2_SHIFT - 14;

	int y = B - (x * C >> 14);
	y     = A - (x * y >> 16);

	return (c >= 0) ? y : (-y);
}
