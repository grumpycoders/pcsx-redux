
#pragma once

#define ISIN_SHIFT  10
#define ISIN2_SHIFT 15
#define ISIN_PI     (1 << (ISIN_SHIFT  + 1))
#define ISIN2_PI    (1 << (ISIN2_SHIFT + 1))

#ifdef __cplusplus
extern "C" {
#endif

int isin(int x);
int isin2(int x);

static inline int icos(int x) {
	return isin(x + (1 << ISIN_SHIFT));
}
static inline int icos2(int x) {
	return isin2(x + (1 << ISIN2_SHIFT));
}

#ifdef __cplusplus
}
#endif
