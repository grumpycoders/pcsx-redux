#include <limits.h>

#include "core/pgxp_value.h"

void SetValue(PGXP_value* pV, uint32_t psxV) {
    psx_value psx;
    psx.d = psxV;

    pV->x = psx.sw.l;
    pV->y = psx.sw.h;
    pV->z = 0.f;
    pV->flags = VALID_01;
    pV->value = psx.d;
}

void MakeValid(PGXP_value* pV, uint32_t psxV) {
    psx_value psx;
    psx.d = psxV;
    if (VALID_01 != (pV->flags & VALID_01)) {
        pV->x = psx.sw.l;
        pV->y = psx.sw.h;
        pV->z = 0.f;
        pV->flags = VALID_01;
        pV->value = psx.d;
    }
}

void Validate(PGXP_value* pV, uint32_t psxV) {
    // assume pV is not NULL
    pV->flags &= (pV->value == psxV) ? ALL : INV_VALID_ALL;
}

void MaskValidate(PGXP_value* pV, uint32_t psxV, uint32_t mask, uint32_t validMask) {
    // assume pV is not NULL
    pV->flags &= ((pV->value & mask) == (psxV & mask)) ? ALL : (ALL ^ (validMask));
}

uint32_t ValueToTolerance(PGXP_value* pV, uint32_t psxV, float tolerance) {
    psx_value psx;
    psx.d = psxV;
    uint32_t retFlags = VALID_ALL;

    if (fabs(pV->x - psx.sw.l) >= tolerance) retFlags = retFlags & (VALID_1 | VALID_2 | VALID_3);

    if (fabs(pV->y - psx.sw.h) >= tolerance) retFlags = retFlags & (VALID_0 | VALID_2 | VALID_3);

    return retFlags;
}

/// float logical arithmetic ///

double f16Sign(double in) {
    uint32_t s = in * (double)((uint32_t)1 << 16);
    return ((double)*((int32_t*)&s)) / (double)((int32_t)1 << 16);
}
double f16Unsign(double in) { return (in >= 0) ? in : ((double)in + (double)USHRT_MAX + 1); }
double fu16Trunc(double in) {
    uint32_t u = in * (double)((uint32_t)1 << 16);
    return (double)u / (double)((uint32_t)1 << 16);
}
double f16Overflow(double in) {
    double out = 0;
    int64_t v = ((int64_t)in) >> 16;
    out = v;
    return out;
}
