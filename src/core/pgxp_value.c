#include "limits.h"
#include "pgxp_value.h"

void SetValue(PGXP_value *pV, u32 psxV) {
    psx_value psx;
    psx.d = psxV;

    pV->x = psx.sw.l;
    pV->y = psx.sw.h;
    pV->z = 0.f;
    pV->flags = VALID_01;
    pV->value = psx.d;
}

void MakeValid(PGXP_value *pV, u32 psxV) {
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

void Validate(PGXP_value *pV, u32 psxV) {
    // assume pV is not NULL
    pV->flags &= (pV->value == psxV) ? ALL : INV_VALID_ALL;
}

void MaskValidate(PGXP_value *pV, u32 psxV, u32 mask, u32 validMask) {
    // assume pV is not NULL
    pV->flags &= ((pV->value & mask) == (psxV & mask)) ? ALL : (ALL ^ (validMask));
}

u32 ValueToTolerance(PGXP_value *pV, u32 psxV, float tolerance) {
    psx_value psx;
    psx.d = psxV;
    u32 retFlags = VALID_ALL;

    if (fabs(pV->x - psx.sw.l) >= tolerance) retFlags = retFlags & (VALID_1 | VALID_2 | VALID_3);

    if (fabs(pV->y - psx.sw.h) >= tolerance) retFlags = retFlags & (VALID_0 | VALID_2 | VALID_3);

    return retFlags;
}

/// float logical arithmetic ///

double f16Sign(double in) {
    u32 s = in * (double)((u32)1 << 16);
    return ((double)*((s32 *)&s)) / (double)((s32)1 << 16);
}
double f16Unsign(double in) { return (in >= 0) ? in : ((double)in + (double)USHRT_MAX + 1); }
double fu16Trunc(double in) {
    u32 u = in * (double)((u32)1 << 16);
    return (double)u / (double)((u32)1 << 16);
}
double f16Overflow(double in) {
    double out = 0;
    s64 v = ((s64)in) >> 16;
    out = v;
    return out;
}