/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include "shell/hull.h"

#include <stddef.h>
#include <stdint.h>

#include "shell/math.h"

static inline void swap(struct Vertex2D *v1, struct Vertex2D *v2) {
    struct Vertex2D temp = *v1;
    *v1 = *v2;
    *v2 = temp;
}

static inline int orientation(struct Vertex2D p, struct Vertex2D q, struct Vertex2D r) {
    int px = p.x >> 17;
    int py = p.y >> 17;
    int qx = q.x >> 17;
    int qy = q.y >> 17;
    int rx = r.x >> 17;
    int ry = r.y >> 17;
    int val = (qy - py) * (rx - qx) - (qx - px) * (ry - qy);
    if (val == 0) return 0;
    return (val > 0) ? 1 : -1;
}

static inline int distSq(struct Vertex2D p1, struct Vertex2D p2) {
    int32_t x1 = p1.x >> 17;
    int32_t x2 = p2.x >> 17;
    int32_t y1 = p1.y >> 17;
    int32_t y2 = p2.y >> 17;
    int32_t dx = x1 - x2;
    int32_t dy = y1 - y2;
    return dx * dx + dy * dy;
}

static struct Vertex2D *s_v0;

static int compare(struct Vertex2D *p1, struct Vertex2D *p2) {
    if (p1 == p2) return 0;

    int o = orientation(*s_v0, *p1, *p2);
    if (o == 0) return (distSq(*s_v0, *p2) >= distSq(*s_v0, *p1)) ? -1 : 1;

    return o;
}

static void qsort(struct Vertex2D *base, size_t nmemb) {
    size_t i, a, b, c;
    while (nmemb > 1) {
        a = 0;
        b = nmemb - 1;
        c = (a + b) / 2; /* Middle element */
        for (;;) {
            while (compare(&base[c], &base[a]) > 0) a++; /* Look for one >= middle */
            while (compare(&base[c], &base[b]) < 0) b--; /* Look for one <= middle */
            if (a >= b) break;                           /* We found no pair */
            swap(&base[a], &base[b]);                    /* swap them */
            if (c == a)                                  /* Keep track of middle element */
                c = b;
            else if (c == b)
                c = a;
            a++; /* These two are already sorted */
            b--;
        } /* a points to first element of right intervall now (b to last of left) */
        b++;
        if (b < nmemb - b) /* do recursion on smaller intervall and iteration on larger one */
        {
            qsort(base, b);
            base = &base[b];
            nmemb = nmemb - b;
        } else {
            qsort(&base[b], nmemb - b);
            nmemb = b;
        }
    }
}

int convexHull(struct Vertex2D *v, int n) {
    s_v0 = &v[0];
    int ymin = v[0].y, min = 0, i, m;
    struct Vertex2D *stack = &v[8];
    for (i = 1; i < n; i++) {
        if ((v[i].y < ymin) || ((v[i].y == ymin) && (v[i].x < v[min].x))) {
            ymin = v[i].y;
            min = i;
        }
    }
    swap(&v[0], &v[min]);
    if (n > 1) qsort(&v[1], n - 1);
    m = 1;
    for (i = 1; i < n; i++) {
        while ((i < n - 1) && orientation(v[0], v[i], v[i + 1]) == 0) i++;
        v[m++] = v[i];
    }
    n = m;
    if (n < 3) return n;
    stack[0] = v[0];
    stack[1] = v[1];
    stack[2] = v[2];
    m = 2;
    for (i = 3; i < n; i++) {
        while (orientation(stack[m - 1], stack[m], v[i]) >= 0) m--;
        stack[++m] = v[i];
    }
    n = ++m;
    return n;
}
