# DIAGNOSTIC solver: aligns the voice-1 tap dump against the hardware goldens the
# same way spu_compare_golden does (onset skip 15, best of all ring offsets) and
# scores candidate rounding rules for the gaussian taps and the ADSR envelope.
import numpy as np, struct, sys, os

ONSET = 15
G = np.load('/tmp/gauss512.npy')
d = np.loadtxt('/tmp/v1dump.txt', dtype=np.int64)
env, raw, prod, out, idx, w0, w1, w2, w3, seq = [d[:, i] for i in range(10)]
W = [w0, w1, w2, w3]
TESTS = ['loop_t0', 'loop_t1', 'sine', 'sine_high', 'triangle', 'square',
         'sine_low', 'sine_pitch_0800', 'sine_pitch_3000', 'sine_pitch_2000']


def golden(name):
    b = open('src/mips/tests/spu/%s.test.pcm' % name, 'rb').read()
    magic, length, warmup, period = struct.unpack('<4I', b[:16])
    s = np.array(struct.unpack('<%dh' % ((len(b) - length) // 2), b[length:]), dtype=np.int64)
    keptS = warmup // 2 + period // 2
    return s[:keptS]


def align(name, vals=None):
    """Best linear offset of the dump against this golden, comparing [ONSET, keptS)."""
    g = golden(name)
    gc = g[ONSET:]
    series = out if vals is None else vals
    N = len(series) - len(g)
    best, bo = -1, -1
    for st in range(0, N, 200000):
        en = min(st + 200000, N)
        ii = np.arange(st, en)[:, None] + np.arange(ONSET, len(g))[None, :]
        mm = (series[ii] == gc[None, :]).sum(1)
        k = int(mm.argmax())
        if mm[k] > best:
            best, bo = int(mm[k]), st + k
    return g, gc, bo, best


def tap(kind, c, x):
    p = c * x
    if kind == 'SAR15':
        return p >> 15
    if kind == 'trunc':
        return np.trunc(p / 32768.0).astype(np.int64)
    if kind == 'round':
        return (p + 16384) >> 15


def adsr(kind, P):
    if kind == 'floor':
        return P >> 15
    if kind == 'round':
        return (P + 16384) >> 15
    if kind == 'trunc':
        return np.trunc(P / 32768.0).astype(np.int64)


def synth(tk, ak, sl):
    i = idx[sl]
    R = (tap(tk, G[0x0FF - i], w0[sl]) + tap(tk, G[0x1FF - i], w1[sl])
         + tap(tk, G[0x100 + i], w2[sl]) + tap(tk, G[0x000 + i], w3[sl]))
    return adsr(ak, env[sl] * R)


if __name__ == '__main__':
    if sys.argv[1] == 'validate':
        print('%-16s %-8s %-26s %s' % ('test', 'compared', 'baseline bad/dmin/dmax', 'idx values'))
        for n in TESTS:
            g, gc, o, best = align(n)
            L = len(g)
            sl = slice(o + ONSET, o + L)
            diff = out[sl] - gc
            bad = int((diff != 0).sum())
            iv = sorted(set(idx[sl].tolist()))
            print('%-16s %-8d bad=%-4d minus1=%-4d dmin=%-7d dmax=%-7d  n_idx=%d %s'
                  % (n, len(gc), bad, int((diff == -1).sum()), diff.min(), diff.max(),
                     len(iv), (iv[:6] if len(iv) <= 6 else str(iv[:5]) + '...')))
    elif sys.argv[1] == 'sweep':
        names = sys.argv[2:] or TESTS
        rows = []
        for tk in ['SAR15', 'trunc', 'round']:
            for ak in ['floor', 'round', 'trunc']:
                tot = ok = 0
                per = []
                for n in names:
                    g, gc, o0, _ = align(n)
                    L = len(g)
                    bl = -1
                    for o in range(o0 - 40, o0 + 41):
                        sl = slice(o + ONSET, o + L)
                        if len(raw[sl]) != len(gc):
                            continue
                        k = int((synth(tk, ak, sl) == gc).sum())
                        if k > bl:
                            bl = k
                    per.append('%s %d/%d' % (n[:9], bl, len(gc)))
                    ok += bl
                    tot += len(gc)
                rows.append((ok, tot, tk, ak, per))
                mark = '  <=== PERFECT' if ok == tot else ''
                print('gauss=%-6s adsr=%-6s %4d/%4d%s' % (tk, ak, ok, tot, mark))
                print('      ' + '  '.join(per))
        rows.sort(reverse=True)
        print('\nBEST: gauss per-tap %s + ADSR %s -> %d/%d' % (rows[0][2], rows[0][3], rows[0][0], rows[0][1]))
