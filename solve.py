# DIAGNOSTIC solver: aligns the voice-1 tap dump against the hardware goldens the
# same way spu_compare_golden does (onset skip 15, best of all ring offsets) and
# scores candidate rounding rules for the gaussian taps and the ADSR envelope.
import numpy as np, struct, sys, os

ONSET = 15
G = np.load('/tmp/gauss512.npy')
def _load(path):
    """The probe writes unbuffered from a live emulator, so the tail can be a
    partial line. Read it as raw ints and drop anything that is not a full row."""
    with open(path) as f:
        rows = [l.split() for l in f]
    ncol = max(len(r) for r in rows)
    rows = [r for r in rows if len(r) == ncol]
    return np.array(rows, dtype=np.int64)


d = _load('/tmp/v1dump.txt')
env, raw, prod, out, idx, w0, w1, w2, w3, seq = [d[:, i] for i in range(10)]
W = [w0, w1, w2, w3]
# Resampler cursor state, present only in dumps from the extended probe.
if d.shape[1] >= 15:
    consumed, spos, sinc, apos, curroff = [d[:, i] for i in range(10, 15)]
else:
    consumed = spos = sinc = apos = curroff = None
TESTS = ['loop_t0', 'loop_t1', 'sine', 'sine_high', 'triangle', 'square',
         'sine_low', 'sine_pitch_0800', 'sine_pitch_3000', 'sine_pitch_2000', 'sine_pitch_1500']


def golden(name):
    """Returns (samples[:keptS], startS). startS mirrors spu_compare_golden as of
    703ad59f6: the warmup region is declared contaminated by prior state, so the
    comparison begins at max(SPU_ONSET_SKIP, warmupS), not at SPU_ONSET_SKIP."""
    b = open('src/mips/tests/spu/%s.test.pcm' % name, 'rb').read()
    magic, length, warmup, period = struct.unpack('<4I', b[:16])
    s = np.array(struct.unpack('<%dh' % ((len(b) - length) // 2), b[length:]), dtype=np.int64)
    warmupS = warmup // 2
    keptS = warmupS + period // 2
    return s[:keptS], max(ONSET, warmupS)


def align(name, vals=None):
    """Best linear offset of the dump against this golden, comparing [startS, keptS)."""
    g, startS = golden(name)
    gc = g[startS:]
    series = out if vals is None else vals
    N = len(series) - len(g)
    best, bo = -1, -1
    for st in range(0, N, 200000):
        en = min(st + 200000, N)
        ii = np.arange(st, en)[:, None] + np.arange(startS, len(g))[None, :]
        mm = (series[ii] == gc[None, :]).sum(1)
        k = int(mm.argmax())
        if mm[k] > best:
            best, bo = int(mm[k]), st + k
    return g, gc, bo, best, startS


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
            g, gc, o, best, startS = align(n)
            L = len(g)
            sl = slice(o + startS, o + L)
            diff = out[sl] - gc
            bad = int((diff != 0).sum())
            iv = sorted(set(idx[sl].tolist()))
            print('%-16s %-8d bad=%-4d minus1=%-4d dmin=%-7d dmax=%-7d  n_idx=%d %s'
                  % (n, len(gc), bad, int((diff == -1).sum()), diff.min(), diff.max(),
                     len(iv), (iv[:6] if len(iv) <= 6 else str(iv[:5]) + '...')))
    elif sys.argv[1] == 'cursor':
        # Dump, rather than infer, what the resampler did across the compared
        # window: the cumulative source samples consumed, the fractional pitch
        # position, and where the ADPCM read cursor sat. The question is WHERE
        # consumed and predicted part company, not at what average rate.
        for n in (sys.argv[2:] or TESTS):
            g, gc, o, best, startS = align(n)
            L = len(g)
            sl = slice(o + startS, o + L)
            diff = out[sl] - gc
            print('== %s  aligned@%d  compared=%d  bad=%d  dmin=%d dmax=%d'
                  % (n, o, len(gc), int((diff != 0).sum()), diff.min(), diff.max()))
            if consumed is None:
                print('   (dump has no cursor columns)')
                continue
            c, sp, si, ap, co = consumed[sl], spos[sl], sinc[sl], apos[sl], curroff[sl]
            # The pitch counter is an identity by construction: every output adds
            # sinc and every consumed sample subtracts kUnity. A break in it means
            # something outside the loop moved the counter.
            pred = c * 65536 + sp - (c[0] * 65536 + sp[0])
            step = np.cumsum(np.concatenate([[0], si[:-1]]))
            drift = pred - step
            brk = np.nonzero(np.diff(drift))[0]
            print('   sinc=%s  identity breaks at %s'
                  % (sorted(set(si.tolist())), (brk[:8].tolist() if len(brk) else 'NONE')))
            # Self-period of what Redux emitted, against the golden's declared one.
            per = (len(g) - (len(g) - len(gc))) if False else None
            o_stream = out[sl]
            selfper = [p for p in range(1, len(o_stream) // 2 + 1)
                       if np.array_equal(o_stream[:-p], o_stream[p:])]
            gper = [p for p in range(1, len(gc) // 2 + 1)
                    if np.array_equal(gc[:-p], gc[p:])]
            print('   redux self-period=%s  golden self-period=%s'
                  % (selfper[:3] or 'none<=half', gper[:3] or 'none<=half'))
            print('   consumed/output=%.4f  apos span=%d..%d  curroff set=%s'
                  % ((c[-1] - c[0]) / max(1, len(c) - 1), ap.min(), ap.max(),
                     sorted(set(co.tolist()))[:8]))
            if int((diff != 0).sum()):
                k = np.nonzero(diff)[0]
                print('   first 10 mismatches (i, redux, golden, d, idx, apos, curroff):')
                for i in k[:10]:
                    print('     %4d %7d %7d %4d  idx=%3d apos=%2d curr=%d'
                          % (i, o_stream[i], gc[i], diff[i], idx[sl][i], ap[i], co[i]))
    elif sys.argv[1] == 'sweep':
        names = sys.argv[2:] or TESTS
        rows = []
        for tk in ['SAR15', 'trunc', 'round']:
            for ak in ['floor', 'round', 'trunc']:
                tot = ok = 0
                per = []
                for n in names:
                    g, gc, o0, _, startS = align(n)
                    L = len(g)
                    bl = -1
                    for o in range(o0 - 40, o0 + 41):
                        sl = slice(o + startS, o + L)
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
