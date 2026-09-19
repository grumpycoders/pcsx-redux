#!/usr/bin/env python3
"""Packs a PNG series into one blob the mdecplayer example links in and plays.

    python3 -P packstream.py --pngs '~/mdec/25fps_*.png' --fps 25 --mode PAL \
        --qscale 4 --mdec <path to the mdec tool> -o stream.bin

The PNGs are not in the repo - they are too big - so this is the step you run
against your own series before building the player.

Everything the guest would otherwise hard-code travels in the blob instead: the
macroblock order, the quantization table, the IDCT matrix, the frame rate, and
how many vsyncs one frame is worth. That is deliberate. The one bug this format
exists to prevent is a player that disagrees with its stream about macroblock
order, which renders as horizontal bands of vertically-striped blocks and which
a round trip between two halves that share the convention cannot see.

The quant table is read out of supportpsx/dct.cc and the IDCT matrix out of the
roundtrip rig's genjob.py rather than transcribed here, so there is one copy of
each in the tree and no second one to get wrong.
"""

import argparse
import glob
import os
import re
import struct
import subprocess
import sys

MAGIC = b'MDPL'
VERSION = 1
HEADER = 0x118  # magic..scale, then the offset table


def std_quant(root):
    src = open(os.path.join(root, 'src', 'supportpsx', 'dct.cc')).read()
    m = re.search(r'c_packStandardQuant\[64\]\s*=\s*\{(.*?)\};', src, re.S)
    if not m:
        sys.exit('packstream: c_packStandardQuant not found in dct.cc')
    vals = [int(x) for x in re.findall(r'\d+', m.group(1))]
    if len(vals) != 64:
        sys.exit('packstream: expected 64 quant entries, read %d' % len(vals))
    return vals


def std_scale(root):
    # genjob.py's STD, the matrix the roundtrip rig uploads with MDEC(3).
    src = open(os.path.join(root, 'src', 'mips', 'tests', 'mdec-roundtrip', 'genjob.py')).read()
    m = re.search(r'^STD = (.*?)^STD = \[v - 0x10000', src, re.S | re.M)
    if not m:
        sys.exit('packstream: STD not found in genjob.py')
    vals = eval(m.group(1).strip())
    vals = [v - 0x10000 if v > 0x7fff else v for v in vals]
    if len(vals) != 64:
        sys.exit('packstream: expected 64 scale entries, read %d' % len(vals))
    return vals


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pngs', required=True, help='glob for the frame series, in order')
    ap.add_argument('--fps', required=True, type=int, choices=(25, 30))
    ap.add_argument('--mode', required=True, choices=('NTSC', 'PAL'))
    ap.add_argument('--qscale', type=int, default=4)
    ap.add_argument('--mdec', required=True, help='path to the mdec tool (needs the BS encoder)')
    ap.add_argument('--root', default=None, help='repo root; defaults to four levels up from here')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--order', choices=('raster', 'column'), default='raster',
                    help="the macroblock order to encode in. Passed through to `mdec -order` AND "
                         "recorded in the blob, so the two cannot disagree. column walks 16-pixel "
                         "columns top to bottom, which makes each column of the decoded frame one "
                         "contiguous run the player can upload as a single VRAM rect.")
    a = ap.parse_args()

    root = a.root or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                  '..', '..', '..', '..', '..'))
    pngs = sorted(glob.glob(os.path.expanduser(a.pngs)))
    if not pngs:
        sys.exit('packstream: no PNGs matched %r' % a.pngs)

    # 60 Hz against 30 fps and 50 Hz against 25 fps both come out at 2, which is
    # why these two series pair with these two video modes.
    refresh = 60 if a.mode == 'NTSC' else 50
    if refresh % a.fps:
        sys.exit('packstream: %d fps does not divide %s\'s %d Hz' % (a.fps, a.mode, refresh))
    vsyncs = refresh // a.fps

    dims = None
    frames = []
    for i, png in enumerate(pngs):
        with open(png, 'rb') as f:
            ihdr = f.read(24)
        w, h = struct.unpack('>II', ihdr[16:24])
        if w % 16 or h % 16:
            sys.exit('packstream: %s is %dx%d, not a whole number of macroblocks' % (png, w, h))
        if dims is None:
            dims = (w, h)
        elif dims != (w, h):
            sys.exit('packstream: %s is %dx%d, the series started at %dx%d' % (png, w, h, *dims))
        tmp = a.out + '.frame.tmp'
        r = subprocess.run([a.mdec, 'bsencode', '-i', png, '-o', tmp, '-qscale', str(a.qscale),
                            '-order', a.order],
                           capture_output=True)
        if r.returncode:
            sys.exit('packstream: bsencode failed on %s: %s' % (png, r.stderr.decode()[:200]))
        bs = open(tmp, 'rb').read()
        os.unlink(tmp)
        if len(bs) < 8 or struct.unpack_from('<H', bs, 2)[0] != 0x3800:
            sys.exit('packstream: %s did not encode to a BS stream' % png)
        frames.append(bs)
        if (i + 1) % 25 == 0:
            print('  %d/%d' % (i + 1, len(pngs)), file=sys.stderr)

    w, h = dims
    # bsdecRlHalfwords is blocks_used * 2, straight out of each frame's header.
    max_rl = max(struct.unpack_from('<H', bs, 0)[0] * 2 for bs in frames)
    max_bs = max(len(bs) for bs in frames)

    body = bytearray()
    offsets = []
    base = HEADER + 4 * len(frames)
    for bs in frames:
        while (base + len(body)) & 3:
            body.append(0)
        offsets.append(base + len(body))
        body += bs

    quant, scale = std_quant(root), std_scale(root)
    blob = bytearray()
    blob += MAGIC
    blob += struct.pack('<HHHH', VERSION, len(frames), w, h)
    blob += struct.pack('<BBBB', a.fps, 1 if a.order == 'column' else 0,
                        1 if a.mode == 'PAL' else 0, vsyncs)
    blob += struct.pack('<II', max_rl, max_bs)
    blob += bytes(quant) * 2            # Y table then UV table, what MDEC(2) wants
    blob += struct.pack('<64h', *scale)  # MDEC(3) matrix
    assert len(blob) == HEADER, (len(blob), HEADER)
    blob += struct.pack('<%dI' % len(offsets), *offsets)
    blob += body

    with open(a.out, 'wb') as f:
        f.write(blob)
    print('%s: %d frames %dx%d, %s %d fps (%d vsyncs/frame), q_scale %d, %s order\n'
          '  %d bytes total, %d max frame, %d max rl halfwords'
          % (a.out, len(frames), w, h, a.mode, a.fps, vsyncs, a.qscale, a.order,
             len(blob), max_bs, max_rl))


if __name__ == '__main__':
    main()
