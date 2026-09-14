#!/usr/bin/env python3
"""Emit job.h for the MDEC roundtrip rig.

The job is baked into the executable. That started as a workaround for PCopen
returning -1 on the farm while PCcreat succeeded, and THAT DIAGNOSIS WAS WRONG:
PCDRV is complete and the protocol is fine; the runner-agent had no references to
input_fileset, so assets attached with --asset were resolved, digest-pinned,
shipped and then dropped. Fixed in the farm's f9d1c4f. Baking it in is kept
because it makes a run self-contained and identical under the emulator, not
because the read half is missing.

COEFFICIENTS ARE PER BLOCK. The six blocks are Cr, Cb, Y1, Y2, Y3, Y4 in that
order; Cr and Cb are one low-resolution 8x8 each covering the whole macroblock,
Y1..Y4 are the four 8x8 luma quadrants. So a sweep that wants to compare
quadrants against each other must leave BOTH chroma blocks empty - chroma with
any AC content lands differently on each quadrant and destroys the comparison.
With chroma flat, the four luma quadrants of one capture are four independent
readings of one run, which is what turns an 8-second console run into a sweep.
"""
import struct, sys

STD = [0x5A82]*8 + [0x7D8A,0x6A6D,0x471C,0x18F8,0xE707,0xB8E3,0x9592,0x8275] \
    + [0x7641,0x30FB,0xCF04,0x89BE,0x89BE,0xCF04,0x30FB,0x7641] \
    + [0x6A6D,0xE707,0x8275,0xB8E3,0x471C,0x7D8A,0x18F8,0x9592] \
    + [0x5A82,0xA57D,0xA57D,0x5A82,0x5A82,0xA57D,0xA57D,0x5A82] \
    + [0x471C,0x8275,0x18F8,0x6A6D,0x9592,0xE707,0x7D8A,0xB8E3] \
    + [0x30FB,0x89BE,0x7641,0xCF04,0xCF04,0x7641,0x89BE,0x30FB] \
    + [0x18F8,0xB8E3,0x6A6D,0x8275,0x7D8A,0x9592,0x471C,0xE707]
STD = [v - 0x10000 if v > 0x7fff else v for v in STD]

# ---------------------------------------------------------------------------
# SINGLE-TERM ARMS (2026-09-14). Arms S and Z each move three things at once,
# which is why neither localises anything. Each arm below moves ONE term, and
# most are self-discriminating INSIDE one capture rather than against a control
# run, so they answer without needing the emulator to be right about anything.
#
# psx-spx rl_decode_block, the model under test:
#     DC  val = signed10bit * qt[0]                      <- no q_scale, no /8, and
#                                                           psx-spx marks it "(?)"
#     AC  val = (signed10bit * qt[k] * q_scale + 4) / 8
#     both  val = minmax(val, -400h, +3FFh)              <- signed 11 bits
#     q_scale == 0: val = signed10bit * 2, no qt, no zigzag
#
#   D8/D63   DC ignores q_scale?  q_scale 8 is the neutral point where the two
#            candidate DC formulas coincide, so D8 == D63 byte-for-byte means the
#            DC genuinely ignores q_scale and the "(?)" line is right.
#   D8F      Output rounding, after D8 and DSAT2 both came back off by exactly
#            +1 on every quadrant whose flat level is an exact .5 and exact
#            everywhere else. Four quadrants at 153.0 / 153.25 / 153.75 / 165.5.
#   DSAT     BLIND, KEPT AS THE RECORD OF WHY. A DC-only block decodes to a flat
#            128 + val/8, so the 11-bit clamp at val 1023 lands at output 255.875
#            and the 8-bit output clip lands at val 1024. They are ONE LSB apart,
#            so both hypotheses predict a flat 255 and the arm cannot fail. Use
#            DSAT2, which lowers the transform gain until the clamp bites first.
#   DSAT2    DC saturation, observable. Same job on a HALVED scale table, whose
#            two-pass gain is 1/4, so the flat level is 128 + val/32 and a clamped
#            1023 lands at 160 with room to spare. Y3 (1024) and Y4 (2044) are
#            IDENTICAL if the DC clamps and 32 levels apart if it does not.
#   ASAT     AC saturation, and this one DOES discriminate even at standard gain,
#            because an AC block is a ramp rather than a flat field: Y3 (1024) and
#            Y4 (4024) share the rails AND the four intermediate ramp values, which
#            a 3.9x steeper unclamped ramp could not do. Read the ramp, not the
#            rails - "both quadrants are railed" would have proved nothing.
#   ZDC      q_scale == 0 DC rule.  ZDCC computes the SAME value by the ordinary
#            route (qt[0]=2 at the neutral q_scale), so identical output means
#            "val = signed10bit * 2 with no quant table" is right.
#   ZAC      q_scale == 0 zigzag.  One AC at k=2, where zscan[2] = 8 != 2, and
#            ZACC computes the same magnitude with q_scale=1/qt=16. The two differ
#            ONLY in whether the zigzag is applied, so they land on different
#            basis functions if psx-spx's "no zigzag" is right and are identical
#            if it is wrong.
# ---------------------------------------------------------------------------

def build(arm):
    upload = arm != 'A'
    st = list(STD)
    if arm in ('D', 'S2', 'Z2'): st[0] += 1                      # forces the general path, basis ~unchanged
    if arm == 'B': st = [v // 2 for v in st]       # halved basis
    quant = 1
    qscale = 8
    dc = [200, -150, 300, -80, 120, -40]
    ac = [(0, 90), (2, -60)]
    acs = None                                     # per-block override

    # S: force the 11-bit saturation psx-spx puts in rl_decode_block. With qt=83
    # (the largest standard entry) and q_scale=63, an AC of 500 dequantizes to
    # 500*83*63/8 = 326,812, which is ~800x the +0x3FF ceiling. If hardware
    # saturates, the output is nothing like the unsaturated arithmetic.
    if arm in ('S', 'S2'):
        quant, qscale = 83, 63
        dc = [400, -400, 500, -500, 450, -450]
        ac = [(0, 500), (1, -500)]

    # Z: q_scale == 0, the mode psx-spx documents as val = signed10bit * 2 with NO
    # quant table and NO zigzag. The emulator implements none of it.
    if arm in ('Z', 'Z2'):
        qscale = 0
        ac = [(0, 200), (3, -150)]

    # --- single-term arms. Chroma is flat in every one of them on purpose. ---
    if arm in ('D8', 'D63'):
        qscale = 8 if arm == 'D8' else 63
        dc = [0, 0, 200, 300, 400, 500]
        acs = [[]] * 6
    if arm == 'D8F':
        # Output rounding. 128 + val/8 for a flat DC-only block, so DCs of
        # 200/202/206/300 put the four quadrants at 153.0, 153.25, 153.75 and
        # 165.5 - one exact integer, one fraction below the half, one above, and
        # one exact tie. floor gives 153/153/153/165 (Y1 == Y2 == Y3); round-half-up
        # gives 153/153/154/166. D8 and DSAT2 already showed silicon taking the
        # LOW side of a .5 tie while the emulator's SCALER rounds up; this arm says
        # whether that is floor everywhere or a tie-break rule only.
        quant, qscale = 1, 8
        dc = [0, 0, 200, 202, 206, 300]
        acs = [[]] * 6
    if arm in ('DSAT', 'DSAT2'):
        quant, qscale = 4, 8
        dc = [0, 0, 100, 200, 256, 511]            # *4 -> 400, 800, 1024, 2044
        acs = [[]] * 6
        # Halving the basis quarters the two-pass gain, which is what pulls the
        # clamped value down off the 8-bit rail and makes the clamp observable.
        if arm == 'DSAT2': st = [v // 2 for v in st]
    if arm == 'ASAT':
        quant, qscale = 1, 63
        dc = [0] * 6
        # (v*63+4)/8 -> 504, 788, 1024, 4024
        acs = [[], [], [(0, 64)], [(0, 100)], [(0, 130)], [(0, 511)]]
    if arm in ('ZDC', 'ZDCC'):
        quant, qscale = (1, 0) if arm == 'ZDC' else (2, 8)
        dc = [0, 0, 100, 200, 300, 400]
        acs = [[]] * 6
    if arm in ('ZAC', 'ZACC'):
        quant, qscale = (1, 0) if arm == 'ZAC' else (16, 1)
        dc = [0] * 6
        # run 1 -> k = 2, and zscan[2] = 8, so the zigzag is observable.
        # ZAC:  val = 300*2            = 600
        # ZACC: val = (300*16*1 + 4)/8 = 600
        acs = [[], [], [(1, 300)], [(1, 300)], [(1, 300)], [(1, 300)]]

    if acs is None: acs = [ac] * 6

    rl = []
    for b in range(6):
        rl += [((qscale & 0x3f) << 10) | (dc[b] & 0x3ff)]
        for run, val in acs[b]:
            rl += [((run & 0x3f) << 10) | (val & 0x3ff)]
        rl += [0xFE00]
    # psx-spx: "DMA0 and DMA1 should be usually used with a blocksize of 20h words.
    # If necessary, the parameters for the MDEC(1) command should be padded with
    # FE00h halfwords to match the 20h words (40h halfwords) DMA blocksize."
    # 40h HALFWORDS, not 20h. Padding to 32 halfwords leaves a 16-word transfer,
    # whose block count (words/32) rounds to ZERO and hangs DMA0 on real hardware.
    while len(rl) % 64: rl.append(0xFE00)
    return upload, st, rl, quant

# R arms probe whether an MDEC reset clears the uploaded tables. All of them
# upload the STANDARD scale table first, so a table that survives reset yields
# the known-good image and a table that does not yields flat grey.
#   R1 reset, then decode                    R3 reset, re-upload scale only
#   R2 reset, re-upload quant only           R4 reset, re-upload both (control)
RESET_MODE = {'R1': 1, 'R2': 2, 'R3': 3, 'R4': 4}

arm = sys.argv[1]
reset = RESET_MODE.get(arm, 0)
upload, st, rl, quant = build('C' if arm.startswith('R') else arm)
out = [f'// Generated by genjob.py {arm} - do not edit.', '#pragma once', '#include <stdint.h>', '']
out.append(f'#define JOB_ARM "{arm}"')
out.append(f'#define JOB_UPLOAD_SCALE {1 if upload else 0}')
out.append(f'#define JOB_RESET_MODE {reset}')
out.append(f'#define JOB_RL_WORDS {len(rl)}')
out.append('static const uint8_t job_quant[128] = {' + ','.join([str(quant)]*128) + '};')
out.append('static const int16_t job_scale[64] = {' + ','.join(str(v) for v in st) + '};')
out.append('static const uint16_t job_rl[%d] = {' % len(rl) + ','.join(str(v) for v in rl) + '};')
open('job.h','w').write('\n'.join(out) + '\n')
print(f'job.h: arm {arm}, upload={upload}, reset_mode={reset}, {len(rl)} rl words, scale[0]={st[0]}')
