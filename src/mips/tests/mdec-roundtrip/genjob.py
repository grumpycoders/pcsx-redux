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
#            ANSWERED: silicon returns 153 / 153 / 154 / 165, so .75 rounds UP and
#            .50 rounds DOWN. That is ROUND-HALF-DOWN and it is NOT floor - floor
#            would have returned 153 for the .75 quadrant. SCALER rounds ties up.
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
#   ZTWO     Two ACs in one block, the last uncovered shape in that mode.
#   ZK5      ZMIX with the coefficient moved to k=5, arm Z's other AC position.
#   ZMIX     q_scale == 0 with a DC AND an AC - the combination ZDC and ZAC each
#            cover half of, and the only untested shape left in that mode.
#   WRAP     The 9-bit clip in the colour path, which psx-spx marks "probably".
#            Needs a clamped DC plus a clamped AC to reach - see the arm.
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

    # G arms: the AC composite gain split, ON SILICON. One AC per arm, DC zero,
    # chroma identical, and the quant table is flat (job_quant is 128 copies of
    # `quant`), so the ONLY thing that differs between them is how many axes of the
    # coefficient's RASTER position sit at DC.
    #   GONE  run 0 -> zigzag 1 -> raster 1  (row 0, col 1): ONE axis at DC
    #   GTWO  run 3 -> zigzag 4 -> raster 9  (row 1, col 1): NEITHER axis at DC
    #
    # Host measurement against real_idct_core says Ginv is 0.1768 and 0.2500, a
    # factor of sqrt(2). The basis at pixel (0,0) is cos(pi/16) for GONE and
    # cos(pi/16)^2 for GTWO, so the two hypotheses predict:
    #   split gain (what we now ship) : GTWO/GONE amplitude = 1.391
    #   uniform gain (what we shipped): GTWO/GONE amplitude = 0.981
    # Near-equality against a 39% difference - these cannot be confused, which is
    # the whole reason the arm is a RATIO of two arms rather than one absolute read.
    # Score on (pixel - flat background) at Y1's top-left corner, same pixel in both.
    #
    # Run through real_idct_core at these exact settings, the luma offset at that
    # pixel is +69 for GONE and +96 for GTWO, ratio 1.3913. Both are well inside
    # range with no clipping at either end of the basis, so a console that clips is
    # reporting something other than this. If silicon comes back near 0.98 the
    # split is wrong and the 8192/1024 divisor in supportpsx/dct.cc must go back.
    #
    # ⚠ This is the one claim in the encoder calibration that has only ever been
    # checked against psx-spx's pseudocode, never against a console.
    if arm in ('GONE', 'GTWO'):
        quant, qscale = 1, 8
        dc = [0] * 6
        acs = [[] for _ in range(6)]
        acs[2] = [(0 if arm == 'GONE' else 3, 400)]   # block 2 = Y1

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
        # ANSWERED 2026-09-14: a tie-break rule only. Measured 153/153/154/165.
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
    if arm == 'ZMIX':
        # q_scale == 0 with a DC *and* ACs, which is the one combination none of
        # the single-term Z arms covers. ZDC (DC only) and ZAC (AC only, DC zero)
        # are both bit-exact; arm Z, which has both plus a second AC, is not, and
        # its survivors run the OPPOSITE way to the wrap (emulator 0 where hardware
        # reads 255). So the terms are individually right and the combination is
        # not - this arm says whether that is the combination itself or arm Z's
        # third variable. Same DC as ZDC, same single AC at k=2 as ZAC, nothing
        # else moved.
        quant, qscale = 1, 0
        dc = [0, 0, 100, 200, 300, 400]
        acs = [[], [], [(1, 300)], [(1, 300)], [(1, 300)], [(1, 300)]]
    if arm == 'ZTWO':
        # Last uncovered shape in q_scale == 0 mode, and the only variable left
        # between the bit-exact arms and arm Z: TWO ACs in one block. ZDC (DC
        # only), ZAC (one AC, no DC), ZMIX (DC + AC at k=2) and ZK5 (DC + AC at
        # k=5) are all bit-exact. Arm Z carries a DC plus ACs at k=1 and k=5 with
        # opposite signs, and rail-flips against hardware. Same AC pair as arm Z,
        # on the controlled DC set, so nothing else moves.
        quant, qscale = 1, 0
        dc = [0, 0, 100, 200, 300, 400]
        acs = [[], [], [(0, 200), (3, -150)]] * 1 + [[(0, 200), (3, -150)]] * 3
    if arm == 'ZK5':
        # ZMIX came back +-1, so q_scale == 0 with a DC and ONE AC is fine and the
        # combination is not the defect. Arm Z's remaining variable is its SECOND
        # AC, at run 3 -> k = 5 (zscan[5] = 2, so the no-zigzag store is observable
        # there too). This is ZMIX with that coefficient in place of the k=2 one and
        # nothing else moved: +-1 means the POSITION is fine and the defect is in
        # carrying TWO ACs, rail flips mean it is the position.
        quant, qscale = 1, 0
        dc = [0, 0, 100, 200, 300, 400]
        acs = [[], [], [(3, 300)], [(3, 300)], [(3, 300)], [(3, 300)]]
    if arm == 'WRAP':
        # The 9-bit clip psx-spx marks "probably" on yuv_to_rgb, borrowed from
        # y_to_mono's `Y = Y AND 1FFh` BEFORE the MinMax(-128,127). A DC-only arm
        # cannot reach it: the 11-bit dequant clamp caps val at 1023, so Y tops out
        # at 127.875 and never crosses 256. It needs a clamped DC AND a clamped AC
        # summing past it. qt=83 puts both at the 1023 rail; the AC at k=1 then
        # adds roughly +-178 to the DC's 127.9, so the bright end of each quadrant
        # crosses 256 and the dark end does not.
        #   WRAP  : Y>=256 masks to a negative 9-bit value, saturates to -128 and
        #           comes out 0, so a DARK BAND appears inside the bright region.
        #   CLAMP : the bright region is flat 255 with no band.
        # A dark band inside a bright region cannot be produced by clamping, so the
        # arm is self-discriminating in one capture.
        quant, qscale = 83, 8
        dc = [0, 0, 400, 400, 400, 400]
        acs = [[], [], [(0, 400)], [(0, 400)], [(0, 400)], [(0, 400)]]
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

# Every arm build() actually branches on, plus C, which is the control and is the
# thing every unmatched name falls through to. That fall-through is why this list
# exists: before it, `genjob.py GTWO2` built the CONTROL job, printed "arm GTWO2"
# and exited 0, so a typo produced a real console run whose pixels were scored as
# an arm that was never built. Fail closed instead - a name added to build() and
# not to this list refuses loudly, which is the direction that cannot lie.
ARMS = frozenset("""
A B C D D8 D63 D8F S S2 Z Z2 ZK5 DSAT DSAT2 ASAT ZTWO ZMIX WRAP
ZDC ZDCC ZAC ZACC GONE GTWO R1 R2 R3 R4
""".split())

arm = sys.argv[1]
if arm not in ARMS:
    sys.exit(f'genjob.py: unknown arm {arm!r}. Known: {" ".join(sorted(ARMS))}\n'
             'An unmatched name would build the control job and report success.')
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
