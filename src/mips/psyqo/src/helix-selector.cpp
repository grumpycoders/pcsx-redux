/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

#include "psyqo/helix-selector.hh"

#include "psyqo/kernel.hh"

void psyqo::HelixSelector::setup(unsigned itemCount, const Config& config) {
    m_config = config;
    m_itemCount = itemCount;
    m_position = FixedPoint<>(int32_t(0), int32_t(0));
    m_target = m_position;
    m_selected = 0;
    m_slotCount = 0;
    // THE SEAM CONSTRAINT. Item `i` sits on spoke `i mod itemsPerTurn`, and the
    // item list wraps at `itemCount`. Unless the list wrap lands ON a lap
    // boundary, the letter that follows the last one comes back on a DIFFERENT
    // spoke, and the join between one turn of the helix and the next visibly
    // slips round. Pad the atlas, or pick a turn size that divides it.
    Kernel::assert((itemCount % config.itemsPerTurn) == 0, "HelixSelector: itemCount must be a whole number of turns");
    FixedPoint<> two = 2.0;
    m_angleStep = two / int32_t(config.itemsPerTurn ? config.itemsPerTurn : 1);
}

void psyqo::HelixSelector::setStickAngle(Angle a) {
    if (m_config.itemsPerTurn == 0) return;
    // The stick angle IS the cursor angle, so this is a straight conversion
    // rather than an integration: no drift, and pointing the stick somewhere
    // new puts the cursor there rather than winding toward it.
    FixedPoint<> want = FixedPoint<>(a) / m_angleStep;
    // `a` lives in (-1.0_pi, 1.0_pi], so `want` lands in one arbitrary lap.
    // Slide it to the lap nearest where the cursor already is; that, and only
    // that, is what the crank accumulates.
    FixedPoint<> lap(int32_t(m_config.itemsPerTurn), int32_t(0));
    FixedPoint<> half = lap / int32_t(2);
    while ((want - m_target).raw() > half.raw()) want -= lap;
    while ((m_target - want).raw() > half.raw()) want += lap;
    m_target = want;
}

void psyqo::HelixSelector::activate() {
    m_position = m_target;
    unsigned index = resolve();
    if (index != m_selected) {
        m_selected = index;
        emit({Event::SelectionChanged, index});
    }
    emit({Event::Activated, index});
}

void psyqo::HelixSelector::update(const Trig<>& trig) {
    m_position += (m_target - m_position) * m_config.settleRate;
    normalize();
    unsigned index = resolve();
    if (index != m_selected) {
        m_selected = index;
        emit({Event::SelectionChanged, index});
    }
    build(trig);
}

void psyqo::HelixSelector::normalize() {
    if (m_itemCount == 0) return;
    FixedPoint<> lap(int32_t(m_itemCount), int32_t(0));
    while (m_position.raw() >= lap.raw()) {
        m_position -= lap;
        m_target -= lap;
    }
    while (m_position.raw() < 0) {
        m_position += lap;
        m_target += lap;
    }
}

unsigned psyqo::HelixSelector::wrap(int32_t i) const {
    if (m_itemCount == 0) return 0;
    int32_t n = int32_t(m_itemCount);
    i %= n;
    if (i < 0) i += n;
    return unsigned(i);
}

void psyqo::HelixSelector::build(const Trig<>& trig) {
    m_slotCount = 0;
    int32_t base = m_position.integer<int32_t>();
    int32_t first = base - int32_t(m_config.nearSpan);
    int32_t last = base + int32_t(m_config.farSpan);
    // Furthest first, so the caller can draw straight down the list. `i` is a
    // position ON THE HELIX, which is unbounded; the item it shows is `i` wrapped.
    for (int32_t i = last; i >= first; i--) {
        if (m_slotCount >= c_maxSlots) break;
        FixedPoint<> d = FixedPoint<>(i, int32_t(0)) - m_position;
        FixedPoint<> z = m_config.cursorZ + d * m_config.pitch;
        // Anything at or behind the camera plane is gone.
        if (z.raw() <= (FixedPoint<>(int32_t(4), int32_t(0))).raw()) continue;
        FixedPoint<> s = m_config.cameraDistance / z;
        // The spoke is the item's OWN and does not move: only `z` above depends
        // on the cursor. `i * angleStep` runs past a full turn and the cosine
        // table normalises through a uint32_t modulo, so i and i+itemsPerTurn
        // land on the same spoke by construction.
        Angle theta = Angle(FixedPoint<>(i, int32_t(0)) * m_angleStep);
        Angle half = Angle(m_angleStep * m_config.gap) / int32_t(2);
        Angle t0 = theta - half;
        Angle t1 = theta + half;
        FixedPoint<> rin = m_config.innerRadius * s;
        FixedPoint<> rout = m_config.outerRadius * s;
        FixedPoint<> c0 = trig.cos(t0), s0 = trig.sin(t0);
        FixedPoint<> c1 = trig.cos(t1), s1 = trig.sin(t1);
        Slot& slot = m_slots[m_slotCount++];
        slot.index = wrap(i);
        slot.a = at(rin, c0, s0);
        slot.b = at(rin, c1, s1);
        slot.c = at(rout, c0, s0);
        slot.d = at(rout, c1, s1);
        FixedPoint<> rmid = (rin + rout) / int32_t(2);
        slot.glyph = at(rmid, trig.cos(theta), trig.sin(theta));
        slot.scale = s * (m_config.cursorZ / m_config.cameraDistance);
        slot.fade = fadeFor(d);
    }
    // The cursor is the thing that moves. Its angle is the continuous cursor
    // position on the same spoke scale, so it sweeps between spokes rather than
    // snapping, and it sits just inside the ring at the cursor's own depth.
    Angle cursorAngle = Angle(m_position * m_angleStep);
    FixedPoint<> cc = trig.cos(cursorAngle), cSin = trig.sin(cursorAngle);
    FixedPoint<> cs = m_config.cameraDistance / m_config.cursorZ;
    FixedPoint<> rTip = m_config.innerRadius * cs - m_config.cursorGap;
    FixedPoint<> rBase = rTip - m_config.cursorLength;
    // Radial unit vector is (cos, sin); its perpendicular is (-sin, cos). No
    // extra trig needed to spin the marker, just the two we already have.
    FixedPoint<> bx = m_config.center.x + (rBase * cc);
    FixedPoint<> by = m_config.center.y + (rBase * cSin);
    FixedPoint<> wx = -(cSin * m_config.cursorHalfWidth);
    FixedPoint<> wy = cc * m_config.cursorHalfWidth;
    m_cursor.tip = at(rTip, cc, cSin);
    m_cursor.left = vtx(bx + wx, by + wy);
    m_cursor.right = vtx(bx - wx, by - wy);
    m_cursorAngle = cursorAngle;
}

psyqo::FixedPoint<> psyqo::HelixSelector::fadeFor(FixedPoint<> d) const {
    if (m_config.fadeItems == 0) return 1.0;
    FixedPoint<> start = FixedPoint<>(int32_t(m_config.farSpan - m_config.fadeItems), int32_t(0));
    if (d.raw() <= start.raw()) return 1.0;
    FixedPoint<> span = FixedPoint<>(int32_t(m_config.fadeItems), int32_t(0));
    FixedPoint<> f = (FixedPoint<>(int32_t(m_config.farSpan), int32_t(0)) - d) / span;
    if (f.raw() < 0) return FixedPoint<>(int32_t(0), int32_t(0));
    return f;
}
