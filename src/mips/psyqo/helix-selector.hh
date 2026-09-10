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

#pragma once

#include <EASTL/functional.h>
#include <stdint.h>

#include "psyqo/fixed-point.hh"
#include "psyqo/kernel.hh"
#include "psyqo/primitives/common.hh"
#include "psyqo/trigonometry.hh"

namespace psyqo {

/**
 * @brief A helix selector, seen down its own axis.
 *
 * @details Items are laid out along a helix wrapped around a cylinder, and the
 * camera looks straight down the helix axis, so the screen shows a spiral of
 * annular sectors.
 *
 * EVERY ITEM OWNS A FIXED SPOKE. Item `i` sits at angle `i * 2pi / itemsPerTurn`
 * and never leaves it. What the crank moves is the CURSOR, which sweeps around
 * the circle; items slide IN AND OUT along their own spokes as it approaches or
 * passes them. So this is a dial, not a carousel: `a` is always in the same place
 * on screen, and the user gets muscle memory for free.
 *
 * It follows that item `i` and item `i + itemsPerTurn` share a spoke exactly, at
 * different radii. That is the far-side doubling that shows what is coming, and
 * it falls out of the geometry rather than being tuned in.
 *
 * It also means the analog adapter is ABSOLUTE: the stick angle IS the cursor
 * angle. Only the lap needs unwrapping, which `setStickAngle` does for you.
 *
 * This class owns the geometry and the selection state and nothing else. It has
 * no idea what a glyph is, what a character is, or that capital letters exist. It
 * hands back quad corners plus a centre point per visible item and reports what
 * got selected or activated; drawing, atlases, casing, text buffers and what
 * "enter" means are all yours.
 *
 * The helix is infinite and the item list is CYCLIC on it: the item at helix
 * offset `d` is `(cursor + d) mod itemCount`, so cranking never hits an end, and
 * one turn out from the first item is whatever the atlas has last.
 */
class HelixSelector {
  public:
    struct Event {
        enum Type { SelectionChanged, Activated } type;
        unsigned index;
    };

    /**
     * @brief One visible item.
     *
     * @details `a`, `b`, `c`, `d` are the corners of the annular sector, already in
     * the Z order `psyqo::Quad` wants. `glyph` is where to centre whatever you draw
     * on top of it, upright. `scale` is the perspective ratio, 1.0 at the cursor,
     * bigger toward the camera and smaller away from it - use it to size your glyph.
     * `fade` is 0..1 and only ramps at the far end of the strip; use it for colour.
     */
    struct Slot {
        unsigned index;
        Vertex a, b, c, d;
        Vertex glyph;
        FixedPoint<> scale;
        FixedPoint<> fade;
    };

    /**
     * @brief The cursor marker, as a triangle you can draw directly.
     *
     * @details Already rotated: `tip` points OUTWARD along the cursor's own spoke,
     * at the box it currently selects, so it turns as the crank turns. `left` and
     * `right` are the base corners. The library computes these because the app has
     * no cheap way to rotate a shape without a trig table of its own.
     */
    struct Cursor {
        Vertex tip, left, right;
    };

    struct Config {
        Vertex center = {{.x = 160, .y = 120}};
        FixedPoint<> innerRadius = 44.0;      // cylinder radii, before projection
        FixedPoint<> outerRadius = 68.0;
        FixedPoint<> cameraDistance = 128.0;  // h in the r = R * h / z divide
        FixedPoint<> cursorZ = 150.0;         // z of the item under the cursor
        FixedPoint<> pitch = 10.0;            // z travelled per item
        FixedPoint<> gap = 0.88;              // fraction of the angular step drawn
        FixedPoint<> settleRate = 0.3;        // per frame, toward the target
        unsigned itemsPerTurn = 20;
        // How much helix is on screen, in items. Since spokes are fixed, these do
        // not decide WHETHER two quads share an angle - `i` and `i + itemsPerTurn`
        // always do - they decide how many LAPS of that are visible either side of
        // the cursor. `(nearSpan + farSpan + 1) / itemsPerTurn` turns, roughly.
        unsigned nearSpan = 13;   // items emitted toward the camera
        unsigned farSpan = 13;    // items emitted away from it
        unsigned fadeItems = 5;   // far-end fade ramp, in items
        FixedPoint<> cursorGap = 5.0;     // from the inner ring to the marker's tip
        FixedPoint<> cursorLength = 9.0;  // tip to base, along the spoke
        FixedPoint<> cursorHalfWidth = 5.0;
    };

    static constexpr unsigned c_maxSlots = 48;

    void setup(unsigned itemCount, const Config& config) {
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
        Kernel::assert((itemCount % config.itemsPerTurn) == 0,
                       "HelixSelector: itemCount must be a whole number of turns");
        FixedPoint<> two = 2.0;
        m_angleStep = two / int32_t(config.itemsPerTurn ? config.itemsPerTurn : 1);
    }

    void setOnEvent(eastl::function<void(Event)>&& callback) { m_callback = eastl::move(callback); }

    /**
     * @brief Crank by an absolute stick angle.
     *
     * @details Feed this the raw stick direction every frame the stick is deflected
     * enough to mean something, and simply stop calling it when it re-centres; the
     * cursor stays where it was. The stick angle IS the cursor angle, so pointing
     * somewhere new puts the cursor there directly. The only thing accumulated is
     * the LAP: crossing the +/-pi seam moves you one turn along the helix rather
     * than jumping the cursor to the far side of the dial.
     */
    void setStickAngle(Angle a) {
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

    /** @brief Crank by whole items. This is the d-pad adapter. */
    void step(int32_t items) {
        m_target += FixedPoint<>(items, int32_t(0));
    }

    /**
     * @brief Your confirm button's rising edge.
     *
     * @details If the helix is still settling this snaps it to the target first and
     * then fires, so a confirm is never swallowed mid-animation.
     */
    void activate() {
        m_position = m_target;
        unsigned index = resolve();
        if (index != m_selected) {
            m_selected = index;
            emit({Event::SelectionChanged, index});
        }
        emit({Event::Activated, index});
    }

    /** @brief Settle one frame and rebuild the visible slots. */
    void update(const Trig<>& trig) {
        m_position += (m_target - m_position) * m_config.settleRate;
        normalize();
        unsigned index = resolve();
        if (index != m_selected) {
            m_selected = index;
            emit({Event::SelectionChanged, index});
        }
        build(trig);
    }

    unsigned currentIndex() const { return m_selected; }
    unsigned visibleCount() const { return m_slotCount; }
    /** @brief Slot 0 is the furthest from the camera. Draw them in order. */
    const Slot& slot(unsigned n) const { return m_slots[n]; }
    /** @brief Where to draw the cursor marker, just inside the ring at the cursor angle. */
    const Cursor& cursor() const { return m_cursor; }
    /** @brief The cursor's current angle, if you want to orient the marker you draw. */
    Angle cursorAngle() const { return m_cursorAngle; }

  private:
    // Slide BOTH by whole laps together, so their difference (which is what the
    // settle animation rides on) is untouched and neither can drift out of range
    // after a few million frames of cranking.
    void normalize() {
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

    unsigned wrap(int32_t i) const {
        if (m_itemCount == 0) return 0;
        int32_t n = int32_t(m_itemCount);
        i %= n;
        if (i < 0) i += n;
        return unsigned(i);
    }

    unsigned resolve() const {
        FixedPoint<> half(int32_t(0), int32_t(FixedPoint<>::scale / 2));
        return wrap((m_position + half).integer<int32_t>());
    }

    void emit(Event e) {
        if (m_callback) m_callback(e);
    }

    void build(const Trig<>& trig) {
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

    FixedPoint<> fadeFor(FixedPoint<> d) const {
        if (m_config.fadeItems == 0) return 1.0;
        FixedPoint<> start = FixedPoint<>(int32_t(m_config.farSpan - m_config.fadeItems), int32_t(0));
        if (d.raw() <= start.raw()) return 1.0;
        FixedPoint<> span = FixedPoint<>(int32_t(m_config.fadeItems), int32_t(0));
        FixedPoint<> f = (FixedPoint<>(int32_t(m_config.farSpan), int32_t(0)) - d) / span;
        if (f.raw() < 0) return FixedPoint<>(int32_t(0), int32_t(0));
        return f;
    }

    static Vertex vtx(FixedPoint<> x, FixedPoint<> y) {
        return Vertex{{.x = int16_t(x.integer<int32_t>()), .y = int16_t(y.integer<int32_t>())}};
    }

    Vertex at(FixedPoint<> r, FixedPoint<> cosT, FixedPoint<> sinT) const {
        int16_t x = int16_t(m_config.center.x + (r * cosT).integer<int32_t>());
        int16_t y = int16_t(m_config.center.y + (r * sinT).integer<int32_t>());
        return Vertex{{.x = x, .y = y}};
    }

    Config m_config;
    eastl::function<void(Event)> m_callback = nullptr;
    Angle m_cursorAngle;
    FixedPoint<> m_angleStep;
    FixedPoint<> m_position;
    FixedPoint<> m_target;
    Cursor m_cursor = {};
    Slot m_slots[c_maxSlots];
    unsigned m_slotCount = 0;
    unsigned m_itemCount = 0;
    unsigned m_selected = 0;
};

}  // namespace psyqo
