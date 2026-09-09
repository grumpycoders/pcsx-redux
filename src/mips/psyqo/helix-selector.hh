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
#include "psyqo/primitives/common.hh"
#include "psyqo/trigonometry.hh"

namespace psyqo {

/**
 * @brief A helix selector, seen down its own axis.
 *
 * @details Items are laid out along a helix wrapped around a cylinder, and the
 * camera looks straight down the helix axis. The result on screen is a spiral of
 * annular sectors: items near the camera are large and far apart, items further
 * along shrink toward the middle and pile up. Selection is whichever item is at
 * the cursor angle; you move through the list by cranking, which rotates and
 * advances at the same time, exactly as if you were walking a spiral staircase.
 *
 * This class owns the geometry and the selection state and nothing else. It has
 * no idea what a glyph is, what a character is, or that capital letters exist. It
 * hands back quad corners plus a centre point per visible item and reports what
 * got selected or activated; drawing, atlases, casing, text buffers and what
 * "enter" means are all yours.
 *
 * The helix is infinite and the item list is CYCLIC on it: the item at helix
 * offset `d` is `(cursor + d) mod itemCount`, so cranking never hits an end, and
 * one turn out from the first item is whatever the atlas has last. The same item
 * can therefore be on screen more than once, at different radii, which is exactly
 * the far-side doubling that tells the user what is coming.
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
        // Two quads may share an angle only well away from the cursor. That is
        // exactly `nearSpan + farSpan + 1 - itemsPerTurn` items of doubling, and it
        // sits opposite the cursor if and only if the two spans are equal. Keep them
        // equal, and keep the excess small.
        unsigned nearSpan = 13;   // items emitted toward the camera
        unsigned farSpan = 13;    // items emitted away from it
        unsigned fadeItems = 5;   // far-end fade ramp, in items
    };

    static constexpr unsigned c_maxSlots = 48;

    void setup(unsigned itemCount, const Config& config) {
        m_config = config;
        m_itemCount = itemCount;
        m_position = FixedPoint<>(int32_t(0), int32_t(0));
        m_target = m_position;
        m_selected = 0;
        m_hasStick = false;
        m_slotCount = 0;
        FixedPoint<> two = 2.0;
        m_angleStep = two / int32_t(config.itemsPerTurn ? config.itemsPerTurn : 1);
    }

    void setOnEvent(eastl::function<void(Event)>&& callback) { m_callback = eastl::move(callback); }

    /**
     * @brief Crank by an absolute stick angle.
     *
     * @details Feed this the raw stick direction every frame while the stick is
     * deflected, and call `releaseStick()` when it returns to centre. Successive
     * angles are unwrapped across the +/-pi seam here, so a full revolution of the
     * stick advances exactly one turn of the helix and crossing the seam never
     * sends the selection the long way round.
     */
    void setStickAngle(Angle a) {
        if (m_hasStick) {
            Angle delta = shortestDelta(a, m_lastStick);
            m_target += FixedPoint<>(delta) / m_angleStep;
        }
        m_lastStick = a;
        m_hasStick = true;
    }

    void releaseStick() { m_hasStick = false; }

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
    Vertex cursor() const { return m_cursor; }

  private:
    static Angle shortestDelta(Angle to, Angle from) {
        Angle d = to - from;
        Angle full = 2.0;
        Angle half = 1.0;
        while (d.raw() > half.raw()) d -= full;
        while (d.raw() <= -half.raw()) d += full;
        return d;
    }

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
            Angle theta = m_cursorAngle + Angle(d * m_angleStep);
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
        FixedPoint<> cz = m_config.cursorZ;
        FixedPoint<> cs = m_config.cameraDistance / cz;
        FixedPoint<> cr = m_config.innerRadius * cs - FixedPoint<>(int32_t(8), int32_t(0));
        m_cursor = at(cr, trig.cos(m_cursorAngle), trig.sin(m_cursorAngle));
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

    Vertex at(FixedPoint<> r, FixedPoint<> cosT, FixedPoint<> sinT) const {
        int16_t x = int16_t(m_config.center.x + (r * cosT).integer<int32_t>());
        int16_t y = int16_t(m_config.center.y + (r * sinT).integer<int32_t>());
        return Vertex{{.x = x, .y = y}};
    }

    Config m_config;
    eastl::function<void(Event)> m_callback = nullptr;
    Angle m_cursorAngle = -0.5;  // straight up, since screen y grows downward
    Angle m_lastStick;
    FixedPoint<> m_angleStep;
    FixedPoint<> m_position;
    FixedPoint<> m_target;
    Vertex m_cursor = {{.x = 0, .y = 0}};
    Slot m_slots[c_maxSlots];
    unsigned m_slotCount = 0;
    unsigned m_itemCount = 0;
    unsigned m_selected = 0;
    bool m_hasStick = false;
};

}  // namespace psyqo
