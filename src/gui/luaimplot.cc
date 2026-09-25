/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "gui/luaimplot.h"

#include <assert.h>
#include <stddef.h>

#include <exception>
#include <string>
#include <type_traits>
#include <vector>

#include "imgui/imgui.h"
#include "implot/implot.h"
#include "implot/implot_internal.h"
#include "lua/luawrapper.h"

namespace {

// Mirror of the ImPlotSpec cdef in gui/implotffi.lua. Any drift between this,
// the Lua cdef, and the real ImPlotSpec fails the build or the Lua load.
struct LuaImPlotSpec {
    ImVec4 LineColor;
    ImU32* LineColors;
    float LineWeight;
    ImVec4 FillColor;
    ImU32* FillColors;
    float FillAlpha;
    int Marker;
    float MarkerSize;
    float* MarkerSizes;
    ImVec4 MarkerLineColor;
    ImU32* MarkerLineColors;
    ImVec4 MarkerFillColor;
    ImU32* MarkerFillColors;
    float Size;
    int Offset;
    int Stride;
    int Flags;
};

static_assert(std::is_standard_layout_v<ImPlotSpec>);
static_assert(sizeof(ImPlotSpec) == sizeof(LuaImPlotSpec));
#define CHECK_SPEC_FIELD(f) static_assert(offsetof(ImPlotSpec, f) == offsetof(LuaImPlotSpec, f))
CHECK_SPEC_FIELD(LineColor);
CHECK_SPEC_FIELD(LineColors);
CHECK_SPEC_FIELD(LineWeight);
CHECK_SPEC_FIELD(FillColor);
CHECK_SPEC_FIELD(FillColors);
CHECK_SPEC_FIELD(FillAlpha);
CHECK_SPEC_FIELD(Marker);
CHECK_SPEC_FIELD(MarkerSize);
CHECK_SPEC_FIELD(MarkerSizes);
CHECK_SPEC_FIELD(MarkerLineColor);
CHECK_SPEC_FIELD(MarkerLineColors);
CHECK_SPEC_FIELD(MarkerFillColor);
CHECK_SPEC_FIELD(MarkerFillColors);
CHECK_SPEC_FIELD(Size);
CHECK_SPEC_FIELD(Offset);
CHECK_SPEC_FIELD(Stride);
CHECK_SPEC_FIELD(Flags);
#undef CHECK_SPEC_FIELD

void implotSpecDefault(ImPlotSpec* s) { *s = ImPlotSpec(); }
int implotSpecSize() { return sizeof(ImPlotSpec); }
int implotSpecFlagsOffset() { return offsetof(ImPlotSpec, Flags); }

const ImPlotSpec& spec(const ImPlotSpec* s) {
    static const ImPlotSpec def;
    return s ? *s : def;
}

ImVec4 color(const float* c) { return c ? ImVec4(c[0], c[1], c[2], c[3]) : IMPLOT_AUTO_COL; }

void outColor(const ImVec4& c, float* out) {
    out[0] = c.x;
    out[1] = c.y;
    out[2] = c.z;
    out[3] = c.w;
}

// Element type codes; the order must match `dataTypes` in gui/implotffi.lua.
template <typename F>
void dispatch(int type, F&& f) {
    switch (type) {
        case 0:
            f(ImS8{});
            break;
        case 1:
            f(ImU8{});
            break;
        case 2:
            f(ImS16{});
            break;
        case 3:
            f(ImU16{});
            break;
        case 4:
            f(ImS32{});
            break;
        case 5:
            f(ImU32{});
            break;
        case 6:
            f(ImS64{});
            break;
        case 7:
            f(ImU64{});
            break;
        case 8:
            f(float{});
            break;
        case 9:
            f(double{});
            break;
    }
}

#define P(p) ((const T*)(p))

// Errors thrown by ImPlot (its asserts throw through the forced include) are
// caught in every shim and handed to Lua through implotTakeError, since a C++
// exception unwinding through an FFI call loses its message.
std::string s_error;
bool s_hasError = false;

template <typename F>
auto guarded(F&& f) -> decltype(f()) {
    try {
        return f();
    } catch (const std::exception& e) {
        s_error = e.what();
    } catch (...) {
        s_error = "unknown C++ exception";
    }
    s_hasError = true;
    if constexpr (!std::is_void_v<decltype(f())>) return decltype(f()){};
}

const char* implotTakeError() {
    static std::string taken;
    if (!s_hasError) return nullptr;
    s_hasError = false;
    taken = std::move(s_error);
    s_error.clear();
    return taken.c_str();
}

// Preconditions ImPlot does not assert on. Plain C arrays are indexed by axis
// and style color without a range check, and SetupLock() dereferences the
// current plot without asserting it exists.
const char* implotCheckPlot() {
    return GImPlot->CurrentPlot ? nullptr : "needs to be called between BeginPlot() and EndPlot()";
}
const char* implotCheckAxis(int axis) {
    return axis >= ImAxis_X1 && axis < ImAxis_COUNT ? nullptr : "axis index out of bounds";
}
const char* implotCheckStyleCol(int idx) {
    return idx >= 0 && idx < ImPlotCol_COUNT ? nullptr : "style color index out of bounds";
}

// Begin/End
bool implotBeginPlot(const char* title, float w, float h, int flags) {
    return guarded([&] { return ImPlot::BeginPlot(title, ImVec2(w, h), flags); });
}
void implotEndPlot() {
    return guarded([&] { ImPlot::EndPlot(); });
}
bool implotBeginSubplots(const char* title, int rows, int cols, float w, float h, int flags, float* rowRatios,
                         float* colRatios) {
    return guarded([&] { return ImPlot::BeginSubplots(title, rows, cols, ImVec2(w, h), flags, rowRatios, colRatios); });
}
void implotEndSubplots() {
    return guarded([&] { ImPlot::EndSubplots(); });
}
bool implotBeginAlignedPlots(const char* id, bool vertical) {
    return guarded([&] { return ImPlot::BeginAlignedPlots(id, vertical); });
}
void implotEndAlignedPlots() {
    return guarded([&] { ImPlot::EndAlignedPlots(); });
}
bool implotBeginLegendPopup(const char* label, int button) {
    return guarded([&] { return ImPlot::BeginLegendPopup(label, button); });
}
void implotEndLegendPopup() {
    return guarded([&] { ImPlot::EndLegendPopup(); });
}
bool implotIsLegendEntryHovered(const char* label) {
    return guarded([&] { return ImPlot::IsLegendEntryHovered(label); });
}
bool implotBeginDragDropTargetPlot() {
    return guarded([&] { return ImPlot::BeginDragDropTargetPlot(); });
}
bool implotBeginDragDropTargetAxis(int axis) {
    return guarded([&] { return ImPlot::BeginDragDropTargetAxis(axis); });
}
bool implotBeginDragDropTargetLegend() {
    return guarded([&] { return ImPlot::BeginDragDropTargetLegend(); });
}
void implotEndDragDropTarget() {
    return guarded([&] { ImPlot::EndDragDropTarget(); });
}
bool implotBeginDragDropSourcePlot(int flags) {
    return guarded([&] { return ImPlot::BeginDragDropSourcePlot(flags); });
}
bool implotBeginDragDropSourceAxis(int axis, int flags) {
    return guarded([&] { return ImPlot::BeginDragDropSourceAxis(axis, flags); });
}
bool implotBeginDragDropSourceItem(const char* label, int flags) {
    return guarded([&] { return ImPlot::BeginDragDropSourceItem(label, flags); });
}
void implotEndDragDropSource() {
    return guarded([&] { ImPlot::EndDragDropSource(); });
}

// Setup
void implotSetupAxis(int axis, const char* label, int flags) {
    return guarded([&] { ImPlot::SetupAxis(axis, label, flags); });
}
void implotSetupAxisLimits(int axis, double vMin, double vMax, int cond) {
    return guarded([&] { ImPlot::SetupAxisLimits(axis, vMin, vMax, cond); });
}
void implotSetupAxisFormat(int axis, const char* fmt) {
    return guarded([&] { ImPlot::SetupAxisFormat(axis, fmt); });
}
void implotSetupAxisTicksValues(int axis, const double* values, int n, const char* const* labels, bool keepDefault) {
    return guarded([&] { ImPlot::SetupAxisTicks(axis, values, n, labels, keepDefault); });
}
void implotSetupAxisTicksRange(int axis, double vMin, double vMax, int n, const char* const* labels, bool keepDefault) {
    return guarded([&] { ImPlot::SetupAxisTicks(axis, vMin, vMax, n, labels, keepDefault); });
}
void implotSetupAxisScale(int axis, int scale) {
    return guarded([&] { ImPlot::SetupAxisScale(axis, scale); });
}
void implotSetupAxisLimitsConstraints(int axis, double vMin, double vMax) {
    return guarded([&] { ImPlot::SetupAxisLimitsConstraints(axis, vMin, vMax); });
}
void implotSetupAxisZoomConstraints(int axis, double zMin, double zMax) {
    return guarded([&] { ImPlot::SetupAxisZoomConstraints(axis, zMin, zMax); });
}
void implotSetupAxes(const char* xLabel, const char* yLabel, int xFlags, int yFlags) {
    return guarded([&] { ImPlot::SetupAxes(xLabel, yLabel, xFlags, yFlags); });
}
void implotSetupAxesLimits(double xMin, double xMax, double yMin, double yMax, int cond) {
    return guarded([&] { ImPlot::SetupAxesLimits(xMin, xMax, yMin, yMax, cond); });
}
void implotSetupLegend(int location, int flags) {
    return guarded([&] { ImPlot::SetupLegend(location, flags); });
}
void implotSetupMouseText(int location, int flags) {
    return guarded([&] { ImPlot::SetupMouseText(location, flags); });
}
void implotSetupFinish() {
    return guarded([&] { ImPlot::SetupFinish(); });
}
void implotSetNextAxisLimits(int axis, double vMin, double vMax, int cond) {
    return guarded([&] { ImPlot::SetNextAxisLimits(axis, vMin, vMax, cond); });
}
void implotSetNextAxisToFit(int axis) {
    return guarded([&] { ImPlot::SetNextAxisToFit(axis); });
}
void implotSetNextAxesLimits(double xMin, double xMax, double yMin, double yMax, int cond) {
    return guarded([&] { ImPlot::SetNextAxesLimits(xMin, xMax, yMin, yMax, cond); });
}
void implotSetNextAxesToFit() {
    return guarded([&] { ImPlot::SetNextAxesToFit(); });
}
void implotSetAxis(int axis) {
    return guarded([&] { ImPlot::SetAxis(axis); });
}
void implotSetAxes(int x, int y) {
    return guarded([&] { ImPlot::SetAxes(x, y); });
}

// Items
void implotPlotLineV(const char* label, int type, const void* values, int count, double xscale, double xstart,
                     const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotLine(label, P(values), count, xscale, xstart, spec(s));
        });
    });
}
void implotPlotLineXY(const char* label, int type, const void* xs, const void* ys, int count, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotLine(label, P(xs), P(ys), count, spec(s));
        });
    });
}
void implotPlotScatterV(const char* label, int type, const void* values, int count, double xscale, double xstart,
                        const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotScatter(label, P(values), count, xscale, xstart, spec(s));
        });
    });
}
void implotPlotScatterXY(const char* label, int type, const void* xs, const void* ys, int count, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotScatter(label, P(xs), P(ys), count, spec(s));
        });
    });
}
void implotPlotBubblesV(const char* label, int type, const void* values, const void* szs, int count, double xscale,
                        double xstart, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotBubbles(label, P(values), P(szs), count, xscale, xstart, spec(s));
        });
    });
}
void implotPlotBubblesXY(const char* label, int type, const void* xs, const void* ys, const void* szs, int count,
                         const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotBubbles(label, P(xs), P(ys), P(szs), count, spec(s));
        });
    });
}
void implotPlotPolygon(const char* label, int type, const void* xs, const void* ys, int count, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotPolygon(label, P(xs), P(ys), count, spec(s));
        });
    });
}
void implotPlotStairsV(const char* label, int type, const void* values, int count, double xscale, double xstart,
                       const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotStairs(label, P(values), count, xscale, xstart, spec(s));
        });
    });
}
void implotPlotStairsXY(const char* label, int type, const void* xs, const void* ys, int count, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotStairs(label, P(xs), P(ys), count, spec(s));
        });
    });
}
void implotPlotShadedV(const char* label, int type, const void* values, int count, double yref, double xscale,
                       double xstart, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotShaded(label, P(values), count, yref, xscale, xstart, spec(s));
        });
    });
}
void implotPlotShadedXY(const char* label, int type, const void* xs, const void* ys, int count, double yref,
                        const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotShaded(label, P(xs), P(ys), count, yref, spec(s));
        });
    });
}
void implotPlotShadedXYY(const char* label, int type, const void* xs, const void* ys1, const void* ys2, int count,
                         const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotShaded(label, P(xs), P(ys1), P(ys2), count, spec(s));
        });
    });
}
void implotPlotBarsV(const char* label, int type, const void* values, int count, double barSize, double shift,
                     const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotBars(label, P(values), count, barSize, shift, spec(s));
        });
    });
}
void implotPlotBarsXY(const char* label, int type, const void* xs, const void* ys, int count, double barSize,
                      const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotBars(label, P(xs), P(ys), count, barSize, spec(s));
        });
    });
}
void implotPlotBarGroups(const char* const* labels, int type, const void* values, int items, int groups,
                         double groupSize, double shift, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotBarGroups(labels, P(values), items, groups, groupSize, shift, spec(s));
        });
    });
}
void implotPlotErrorBars(const char* label, int type, const void* xs, const void* ys, const void* err, int count,
                         const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotErrorBars(label, P(xs), P(ys), P(err), count, spec(s));
        });
    });
}
void implotPlotErrorBarsNP(const char* label, int type, const void* xs, const void* ys, const void* neg,
                           const void* pos, int count, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotErrorBars(label, P(xs), P(ys), P(neg), P(pos), count, spec(s));
        });
    });
}
void implotPlotStemsV(const char* label, int type, const void* values, int count, double ref, double scale,
                      double start, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotStems(label, P(values), count, ref, scale, start, spec(s));
        });
    });
}
void implotPlotStemsXY(const char* label, int type, const void* xs, const void* ys, int count, double ref,
                       const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotStems(label, P(xs), P(ys), count, ref, spec(s));
        });
    });
}
void implotPlotInfLines(const char* label, int type, const void* values, int count, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotInfLines(label, P(values), count, spec(s));
        });
    });
}
void implotPlotPieChart(const char* const* labels, int type, const void* values, int count, double x, double y,
                        double radius, const char* fmt, double angle0, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotPieChart(labels, P(values), count, x, y, radius, fmt, angle0, spec(s));
        });
    });
}
void implotPlotHeatmap(const char* label, int type, const void* values, int rows, int cols, double scaleMin,
                       double scaleMax, const char* fmt, double minX, double minY, double maxX, double maxY,
                       const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotHeatmap(label, P(values), rows, cols, scaleMin, scaleMax, fmt, ImPlotPoint(minX, minY),
                                ImPlotPoint(maxX, maxY), spec(s));
        });
    });
}
double implotPlotHistogram(const char* label, int type, const void* values, int count, int bins, double barScale,
                           double rangeMin, double rangeMax, const ImPlotSpec* s) {
    return guarded([&] {
        double ret = 0;
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ret = ImPlot::PlotHistogram(label, P(values), count, bins, barScale, ImPlotRange(rangeMin, rangeMax),
                                        spec(s));
        });
        return ret;
    });
}
double implotPlotHistogram2D(const char* label, int type, const void* xs, const void* ys, int count, int xBins,
                             int yBins, double xMin, double xMax, double yMin, double yMax, const ImPlotSpec* s) {
    return guarded([&] {
        double ret = 0;
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ret = ImPlot::PlotHistogram2D(label, P(xs), P(ys), count, xBins, yBins, ImPlotRect(xMin, xMax, yMin, yMax),
                                          spec(s));
        });
        return ret;
    });
}
void implotPlotDigital(const char* label, int type, const void* xs, const void* ys, int count, const ImPlotSpec* s) {
    return guarded([&] {
        dispatch(type, [&](auto t) {
            using T = decltype(t);
            ImPlot::PlotDigital(label, P(xs), P(ys), count, spec(s));
        });
    });
}
void implotPlotText(const char* text, double x, double y, float offX, float offY, const ImPlotSpec* s) {
    return guarded([&] { ImPlot::PlotText(text, x, y, ImVec2(offX, offY), spec(s)); });
}
void implotPlotDummy(const char* label, const ImPlotSpec* s) {
    return guarded([&] { ImPlot::PlotDummy(label, spec(s)); });
}

#undef P

// Tools
bool implotDragPoint(int id, double* x, double* y, const float* col, float size, int flags, bool* out) {
    return guarded([&] { return ImPlot::DragPoint(id, x, y, color(col), size, flags, &out[0], &out[1], &out[2]); });
}
bool implotDragLineX(int id, double* x, const float* col, float thickness, int flags, bool* out) {
    return guarded([&] { return ImPlot::DragLineX(id, x, color(col), thickness, flags, &out[0], &out[1], &out[2]); });
}
bool implotDragLineY(int id, double* y, const float* col, float thickness, int flags, bool* out) {
    return guarded([&] { return ImPlot::DragLineY(id, y, color(col), thickness, flags, &out[0], &out[1], &out[2]); });
}
bool implotDragRect(int id, double* coords, const float* col, int flags, bool* out) {
    return guarded([&] {
        return ImPlot::DragRect(id, &coords[0], &coords[1], &coords[2], &coords[3], color(col), flags, &out[0], &out[1],
                                &out[2]);
    });
}
void implotAnnotation(double x, double y, const float* col, float offX, float offY, bool clamp, bool round) {
    return guarded([&] { ImPlot::Annotation(x, y, color(col), ImVec2(offX, offY), clamp, round); });
}
void implotAnnotationText(double x, double y, const float* col, float offX, float offY, bool clamp, const char* text) {
    return guarded([&] { ImPlot::Annotation(x, y, color(col), ImVec2(offX, offY), clamp, "%s", text); });
}
void implotTagX(double x, const float* col, bool round) {
    return guarded([&] { ImPlot::TagX(x, color(col), round); });
}
void implotTagXText(double x, const float* col, const char* text) {
    return guarded([&] { ImPlot::TagX(x, color(col), "%s", text); });
}
void implotTagY(double y, const float* col, bool round) {
    return guarded([&] { ImPlot::TagY(y, color(col), round); });
}
void implotTagYText(double y, const float* col, const char* text) {
    return guarded([&] { ImPlot::TagY(y, color(col), "%s", text); });
}

// Utils
void implotPixelsToPlot(float x, float y, int xAxis, int yAxis, double* out) {
    return guarded([&] {
        auto p = ImPlot::PixelsToPlot(x, y, xAxis, yAxis);
        out[0] = p.x;
        out[1] = p.y;
    });
}
void implotPlotToPixels(double x, double y, int xAxis, int yAxis, float* out) {
    return guarded([&] {
        auto p = ImPlot::PlotToPixels(x, y, xAxis, yAxis);
        out[0] = p.x;
        out[1] = p.y;
    });
}
void implotGetPlotPos(float* out) {
    return guarded([&] {
        auto p = ImPlot::GetPlotPos();
        out[0] = p.x;
        out[1] = p.y;
    });
}
void implotGetPlotSize(float* out) {
    return guarded([&] {
        auto p = ImPlot::GetPlotSize();
        out[0] = p.x;
        out[1] = p.y;
    });
}
void implotGetPlotMousePos(int xAxis, int yAxis, double* out) {
    return guarded([&] {
        auto p = ImPlot::GetPlotMousePos(xAxis, yAxis);
        out[0] = p.x;
        out[1] = p.y;
    });
}
void implotGetPlotLimits(int xAxis, int yAxis, double* out) {
    return guarded([&] {
        auto r = ImPlot::GetPlotLimits(xAxis, yAxis);
        out[0] = r.X.Min;
        out[1] = r.X.Max;
        out[2] = r.Y.Min;
        out[3] = r.Y.Max;
    });
}
void implotGetPlotSelection(int xAxis, int yAxis, double* out) {
    return guarded([&] {
        auto r = ImPlot::GetPlotSelection(xAxis, yAxis);
        out[0] = r.X.Min;
        out[1] = r.X.Max;
        out[2] = r.Y.Min;
        out[3] = r.Y.Max;
    });
}
bool implotIsPlotHovered() {
    return guarded([&] { return ImPlot::IsPlotHovered(); });
}
bool implotIsAxisHovered(int axis) {
    return guarded([&] { return ImPlot::IsAxisHovered(axis); });
}
bool implotIsSubplotsHovered() {
    return guarded([&] { return ImPlot::IsSubplotsHovered(); });
}
bool implotIsPlotSelected() {
    return guarded([&] { return ImPlot::IsPlotSelected(); });
}
void implotCancelPlotSelection() {
    return guarded([&] { ImPlot::CancelPlotSelection(); });
}
void implotHideNextItem(bool hidden, int cond) {
    return guarded([&] { ImPlot::HideNextItem(hidden, cond); });
}

// Style
void implotPushStyleColorU32(int idx, unsigned col) {
    return guarded([&] { ImPlot::PushStyleColor(idx, ImU32(col)); });
}
void implotPushStyleColorVec4(int idx, const float* col) {
    return guarded([&] { ImPlot::PushStyleColor(idx, color(col)); });
}
void implotPopStyleColor(int count) {
    return guarded([&] { ImPlot::PopStyleColor(count); });
}
void implotPushStyleVarFloat(int idx, float val) {
    return guarded([&] { ImPlot::PushStyleVar(idx, val); });
}
void implotPushStyleVarVec2(int idx, float x, float y) {
    return guarded([&] { ImPlot::PushStyleVar(idx, ImVec2(x, y)); });
}
void implotPopStyleVar(int count) {
    return guarded([&] { ImPlot::PopStyleVar(count); });
}
void implotStyleColorsAuto() {
    return guarded([&] { ImPlot::StyleColorsAuto(); });
}
void implotStyleColorsClassic() {
    return guarded([&] { ImPlot::StyleColorsClassic(); });
}
void implotStyleColorsDark() {
    return guarded([&] { ImPlot::StyleColorsDark(); });
}
void implotStyleColorsLight() {
    return guarded([&] { ImPlot::StyleColorsLight(); });
}
void implotGetLastItemColor(float* out) {
    return guarded([&] { outColor(ImPlot::GetLastItemColor(), out); });
}
const char* implotGetStyleColorName(int idx) {
    return guarded([&] { return ImPlot::GetStyleColorName(idx); });
}
const char* implotGetMarkerName(int idx) {
    return guarded([&] { return ImPlot::GetMarkerName(idx); });
}
int implotNextMarker() {
    return guarded([&] { return ImPlot::NextMarker(); });
}

// Colormaps
int implotAddColormap(const char* name, const float* cols, int size, bool qual) {
    return guarded([&] {
        std::vector<ImVec4> v;
        v.reserve(size);
        for (int i = 0; i < size; i++) v.emplace_back(cols[i * 4], cols[i * 4 + 1], cols[i * 4 + 2], cols[i * 4 + 3]);
        return ImPlot::AddColormap(name, v.data(), size, qual);
    });
}
int implotGetColormapCount() {
    return guarded([&] { return ImPlot::GetColormapCount(); });
}
const char* implotGetColormapName(int cmap) {
    return guarded([&] { return ImPlot::GetColormapName(cmap); });
}
int implotGetColormapIndex(const char* name) {
    return guarded([&] { return ImPlot::GetColormapIndex(name); });
}
void implotPushColormapIndex(int cmap) {
    return guarded([&] { ImPlot::PushColormap(cmap); });
}
void implotPushColormapName(const char* name) {
    return guarded([&] { ImPlot::PushColormap(name); });
}
void implotPopColormap(int count) {
    return guarded([&] { ImPlot::PopColormap(count); });
}
void implotNextColormapColor(float* out) {
    return guarded([&] { outColor(ImPlot::NextColormapColor(), out); });
}
int implotGetColormapSize(int cmap) {
    return guarded([&] { return ImPlot::GetColormapSize(cmap); });
}
void implotGetColormapColor(int idx, int cmap, float* out) {
    return guarded([&] { outColor(ImPlot::GetColormapColor(idx, cmap), out); });
}
void implotSampleColormap(float t, int cmap, float* out) {
    return guarded([&] { outColor(ImPlot::SampleColormap(t, cmap), out); });
}
void implotColormapScale(const char* label, double scaleMin, double scaleMax, float w, float h, const char* fmt,
                         int flags, int cmap) {
    return guarded([&] { ImPlot::ColormapScale(label, scaleMin, scaleMax, ImVec2(w, h), fmt, flags, cmap); });
}
bool implotColormapSlider(const char* label, float* t, float* out, const char* fmt, int cmap) {
    return guarded([&] {
        ImVec4 c;
        bool ret = ImPlot::ColormapSlider(label, t, &c, fmt, cmap);
        outColor(c, out);
        return ret;
    });
}
bool implotColormapButton(const char* label, float w, float h, int cmap) {
    return guarded([&] { return ImPlot::ColormapButton(label, ImVec2(w, h), cmap); });
}
void implotBustColorCache(const char* title) {
    return guarded([&] { ImPlot::BustColorCache(title); });
}

// Input mapping and misc
void implotMapInputDefault() {
    return guarded([&] { ImPlot::MapInputDefault(); });
}
void implotMapInputReverse() {
    return guarded([&] { ImPlot::MapInputReverse(); });
}
void implotItemIconVec4(const float* col) {
    return guarded([&] { ImPlot::ItemIcon(color(col)); });
}
void implotItemIconU32(unsigned col) {
    return guarded([&] { ImPlot::ItemIcon(ImU32(col)); });
}
void implotColormapIcon(int cmap) {
    return guarded([&] { ImPlot::ColormapIcon(cmap); });
}
void implotPushPlotClipRect(float expand) {
    return guarded([&] { ImPlot::PushPlotClipRect(expand); });
}
void implotPopPlotClipRect() {
    return guarded([&] { ImPlot::PopPlotClipRect(); });
}
bool implotShowStyleSelector(const char* label) {
    return guarded([&] { return ImPlot::ShowStyleSelector(label); });
}
bool implotShowColormapSelector(const char* label) {
    return guarded([&] { return ImPlot::ShowColormapSelector(label); });
}
bool implotShowInputMapSelector(const char* label) {
    return guarded([&] { return ImPlot::ShowInputMapSelector(label); });
}
void implotShowStyleEditor() {
    return guarded([&] { ImPlot::ShowStyleEditor(); });
}
void implotShowUserGuide() {
    return guarded([&] { ImPlot::ShowUserGuide(); });
}
void implotShowMetricsWindow(bool* open) {
    return guarded([&] { ImPlot::ShowMetricsWindow(open); });
}
void implotShowDemoWindow(bool* open) {
    return guarded([&] { ImPlot::ShowDemoWindow(open); });
}

template <typename T, size_t S>
void registerSymbol(PCSX::Lua L, const char (&name)[S], const T ptr) {
    L.push<S>(name);
    L.push((void*)ptr);
    L.settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

void registerAllSymbols(PCSX::Lua L) {
    L.getfieldtable("_CLIBS", LUA_REGISTRYINDEX);
    L.push("IMPLOT");
    L.newtable();

    REGISTER(L, implotSpecDefault);
    REGISTER(L, implotSpecSize);
    REGISTER(L, implotSpecFlagsOffset);

    REGISTER(L, implotTakeError);
    REGISTER(L, implotCheckPlot);
    REGISTER(L, implotCheckAxis);
    REGISTER(L, implotCheckStyleCol);

    REGISTER(L, implotBeginPlot);
    REGISTER(L, implotEndPlot);
    REGISTER(L, implotBeginSubplots);
    REGISTER(L, implotEndSubplots);
    REGISTER(L, implotBeginAlignedPlots);
    REGISTER(L, implotEndAlignedPlots);
    REGISTER(L, implotBeginLegendPopup);
    REGISTER(L, implotEndLegendPopup);
    REGISTER(L, implotIsLegendEntryHovered);
    REGISTER(L, implotBeginDragDropTargetPlot);
    REGISTER(L, implotBeginDragDropTargetAxis);
    REGISTER(L, implotBeginDragDropTargetLegend);
    REGISTER(L, implotEndDragDropTarget);
    REGISTER(L, implotBeginDragDropSourcePlot);
    REGISTER(L, implotBeginDragDropSourceAxis);
    REGISTER(L, implotBeginDragDropSourceItem);
    REGISTER(L, implotEndDragDropSource);

    REGISTER(L, implotSetupAxis);
    REGISTER(L, implotSetupAxisLimits);
    REGISTER(L, implotSetupAxisFormat);
    REGISTER(L, implotSetupAxisTicksValues);
    REGISTER(L, implotSetupAxisTicksRange);
    REGISTER(L, implotSetupAxisScale);
    REGISTER(L, implotSetupAxisLimitsConstraints);
    REGISTER(L, implotSetupAxisZoomConstraints);
    REGISTER(L, implotSetupAxes);
    REGISTER(L, implotSetupAxesLimits);
    REGISTER(L, implotSetupLegend);
    REGISTER(L, implotSetupMouseText);
    REGISTER(L, implotSetupFinish);
    REGISTER(L, implotSetNextAxisLimits);
    REGISTER(L, implotSetNextAxisToFit);
    REGISTER(L, implotSetNextAxesLimits);
    REGISTER(L, implotSetNextAxesToFit);
    REGISTER(L, implotSetAxis);
    REGISTER(L, implotSetAxes);

    REGISTER(L, implotPlotLineV);
    REGISTER(L, implotPlotLineXY);
    REGISTER(L, implotPlotScatterV);
    REGISTER(L, implotPlotScatterXY);
    REGISTER(L, implotPlotBubblesV);
    REGISTER(L, implotPlotBubblesXY);
    REGISTER(L, implotPlotPolygon);
    REGISTER(L, implotPlotStairsV);
    REGISTER(L, implotPlotStairsXY);
    REGISTER(L, implotPlotShadedV);
    REGISTER(L, implotPlotShadedXY);
    REGISTER(L, implotPlotShadedXYY);
    REGISTER(L, implotPlotBarsV);
    REGISTER(L, implotPlotBarsXY);
    REGISTER(L, implotPlotBarGroups);
    REGISTER(L, implotPlotErrorBars);
    REGISTER(L, implotPlotErrorBarsNP);
    REGISTER(L, implotPlotStemsV);
    REGISTER(L, implotPlotStemsXY);
    REGISTER(L, implotPlotInfLines);
    REGISTER(L, implotPlotPieChart);
    REGISTER(L, implotPlotHeatmap);
    REGISTER(L, implotPlotHistogram);
    REGISTER(L, implotPlotHistogram2D);
    REGISTER(L, implotPlotDigital);
    REGISTER(L, implotPlotText);
    REGISTER(L, implotPlotDummy);

    REGISTER(L, implotDragPoint);
    REGISTER(L, implotDragLineX);
    REGISTER(L, implotDragLineY);
    REGISTER(L, implotDragRect);
    REGISTER(L, implotAnnotation);
    REGISTER(L, implotAnnotationText);
    REGISTER(L, implotTagX);
    REGISTER(L, implotTagXText);
    REGISTER(L, implotTagY);
    REGISTER(L, implotTagYText);

    REGISTER(L, implotPixelsToPlot);
    REGISTER(L, implotPlotToPixels);
    REGISTER(L, implotGetPlotPos);
    REGISTER(L, implotGetPlotSize);
    REGISTER(L, implotGetPlotMousePos);
    REGISTER(L, implotGetPlotLimits);
    REGISTER(L, implotGetPlotSelection);
    REGISTER(L, implotIsPlotHovered);
    REGISTER(L, implotIsAxisHovered);
    REGISTER(L, implotIsSubplotsHovered);
    REGISTER(L, implotIsPlotSelected);
    REGISTER(L, implotCancelPlotSelection);
    REGISTER(L, implotHideNextItem);

    REGISTER(L, implotPushStyleColorU32);
    REGISTER(L, implotPushStyleColorVec4);
    REGISTER(L, implotPopStyleColor);
    REGISTER(L, implotPushStyleVarFloat);
    REGISTER(L, implotPushStyleVarVec2);
    REGISTER(L, implotPopStyleVar);
    REGISTER(L, implotStyleColorsAuto);
    REGISTER(L, implotStyleColorsClassic);
    REGISTER(L, implotStyleColorsDark);
    REGISTER(L, implotStyleColorsLight);
    REGISTER(L, implotGetLastItemColor);
    REGISTER(L, implotGetStyleColorName);
    REGISTER(L, implotGetMarkerName);
    REGISTER(L, implotNextMarker);

    REGISTER(L, implotAddColormap);
    REGISTER(L, implotGetColormapCount);
    REGISTER(L, implotGetColormapName);
    REGISTER(L, implotGetColormapIndex);
    REGISTER(L, implotPushColormapIndex);
    REGISTER(L, implotPushColormapName);
    REGISTER(L, implotPopColormap);
    REGISTER(L, implotNextColormapColor);
    REGISTER(L, implotGetColormapSize);
    REGISTER(L, implotGetColormapColor);
    REGISTER(L, implotSampleColormap);
    REGISTER(L, implotColormapScale);
    REGISTER(L, implotColormapSlider);
    REGISTER(L, implotColormapButton);
    REGISTER(L, implotBustColorCache);

    REGISTER(L, implotMapInputDefault);
    REGISTER(L, implotMapInputReverse);
    REGISTER(L, implotItemIconVec4);
    REGISTER(L, implotItemIconU32);
    REGISTER(L, implotColormapIcon);
    REGISTER(L, implotPushPlotClipRect);
    REGISTER(L, implotPopPlotClipRect);
    REGISTER(L, implotShowStyleSelector);
    REGISTER(L, implotShowColormapSelector);
    REGISTER(L, implotShowInputMapSelector);
    REGISTER(L, implotShowStyleEditor);
    REGISTER(L, implotShowUserGuide);
    REGISTER(L, implotShowMetricsWindow);
    REGISTER(L, implotShowDemoWindow);

    L.settable();
    L.pop();
}

// Pushes implot.constant.<Group>.<Name> with values taken from implot.h.
void pushConstants(PCSX::Lua L) {
    L.push("constant");
    L.newtable();
#define ENUM_GROUP(group) \
    L.push(#group);       \
    L.newtable();
#define ENUM(prefix, name)               \
    L.push(#name);                       \
    L.push(lua_Number(prefix##_##name)); \
    L.settable();
#define END_GROUP() L.settable();
    ENUM_GROUP(Axis)
    ENUM(ImAxis, X1)
    ENUM(ImAxis, X2)
    ENUM(ImAxis, X3)
    ENUM(ImAxis, Y1)
    ENUM(ImAxis, Y2)
    ENUM(ImAxis, Y3)
    END_GROUP()
    ENUM_GROUP(Prop)
    ENUM(ImPlotProp, LineColor)
    ENUM(ImPlotProp, LineColors)
    ENUM(ImPlotProp, LineWeight)
    ENUM(ImPlotProp, FillColor)
    ENUM(ImPlotProp, FillColors)
    ENUM(ImPlotProp, FillAlpha)
    ENUM(ImPlotProp, Marker)
    ENUM(ImPlotProp, MarkerSize)
    ENUM(ImPlotProp, MarkerSizes)
    ENUM(ImPlotProp, MarkerLineColor)
    ENUM(ImPlotProp, MarkerLineColors)
    ENUM(ImPlotProp, MarkerFillColor)
    ENUM(ImPlotProp, MarkerFillColors)
    ENUM(ImPlotProp, Size)
    ENUM(ImPlotProp, Offset)
    ENUM(ImPlotProp, Stride)
    ENUM(ImPlotProp, Flags)
    END_GROUP()
    ENUM_GROUP(Flags)
    ENUM(ImPlotFlags, None)
    ENUM(ImPlotFlags, NoTitle)
    ENUM(ImPlotFlags, NoLegend)
    ENUM(ImPlotFlags, NoMouseText)
    ENUM(ImPlotFlags, NoInputs)
    ENUM(ImPlotFlags, NoMenus)
    ENUM(ImPlotFlags, NoBoxSelect)
    ENUM(ImPlotFlags, NoFrame)
    ENUM(ImPlotFlags, Equal)
    ENUM(ImPlotFlags, Crosshairs)
    ENUM(ImPlotFlags, CanvasOnly)
    END_GROUP()
    ENUM_GROUP(AxisFlags)
    ENUM(ImPlotAxisFlags, None)
    ENUM(ImPlotAxisFlags, NoLabel)
    ENUM(ImPlotAxisFlags, NoGridLines)
    ENUM(ImPlotAxisFlags, NoTickMarks)
    ENUM(ImPlotAxisFlags, NoTickLabels)
    ENUM(ImPlotAxisFlags, NoInitialFit)
    ENUM(ImPlotAxisFlags, NoMenus)
    ENUM(ImPlotAxisFlags, NoSideSwitch)
    ENUM(ImPlotAxisFlags, NoHighlight)
    ENUM(ImPlotAxisFlags, Opposite)
    ENUM(ImPlotAxisFlags, Foreground)
    ENUM(ImPlotAxisFlags, Invert)
    ENUM(ImPlotAxisFlags, AutoFit)
    ENUM(ImPlotAxisFlags, RangeFit)
    ENUM(ImPlotAxisFlags, PanStretch)
    ENUM(ImPlotAxisFlags, LockMin)
    ENUM(ImPlotAxisFlags, LockMax)
    ENUM(ImPlotAxisFlags, Lock)
    ENUM(ImPlotAxisFlags, NoDecorations)
    ENUM(ImPlotAxisFlags, AuxDefault)
    END_GROUP()
    ENUM_GROUP(SubplotFlags)
    ENUM(ImPlotSubplotFlags, None)
    ENUM(ImPlotSubplotFlags, NoTitle)
    ENUM(ImPlotSubplotFlags, NoLegend)
    ENUM(ImPlotSubplotFlags, NoMenus)
    ENUM(ImPlotSubplotFlags, NoResize)
    ENUM(ImPlotSubplotFlags, NoAlign)
    ENUM(ImPlotSubplotFlags, ShareItems)
    ENUM(ImPlotSubplotFlags, LinkRows)
    ENUM(ImPlotSubplotFlags, LinkCols)
    ENUM(ImPlotSubplotFlags, LinkAllX)
    ENUM(ImPlotSubplotFlags, LinkAllY)
    ENUM(ImPlotSubplotFlags, ColMajor)
    END_GROUP()
    ENUM_GROUP(LegendFlags)
    ENUM(ImPlotLegendFlags, None)
    ENUM(ImPlotLegendFlags, NoButtons)
    ENUM(ImPlotLegendFlags, NoHighlightItem)
    ENUM(ImPlotLegendFlags, NoHighlightAxis)
    ENUM(ImPlotLegendFlags, NoMenus)
    ENUM(ImPlotLegendFlags, Outside)
    ENUM(ImPlotLegendFlags, Horizontal)
    ENUM(ImPlotLegendFlags, Sort)
    ENUM(ImPlotLegendFlags, Reverse)
    END_GROUP()
    ENUM_GROUP(MouseTextFlags)
    ENUM(ImPlotMouseTextFlags, None)
    ENUM(ImPlotMouseTextFlags, NoAuxAxes)
    ENUM(ImPlotMouseTextFlags, NoFormat)
    ENUM(ImPlotMouseTextFlags, ShowAlways)
    END_GROUP()
    ENUM_GROUP(DragToolFlags)
    ENUM(ImPlotDragToolFlags, None)
    ENUM(ImPlotDragToolFlags, NoCursors)
    ENUM(ImPlotDragToolFlags, NoFit)
    ENUM(ImPlotDragToolFlags, NoInputs)
    ENUM(ImPlotDragToolFlags, Delayed)
    END_GROUP()
    ENUM_GROUP(ColormapScaleFlags)
    ENUM(ImPlotColormapScaleFlags, None)
    ENUM(ImPlotColormapScaleFlags, NoLabel)
    ENUM(ImPlotColormapScaleFlags, Opposite)
    ENUM(ImPlotColormapScaleFlags, Invert)
    END_GROUP()
    ENUM_GROUP(ItemFlags)
    ENUM(ImPlotItemFlags, None)
    ENUM(ImPlotItemFlags, NoLegend)
    ENUM(ImPlotItemFlags, NoFit)
    END_GROUP()
    ENUM_GROUP(LineFlags)
    ENUM(ImPlotLineFlags, None)
    ENUM(ImPlotLineFlags, Segments)
    ENUM(ImPlotLineFlags, Loop)
    ENUM(ImPlotLineFlags, SkipNaN)
    ENUM(ImPlotLineFlags, NoClip)
    ENUM(ImPlotLineFlags, Shaded)
    END_GROUP()
    ENUM_GROUP(ScatterFlags)
    ENUM(ImPlotScatterFlags, None)
    ENUM(ImPlotScatterFlags, NoClip)
    END_GROUP()
    ENUM_GROUP(BubblesFlags)
    ENUM(ImPlotBubblesFlags, None)
    END_GROUP()
    ENUM_GROUP(PolygonFlags)
    ENUM(ImPlotPolygonFlags, None)
    ENUM(ImPlotPolygonFlags, Concave)
    END_GROUP()
    ENUM_GROUP(StairsFlags)
    ENUM(ImPlotStairsFlags, None)
    ENUM(ImPlotStairsFlags, PreStep)
    ENUM(ImPlotStairsFlags, Shaded)
    END_GROUP()
    ENUM_GROUP(ShadedFlags)
    ENUM(ImPlotShadedFlags, None)
    END_GROUP()
    ENUM_GROUP(BarsFlags)
    ENUM(ImPlotBarsFlags, None)
    ENUM(ImPlotBarsFlags, Horizontal)
    END_GROUP()
    ENUM_GROUP(BarGroupsFlags)
    ENUM(ImPlotBarGroupsFlags, None)
    ENUM(ImPlotBarGroupsFlags, Horizontal)
    ENUM(ImPlotBarGroupsFlags, Stacked)
    END_GROUP()
    ENUM_GROUP(ErrorBarsFlags)
    ENUM(ImPlotErrorBarsFlags, None)
    ENUM(ImPlotErrorBarsFlags, Horizontal)
    END_GROUP()
    ENUM_GROUP(StemsFlags)
    ENUM(ImPlotStemsFlags, None)
    ENUM(ImPlotStemsFlags, Horizontal)
    END_GROUP()
    ENUM_GROUP(InfLinesFlags)
    ENUM(ImPlotInfLinesFlags, None)
    ENUM(ImPlotInfLinesFlags, Horizontal)
    END_GROUP()
    ENUM_GROUP(PieChartFlags)
    ENUM(ImPlotPieChartFlags, None)
    ENUM(ImPlotPieChartFlags, Normalize)
    ENUM(ImPlotPieChartFlags, IgnoreHidden)
    ENUM(ImPlotPieChartFlags, Exploding)
    ENUM(ImPlotPieChartFlags, NoSliceBorder)
    END_GROUP()
    ENUM_GROUP(HeatmapFlags)
    ENUM(ImPlotHeatmapFlags, None)
    ENUM(ImPlotHeatmapFlags, ColMajor)
    END_GROUP()
    ENUM_GROUP(HistogramFlags)
    ENUM(ImPlotHistogramFlags, None)
    ENUM(ImPlotHistogramFlags, Horizontal)
    ENUM(ImPlotHistogramFlags, Cumulative)
    ENUM(ImPlotHistogramFlags, Density)
    ENUM(ImPlotHistogramFlags, NoOutliers)
    ENUM(ImPlotHistogramFlags, ColMajor)
    END_GROUP()
    ENUM_GROUP(DigitalFlags)
    ENUM(ImPlotDigitalFlags, None)
    END_GROUP()
    ENUM_GROUP(ImageFlags)
    ENUM(ImPlotImageFlags, None)
    END_GROUP()
    ENUM_GROUP(TextFlags)
    ENUM(ImPlotTextFlags, None)
    ENUM(ImPlotTextFlags, Vertical)
    END_GROUP()
    ENUM_GROUP(DummyFlags)
    ENUM(ImPlotDummyFlags, None)
    END_GROUP()
    ENUM_GROUP(Cond)
    ENUM(ImPlotCond, None)
    ENUM(ImPlotCond, Always)
    ENUM(ImPlotCond, Once)
    END_GROUP()
    ENUM_GROUP(Col)
    ENUM(ImPlotCol, FrameBg)
    ENUM(ImPlotCol, PlotBg)
    ENUM(ImPlotCol, PlotBorder)
    ENUM(ImPlotCol, LegendBg)
    ENUM(ImPlotCol, LegendBorder)
    ENUM(ImPlotCol, LegendText)
    ENUM(ImPlotCol, TitleText)
    ENUM(ImPlotCol, InlayText)
    ENUM(ImPlotCol, AxisText)
    ENUM(ImPlotCol, AxisGrid)
    ENUM(ImPlotCol, AxisTick)
    ENUM(ImPlotCol, AxisBg)
    ENUM(ImPlotCol, AxisBgHovered)
    ENUM(ImPlotCol, AxisBgActive)
    ENUM(ImPlotCol, Selection)
    ENUM(ImPlotCol, Crosshairs)
    END_GROUP()
    ENUM_GROUP(StyleVar)
    ENUM(ImPlotStyleVar, PlotDefaultSize)
    ENUM(ImPlotStyleVar, PlotMinSize)
    ENUM(ImPlotStyleVar, PlotBorderSize)
    ENUM(ImPlotStyleVar, MinorAlpha)
    ENUM(ImPlotStyleVar, MajorTickLen)
    ENUM(ImPlotStyleVar, MinorTickLen)
    ENUM(ImPlotStyleVar, MajorTickSize)
    ENUM(ImPlotStyleVar, MinorTickSize)
    ENUM(ImPlotStyleVar, MajorGridSize)
    ENUM(ImPlotStyleVar, MinorGridSize)
    ENUM(ImPlotStyleVar, PlotPadding)
    ENUM(ImPlotStyleVar, LabelPadding)
    ENUM(ImPlotStyleVar, LegendPadding)
    ENUM(ImPlotStyleVar, LegendInnerPadding)
    ENUM(ImPlotStyleVar, LegendSpacing)
    ENUM(ImPlotStyleVar, MousePosPadding)
    ENUM(ImPlotStyleVar, AnnotationPadding)
    ENUM(ImPlotStyleVar, FitPadding)
    ENUM(ImPlotStyleVar, DigitalPadding)
    ENUM(ImPlotStyleVar, DigitalSpacing)
    END_GROUP()
    ENUM_GROUP(Scale)
    ENUM(ImPlotScale, Linear)
    ENUM(ImPlotScale, Time)
    ENUM(ImPlotScale, Log10)
    ENUM(ImPlotScale, SymLog)
    END_GROUP()
    ENUM_GROUP(Marker)
    ENUM(ImPlotMarker, None)
    ENUM(ImPlotMarker, Auto)
    ENUM(ImPlotMarker, Circle)
    ENUM(ImPlotMarker, Square)
    ENUM(ImPlotMarker, Diamond)
    ENUM(ImPlotMarker, Up)
    ENUM(ImPlotMarker, Down)
    ENUM(ImPlotMarker, Left)
    ENUM(ImPlotMarker, Right)
    ENUM(ImPlotMarker, Cross)
    ENUM(ImPlotMarker, Plus)
    ENUM(ImPlotMarker, Asterisk)
    ENUM(ImPlotMarker, Vertical)
    ENUM(ImPlotMarker, Horizontal)
    END_GROUP()
    ENUM_GROUP(Colormap)
    ENUM(ImPlotColormap, Deep)
    ENUM(ImPlotColormap, Dark)
    ENUM(ImPlotColormap, Pastel)
    ENUM(ImPlotColormap, Paired)
    ENUM(ImPlotColormap, Viridis)
    ENUM(ImPlotColormap, Plasma)
    ENUM(ImPlotColormap, Hot)
    ENUM(ImPlotColormap, Cool)
    ENUM(ImPlotColormap, Pink)
    ENUM(ImPlotColormap, Jet)
    ENUM(ImPlotColormap, Twilight)
    ENUM(ImPlotColormap, RdBu)
    ENUM(ImPlotColormap, BrBG)
    ENUM(ImPlotColormap, PiYG)
    ENUM(ImPlotColormap, Spectral)
    ENUM(ImPlotColormap, Greys)
    END_GROUP()
    ENUM_GROUP(Location)
    ENUM(ImPlotLocation, Center)
    ENUM(ImPlotLocation, North)
    ENUM(ImPlotLocation, South)
    ENUM(ImPlotLocation, West)
    ENUM(ImPlotLocation, East)
    ENUM(ImPlotLocation, NorthWest)
    ENUM(ImPlotLocation, NorthEast)
    ENUM(ImPlotLocation, SouthWest)
    ENUM(ImPlotLocation, SouthEast)
    END_GROUP()
    ENUM_GROUP(Bin)
    ENUM(ImPlotBin, Sqrt)
    ENUM(ImPlotBin, Sturges)
    ENUM(ImPlotBin, Rice)
    ENUM(ImPlotBin, Scott)
    END_GROUP()
#undef ENUM_GROUP
#undef ENUM
#undef END_GROUP
    L.settable();
}

}  // namespace

void PCSX::LuaFFI::open_implot(Lua L) {
    registerAllSymbols(L);
    L.getfieldtable("implot", LUA_GLOBALSINDEX);
    pushConstants(L);
    L.push("AUTO");
    L.push(lua_Number(IMPLOT_AUTO));
    L.settable();
    L.pop();
    static int lualoader = 2;
    static const char* implotffi = (
#include "gui/implotffi.lua"
    );
    L.load(implotffi, "src:gui/implotffi.lua");
    static const char* implotsafe = (
#include "gui/implotsafe.lua"
    );
    L.load(implotsafe, "src:gui/implotsafe.lua");
    assert(L.gettop() == 0);
}
