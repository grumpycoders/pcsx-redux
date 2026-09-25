-- lualoader, R"EOF(--
--   Copyright (C) 2026 PCSX-Redux authors
--
--   This program is free software; you can redistribute it and/or modify
--   it under the terms of the GNU General Public License as published by
--   the Free Software Foundation; either version 2 of the License, or
--   (at your option) any later version.
--
--   This program is distributed in the hope that it will be useful,
--   but WITHOUT ANY WARRANTY; without even the implied warranty of
--   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--   GNU General Public License for more details.
--
--   You should have received a copy of the GNU General Public License
--   along with this program; if not, write to the
--   Free Software Foundation, Inc.,
--   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
ffi.cdef [[
typedef struct { float x, y, z, w; } ImPlotLuaVec4;
typedef struct {
    ImPlotLuaVec4 LineColor;
    uint32_t* LineColors;
    float LineWeight;
    ImPlotLuaVec4 FillColor;
    uint32_t* FillColors;
    float FillAlpha;
    int Marker;
    float MarkerSize;
    float* MarkerSizes;
    ImPlotLuaVec4 MarkerLineColor;
    uint32_t* MarkerLineColors;
    ImPlotLuaVec4 MarkerFillColor;
    uint32_t* MarkerFillColors;
    float Size;
    int Offset;
    int Stride;
    int Flags;
} ImPlotSpec;

void implotSpecDefault(ImPlotSpec* s);
int implotSpecSize();
int implotSpecFlagsOffset();

const char* implotTakeError();
const char* implotCheckPlot();
const char* implotCheckAxis(int axis);
const char* implotCheckStyleCol(int idx);

bool implotBeginPlot(const char* title, float w, float h, int flags);
void implotEndPlot();
bool implotBeginSubplots(const char* title, int rows, int cols, float w, float h, int flags, float* rowRatios, float* colRatios);
void implotEndSubplots();
bool implotBeginAlignedPlots(const char* id, bool vertical);
void implotEndAlignedPlots();
bool implotBeginLegendPopup(const char* label, int button);
void implotEndLegendPopup();
bool implotIsLegendEntryHovered(const char* label);
bool implotBeginDragDropTargetPlot();
bool implotBeginDragDropTargetAxis(int axis);
bool implotBeginDragDropTargetLegend();
void implotEndDragDropTarget();
bool implotBeginDragDropSourcePlot(int flags);
bool implotBeginDragDropSourceAxis(int axis, int flags);
bool implotBeginDragDropSourceItem(const char* label, int flags);
void implotEndDragDropSource();

void implotSetupAxis(int axis, const char* label, int flags);
void implotSetupAxisLimits(int axis, double vMin, double vMax, int cond);
void implotSetupAxisFormat(int axis, const char* fmt);
void implotSetupAxisTicksValues(int axis, const double* values, int n, const char* const* labels, bool keepDefault);
void implotSetupAxisTicksRange(int axis, double vMin, double vMax, int n, const char* const* labels, bool keepDefault);
void implotSetupAxisScale(int axis, int scale);
void implotSetupAxisLimitsConstraints(int axis, double vMin, double vMax);
void implotSetupAxisZoomConstraints(int axis, double zMin, double zMax);
void implotSetupAxes(const char* xLabel, const char* yLabel, int xFlags, int yFlags);
void implotSetupAxesLimits(double xMin, double xMax, double yMin, double yMax, int cond);
void implotSetupLegend(int location, int flags);
void implotSetupMouseText(int location, int flags);
void implotSetupFinish();
void implotSetNextAxisLimits(int axis, double vMin, double vMax, int cond);
void implotSetNextAxisToFit(int axis);
void implotSetNextAxesLimits(double xMin, double xMax, double yMin, double yMax, int cond);
void implotSetNextAxesToFit();
void implotSetAxis(int axis);
void implotSetAxes(int x, int y);

void implotPlotLineV(const char* label, int type, const void* values, int count, double xscale, double xstart, const ImPlotSpec* s);
void implotPlotLineXY(const char* label, int type, const void* xs, const void* ys, int count, const ImPlotSpec* s);
void implotPlotScatterV(const char* label, int type, const void* values, int count, double xscale, double xstart, const ImPlotSpec* s);
void implotPlotScatterXY(const char* label, int type, const void* xs, const void* ys, int count, const ImPlotSpec* s);
void implotPlotBubblesV(const char* label, int type, const void* values, const void* szs, int count, double xscale, double xstart, const ImPlotSpec* s);
void implotPlotBubblesXY(const char* label, int type, const void* xs, const void* ys, const void* szs, int count, const ImPlotSpec* s);
void implotPlotPolygon(const char* label, int type, const void* xs, const void* ys, int count, const ImPlotSpec* s);
void implotPlotStairsV(const char* label, int type, const void* values, int count, double xscale, double xstart, const ImPlotSpec* s);
void implotPlotStairsXY(const char* label, int type, const void* xs, const void* ys, int count, const ImPlotSpec* s);
void implotPlotShadedV(const char* label, int type, const void* values, int count, double yref, double xscale, double xstart, const ImPlotSpec* s);
void implotPlotShadedXY(const char* label, int type, const void* xs, const void* ys, int count, double yref, const ImPlotSpec* s);
void implotPlotShadedXYY(const char* label, int type, const void* xs, const void* ys1, const void* ys2, int count, const ImPlotSpec* s);
void implotPlotBarsV(const char* label, int type, const void* values, int count, double barSize, double shift, const ImPlotSpec* s);
void implotPlotBarsXY(const char* label, int type, const void* xs, const void* ys, int count, double barSize, const ImPlotSpec* s);
void implotPlotBarGroups(const char* const* labels, int type, const void* values, int items, int groups, double groupSize, double shift, const ImPlotSpec* s);
void implotPlotErrorBars(const char* label, int type, const void* xs, const void* ys, const void* err, int count, const ImPlotSpec* s);
void implotPlotErrorBarsNP(const char* label, int type, const void* xs, const void* ys, const void* neg, const void* pos, int count, const ImPlotSpec* s);
void implotPlotStemsV(const char* label, int type, const void* values, int count, double ref, double scale, double start, const ImPlotSpec* s);
void implotPlotStemsXY(const char* label, int type, const void* xs, const void* ys, int count, double ref, const ImPlotSpec* s);
void implotPlotInfLines(const char* label, int type, const void* values, int count, const ImPlotSpec* s);
void implotPlotPieChart(const char* const* labels, int type, const void* values, int count, double x, double y, double radius, const char* fmt, double angle0, const ImPlotSpec* s);
void implotPlotHeatmap(const char* label, int type, const void* values, int rows, int cols, double scaleMin, double scaleMax, const char* fmt, double minX, double minY, double maxX, double maxY, const ImPlotSpec* s);
double implotPlotHistogram(const char* label, int type, const void* values, int count, int bins, double barScale, double rangeMin, double rangeMax, const ImPlotSpec* s);
double implotPlotHistogram2D(const char* label, int type, const void* xs, const void* ys, int count, int xBins, int yBins, double xMin, double xMax, double yMin, double yMax, const ImPlotSpec* s);
void implotPlotDigital(const char* label, int type, const void* xs, const void* ys, int count, const ImPlotSpec* s);
void implotPlotText(const char* text, double x, double y, float offX, float offY, const ImPlotSpec* s);
void implotPlotDummy(const char* label, const ImPlotSpec* s);
]]
-- )EOF" R"EOF(--
ffi.cdef [[
bool implotDragPoint(int id, double* x, double* y, const float* col, float size, int flags, bool* out);
bool implotDragLineX(int id, double* x, const float* col, float thickness, int flags, bool* out);
bool implotDragLineY(int id, double* y, const float* col, float thickness, int flags, bool* out);
bool implotDragRect(int id, double* coords, const float* col, int flags, bool* out);
void implotAnnotation(double x, double y, const float* col, float offX, float offY, bool clamp, bool round);
void implotAnnotationText(double x, double y, const float* col, float offX, float offY, bool clamp, const char* text);
void implotTagX(double x, const float* col, bool round);
void implotTagXText(double x, const float* col, const char* text);
void implotTagY(double y, const float* col, bool round);
void implotTagYText(double y, const float* col, const char* text);

void implotPixelsToPlot(float x, float y, int xAxis, int yAxis, double* out);
void implotPlotToPixels(double x, double y, int xAxis, int yAxis, float* out);
void implotGetPlotPos(float* out);
void implotGetPlotSize(float* out);
void implotGetPlotMousePos(int xAxis, int yAxis, double* out);
void implotGetPlotLimits(int xAxis, int yAxis, double* out);
void implotGetPlotSelection(int xAxis, int yAxis, double* out);
bool implotIsPlotHovered();
bool implotIsAxisHovered(int axis);
bool implotIsSubplotsHovered();
bool implotIsPlotSelected();
void implotCancelPlotSelection();
void implotHideNextItem(bool hidden, int cond);

void implotPushStyleColorU32(int idx, unsigned col);
void implotPushStyleColorVec4(int idx, const float* col);
void implotPopStyleColor(int count);
void implotPushStyleVarFloat(int idx, float val);
void implotPushStyleVarVec2(int idx, float x, float y);
void implotPopStyleVar(int count);
void implotStyleColorsAuto();
void implotStyleColorsClassic();
void implotStyleColorsDark();
void implotStyleColorsLight();
void implotGetLastItemColor(float* out);
const char* implotGetStyleColorName(int idx);
const char* implotGetMarkerName(int idx);
int implotNextMarker();

int implotAddColormap(const char* name, const float* cols, int size, bool qual);
int implotGetColormapCount();
const char* implotGetColormapName(int cmap);
int implotGetColormapIndex(const char* name);
void implotPushColormapIndex(int cmap);
void implotPushColormapName(const char* name);
void implotPopColormap(int count);
void implotNextColormapColor(float* out);
int implotGetColormapSize(int cmap);
void implotGetColormapColor(int idx, int cmap, float* out);
void implotSampleColormap(float t, int cmap, float* out);
void implotColormapScale(const char* label, double scaleMin, double scaleMax, float w, float h, const char* fmt, int flags, int cmap);
bool implotColormapSlider(const char* label, float* t, float* out, const char* fmt, int cmap);
bool implotColormapButton(const char* label, float w, float h, int cmap);
void implotBustColorCache(const char* title);

void implotMapInputDefault();
void implotMapInputReverse();
void implotItemIconVec4(const float* col);
void implotItemIconU32(unsigned col);
void implotColormapIcon(int cmap);
void implotPushPlotClipRect(float expand);
void implotPopPlotClipRect();
bool implotShowStyleSelector(const char* label);
bool implotShowColormapSelector(const char* label);
bool implotShowInputMapSelector(const char* label);
void implotShowStyleEditor();
void implotShowUserGuide();
void implotShowMetricsWindow(bool* open);
void implotShowDemoWindow(bool* open);
]]

local raw = ffi.load 'IMPLOT'

-- ImPlot asserts throw C++ exceptions; each shim catches them and keeps the
-- message for implotTakeError. Every call through C below raises it as a Lua
-- error located at the first caller outside this file.
local chunk = debug.getinfo(1, 'S').source
local function raiseCaught()
    local err = raw.implotTakeError()
    if err == nil then return end
    local level = 3
    while true do
        local info = debug.getinfo(level, 'S')
        if info == nil or info.source ~= chunk then break end
        level = level + 1
    end
    error('implot: ' .. ffi.string(err), level)
end
local C = setmetatable({}, {
    __index = function(t, name)
        local f = raw[name]
        local w = function(...)
            local ret = f(...)
            raiseCaught()
            return ret
        end
        t[name] = w
        return w
    end,
})

if ffi.sizeof('ImPlotSpec') ~= C.implotSpecSize() or ffi.offsetof('ImPlotSpec', 'Flags') ~= C.implotSpecFlagsOffset() then
    error('implot: ImPlotSpec cdef does not match the C++ layout')
end

implot = implot or {}
local implot = implot
local AUTO = implot.AUTO
local constant = implot.constant

local function check(name, err)
    if err ~= nil then error(name .. ': ' .. ffi.string(err), 3) end
end

local function str(name, v, what)
    if type(v) ~= 'string' then error(name .. ': ' .. what .. ' must be a string', 3) end
    return v
end

-- ImPlot formats a double with these strings: allow at most one floating
-- point conversion and nothing else.
local function checkFormat(name, fmt)
    if fmt == nil or fmt == false then return nil end
    if type(fmt) ~= 'string' then error(name .. ': format must be a string', 3) end
    local conversions, i = 0, 1
    while true do
        local s = fmt:find('%', i, true)
        if not s then break end
        if fmt:sub(s + 1, s + 1) == '%' then
            i = s + 2
        else
            local conv, e = fmt:match('^%%[-+ #0]*%d*%.?%d*l?(%a)()', s)
            if not conv or not conv:find('^[eEfFgGaA]$') then
                error(name .. ': format may only contain a floating point conversion', 3)
            end
            conversions = conversions + 1
            i = e
        end
    end
    if conversions > 1 then error(name .. ': format may only contain one conversion', 3) end
    return fmt
end

local colorBuf = ffi.new('float[4]')
local function color(name, c)
    if c == nil then return nil end
    local tc = type(c)
    if tc == 'table' then
        colorBuf[0], colorBuf[1], colorBuf[2], colorBuf[3] = c.r or 0, c.g or 0, c.b or 0, c.a or 1
    elseif tc == 'cdata' then
        colorBuf[0], colorBuf[1], colorBuf[2], colorBuf[3] = c.x, c.y, c.z, c.w
    else
        error(name .. ': color must be a table with r, g, b, a fields', 3)
    end
    return colorBuf
end

local function colorTable(buf) return { r = buf[0], g = buf[1], b = buf[2], a = buf[3] } end

-- Element types accepted for data arrays, in the order of dispatch() in
-- luaimplot.cc. Keys are LuaJIT's canonical spelling of each type.
local dataTypes = { 'int8_t', 'uint8_t', 'int16_t', 'uint16_t', 'int32_t', 'uint32_t', 'int64_t', 'uint64_t', 'float', 'double' }
local DOUBLE = 9
local typeCodes = {}
local arrayTypes = {}
for i, t in ipairs(dataTypes) do
    typeCodes[tostring(ffi.typeof(t)):match('^ctype<(.*)>$')] = i - 1
    arrayTypes[i - 1] = ffi.typeof(t .. '[?]')
end
if typeCodes.char == nil then typeCodes.char = ffi.cast('char', -1) < 0 and 0 or 1 end

local function ctypeName(v) return tostring(ffi.typeof(v)):match('^ctype<(.*)>$') end

-- Returns the type code of the elements of a pointer, array, or reference to
-- array cdata, or nil if it is not one of the supported scalar types.
local function elementType(v)
    local name = ctypeName(v)
    local base = name:gsub('%f[%w_]const%f[^%w_]', ''):gsub('%f[%w_]volatile%f[^%w_]', ''):gsub('%(&%)', '')
    local dims
    base, dims = base:gsub('%[[^%]]*%]', '')
    if dims == 0 then
        local stars
        base, stars = base:gsub('[%*&]%s*$', '')
        if stars == 0 then return nil, name end
    end
    base = base:gsub('^%s+', ''):gsub('%s+$', ''):gsub('%s+', ' ')
    return typeCodes[base], name
end

local function isData(v)
    local t = type(v)
    if t == 'table' then return true end
    return t == 'cdata' and ctypeName(v):find('[%*%[&]') ~= nil
end

local buildSpec

local function toSpec(name, s)
    if s == nil then return nil end
    if type(s) == 'table' then
        local ret = buildSpec(s, 4)
        return ret
    end
    if ffi.istype('ImPlotSpec', s) or ffi.istype('ImPlotSpec*', s) then return s end
    error(name .. ': spec must be a table or an ImPlotSpec', 3)
end

-- Resolves data arguments into (type code, count, pointers...). Cdata pointers
-- and arrays are passed through without copying, and must all share the same
-- element type. Lua tables are copied into a temporary array of that element
-- type, or of doubles if no cdata is involved. When count is nil it defaults
-- to the shortest table, and is required as soon as cdata is involved.
local function resolve(name, count, spec, ...)
    local n = select('#', ...)
    local args = { ... }
    local code, hasTable
    for i = 1, n do
        local v = args[i]
        local t = type(v)
        if t == 'cdata' then
            local c, ctname = elementType(v)
            if c == nil then
                error(name .. ': unsupported data type ' .. ctname ..
                    ', expected a pointer or array of int8_t, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t, float or double', 3)
            end
            if code ~= nil and code ~= c then error(name .. ': all cdata arguments must have the same element type', 3) end
            code = c
        elseif t == 'table' then
            hasTable = true
        else
            error(name .. ': data arguments must be tables or cdata pointers, got ' .. t, 3)
        end
    end
    if count == nil then
        if code ~= nil then error(name .. ': count is required when passing cdata', 3) end
        for i = 1, n do
            local l = #args[i]
            if count == nil or l < count then count = l end
        end
    else
        count = tonumber(count)
        if count == nil or count < 0 or count ~= math.floor(count) then error(name .. ': count must be a non-negative integer', 3) end
    end
    code = code or DOUBLE
    if hasTable then
        if spec ~= nil and spec.Stride ~= AUTO then error(name .. ': Stride can only be used with cdata arguments', 3) end
        local ct = arrayTypes[code]
        for i = 1, n do
            local t = args[i]
            if type(t) == 'table' then
                if #t < count then error(name .. ': table argument has fewer than ' .. count .. ' elements', 3) end
                local a = ffi.new(ct, count > 0 and count or 1)
                for j = 1, count do a[j - 1] = t[j] end
                args[i] = a
            end
        end
    end
    return code, count, unpack(args, 1, n)
end

-- Returns a const char*[] and a table anchoring the strings for the call.
local function strings(name, t, n, what)
    if type(t) ~= 'table' then error(name .. ': ' .. what .. ' must be a table of strings', 3) end
    if #t < n then error(name .. ': ' .. what .. ' needs at least ' .. n .. ' entries', 3) end
    local arr = ffi.new('const char*[?]', n > 0 and n or 1)
    local keep = {}
    for i = 1, n do
        local s = t[i]
        if type(s) ~= 'string' then s = tostring(s) end
        keep[i] = s
        arr[i - 1] = s
    end
    return arr, keep
end

local specFields = {
    LineColor = 'color', LineColors = 'colors', LineWeight = 'number',
    FillColor = 'color', FillColors = 'colors', FillAlpha = 'number',
    Marker = 'number', MarkerSize = 'number', MarkerSizes = 'sizes',
    MarkerLineColor = 'color', MarkerLineColors = 'colors',
    MarkerFillColor = 'color', MarkerFillColors = 'colors',
    Size = 'number', Offset = 'number', Stride = 'number', Flags = 'number',
}
-- Keeps arrays referenced by pointer fields alive as long as their spec.
local specAnchors = setmetatable({}, { __mode = 'k' })

-- Builds an ImPlotSpec cdata from a table of field names; colors are tables
-- with r, g, b, a fields; the *Colors and MarkerSizes fields take either a
-- Lua table of numbers or a cdata pointer.
function buildSpec(tbl, level)
    local s = ffi.new('ImPlotSpec')
    C.implotSpecDefault(s)
    if tbl == nil then return s end
    if type(tbl) ~= 'table' then error('implot.Spec: argument must be a table', level) end
    local keep
    for k, v in pairs(tbl) do
        local kind = specFields[k]
        if kind == nil then error('implot.Spec: unknown field ' .. tostring(k), level) end
        if kind == 'color' then
            if type(v) ~= 'table' then error('implot.Spec: ' .. k .. ' must be a table with r, g, b, a fields', level) end
            local f = s[k]
            f.x, f.y, f.z, f.w = v.r or 0, v.g or 0, v.b or 0, v.a or 1
        elseif kind == 'number' then
            if type(v) ~= 'number' then error('implot.Spec: ' .. k .. ' must be a number', level) end
            s[k] = v
        else
            if type(v) == 'table' then
                local a = ffi.new(kind == 'sizes' and 'float[?]' or 'uint32_t[?]', #v > 0 and #v or 1)
                for i = 1, #v do a[i - 1] = v[i] end
                v = a
            end
            keep = keep or {}
            keep[k] = v
            s[k] = v
        end
    end
    if keep then specAnchors[s] = keep end
    return s
end
function implot.Spec(tbl)
    local ret = buildSpec(tbl, 3)
    return ret
end
-- )EOF" R"EOF(--

-- Begin/End. Prefer implot.safe.* which pair these automatically.
function implot.BeginPlot(title, w, h, flags)
    return C.implotBeginPlot(str('BeginPlot', title, 'title'), w or -1, h or 0, flags or 0)
end
function implot.EndPlot()
    C.implotEndPlot()
end

-- Ratio tables are updated in place when the user resizes the subplots.
local function ratios(name, r, n)
    if r == nil or type(r) == 'cdata' then return r end
    if type(r) ~= 'table' or #r < n then error(name .. ': ratios must be a table with an entry per row or column', 3) end
    local a = ffi.new('float[?]', n)
    for i = 1, n do a[i - 1] = r[i] end
    return a
end
local function writeBack(r, a, n)
    if type(r) ~= 'table' then return end
    for i = 1, n do r[i] = a[i - 1] end
end
function implot.BeginSubplots(title, rows, cols, w, h, flags, rowRatios, colRatios)
    local rr = ratios('BeginSubplots', rowRatios, rows)
    local cr = ratios('BeginSubplots', colRatios, cols)
    local ret = C.implotBeginSubplots(str('BeginSubplots', title, 'title'), rows, cols, w or -1, h or 0, flags or 0, rr, cr)
    writeBack(rowRatios, rr, rows)
    writeBack(colRatios, cr, cols)
    return ret
end
function implot.EndSubplots()
    C.implotEndSubplots()
end
function implot.BeginAlignedPlots(id, vertical)
    if vertical == nil then vertical = true end
    return C.implotBeginAlignedPlots(str('BeginAlignedPlots', id, 'group_id'), vertical)
end
function implot.EndAlignedPlots()
    C.implotEndAlignedPlots()
end
function implot.BeginLegendPopup(label, button)
    return C.implotBeginLegendPopup(str('BeginLegendPopup', label, 'label'), button or 1)
end
function implot.EndLegendPopup()
    check('EndLegendPopup', C.implotCheckPlot())
    C.implotEndLegendPopup()
end
function implot.IsLegendEntryHovered(label)
    return C.implotIsLegendEntryHovered(str('IsLegendEntryHovered', label, 'label'))
end
function implot.BeginDragDropTargetPlot()
    check('BeginDragDropTargetPlot', C.implotCheckPlot())
    return C.implotBeginDragDropTargetPlot()
end
function implot.BeginDragDropTargetAxis(axis)
    check('BeginDragDropTargetAxis', C.implotCheckPlot())
    check('BeginDragDropTargetAxis', C.implotCheckAxis(axis))
    return C.implotBeginDragDropTargetAxis(axis)
end
function implot.BeginDragDropTargetLegend()
    check('BeginDragDropTargetLegend', C.implotCheckPlot())
    return C.implotBeginDragDropTargetLegend()
end
function implot.EndDragDropTarget()
    check('EndDragDropTarget', C.implotCheckPlot())
    C.implotEndDragDropTarget()
end
function implot.BeginDragDropSourcePlot(flags)
    check('BeginDragDropSourcePlot', C.implotCheckPlot())
    return C.implotBeginDragDropSourcePlot(flags or 0)
end
function implot.BeginDragDropSourceAxis(axis, flags)
    check('BeginDragDropSourceAxis', C.implotCheckPlot())
    check('BeginDragDropSourceAxis', C.implotCheckAxis(axis))
    return C.implotBeginDragDropSourceAxis(axis, flags or 0)
end
function implot.BeginDragDropSourceItem(label, flags)
    check('BeginDragDropSourceItem', C.implotCheckPlot())
    return C.implotBeginDragDropSourceItem(str('BeginDragDropSourceItem', label, 'label'), flags or 0)
end
function implot.EndDragDropSource()
    check('EndDragDropSource', C.implotCheckPlot())
    C.implotEndDragDropSource()
end

-- Setup
function implot.SetupAxis(axis, label, flags)
    check('SetupAxis', C.implotCheckAxis(axis))
    C.implotSetupAxis(axis, label, flags or 0)
end
function implot.SetupAxisLimits(axis, vMin, vMax, cond)
    check('SetupAxisLimits', C.implotCheckAxis(axis))
    C.implotSetupAxisLimits(axis, vMin, vMax, cond or constant.Cond.Once)
end
function implot.SetupAxisFormat(axis, fmt)
    check('SetupAxisFormat', C.implotCheckAxis(axis))
    C.implotSetupAxisFormat(axis, checkFormat('SetupAxisFormat', fmt))
end
-- SetupAxisTicks(axis, values, [n], [labels], [keepDefault]) with a table or
-- double cdata of tick positions, or SetupAxisTicks(axis, vMin, vMax, n,
-- [labels], [keepDefault]) for evenly spaced ticks.
function implot.SetupAxisTicks(axis, a, b, c, d, e)
    check('SetupAxisTicks', C.implotCheckAxis(axis))
    if type(a) == 'number' then
        local n, labels, keep = c, d, e
        if type(n) ~= 'number' then error('SetupAxisTicks: n_ticks must be a number', 2) end
        local arr, anchor
        if labels ~= nil then
            arr, anchor = strings('SetupAxisTicks', labels, n, 'labels')
        end
        C.implotSetupAxisTicksRange(axis, a, b, n, arr, not not keep)
    else
        local labels, keep = c, d
        local code, n, values = resolve('SetupAxisTicks', b, nil, a)
        if code ~= DOUBLE then error('SetupAxisTicks: cdata tick values must be doubles', 2) end
        local arr, anchor
        if labels ~= nil then arr, anchor = strings('SetupAxisTicks', labels, n, 'labels') end
        C.implotSetupAxisTicksValues(axis, values, n, arr, not not keep)
    end
end
function implot.SetupAxisScale(axis, scale)
    check('SetupAxisScale', C.implotCheckAxis(axis))
    C.implotSetupAxisScale(axis, scale)
end
function implot.SetupAxisLimitsConstraints(axis, vMin, vMax)
    check('SetupAxisLimitsConstraints', C.implotCheckAxis(axis))
    C.implotSetupAxisLimitsConstraints(axis, vMin, vMax)
end
function implot.SetupAxisZoomConstraints(axis, zMin, zMax)
    check('SetupAxisZoomConstraints', C.implotCheckAxis(axis))
    C.implotSetupAxisZoomConstraints(axis, zMin, zMax)
end
function implot.SetupAxes(xLabel, yLabel, xFlags, yFlags)
    C.implotSetupAxes(xLabel, yLabel, xFlags or 0, yFlags or 0)
end
function implot.SetupAxesLimits(xMin, xMax, yMin, yMax, cond)
    C.implotSetupAxesLimits(xMin, xMax, yMin, yMax, cond or constant.Cond.Once)
end
function implot.SetupLegend(location, flags)
    C.implotSetupLegend(location, flags or 0)
end
function implot.SetupMouseText(location, flags)
    C.implotSetupMouseText(location, flags or 0)
end
function implot.SetupFinish()
    C.implotSetupFinish()
end
function implot.SetNextAxisLimits(axis, vMin, vMax, cond)
    check('SetNextAxisLimits', C.implotCheckAxis(axis))
    C.implotSetNextAxisLimits(axis, vMin, vMax, cond or constant.Cond.Once)
end
function implot.SetNextAxisToFit(axis)
    check('SetNextAxisToFit', C.implotCheckAxis(axis))
    C.implotSetNextAxisToFit(axis)
end
function implot.SetNextAxesLimits(xMin, xMax, yMin, yMax, cond)
    C.implotSetNextAxesLimits(xMin, xMax, yMin, yMax, cond or constant.Cond.Once)
end
function implot.SetNextAxesToFit()
    C.implotSetNextAxesToFit()
end
function implot.SetAxis(axis)
    C.implotSetAxis(axis)
end
function implot.SetAxes(x, y)
    C.implotSetAxes(x, y)
end
-- )EOF" R"EOF(--

-- Plot items. Data arguments are Lua tables of numbers (copied) or cdata
-- pointers/arrays of a supported scalar type (passed without copying, which
-- makes e.g. implot.PlotLine('ram', PCSX.getMemPtr() + 0x1000, 256) plot live
-- memory). The optional trailing spec is a table of ImPlotSpec fields or an
-- implot.Spec() result.
--
-- ImPlot overloads that differ only by arity are resolved by argument shape:
-- if the argument following the first data array is a number or nil, the
-- values form (label, values, count, ...) is used; if it is a table or cdata
-- array, the xs/ys form (label, xs, ys, count, ...) is used.
function implot.PlotLine(label, a, b, c, d, e)
    str('PlotLine', label, 'label')
    if isData(b) then
        local s = toSpec('PlotLine', d)
        local code, n, xs, ys = resolve('PlotLine', c, s, a, b)
        C.implotPlotLineXY(label, code, xs, ys, n, s)
    else
        local s = toSpec('PlotLine', e)
        local code, n, values = resolve('PlotLine', b, s, a)
        C.implotPlotLineV(label, code, values, n, c or 1, d or 0, s)
    end
end
function implot.PlotScatter(label, a, b, c, d, e)
    str('PlotScatter', label, 'label')
    if isData(b) then
        local s = toSpec('PlotScatter', d)
        local code, n, xs, ys = resolve('PlotScatter', c, s, a, b)
        C.implotPlotScatterXY(label, code, xs, ys, n, s)
    else
        local s = toSpec('PlotScatter', e)
        local code, n, values = resolve('PlotScatter', b, s, a)
        C.implotPlotScatterV(label, code, values, n, c or 1, d or 0, s)
    end
end
function implot.PlotStairs(label, a, b, c, d, e)
    str('PlotStairs', label, 'label')
    if isData(b) then
        local s = toSpec('PlotStairs', d)
        local code, n, xs, ys = resolve('PlotStairs', c, s, a, b)
        C.implotPlotStairsXY(label, code, xs, ys, n, s)
    else
        local s = toSpec('PlotStairs', e)
        local code, n, values = resolve('PlotStairs', b, s, a)
        C.implotPlotStairsV(label, code, values, n, c or 1, d or 0, s)
    end
end
-- PlotBubbles(label, values, szs, count, [xscale], [xstart], [spec]) or
-- PlotBubbles(label, xs, ys, szs, count, [spec]).
function implot.PlotBubbles(label, a, b, c, d, e, f)
    str('PlotBubbles', label, 'label')
    if isData(c) then
        local s = toSpec('PlotBubbles', e)
        local code, n, xs, ys, szs = resolve('PlotBubbles', d, s, a, b, c)
        C.implotPlotBubblesXY(label, code, xs, ys, szs, n, s)
    else
        local s = toSpec('PlotBubbles', f)
        local code, n, values, szs = resolve('PlotBubbles', c, s, a, b)
        C.implotPlotBubblesV(label, code, values, szs, n, d or 1, e or 0, s)
    end
end
function implot.PlotPolygon(label, xs, ys, count, spec)
    local s = toSpec('PlotPolygon', spec)
    local code, n, pxs, pys = resolve('PlotPolygon', count, s, xs, ys)
    C.implotPlotPolygon(str('PlotPolygon', label, 'label'), code, pxs, pys, n, s)
end
-- PlotShaded(label, values, count, [yref], [xscale], [xstart], [spec]),
-- PlotShaded(label, xs, ys, count, [yref], [spec]) or
-- PlotShaded(label, xs, ys1, ys2, count, [spec]).
function implot.PlotShaded(label, a, b, c, d, e, f)
    str('PlotShaded', label, 'label')
    if isData(b) and isData(c) then
        local s = toSpec('PlotShaded', e)
        local code, n, xs, ys1, ys2 = resolve('PlotShaded', d, s, a, b, c)
        C.implotPlotShadedXYY(label, code, xs, ys1, ys2, n, s)
    elseif isData(b) then
        local s = toSpec('PlotShaded', e)
        local code, n, xs, ys = resolve('PlotShaded', c, s, a, b)
        C.implotPlotShadedXY(label, code, xs, ys, n, d or 0, s)
    else
        local s = toSpec('PlotShaded', f)
        local code, n, values = resolve('PlotShaded', b, s, a)
        C.implotPlotShadedV(label, code, values, n, c or 0, d or 1, e or 0, s)
    end
end
-- PlotBars(label, values, count, [barSize], [shift], [spec]) or
-- PlotBars(label, xs, ys, count, [barSize], [spec]).
function implot.PlotBars(label, a, b, c, d, e)
    str('PlotBars', label, 'label')
    if isData(b) then
        local s = toSpec('PlotBars', e)
        local code, n, xs, ys = resolve('PlotBars', c, s, a, b)
        C.implotPlotBarsXY(label, code, xs, ys, n, d or 0.67, s)
    else
        local s = toSpec('PlotBars', e)
        local code, n, values = resolve('PlotBars', b, s, a)
        C.implotPlotBarsV(label, code, values, n, c or 0.67, d or 0, s)
    end
end
-- values is row-major with itemCount rows and groupCount columns.
function implot.PlotBarGroups(labels, values, itemCount, groupCount, groupSize, shift, spec)
    check('PlotBarGroups', C.implotCheckPlot())
    if type(itemCount) ~= 'number' or type(groupCount) ~= 'number' then
        error('PlotBarGroups: item_count and group_count must be numbers', 2)
    end
    local s = toSpec('PlotBarGroups', spec)
    local code, n, pvalues = resolve('PlotBarGroups', itemCount * groupCount, s, values)
    local arr, anchor = strings('PlotBarGroups', labels, itemCount, 'label_ids')
    C.implotPlotBarGroups(arr, code, pvalues, itemCount, groupCount, groupSize or 0.67, shift or 0, s)
end
-- PlotErrorBars(label, xs, ys, err, count, [spec]) or
-- PlotErrorBars(label, xs, ys, neg, pos, count, [spec]).
function implot.PlotErrorBars(label, xs, ys, a, b, c, d)
    str('PlotErrorBars', label, 'label')
    if isData(b) then
        local s = toSpec('PlotErrorBars', d)
        local code, n, pxs, pys, neg, pos = resolve('PlotErrorBars', c, s, xs, ys, a, b)
        C.implotPlotErrorBarsNP(label, code, pxs, pys, neg, pos, n, s)
    else
        local s = toSpec('PlotErrorBars', c)
        local code, n, pxs, pys, err = resolve('PlotErrorBars', b, s, xs, ys, a)
        C.implotPlotErrorBars(label, code, pxs, pys, err, n, s)
    end
end
-- PlotStems(label, values, count, [ref], [scale], [start], [spec]) or
-- PlotStems(label, xs, ys, count, [ref], [spec]).
function implot.PlotStems(label, a, b, c, d, e, f)
    str('PlotStems', label, 'label')
    if isData(b) then
        local s = toSpec('PlotStems', e)
        local code, n, xs, ys = resolve('PlotStems', c, s, a, b)
        C.implotPlotStemsXY(label, code, xs, ys, n, d or 0, s)
    else
        local s = toSpec('PlotStems', f)
        local code, n, values = resolve('PlotStems', b, s, a)
        C.implotPlotStemsV(label, code, values, n, c or 0, d or 1, e or 0, s)
    end
end
function implot.PlotInfLines(label, values, count, spec)
    local s = toSpec('PlotInfLines', spec)
    local code, n, pvalues = resolve('PlotInfLines', count, s, values)
    C.implotPlotInfLines(str('PlotInfLines', label, 'label'), code, pvalues, n, s)
end
-- fmt defaults to '%.1f'; pass false for no labels.
function implot.PlotPieChart(labels, values, count, x, y, radius, fmt, angle0, spec)
    local s = toSpec('PlotPieChart', spec)
    local code, n, pvalues = resolve('PlotPieChart', count, s, values)
    local arr, anchor = strings('PlotPieChart', labels, n, 'label_ids')
    if fmt == nil then fmt = '%.1f' end
    C.implotPlotPieChart(arr, code, pvalues, n, x, y, radius, checkFormat('PlotPieChart', fmt), angle0 or 90, s)
end
-- fmt defaults to '%.1f'; pass false for no labels.
function implot.PlotHeatmap(label, values, rows, cols, scaleMin, scaleMax, fmt, minX, minY, maxX, maxY, spec)
    if type(rows) ~= 'number' or type(cols) ~= 'number' then error('PlotHeatmap: rows and cols must be numbers', 2) end
    local s = toSpec('PlotHeatmap', spec)
    local code, n, pvalues = resolve('PlotHeatmap', rows * cols, s, values)
    if fmt == nil then fmt = '%.1f' end
    C.implotPlotHeatmap(str('PlotHeatmap', label, 'label'), code, pvalues, rows, cols, scaleMin or 0, scaleMax or 0,
        checkFormat('PlotHeatmap', fmt), minX or 0, minY or 0, maxX or 1, maxY or 1, s)
end
-- Leaving rangeMin and rangeMax at 0 uses the data extents.
function implot.PlotHistogram(label, values, count, bins, barScale, rangeMin, rangeMax, spec)
    local s = toSpec('PlotHistogram', spec)
    local code, n, pvalues = resolve('PlotHistogram', count, s, values)
    return C.implotPlotHistogram(str('PlotHistogram', label, 'label'), code, pvalues, n, bins or constant.Bin.Sturges,
        barScale or 1, rangeMin or 0, rangeMax or 0, s)
end
function implot.PlotHistogram2D(label, xs, ys, count, xBins, yBins, xMin, xMax, yMin, yMax, spec)
    local s = toSpec('PlotHistogram2D', spec)
    local code, n, pxs, pys = resolve('PlotHistogram2D', count, s, xs, ys)
    return C.implotPlotHistogram2D(str('PlotHistogram2D', label, 'label'), code, pxs, pys, n,
        xBins or constant.Bin.Sturges, yBins or constant.Bin.Sturges, xMin or 0, xMax or 0, yMin or 0, yMax or 0, s)
end
function implot.PlotDigital(label, xs, ys, count, spec)
    local s = toSpec('PlotDigital', spec)
    local code, n, pxs, pys = resolve('PlotDigital', count, s, xs, ys)
    C.implotPlotDigital(str('PlotDigital', label, 'label'), code, pxs, pys, n, s)
end
function implot.PlotText(text, x, y, offX, offY, spec)
    C.implotPlotText(str('PlotText', text, 'text'), x, y, offX or 0, offY or 0, toSpec('PlotText', spec))
end
function implot.PlotDummy(label, spec)
    C.implotPlotDummy(str('PlotDummy', label, 'label'), toSpec('PlotDummy', spec))
end
-- )EOF" R"EOF(--

-- Tools. Pointer arguments become plain values in and multiple returns out.
-- Colors are tables with r, g, b, a fields; nil uses the text color.
local dragOut = ffi.new('bool[3]')
local dragXY = ffi.new('double[4]')
function implot.DragPoint(id, x, y, col, size, flags)
    dragXY[0], dragXY[1] = x, y
    local changed = C.implotDragPoint(id, dragXY, dragXY + 1, color('DragPoint', col), size or 4, flags or 0, dragOut)
    return changed, dragXY[0], dragXY[1], dragOut[0], dragOut[1], dragOut[2]
end
function implot.DragLineX(id, x, col, thickness, flags)
    dragXY[0] = x
    local changed = C.implotDragLineX(id, dragXY, color('DragLineX', col), thickness or 1, flags or 0, dragOut)
    return changed, dragXY[0], dragOut[0], dragOut[1], dragOut[2]
end
function implot.DragLineY(id, y, col, thickness, flags)
    dragXY[0] = y
    local changed = C.implotDragLineY(id, dragXY, color('DragLineY', col), thickness or 1, flags or 0, dragOut)
    return changed, dragXY[0], dragOut[0], dragOut[1], dragOut[2]
end
function implot.DragRect(id, x1, y1, x2, y2, col, flags)
    dragXY[0], dragXY[1], dragXY[2], dragXY[3] = x1, y1, x2, y2
    local changed = C.implotDragRect(id, dragXY, color('DragRect', col), flags or 0, dragOut)
    return changed, dragXY[0], dragXY[1], dragXY[2], dragXY[3], dragOut[0], dragOut[1], dragOut[2]
end
-- The last argument is either a text string (displayed verbatim) or the
-- round boolean of the value-only overload.
function implot.Annotation(x, y, col, offX, offY, clamp, textOrRound)
    local c = color('Annotation', col)
    if type(textOrRound) == 'string' then
        C.implotAnnotationText(x, y, c, offX or 0, offY or 0, not not clamp, textOrRound)
    else
        C.implotAnnotation(x, y, c, offX or 0, offY or 0, not not clamp, not not textOrRound)
    end
end
function implot.TagX(x, col, textOrRound)
    if type(textOrRound) == 'string' then
        C.implotTagXText(x, color('TagX', col), textOrRound)
    else
        C.implotTagX(x, color('TagX', col), not not textOrRound)
    end
end
function implot.TagY(y, col, textOrRound)
    if type(textOrRound) == 'string' then
        C.implotTagYText(y, color('TagY', col), textOrRound)
    else
        C.implotTagY(y, color('TagY', col), not not textOrRound)
    end
end

-- Utils
local outD = ffi.new('double[4]')
local outF = ffi.new('float[4]')
function implot.PixelsToPlot(x, y, xAxis, yAxis)
    xAxis, yAxis = xAxis or AUTO, yAxis or AUTO
    C.implotPixelsToPlot(x, y, xAxis, yAxis, outD)
    return outD[0], outD[1]
end
function implot.PlotToPixels(x, y, xAxis, yAxis)
    xAxis, yAxis = xAxis or AUTO, yAxis or AUTO
    C.implotPlotToPixels(x, y, xAxis, yAxis, outF)
    return outF[0], outF[1]
end
function implot.GetPlotPos()
    C.implotGetPlotPos(outF)
    return outF[0], outF[1]
end
function implot.GetPlotSize()
    C.implotGetPlotSize(outF)
    return outF[0], outF[1]
end
function implot.GetPlotMousePos(xAxis, yAxis)
    xAxis, yAxis = xAxis or AUTO, yAxis or AUTO
    C.implotGetPlotMousePos(xAxis, yAxis, outD)
    return outD[0], outD[1]
end
local function rect() return { X = { Min = outD[0], Max = outD[1] }, Y = { Min = outD[2], Max = outD[3] } } end
function implot.GetPlotLimits(xAxis, yAxis)
    xAxis, yAxis = xAxis or AUTO, yAxis or AUTO
    C.implotGetPlotLimits(xAxis, yAxis, outD)
    return rect()
end
function implot.GetPlotSelection(xAxis, yAxis)
    xAxis, yAxis = xAxis or AUTO, yAxis or AUTO
    C.implotGetPlotSelection(xAxis, yAxis, outD)
    return rect()
end
function implot.IsPlotHovered()
    return C.implotIsPlotHovered()
end
function implot.IsAxisHovered(axis)
    check('IsAxisHovered', C.implotCheckAxis(axis))
    return C.implotIsAxisHovered(axis)
end
function implot.IsSubplotsHovered()
    return C.implotIsSubplotsHovered()
end
function implot.IsPlotSelected()
    return C.implotIsPlotSelected()
end
function implot.CancelPlotSelection()
    C.implotCancelPlotSelection()
end
function implot.HideNextItem(hidden, cond)
    if hidden == nil then hidden = true end
    C.implotHideNextItem(hidden, cond or constant.Cond.Once)
end

-- Style. PushStyleColor takes an ImU32 number or an r, g, b, a table;
-- PushStyleVar takes one number for float variables, two for ImVec2 ones.
function implot.PushStyleColor(idx, col)
    check('PushStyleColor', C.implotCheckStyleCol(idx))
    if type(col) == 'number' then
        C.implotPushStyleColorU32(idx, col)
    else
        C.implotPushStyleColorVec4(idx, color('PushStyleColor', col) or error('PushStyleColor: color is required', 2))
    end
end
function implot.PopStyleColor(count)
    count = count or 1
    C.implotPopStyleColor(count)
end
function implot.PushStyleVar(idx, x, y)
    if y == nil then
        C.implotPushStyleVarFloat(idx, x)
    else
        C.implotPushStyleVarVec2(idx, x, y)
    end
end
function implot.PopStyleVar(count)
    count = count or 1
    C.implotPopStyleVar(count)
end
implot.StyleColorsAuto = C.implotStyleColorsAuto
implot.StyleColorsClassic = C.implotStyleColorsClassic
implot.StyleColorsDark = C.implotStyleColorsDark
implot.StyleColorsLight = C.implotStyleColorsLight
function implot.GetLastItemColor()
    C.implotGetLastItemColor(outF)
    return colorTable(outF)
end
function implot.GetStyleColorName(idx)
    check('GetStyleColorName', C.implotCheckStyleCol(idx))
    return ffi.string(C.implotGetStyleColorName(idx))
end
function implot.GetMarkerName(idx) return ffi.string(C.implotGetMarkerName(idx)) end
function implot.NextMarker()
    return C.implotNextMarker()
end

-- Colormaps. cmap arguments default to the current colormap.
-- colors is a table of r, g, b, a tables or ImU32 numbers.
function implot.AddColormap(name, colors, qual)
    str('AddColormap', name, 'name')
    if type(colors) ~= 'table' then error('AddColormap: colors must be a table of colors', 2) end
    local n = #colors
    local cols = ffi.new('float[?]', n * 4)
    for i = 1, n do
        local c = colors[i]
        local o = (i - 1) * 4
        if type(c) == 'number' then
            cols[o], cols[o + 1], cols[o + 2], cols[o + 3] = bit.band(c, 0xff) / 255, bit.band(bit.rshift(c, 8), 0xff) / 255,
                bit.band(bit.rshift(c, 16), 0xff) / 255, bit.band(bit.rshift(c, 24), 0xff) / 255
        elseif type(c) == 'table' then
            cols[o], cols[o + 1], cols[o + 2], cols[o + 3] = c.r or 0, c.g or 0, c.b or 0, c.a or 1
        else
            error('AddColormap: colors must be r, g, b, a tables or ImU32 numbers', 2)
        end
    end
    if qual == nil then qual = true end
    return C.implotAddColormap(name, cols, n, qual)
end
implot.GetColormapCount = C.implotGetColormapCount
function implot.GetColormapName(cmap)
    local ret = C.implotGetColormapName(cmap)
    if ret == nil then return nil end
    return ffi.string(ret)
end
function implot.GetColormapIndex(name) return C.implotGetColormapIndex(str('GetColormapIndex', name, 'name')) end
-- Accepts a colormap index or name.
function implot.PushColormap(cmap)
    if type(cmap) == 'string' then
        C.implotPushColormapName(cmap)
    else
        C.implotPushColormapIndex(cmap)
    end
end
function implot.PopColormap(count)
    count = count or 1
    C.implotPopColormap(count)
end
function implot.NextColormapColor()
    C.implotNextColormapColor(outF)
    return colorTable(outF)
end
function implot.GetColormapSize(cmap) return C.implotGetColormapSize(cmap or AUTO) end
function implot.GetColormapColor(idx, cmap)
    C.implotGetColormapColor(idx, cmap or AUTO, outF)
    return colorTable(outF)
end
function implot.SampleColormap(t, cmap)
    C.implotSampleColormap(t, cmap or AUTO, outF)
    return colorTable(outF)
end
function implot.ColormapScale(label, scaleMin, scaleMax, w, h, fmt, flags, cmap)
    C.implotColormapScale(str('ColormapScale', label, 'label'), scaleMin, scaleMax, w or 0, h or 0,
        checkFormat('ColormapScale', fmt or '%g'), flags or 0, cmap or AUTO)
end
-- Returns changed, t, and the sampled color.
function implot.ColormapSlider(label, t, fmt, cmap)
    local pt = ffi.new('float[1]', t or 0)
    local changed = C.implotColormapSlider(str('ColormapSlider', label, 'label'), pt, outF,
        checkFormat('ColormapSlider', fmt or ''), cmap or AUTO)
    return changed, pt[0], colorTable(outF)
end
function implot.ColormapButton(label, w, h, cmap)
    return C.implotColormapButton(str('ColormapButton', label, 'label'), w or 0, h or 0, cmap or AUTO)
end
function implot.BustColorCache(title) C.implotBustColorCache(title) end

-- Input mapping and misc
implot.MapInputDefault = C.implotMapInputDefault
implot.MapInputReverse = C.implotMapInputReverse
function implot.ItemIcon(col)
    if type(col) == 'number' then
        C.implotItemIconU32(col)
    else
        C.implotItemIconVec4(color('ItemIcon', col) or error('ItemIcon: color is required', 2))
    end
end
function implot.ColormapIcon(cmap)
    C.implotColormapIcon(cmap)
end
function implot.PushPlotClipRect(expand)
    C.implotPushPlotClipRect(expand or 0)
end
function implot.PopPlotClipRect()
    check('PopPlotClipRect', C.implotCheckPlot())
    C.implotPopPlotClipRect()
end
function implot.ShowStyleSelector(label) return C.implotShowStyleSelector(str('ShowStyleSelector', label, 'label')) end
function implot.ShowColormapSelector(label) return C.implotShowColormapSelector(str('ShowColormapSelector', label, 'label')) end
function implot.ShowInputMapSelector(label) return C.implotShowInputMapSelector(str('ShowInputMapSelector', label, 'label')) end
implot.ShowStyleEditor = C.implotShowStyleEditor
implot.ShowUserGuide = C.implotShowUserGuide

-- With an open argument, returns its updated value (false once closed).
local function window(f)
    return function(open)
        if open == nil then
            f(nil)
            return
        end
        local p = ffi.new('bool[1]', open)
        f(p)
        return p[0]
    end
end
implot.ShowMetricsWindow = window(C.implotShowMetricsWindow)
implot.ShowDemoWindow = window(C.implotShowDemoWindow)

-- )EOF"
