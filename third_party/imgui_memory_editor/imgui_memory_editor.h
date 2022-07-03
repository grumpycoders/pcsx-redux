// Mini memory editor for Dear ImGui (to embed in your game/tools)
// Get latest version at http://www.github.com/ocornut/imgui_club
//
// Right-click anywhere to access the Options menu!
// You can adjust the keyboard repeat delay/rate in ImGuiIO.
// The code assume a mono-space font for simplicity!
// If you don't use the default font, use ImGui::PushFont()/PopFont() to switch to a mono-space font before calling this.
//
// Usage:
//   // Create a window and draw memory editor inside it:
//   static MemoryEditor mem_edit_1;
//   static char data[0x10000];
//   size_t data_size = 0x10000;
//   mem_edit_1.DrawWindow("Memory Editor", data, data_size);
//
// Usage:
//   // If you already have a window, use DrawContents() instead:
//   static MemoryEditor mem_edit_2;
//   ImGui::Begin("MyWindow")
//   mem_edit_2.DrawContents(this, sizeof(*this), (size_t)this);
//   ImGui::End();
//
// Changelog:
// - v0.10: initial version
// - v0.23 (2017/08/17): added to github. fixed right-arrow triggering a byte write.
// - v0.24 (2018/06/02): changed DragInt("Rows" to use a %d data format (which is desirable since imgui 1.61).
// - v0.25 (2018/07/11): fixed wording: all occurrences of "Rows" renamed to "Columns".
// - v0.26 (2018/08/02): fixed clicking on hex region
// - v0.30 (2018/08/02): added data preview for common data types
// - v0.31 (2018/10/10): added OptUpperCaseHex option to select lower/upper casing display [@samhocevar]
// - v0.32 (2018/10/10): changed signatures to use void* instead of unsigned char*
// - v0.33 (2018/10/10): added OptShowOptions option to hide all the interactive option setting.
// - v0.34 (2019/05/07): binary preview now applies endianness setting [@nicolasnoble]
// - v0.35 (2020/01/29): using ImGuiDataType available since Dear ImGui 1.69.
// - v0.36 (2020/05/05): minor tweaks, minor refactor.
// - v0.40 (2020/10/04): fix misuse of ImGuiListClipper API, broke with Dear ImGui 1.79. made cursor position appears on left-side of edit box. option popup appears on mouse release. fix MSVC warnings where _CRT_SECURE_NO_WARNINGS wasn't working in recent versions.
// - v0.41 (2020/10/05): fix when using with keyboard/gamepad navigation enabled.
// - v0.42 (2020/10/14): fix for . character in ASCII view always being greyed out.
// - v0.43 (2021/03/12): added OptFooterExtraHeight to allow for custom drawing at the bottom of the editor [@leiradel]
// - v0.44 (2021/03/12): use ImGuiInputTextFlags_AlwaysOverwrite in 1.82 + fix hardcoded width.
// - v0.50 (2021/11/12): various fixes for recent dear imgui versions (fixed misuse of clipper, relying on SetKeyboardFocusHere() handling scrolling from 1.85). added default size.
//
// Todo/Bugs:
// - This is generally old/crappy code, it should work but isn't very good.. to be rewritten some day.
// - PageUp/PageDown are supported because we use _NoNav. This is a good test scenario for working out idioms of how to mix natural nav and our own...
// - Arrows are being sent to the InputText() about to disappear which for LeftArrow makes the text cursor appear at position 1 for one frame.
// - Using InputText() is awkward and maybe overkill here, consider implementing something custom.

#pragma once

#include <stdlib.h>
#include <stdint.h>

#include <functional>
#include <string>

#include "imgui.h"

struct MemoryEditor
{
    enum DataFormat
    {
        DataFormat_Bin = 0,
        DataFormat_Dec = 1,
        DataFormat_Hex = 2,
        DataFormat_COUNT
    };

    // Settings
    bool            Open;                                       // = true   // set to false when DrawWindow() was closed. ignore if not using DrawWindow().
    bool            ReadOnly;                                   // = false  // disable any editing.
    int             Cols;                                       // = 16     // number of columns to display.
    bool            OptShowOptions;                             // = true   // display options button/context menu. when disabled, options will be locked unless you provide your own UI for them.
    bool            OptShowDataPreview;                         // = false  // display a footer previewing the decimal/binary/hex/float representation of the currently selected bytes.
    bool            OptShowHexII;                               // = false  // display values in HexII representation instead of regular hexadecimal: hide null/zero bytes, ascii values as ".X".
    bool            OptShowAscii;                               // = true   // display ASCII representation on the right side.
    bool            OptGreyOutZeroes;                           // = true   // display null/zero bytes using the TextDisabled color.
    bool            OptUpperCaseHex;                            // = true   // display hexadecimal values as "FF" instead of "ff".
    int             OptMidColsCount;                            // = 8      // set to 0 to disable extra spacing between every mid-cols.
    int             OptAddrDigitsCount;                         // = 0      // number of addr digits to display (default calculated based on maximum displayed addr).
    float           OptFooterExtraHeight;                       // = 0      // space to reserve at the bottom of the widget to add custom widgets
    ImU32           HighlightColor;                             //          // background color of highlighted bytes.
    ImU8            (*ReadFn)(const ImU8* data, size_t off);    // = 0      // optional handler to read bytes.
    void            (*WriteFn)(ImU8* data, size_t off, ImU8 d); // = 0      // optional handler to write bytes.
    bool            (*HighlightFn)(const ImU8* data, size_t off);//= 0      // optional handler to return Highlight property (to support non-contiguous highlighting).
    std::function<void()> PushMonoFont = nullptr;

private:
    // [Internal State]
    bool            ContentsWidthChanged;
    size_t          DataPreviewAddr;
    size_t          DataEditingAddr;
    bool            DataEditingTakeFocus;
    std::string     DataInputBuf;
    std::string     AddrInputBuf;
    size_t          GotoAddr;
    size_t          HighlightMin, HighlightMax;
    int             PreviewEndianess;

public:
    ImGuiDataType   PreviewDataType;
    
    MemoryEditor();
    void GotoAddrAndHighlight(size_t addr_min, size_t addr_max);

    struct Sizes
    {
        int     AddrDigitsCount;
        float   LineHeight;
        float   GlyphWidth;
        float   ByteWidth;
        float   ByteSpacingWidth;
        float   HexCellWidth;
        float   SpacingBetweenMidCols;
        float   PosHexStart;
        float   PosHexEnd;
        float   PosAsciiStart;
        float   PosAsciiEnd;
        float   WindowWidth;

        Sizes() { memset(this, 0, sizeof(*this)); }
    };

    void CalcSizes(Sizes& s, size_t mem_size, size_t base_display_addr);
    // Standalone Memory Editor window
    void DrawWindow(const char* title, void* mem_data, size_t mem_size, size_t base_display_addr = 0x0000);
    // Memory Editor contents only
    void DrawContents(void* mem_data_void, size_t mem_size, size_t base_display_addr = 0x0000);
    void DrawOptionsLine(const Sizes& s, void* mem_data, size_t mem_size, size_t base_display_addr);
    void DrawPreviewLine(const Sizes& s, void* mem_data_void, size_t mem_size, size_t base_display_addr);
    // Utilities for Data Preview
    const char* DataTypeGetDesc(ImGuiDataType data_type) const;
    size_t DataTypeGetSize(ImGuiDataType data_type) const;
    const char* DataFormatGetDesc(DataFormat data_format) const;
    bool IsBigEndian() const;
    static void* EndianessCopyBigEndian(void* _dst, void* _src, size_t s, int is_little_endian);
    static void* EndianessCopyLittleEndian(void* _dst, void* _src, size_t s, int is_little_endian);
    void* EndianessCopy(void* dst, void* src, size_t size) const;
    const char* FormatBinary(const uint8_t* buf, int width) const;

private:
    // [Internal]
    void DrawPreviewData(size_t addr, const ImU8* mem_data, size_t mem_size, ImGuiDataType data_type, DataFormat data_format, char* out_buf, size_t out_buf_size) const;
};
