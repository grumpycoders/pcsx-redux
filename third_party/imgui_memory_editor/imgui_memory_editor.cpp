#include "imgui_memory_editor.h"

#include <stdio.h>      // sprintf, scanf
#include <stdint.h>     // uint8_t, etc.

#include "fmt/format.h"
#include "imgui_stdlib.h"

#ifdef _MSC_VER
#define _PRISizeT   "I"
#define ImSnprintf  _snprintf
#else
#define _PRISizeT   "z"
#define ImSnprintf  snprintf
#endif

#ifdef _MSC_VER
#pragma warning (push)
#pragma warning (disable: 4996) // warning C4996: 'sprintf': This function or variable may be unsafe.
#endif

MemoryEditor::MemoryEditor()
{
	// Settings
	Open = true;
	ReadOnly = false;
	Cols = 16;
	OptShowOptions = true;
	OptShowDataPreview = false;
	OptShowHexII = false;
	OptShowAscii = true;
	OptGreyOutZeroes = true;
	OptUpperCaseHex = true;
	OptMidColsCount = 8;
	OptAddrDigitsCount = 0;
	OptFooterExtraHeight = 0.0f;
	HighlightColor = IM_COL32(255, 255, 255, 50);
	ReadFn = NULL;
	WriteFn = NULL;
	HighlightFn = NULL;

	// State/Internals
	ContentsWidthChanged = false;
	DataPreviewAddr = DataEditingAddr = (size_t)-1;
	DataEditingTakeFocus = false;
	GotoAddr = (size_t)-1;
	HighlightMin = HighlightMax = (size_t)-1;
	PreviewEndianess = 0;
	PreviewDataType = ImGuiDataType_S32;
}

void MemoryEditor::GotoAddrAndHighlight(size_t addr_min, size_t addr_max)
{
	GotoAddr = addr_min;
	HighlightMin = addr_min;
	HighlightMax = addr_max;
}

void MemoryEditor::CalcSizes(Sizes& s, size_t mem_size, size_t base_display_addr)
{
	if (PushMonoFont) PushMonoFont();
	ImGuiStyle& style = ImGui::GetStyle();
	s.AddrDigitsCount = OptAddrDigitsCount;
	if (s.AddrDigitsCount == 0)
		for (size_t n = base_display_addr + mem_size - 1; n > 0; n >>= 4)
			s.AddrDigitsCount++;
	s.LineHeight = ImGui::GetTextLineHeight();
	s.GlyphWidth = ImGui::CalcTextSize("F").x + 1;                  // We assume the font is mono-space
	s.HexCellWidth = (float)(int)(s.GlyphWidth * 2.5f);             // "FF " we include trailing space in the width to easily catch clicks everywhere
	s.SpacingBetweenMidCols = (float)(int)(s.HexCellWidth * 0.25f); // Every OptMidColsCount columns we add a bit of extra spacing
	s.PosHexStart = (s.AddrDigitsCount + 2) * s.GlyphWidth;
	s.PosHexEnd = s.PosHexStart + (s.HexCellWidth * Cols);
	s.PosAsciiStart = s.PosAsciiEnd = s.PosHexEnd;
	if (OptShowAscii)
	{
		s.PosAsciiStart = s.PosHexEnd + s.GlyphWidth * 1;
		if (OptMidColsCount > 0)
			s.PosAsciiStart += (float)((Cols + OptMidColsCount - 1) / OptMidColsCount) * s.SpacingBetweenMidCols;
		s.PosAsciiEnd = s.PosAsciiStart + Cols * s.GlyphWidth;
	}
	s.WindowWidth = s.PosAsciiEnd + style.ScrollbarSize + style.WindowPadding.x * 2 + s.GlyphWidth;
	if (PushMonoFont) ImGui::PopFont();
}

// Standalone Memory Editor window
void MemoryEditor::DrawWindow(const char* title, void* mem_data, size_t mem_size, size_t base_display_addr)
{
	Sizes s;
	CalcSizes(s, mem_size, base_display_addr);
	ImGui::SetNextWindowSize(ImVec2(s.WindowWidth, s.WindowWidth * 0.60f), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSizeConstraints(ImVec2(0.0f, 0.0f), ImVec2(s.WindowWidth, FLT_MAX));

	Open = true;
	if (ImGui::Begin(title, &Open, ImGuiWindowFlags_NoScrollbar))
	{
		if (ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows) && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
			ImGui::OpenPopup("context");
		DrawContents(mem_data, mem_size, base_display_addr);
		if (ContentsWidthChanged)
		{
			CalcSizes(s, mem_size, base_display_addr);
			ImGui::SetWindowSize(ImVec2(s.WindowWidth, ImGui::GetWindowSize().y));
		}
	}
	ImGui::End();
}

// Memory Editor contents only
void MemoryEditor::DrawContents(void* mem_data_void, size_t mem_size, size_t base_display_addr)
{
	if (Cols < 1)
		Cols = 1;


	ImU8* mem_data = (ImU8*)mem_data_void;
	Sizes s;
	CalcSizes(s, mem_size, base_display_addr);
	if (PushMonoFont) PushMonoFont();
	ImGuiStyle& style = ImGui::GetStyle();

	// We begin into our scrolling region with the 'ImGuiWindowFlags_NoMove' in order to prevent click from moving the window.
	// This is used as a facility since our main click detection code doesn't assign an ActiveId so the click would normally be caught as a window-move.
	const float height_separator = style.ItemSpacing.y;
	float footer_height = OptFooterExtraHeight;
	if (OptShowOptions)
		footer_height += height_separator + ImGui::GetFrameHeightWithSpacing() * 1;
	if (OptShowDataPreview)
		footer_height += height_separator + ImGui::GetFrameHeightWithSpacing() * 1 + ImGui::GetTextLineHeightWithSpacing() * 3;
	ImGui::BeginChild("##scrolling", ImVec2(0, -footer_height), false, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoNav);
	ImDrawList* draw_list = ImGui::GetWindowDrawList();

	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));

	// We are not really using the clipper API correctly here, because we rely on visible_start_addr/visible_end_addr for our scrolling function.
	const int line_total_count = (int)((mem_size + Cols - 1) / Cols);
	ImGuiListClipper clipper;
	clipper.Begin(line_total_count, s.LineHeight);

	bool data_next = false;

	if (ReadOnly || DataEditingAddr >= mem_size)
		DataEditingAddr = (size_t)-1;
	if (DataPreviewAddr >= mem_size)
		DataPreviewAddr = (size_t)-1;

	size_t preview_data_type_size = OptShowDataPreview ? DataTypeGetSize(PreviewDataType) : 0;

	size_t data_editing_addr_next = (size_t)-1;
	if (DataEditingAddr != (size_t)-1)
	{
		// Move cursor but only apply on next frame so scrolling with be synchronized (because currently we can't change the scrolling while the window is being rendered)
		if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_UpArrow)) && (ptrdiff_t)DataEditingAddr >= (ptrdiff_t)Cols) { data_editing_addr_next = DataEditingAddr - Cols; }
		else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_DownArrow)) && (ptrdiff_t)DataEditingAddr < (ptrdiff_t)mem_size - Cols) { data_editing_addr_next = DataEditingAddr + Cols; }
		else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_LeftArrow)) && (ptrdiff_t)DataEditingAddr > (ptrdiff_t)0) { data_editing_addr_next = DataEditingAddr - 1; }
		else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_RightArrow)) && (ptrdiff_t)DataEditingAddr < (ptrdiff_t)mem_size - 1) { data_editing_addr_next = DataEditingAddr + 1; }
	}

	// Draw vertical separator
	ImVec2 window_pos = ImGui::GetWindowPos();
	if (OptShowAscii)
		draw_list->AddLine(ImVec2(window_pos.x + s.PosAsciiStart - s.GlyphWidth, window_pos.y), ImVec2(window_pos.x + s.PosAsciiStart - s.GlyphWidth, window_pos.y + 9999), ImGui::GetColorU32(ImGuiCol_Border));

	const ImU32 color_text = ImGui::GetColorU32(ImGuiCol_Text);
	const ImU32 color_disabled = OptGreyOutZeroes ? ImGui::GetColorU32(ImGuiCol_TextDisabled) : color_text;

	const char* format_address = OptUpperCaseHex ? "%0*" _PRISizeT "X: " : "%0*" _PRISizeT "x: ";
	const char* format_data = OptUpperCaseHex ? "%0*" _PRISizeT "X" : "%0*" _PRISizeT "x";
	const char* format_byte = OptUpperCaseHex ? "%02X" : "%02x";
	const char* format_byte_space = OptUpperCaseHex ? "%02X " : "%02x ";

	auto formatter_variable_hex = [this](size_t count, size_t addr) {
		return fmt::format(fmt::runtime(OptUpperCaseHex ? "{0:0{1}X}" : "{0:0{1}x}"), addr, count);
	};

	auto formatter_byte = [this](ImU8 byte) {
		return fmt::format(fmt::runtime(OptUpperCaseHex ? "{:02X}" : "{:02x}"), byte);
	};

	while (clipper.Step())
		for (int line_i = clipper.DisplayStart; line_i < clipper.DisplayEnd; line_i++) // display only visible lines
		{
			size_t addr = (size_t)(line_i * Cols);
			ImGui::Text(format_address, s.AddrDigitsCount, base_display_addr + addr);

			// Draw Hexadecimal
			for (int n = 0; n < Cols && addr < mem_size; n++, addr++)
			{
				float byte_pos_x = s.PosHexStart + s.HexCellWidth * n;
				if (OptMidColsCount > 0)
					byte_pos_x += (float)(n / OptMidColsCount) * s.SpacingBetweenMidCols;
				ImGui::SameLine(byte_pos_x);

				// Draw highlight
				bool is_highlight_from_user_range = (addr >= HighlightMin && addr < HighlightMax);
				bool is_highlight_from_user_func = (HighlightFn && HighlightFn(mem_data, addr));
				bool is_highlight_from_preview = (addr >= DataPreviewAddr && addr < DataPreviewAddr + preview_data_type_size);
				if (is_highlight_from_user_range || is_highlight_from_user_func || is_highlight_from_preview)
				{
					ImVec2 pos = ImGui::GetCursorScreenPos();
					float highlight_width = s.GlyphWidth * 2;
					bool is_next_byte_highlighted = (addr + 1 < mem_size) && ((HighlightMax != (size_t)-1 && addr + 1 < HighlightMax) || (HighlightFn && HighlightFn(mem_data, addr + 1)));
					if (is_next_byte_highlighted || (n + 1 == Cols))
					{
						highlight_width = s.HexCellWidth;
						if (OptMidColsCount > 0 && n > 0 && (n + 1) < Cols && ((n + 1) % OptMidColsCount) == 0)
							highlight_width += s.SpacingBetweenMidCols;
					}
					draw_list->AddRectFilled(pos, ImVec2(pos.x + highlight_width, pos.y + s.LineHeight), HighlightColor);
				}

				if (DataEditingAddr == addr)
				{
					// Display text input on current byte
					bool data_write = false;
					ImGui::PushID((void*)addr);
					if (DataEditingTakeFocus)
					{
						ImGui::SetKeyboardFocusHere(0);
						AddrInputBuf = formatter_variable_hex(s.AddrDigitsCount, base_display_addr + addr);
						auto byte = ReadFn ? ReadFn(mem_data, addr) : mem_data[addr];
						DataInputBuf = formatter_byte(byte);
					}
					struct UserData
					{
						// FIXME: We should have a way to retrieve the text edit cursor position more easily in the API, this is rather tedious. This is such a ugly mess we may be better off not using InputText() at all here.
						static int Callback(ImGuiInputTextCallbackData* data)
						{
							UserData* user_data = (UserData*)data->UserData;
							if (!data->HasSelection())
								user_data->CursorPos = data->CursorPos;
							if (data->SelectionStart == 0 && data->SelectionEnd == data->BufTextLen)
							{
								// When not editing a byte, always refresh its InputText content pulled from underlying memory data
								// (this is a bit tricky, since InputText technically "owns" the master copy of the buffer we edit it in there)
								data->DeleteChars(0, data->BufTextLen);
								data->InsertChars(0, user_data->CurrentBufOverwrite);
								data->SelectionStart = 0;
								data->SelectionEnd = 2;
								data->CursorPos = 0;
							}
							return 0;
						}
						char   CurrentBufOverwrite[3];  // Input
						int    CursorPos;               // Output
					};
					UserData user_data;
					user_data.CursorPos = -1;
					sprintf(user_data.CurrentBufOverwrite, format_byte, ReadFn ? ReadFn(mem_data, addr) : mem_data[addr]);
					ImGuiInputTextFlags flags = ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_NoHorizontalScroll | ImGuiInputTextFlags_CallbackAlways;
#if IMGUI_VERSION_NUM >= 18104
					flags |= ImGuiInputTextFlags_AlwaysOverwrite;
#else
					flags |= ImGuiInputTextFlags_AlwaysInsertMode;
#endif
					ImGui::SetNextItemWidth(s.GlyphWidth * 2);
					if (ImGui::InputText("##data", &DataInputBuf, flags, UserData::Callback, &user_data))
						data_write = data_next = true;
					else if (!DataEditingTakeFocus && !ImGui::IsItemActive())
						DataEditingAddr = data_editing_addr_next = (size_t)-1;
					DataEditingTakeFocus = false;
					if (user_data.CursorPos >= 2)
						data_write = data_next = true;
					if (data_editing_addr_next != (size_t)-1)
						data_write = data_next = false;
					unsigned int data_input_value = 0;
					if (data_write && sscanf(DataInputBuf.c_str(), "%X", &data_input_value) == 1)
					{
						if (WriteFn)
							WriteFn(mem_data, addr, (ImU8)data_input_value);
						else
							mem_data[addr] = (ImU8)data_input_value;
					}
					ImGui::PopID();
				}
				else
				{
					// NB: The trailing space is not visible but ensure there's no gap that the mouse cannot click on.
					ImU8 b = ReadFn ? ReadFn(mem_data, addr) : mem_data[addr];

					if (OptShowHexII)
					{
						if ((b >= 32 && b < 128))
							ImGui::Text(".%c ", b);
						else if (b == 0xFF && OptGreyOutZeroes)
							ImGui::TextDisabled("## ");
						else if (b == 0x00)
							ImGui::Text("   ");
						else
							ImGui::Text(format_byte_space, b);
					}
					else
					{
						if (b == 0 && OptGreyOutZeroes)
							ImGui::TextDisabled("00 ");
						else
							ImGui::Text(format_byte_space, b);
					}
					if (!ReadOnly && ImGui::IsItemHovered() && ImGui::IsMouseClicked(0))
					{
						DataEditingTakeFocus = true;
						data_editing_addr_next = addr;
					}
				}
			}

			if (OptShowAscii)
			{
				// Draw ASCII values
				ImGui::SameLine(s.PosAsciiStart);
				ImVec2 pos = ImGui::GetCursorScreenPos();
				addr = line_i * Cols;
				ImGui::PushID(line_i);
				if (ImGui::InvisibleButton("ascii", ImVec2(s.PosAsciiEnd - s.PosAsciiStart, s.LineHeight)))
				{
					DataEditingAddr = DataPreviewAddr = addr + (size_t)((ImGui::GetIO().MousePos.x - pos.x) / s.GlyphWidth);
					DataEditingTakeFocus = true;
				}
				ImGui::PopID();
				for (int n = 0; n < Cols && addr < mem_size; n++, addr++)
				{
					if (addr == DataEditingAddr)
					{
						draw_list->AddRectFilled(pos, ImVec2(pos.x + s.GlyphWidth, pos.y + s.LineHeight), ImGui::GetColorU32(ImGuiCol_FrameBg));
						draw_list->AddRectFilled(pos, ImVec2(pos.x + s.GlyphWidth, pos.y + s.LineHeight), ImGui::GetColorU32(ImGuiCol_TextSelectedBg));
					}
					unsigned char c = ReadFn ? ReadFn(mem_data, addr) : mem_data[addr];
					char display_c = (c < 32 || c >= 128) ? '.' : c;
					draw_list->AddText(pos, (display_c == c) ? color_text : color_disabled, &display_c, &display_c + 1);
					pos.x += s.GlyphWidth;
				}
			}
		}
	if (PushMonoFont) ImGui::PopFont();
	ImGui::PopStyleVar(2);
	ImGui::EndChild();

	// Notify the main window of our ideal child content size (FIXME: we are missing an API to get the contents size from the child)
	ImGui::SetCursorPosX(s.WindowWidth);

	if (data_next && DataEditingAddr + 1 < mem_size)
	{
		DataEditingAddr = DataPreviewAddr = DataEditingAddr + 1;
		DataEditingTakeFocus = true;
	}
	else if (data_editing_addr_next != (size_t)-1)
	{
		DataEditingAddr = DataPreviewAddr = data_editing_addr_next;
		DataEditingTakeFocus = true;
	}

	const bool lock_show_data_preview = OptShowDataPreview;
	if (OptShowOptions)
	{
		ImGui::Separator();
		DrawOptionsLine(s, mem_data, mem_size, base_display_addr);
	}

	if (lock_show_data_preview)
	{
		ImGui::Separator();
		DrawPreviewLine(s, mem_data, mem_size, base_display_addr);
	}
}

void MemoryEditor::DrawOptionsLine(const Sizes& s, void* mem_data, size_t mem_size, size_t base_display_addr)
{
	IM_UNUSED(mem_data);
	ImGuiStyle& style = ImGui::GetStyle();
	const char* format_range = OptUpperCaseHex ? "Range %0*" _PRISizeT "X..%0*" _PRISizeT "X" : "Range %0*" _PRISizeT "x..%0*" _PRISizeT "x";

	// Options menu
	if (ImGui::Button("Options"))
		ImGui::OpenPopup("context");
	if (ImGui::BeginPopup("context"))
	{
		ImGui::SetNextItemWidth(s.GlyphWidth * 7 + style.FramePadding.x * 2.0f);
		if (ImGui::DragInt("##cols", &Cols, 0.2f, 4, 32, "%d cols")) { ContentsWidthChanged = true; if (Cols < 1) Cols = 1; }
		ImGui::Checkbox("Show Data Preview", &OptShowDataPreview);
		ImGui::Checkbox("Show HexII", &OptShowHexII);
		if (ImGui::Checkbox("Show Ascii", &OptShowAscii)) { ContentsWidthChanged = true; }
		ImGui::Checkbox("Grey out zeroes", &OptGreyOutZeroes);
		ImGui::Checkbox("Uppercase Hex", &OptUpperCaseHex);

		ImGui::EndPopup();
	}

	ImGui::SameLine();
	ImGui::Text(format_range, s.AddrDigitsCount, base_display_addr, s.AddrDigitsCount, base_display_addr + mem_size - 1);
	ImGui::SameLine();
	ImGui::SetNextItemWidth((s.AddrDigitsCount + 1) * s.GlyphWidth + style.FramePadding.x * 2.0f);
	if (ImGui::InputText("##addr", &AddrInputBuf, ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue))
	{
		size_t goto_addr;
		if (sscanf(AddrInputBuf.c_str(), "%" _PRISizeT "X", &goto_addr) == 1)
		{
			GotoAddr = goto_addr - base_display_addr;
			HighlightMin = HighlightMax = (size_t)-1;
		}
	}

	if (GotoAddr != (size_t)-1)
	{
		if (GotoAddr < mem_size)
		{
			ImGui::BeginChild("##scrolling");
			ImGui::SetScrollFromPosY(ImGui::GetCursorStartPos().y + (GotoAddr / Cols) * ImGui::GetTextLineHeight());
			ImGui::EndChild();
			DataEditingAddr = DataPreviewAddr = GotoAddr;
			DataEditingTakeFocus = true;
		}
		GotoAddr = (size_t)-1;
	}
}

void MemoryEditor::DrawPreviewLine(const Sizes& s, void* mem_data_void, size_t mem_size, size_t base_display_addr)
{
	IM_UNUSED(base_display_addr);
	ImU8* mem_data = (ImU8*)mem_data_void;
	ImGuiStyle& style = ImGui::GetStyle();
	ImGui::AlignTextToFramePadding();
	ImGui::Text("Preview as:");
	ImGui::SameLine();
	ImGui::SetNextItemWidth((s.GlyphWidth * 10.0f) + style.FramePadding.x * 2.0f + style.ItemInnerSpacing.x);
	if (ImGui::BeginCombo("##combo_type", DataTypeGetDesc(PreviewDataType), ImGuiComboFlags_HeightLargest))
	{
		for (int n = 0; n < ImGuiDataType_COUNT; n++)
			if (ImGui::Selectable(DataTypeGetDesc((ImGuiDataType)n), PreviewDataType == n))
				PreviewDataType = (ImGuiDataType)n;
		ImGui::EndCombo();
	}
	ImGui::SameLine();
	ImGui::SetNextItemWidth((s.GlyphWidth * 6.0f) + style.FramePadding.x * 2.0f + style.ItemInnerSpacing.x);
	ImGui::Combo("##combo_endianess", &PreviewEndianess, "LE\0BE\0\0");

	char buf[128] = "";
	float x = s.GlyphWidth * 6.0f;
	bool has_value = DataPreviewAddr != (size_t)-1;
	if (has_value)
		DrawPreviewData(DataPreviewAddr, mem_data, mem_size, PreviewDataType, DataFormat_Dec, buf, (size_t)IM_ARRAYSIZE(buf));
	ImGui::Text("Dec"); ImGui::SameLine(x); ImGui::TextUnformatted(has_value ? buf : "N/A");
	if (has_value)
		DrawPreviewData(DataPreviewAddr, mem_data, mem_size, PreviewDataType, DataFormat_Hex, buf, (size_t)IM_ARRAYSIZE(buf));
	ImGui::Text("Hex"); ImGui::SameLine(x); ImGui::TextUnformatted(has_value ? buf : "N/A");
	if (has_value)
		DrawPreviewData(DataPreviewAddr, mem_data, mem_size, PreviewDataType, DataFormat_Bin, buf, (size_t)IM_ARRAYSIZE(buf));
	buf[IM_ARRAYSIZE(buf) - 1] = 0;
	ImGui::Text("Bin"); ImGui::SameLine(x); ImGui::TextUnformatted(has_value ? buf : "N/A");
}

// Utilities for Data Preview
const char* MemoryEditor::DataTypeGetDesc(ImGuiDataType data_type) const
{
	const char* descs[] = { "Int8", "Uint8", "Int16", "Uint16", "Int32", "Uint32", "Int64", "Uint64", "Float", "Double" };
	IM_ASSERT(data_type >= 0 && data_type < ImGuiDataType_COUNT);
	return descs[data_type];
}

size_t MemoryEditor::DataTypeGetSize(ImGuiDataType data_type) const
{
	const size_t sizes[] = { 1, 1, 2, 2, 4, 4, 8, 8, sizeof(float), sizeof(double) };
	IM_ASSERT(data_type >= 0 && data_type < ImGuiDataType_COUNT);
	return sizes[data_type];
}

const char* MemoryEditor::DataFormatGetDesc(DataFormat data_format) const
{
	const char* descs[] = { "Bin", "Dec", "Hex" };
	IM_ASSERT(data_format >= 0 && data_format < DataFormat_COUNT);
	return descs[data_format];
}

bool MemoryEditor::IsBigEndian() const
{
	uint16_t x = 1;
	char c[2];
	memcpy(c, &x, 2);
	return c[0] != 0;
}

void* MemoryEditor::EndianessCopyBigEndian(void* _dst, void* _src, size_t s, int is_little_endian)
{
	if (is_little_endian)
	{
		uint8_t* dst = (uint8_t*)_dst;
		uint8_t* src = (uint8_t*)_src + s - 1;
		for (int i = 0, n = (int)s; i < n; ++i)
			memcpy(dst++, src--, 1);
		return _dst;
	}
	else
	{
		return memcpy(_dst, _src, s);
	}
}

void* MemoryEditor::EndianessCopyLittleEndian(void* _dst, void* _src, size_t s, int is_little_endian)
{
	if (is_little_endian)
	{
		return memcpy(_dst, _src, s);
	}
	else
	{
		uint8_t* dst = (uint8_t*)_dst;
		uint8_t* src = (uint8_t*)_src + s - 1;
		for (int i = 0, n = (int)s; i < n; ++i)
			memcpy(dst++, src--, 1);
		return _dst;
	}
}

void* MemoryEditor::EndianessCopy(void* dst, void* src, size_t size) const
{
	static void* (*fp)(void*, void*, size_t, int) = NULL;
	if (fp == NULL)
		fp = IsBigEndian() ? EndianessCopyBigEndian : EndianessCopyLittleEndian;
	return fp(dst, src, size, PreviewEndianess);
}

const char* MemoryEditor::FormatBinary(const uint8_t* buf, int width) const
{
	IM_ASSERT(width <= 64);
	size_t out_n = 0;
	static char out_buf[64 + 8 + 1];
	int n = width / 8;
	for (int j = n - 1; j >= 0; --j)
	{
		for (int i = 0; i < 8; ++i)
			out_buf[out_n++] = (buf[j] & (1 << (7 - i))) ? '1' : '0';
		out_buf[out_n++] = ' ';
	}
	IM_ASSERT(out_n < IM_ARRAYSIZE(out_buf));
	out_buf[out_n] = 0;
	return out_buf;
}

// [Internal]
void MemoryEditor::DrawPreviewData(size_t addr, const ImU8* mem_data, size_t mem_size, ImGuiDataType data_type, DataFormat data_format, char* out_buf, size_t out_buf_size) const
{
	uint8_t buf[8];
	size_t elem_size = DataTypeGetSize(data_type);
	size_t size = addr + elem_size > mem_size ? mem_size - addr : elem_size;
	if (ReadFn)
		for (int i = 0, n = (int)size; i < n; ++i)
			buf[i] = ReadFn(mem_data, addr + i);
	else
		memcpy(buf, mem_data + addr, size);

	if (data_format == DataFormat_Bin)
	{
		uint8_t binbuf[8];
		EndianessCopy(binbuf, buf, size);
		ImSnprintf(out_buf, out_buf_size, "%s", FormatBinary(binbuf, (int)size * 8));
		return;
	}

	out_buf[0] = 0;
	switch (data_type)
	{
	case ImGuiDataType_S8:
	{
		int8_t int8 = 0;
		EndianessCopy(&int8, buf, size);
		if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%hhd", int8); return; }
		if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%02x", int8 & 0xFF); return; }
		break;
	}
	case ImGuiDataType_U8:
	{
		uint8_t uint8 = 0;
		EndianessCopy(&uint8, buf, size);
		if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%hhu", uint8); return; }
		if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%02x", uint8 & 0XFF); return; }
		break;
	}
	case ImGuiDataType_S16:
	{
		int16_t int16 = 0;
		EndianessCopy(&int16, buf, size);
		if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%hd", int16); return; }
		if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%04x", int16 & 0xFFFF); return; }
		break;
	}
	case ImGuiDataType_U16:
	{
		uint16_t uint16 = 0;
		EndianessCopy(&uint16, buf, size);
		if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%hu", uint16); return; }
		if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%04x", uint16 & 0xFFFF); return; }
		break;
	}
	case ImGuiDataType_S32:
	{
		int32_t int32 = 0;
		EndianessCopy(&int32, buf, size);
		if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%d", int32); return; }
		if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%08x", int32); return; }
		break;
	}
	case ImGuiDataType_U32:
	{
		uint32_t uint32 = 0;
		EndianessCopy(&uint32, buf, size);
		if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%u", uint32); return; }
		if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%08x", uint32); return; }
		break;
	}
	case ImGuiDataType_S64:
	{
		int64_t int64 = 0;
		EndianessCopy(&int64, buf, size);
		if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%lld", (long long)int64); return; }
		if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%016llx", (long long)int64); return; }
		break;
	}
	case ImGuiDataType_U64:
	{
		uint64_t uint64 = 0;
		EndianessCopy(&uint64, buf, size);
		if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%llu", (long long)uint64); return; }
		if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%016llx", (long long)uint64); return; }
		break;
	}
	case ImGuiDataType_Float:
	{
		float float32 = 0.0f;
		EndianessCopy(&float32, buf, size);
		if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%f", float32); return; }
		if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "%a", float32); return; }
		break;
	}
	case ImGuiDataType_Double:
	{
		double float64 = 0.0;
		EndianessCopy(&float64, buf, size);
		if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%f", float64); return; }
		if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "%a", float64); return; }
		break;
	}
	case ImGuiDataType_COUNT:
		break;
	} // Switch
	IM_ASSERT(0); // Shouldn't reach
}
