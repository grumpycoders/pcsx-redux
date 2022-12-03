//struct ImVec2

//struct ImVec4

//namespace ImGui

//    IMGUI_API ImGuiContext* CreateContext(ImFontAtlas* shared_font_atlas = NULL);
// Unsupported return type ImGuiContext*
// Unsupported arg type ImFontAtlas* shared_font_atlas = NULL
//    IMGUI_API void          DestroyContext(ImGuiContext* ctx = NULL);   // NULL = destroy current context
// Unsupported arg type ImGuiContext* ctx = NULL
//    IMGUI_API ImGuiContext* GetCurrentContext();
// Unsupported return type ImGuiContext*
//    IMGUI_API void          SetCurrentContext(ImGuiContext* ctx);
// Unsupported arg type ImGuiContext* ctx
//    IMGUI_API ImGuiIO&      GetIO();                                    // access the IO structure (mouse/keyboard/gamepad inputs, time, various configuration options/flags)
// Unsupported return type ImGuiIO&
//    IMGUI_API ImGuiStyle&   GetStyle();                                 // access the Style structure (colors, sizes). Always use PushStyleCol(), PushStyleVar() to modify style mid-frame!
// Unsupported return type ImGuiStyle&
//    IMGUI_API void          NewFrame();                                 // start a new Dear ImGui frame, you can submit any command from this point until Render()/EndFrame().
//Not allowed to use this function
//    IMGUI_API void          EndFrame();                                 // ends the Dear ImGui frame. automatically called by Render(). If you don't need to render data (skipping rendering) you may call EndFrame() without Render()... but you'll have wasted CPU already! If you don't need to render, better to not create any windows and not call NewFrame() at all!
IMGUI_FUNCTION(EndFrame)
CALL_FUNCTION_NO_RET(EndFrame)
POP_END_STACK(0)
END_IMGUI_FUNC
//    IMGUI_API void          Render();                                   // ends the Dear ImGui frame, finalize the draw data. You can then get call GetDrawData().
//Not allowed to use this function
//    IMGUI_API ImDrawData*   GetDrawData();                              // valid after Render() and until the next call to NewFrame(). this is what you have to render.
// Unsupported return type ImDrawData*
//    IMGUI_API void          ShowDemoWindow(bool* p_open = NULL);        // create Demo window. demonstrate most ImGui features. call this to learn about the library! try to make it always available in your application!
IMGUI_FUNCTION(ShowDemoWindow)
OPTIONAL_BOOL_POINTER_ARG(p_open)
CALL_FUNCTION_NO_RET(ShowDemoWindow, p_open)
END_BOOL_POINTER(p_open)
END_IMGUI_FUNC
//    IMGUI_API void          ShowMetricsWindow(bool* p_open = NULL);     // create Metrics/Debugger window. display Dear ImGui internals: windows, draw commands, various internal state, etc.
IMGUI_FUNCTION(ShowMetricsWindow)
OPTIONAL_BOOL_POINTER_ARG(p_open)
CALL_FUNCTION_NO_RET(ShowMetricsWindow, p_open)
END_BOOL_POINTER(p_open)
END_IMGUI_FUNC
//    IMGUI_API void          ShowDebugLogWindow(bool* p_open = NULL);    // create Debug Log window. display a simplified log of important dear imgui events.
IMGUI_FUNCTION(ShowDebugLogWindow)
OPTIONAL_BOOL_POINTER_ARG(p_open)
CALL_FUNCTION_NO_RET(ShowDebugLogWindow, p_open)
END_BOOL_POINTER(p_open)
END_IMGUI_FUNC
//    IMGUI_API void          ShowStackToolWindow(bool* p_open = NULL);   // create Stack Tool window. hover items with mouse to query information about the source of their unique ID.
IMGUI_FUNCTION(ShowStackToolWindow)
OPTIONAL_BOOL_POINTER_ARG(p_open)
CALL_FUNCTION_NO_RET(ShowStackToolWindow, p_open)
END_BOOL_POINTER(p_open)
END_IMGUI_FUNC
//    IMGUI_API void          ShowAboutWindow(bool* p_open = NULL);       // create About window. display Dear ImGui version, credits and build/system information.
IMGUI_FUNCTION(ShowAboutWindow)
OPTIONAL_BOOL_POINTER_ARG(p_open)
CALL_FUNCTION_NO_RET(ShowAboutWindow, p_open)
END_BOOL_POINTER(p_open)
END_IMGUI_FUNC
//    IMGUI_API void          ShowStyleEditor(ImGuiStyle* ref = NULL);    // add style editor block (not a window). you can pass in a reference ImGuiStyle structure to compare to, revert to and save to (else it uses the default style)
// Unsupported arg type ImGuiStyle* ref = NULL
//    IMGUI_API bool          ShowStyleSelector(const char* label);       // add style selector block (not a window), essentially a combo listing the default styles.
IMGUI_FUNCTION(ShowStyleSelector)
LABEL_ARG(label)
CALL_FUNCTION(ShowStyleSelector, bool, label)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          ShowFontSelector(const char* label);        // add font selector block (not a window), essentially a combo listing the loaded fonts.
IMGUI_FUNCTION(ShowFontSelector)
LABEL_ARG(label)
CALL_FUNCTION_NO_RET(ShowFontSelector, label)
END_IMGUI_FUNC
//    IMGUI_API void          ShowUserGuide();                            // add basic help/info block (not a window): how to manipulate ImGui as an end-user (mouse/keyboard controls).
IMGUI_FUNCTION(ShowUserGuide)
CALL_FUNCTION_NO_RET(ShowUserGuide)
END_IMGUI_FUNC
//    IMGUI_API const char*   GetVersion();                               // get the compiled version string e.g. "1.80 WIP" (essentially the value for IMGUI_VERSION from the compiled version of imgui.cpp)
IMGUI_FUNCTION(GetVersion)
CALL_FUNCTION(GetVersion, const char*)
PUSH_STRING(ret)
END_IMGUI_FUNC
//    IMGUI_API void          StyleColorsDark(ImGuiStyle* dst = NULL);    // new, recommended style (default)
// Unsupported arg type ImGuiStyle* dst = NULL
//    IMGUI_API void          StyleColorsLight(ImGuiStyle* dst = NULL);   // best used with borders and a custom, thicker font
// Unsupported arg type ImGuiStyle* dst = NULL
//    IMGUI_API void          StyleColorsClassic(ImGuiStyle* dst = NULL); // classic imgui style
// Unsupported arg type ImGuiStyle* dst = NULL
//    IMGUI_API bool          Begin(const char* name, bool* p_open = NULL, ImGuiWindowFlags flags = 0);
IMGUI_FUNCTION(Begin)
LABEL_ARG(name)
OPTIONAL_BOOL_POINTER_ARG(p_open)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(Begin, bool, name, p_open, flags)
IF_RET_ADD_END_STACK(1)
PUSH_BOOL(ret)
END_BOOL_POINTER(p_open)
END_IMGUI_FUNC
//    IMGUI_API void          End();
IMGUI_FUNCTION(End)
CALL_FUNCTION_NO_RET(End)
POP_END_STACK(1)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginChild(const char* str_id, const ImVec2& size = ImVec2 0  0, bool border = false, ImGuiWindowFlags flags = 0);
IMGUI_FUNCTION(BeginChild)
LABEL_ARG(str_id)
OPTIONAL_IM_VEC_2_ARG(size, 0, 0)
OPTIONAL_BOOL_ARG(border, false)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(BeginChild, bool, str_id, size, border, flags)
IF_RET_ADD_END_STACK(2)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginChild(ImGuiID id, const ImVec2& size = ImVec2 0  0, bool border = false, ImGuiWindowFlags flags = 0);
IMGUI_FUNCTION(BeginChild_4)
UINT_ARG(id)
OPTIONAL_IM_VEC_2_ARG(size, 0, 0)
OPTIONAL_BOOL_ARG(border, false)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(BeginChild, bool, id, size, border, flags)
IF_RET_ADD_END_STACK(2)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          EndChild();
IMGUI_FUNCTION(EndChild)
CALL_FUNCTION_NO_RET(EndChild)
POP_END_STACK(2)
END_IMGUI_FUNC
//    IMGUI_API bool          IsWindowAppearing();
IMGUI_FUNCTION(IsWindowAppearing)
CALL_FUNCTION(IsWindowAppearing, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsWindowCollapsed();
IMGUI_FUNCTION(IsWindowCollapsed)
CALL_FUNCTION(IsWindowCollapsed, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsWindowFocused(ImGuiFocusedFlags flags=0); // is current window focused? or its root/child, depending on flags. see flags for options.
IMGUI_FUNCTION(IsWindowFocused)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(IsWindowFocused, bool, flags)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsWindowHovered(ImGuiHoveredFlags flags=0); // is current window hovered (and typically: not blocked by a popup/modal)? see flags for options. NB: If you are trying to check whether your mouse should be dispatched to imgui or to your app, you should use the 'io.WantCaptureMouse' boolean for that! Please read the FAQ!
IMGUI_FUNCTION(IsWindowHovered)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(IsWindowHovered, bool, flags)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API ImDrawList*   GetWindowDrawList();                        // get draw list associated to the current window, to append your own drawing primitives
// Unsupported return type ImDrawList*
//    IMGUI_API float         GetWindowDpiScale();                        // get DPI scale currently associated to the current window's viewport.
IMGUI_FUNCTION(GetWindowDpiScale)
CALL_FUNCTION(GetWindowDpiScale, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetWindowPos();                             // get current window position in screen space (useful if you want to do your own drawing via the DrawList API)
IMGUI_FUNCTION(GetWindowPos)
CALL_FUNCTION(GetWindowPos, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetWindowSize();                            // get current window size
IMGUI_FUNCTION(GetWindowSize)
CALL_FUNCTION(GetWindowSize, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API float         GetWindowWidth();                           // get current window width (shortcut for GetWindowSize().x)
IMGUI_FUNCTION(GetWindowWidth)
CALL_FUNCTION(GetWindowWidth, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API float         GetWindowHeight();                          // get current window height (shortcut for GetWindowSize().y)
IMGUI_FUNCTION(GetWindowHeight)
CALL_FUNCTION(GetWindowHeight, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API ImGuiViewport*GetWindowViewport();                        // get viewport currently associated to the current window.
// Unsupported return type ImGuiViewport*GetWindowViewpor
//    IMGUI_API void          SetNextWindowPos(const ImVec2& pos, ImGuiCond cond = 0, const ImVec2& pivot = ImVec2 0  0); // set next window position. call before Begin(). use pivot=(0.5f,0.5f) to center on given point, etc.
IMGUI_FUNCTION(SetNextWindowPos)
IM_VEC_2_ARG(pos)
OPTIONAL_INT_ARG(cond, 0)
OPTIONAL_IM_VEC_2_ARG(pivot, 0, 0)
CALL_FUNCTION_NO_RET(SetNextWindowPos, pos, cond, pivot)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextWindowSize(const ImVec2& size, ImGuiCond cond = 0);                  // set next window size. set axis to 0.0f to force an auto-fit on this axis. call before Begin()
IMGUI_FUNCTION(SetNextWindowSize)
IM_VEC_2_ARG(size)
OPTIONAL_INT_ARG(cond, 0)
CALL_FUNCTION_NO_RET(SetNextWindowSize, size, cond)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextWindowSizeConstraints(const ImVec2& size_min, const ImVec2& size_max, ImGuiSizeCallback custom_callback = NULL, void* custom_callback_data = NULL); // set next window size limits. use -1,-1 on either X/Y axis to preserve the current size. Sizes will be rounded down. Use callback to apply non-trivial programmatic constraints.
// Unsupported arg type  ImGuiSizeCallback custom_callback = NULL
// Unsupported arg type  void* custom_callback_data = NULL
//    IMGUI_API void          SetNextWindowContentSize(const ImVec2& size);                               // set next window content size (~ scrollable client area, which enforce the range of scrollbars). Not including window decorations (title bar, menu bar, etc.) nor WindowPadding. set an axis to 0.0f to leave it automatic. call before Begin()
IMGUI_FUNCTION(SetNextWindowContentSize)
IM_VEC_2_ARG(size)
CALL_FUNCTION_NO_RET(SetNextWindowContentSize, size)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextWindowCollapsed(bool collapsed, ImGuiCond cond = 0);                 // set next window collapsed state. call before Begin()
IMGUI_FUNCTION(SetNextWindowCollapsed)
BOOL_ARG(collapsed)
OPTIONAL_INT_ARG(cond, 0)
CALL_FUNCTION_NO_RET(SetNextWindowCollapsed, collapsed, cond)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextWindowFocus();                                                       // set next window to be focused / top-most. call before Begin()
IMGUI_FUNCTION(SetNextWindowFocus)
CALL_FUNCTION_NO_RET(SetNextWindowFocus)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextWindowScroll(const ImVec2& scroll);                                  // set next window scrolling value (use < 0.0f to not affect a given axis).
IMGUI_FUNCTION(SetNextWindowScroll)
IM_VEC_2_ARG(scroll)
CALL_FUNCTION_NO_RET(SetNextWindowScroll, scroll)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextWindowBgAlpha(float alpha);                                          // set next window background color alpha. helper to easily override the Alpha component of ImGuiCol_WindowBg/ChildBg/PopupBg. you may also use ImGuiWindowFlags_NoBackground.
IMGUI_FUNCTION(SetNextWindowBgAlpha)
NUMBER_ARG(alpha)
CALL_FUNCTION_NO_RET(SetNextWindowBgAlpha, alpha)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextWindowViewport(ImGuiID viewport_id);                                 // set next window viewport
IMGUI_FUNCTION(SetNextWindowViewport)
UINT_ARG(viewport_id)
CALL_FUNCTION_NO_RET(SetNextWindowViewport, viewport_id)
END_IMGUI_FUNC
//    IMGUI_API void          SetWindowPos(const ImVec2& pos, ImGuiCond cond = 0);                        // (not recommended) set current window position - call within Begin()/End(). prefer using SetNextWindowPos(), as this may incur tearing and side-effects.
IMGUI_FUNCTION(SetWindowPos)
IM_VEC_2_ARG(pos)
OPTIONAL_INT_ARG(cond, 0)
CALL_FUNCTION_NO_RET(SetWindowPos, pos, cond)
END_IMGUI_FUNC
//    IMGUI_API void          SetWindowSize(const ImVec2& size, ImGuiCond cond = 0);                      // (not recommended) set current window size - call within Begin()/End(). set to ImVec2 0  0 to force an auto-fit. prefer using SetNextWindowSize(), as this may incur tearing and minor side-effects.
IMGUI_FUNCTION(SetWindowSize)
IM_VEC_2_ARG(size)
OPTIONAL_INT_ARG(cond, 0)
CALL_FUNCTION_NO_RET(SetWindowSize, size, cond)
END_IMGUI_FUNC
//    IMGUI_API void          SetWindowCollapsed(bool collapsed, ImGuiCond cond = 0);                     // (not recommended) set current window collapsed state. prefer using SetNextWindowCollapsed().
IMGUI_FUNCTION(SetWindowCollapsed)
BOOL_ARG(collapsed)
OPTIONAL_INT_ARG(cond, 0)
CALL_FUNCTION_NO_RET(SetWindowCollapsed, collapsed, cond)
END_IMGUI_FUNC
//    IMGUI_API void          SetWindowFocus();                                                           // (not recommended) set current window to be focused / top-most. prefer using SetNextWindowFocus().
IMGUI_FUNCTION(SetWindowFocus)
CALL_FUNCTION_NO_RET(SetWindowFocus)
END_IMGUI_FUNC
//    IMGUI_API void          SetWindowFontScale(float scale);                                            // [OBSOLETE] set font scale. Adjust IO.FontGlobalScale if you want to scale all windows. This is an old API! For correct scaling, prefer to reload font + rebuild ImFontAtlas + call style.ScaleAllSizes().
IMGUI_FUNCTION(SetWindowFontScale)
NUMBER_ARG(scale)
CALL_FUNCTION_NO_RET(SetWindowFontScale, scale)
END_IMGUI_FUNC
//    IMGUI_API void          SetWindowPos(const char* name, const ImVec2& pos, ImGuiCond cond = 0);      // set named window position.
IMGUI_FUNCTION(SetWindowPos_3)
LABEL_ARG(name)
IM_VEC_2_ARG(pos)
OPTIONAL_INT_ARG(cond, 0)
CALL_FUNCTION_NO_RET(SetWindowPos, name, pos, cond)
END_IMGUI_FUNC
//    IMGUI_API void          SetWindowSize(const char* name, const ImVec2& size, ImGuiCond cond = 0);    // set named window size. set axis to 0.0f to force an auto-fit on this axis.
IMGUI_FUNCTION(SetWindowSize_3)
LABEL_ARG(name)
IM_VEC_2_ARG(size)
OPTIONAL_INT_ARG(cond, 0)
CALL_FUNCTION_NO_RET(SetWindowSize, name, size, cond)
END_IMGUI_FUNC
//    IMGUI_API void          SetWindowCollapsed(const char* name, bool collapsed, ImGuiCond cond = 0);   // set named window collapsed state
IMGUI_FUNCTION(SetWindowCollapsed_3)
LABEL_ARG(name)
BOOL_ARG(collapsed)
OPTIONAL_INT_ARG(cond, 0)
CALL_FUNCTION_NO_RET(SetWindowCollapsed, name, collapsed, cond)
END_IMGUI_FUNC
//    IMGUI_API void          SetWindowFocus(const char* name);                                           // set named window to be focused / top-most. use NULL to remove focus.
IMGUI_FUNCTION(SetWindowFocus_1)
LABEL_ARG(name)
CALL_FUNCTION_NO_RET(SetWindowFocus, name)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetContentRegionAvail();                                        // == GetContentRegionMax() - GetCursorPos()
IMGUI_FUNCTION(GetContentRegionAvail)
CALL_FUNCTION(GetContentRegionAvail, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetContentRegionMax();                                          // current content boundaries (typically window boundaries including scrolling, or current column boundaries), in windows coordinates
IMGUI_FUNCTION(GetContentRegionMax)
CALL_FUNCTION(GetContentRegionMax, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetWindowContentRegionMin();                                    // content boundaries min for the full window (roughly (0,0)-Scroll), in window coordinates
IMGUI_FUNCTION(GetWindowContentRegionMin)
CALL_FUNCTION(GetWindowContentRegionMin, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetWindowContentRegionMax();                                    // content boundaries max for the full window (roughly (0,0)+Size-Scroll) where Size can be overridden with SetNextWindowContentSize(), in window coordinates
IMGUI_FUNCTION(GetWindowContentRegionMax)
CALL_FUNCTION(GetWindowContentRegionMax, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API float         GetScrollX();                                                   // get scrolling amount [0 .. GetScrollMaxX()]
IMGUI_FUNCTION(GetScrollX)
CALL_FUNCTION(GetScrollX, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API float         GetScrollY();                                                   // get scrolling amount [0 .. GetScrollMaxY()]
IMGUI_FUNCTION(GetScrollY)
CALL_FUNCTION(GetScrollY, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API void          SetScrollX(float scroll_x);                                     // set scrolling amount [0 .. GetScrollMaxX()]
IMGUI_FUNCTION(SetScrollX)
NUMBER_ARG(scroll_x)
CALL_FUNCTION_NO_RET(SetScrollX, scroll_x)
END_IMGUI_FUNC
//    IMGUI_API void          SetScrollY(float scroll_y);                                     // set scrolling amount [0 .. GetScrollMaxY()]
IMGUI_FUNCTION(SetScrollY)
NUMBER_ARG(scroll_y)
CALL_FUNCTION_NO_RET(SetScrollY, scroll_y)
END_IMGUI_FUNC
//    IMGUI_API float         GetScrollMaxX();                                                // get maximum scrolling amount ~~ ContentSize.x - WindowSize.x - DecorationsSize.x
IMGUI_FUNCTION(GetScrollMaxX)
CALL_FUNCTION(GetScrollMaxX, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API float         GetScrollMaxY();                                                // get maximum scrolling amount ~~ ContentSize.y - WindowSize.y - DecorationsSize.y
IMGUI_FUNCTION(GetScrollMaxY)
CALL_FUNCTION(GetScrollMaxY, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API void          SetScrollHereX(float center_x_ratio = 0.5f);                    // adjust scrolling amount to make current cursor position visible. center_x_ratio=0.0: left, 0.5: center, 1.0: right. When using to make a "default/current item" visible, consider using SetItemDefaultFocus() instead.
IMGUI_FUNCTION(SetScrollHereX)
OPTIONAL_NUMBER_ARG(center_x_ratio, 0.5f)
CALL_FUNCTION_NO_RET(SetScrollHereX, center_x_ratio)
END_IMGUI_FUNC
//    IMGUI_API void          SetScrollHereY(float center_y_ratio = 0.5f);                    // adjust scrolling amount to make current cursor position visible. center_y_ratio=0.0: top, 0.5: center, 1.0: bottom. When using to make a "default/current item" visible, consider using SetItemDefaultFocus() instead.
IMGUI_FUNCTION(SetScrollHereY)
OPTIONAL_NUMBER_ARG(center_y_ratio, 0.5f)
CALL_FUNCTION_NO_RET(SetScrollHereY, center_y_ratio)
END_IMGUI_FUNC
//    IMGUI_API void          SetScrollFromPosX(float local_x, float center_x_ratio = 0.5f);  // adjust scrolling amount to make given position visible. Generally GetCursorStartPos() + offset to compute a valid position.
IMGUI_FUNCTION(SetScrollFromPosX)
NUMBER_ARG(local_x)
OPTIONAL_NUMBER_ARG(center_x_ratio, 0.5f)
CALL_FUNCTION_NO_RET(SetScrollFromPosX, local_x, center_x_ratio)
END_IMGUI_FUNC
//    IMGUI_API void          SetScrollFromPosY(float local_y, float center_y_ratio = 0.5f);  // adjust scrolling amount to make given position visible. Generally GetCursorStartPos() + offset to compute a valid position.
IMGUI_FUNCTION(SetScrollFromPosY)
NUMBER_ARG(local_y)
OPTIONAL_NUMBER_ARG(center_y_ratio, 0.5f)
CALL_FUNCTION_NO_RET(SetScrollFromPosY, local_y, center_y_ratio)
END_IMGUI_FUNC
//    IMGUI_API void          PushFont(ImFont* font);                                         // use NULL as a shortcut to push default font
// Unsupported arg type ImFont* font
//    IMGUI_API void          PopFont();
IMGUI_FUNCTION(PopFont)
CALL_FUNCTION_NO_RET(PopFont)
END_IMGUI_FUNC
//    IMGUI_API void          PushStyleColor(ImGuiCol idx, ImU32 col);                        // modify a style color. always use this if you modify the style after NewFrame().
IMGUI_FUNCTION(PushStyleColor)
INT_ARG(idx)
UINT_ARG(col)
CALL_FUNCTION_NO_RET(PushStyleColor, idx, col)
END_IMGUI_FUNC
//    IMGUI_API void          PushStyleColor(ImGuiCol idx, const ImVec4& col);
IMGUI_FUNCTION(PushStyleColor_2)
INT_ARG(idx)
IM_VEC_4_ARG(col)
CALL_FUNCTION_NO_RET(PushStyleColor, idx, col)
END_IMGUI_FUNC
//    IMGUI_API void          PopStyleColor(int count = 1);
IMGUI_FUNCTION(PopStyleColor)
OPTIONAL_INT_ARG(count, 1)
CALL_FUNCTION_NO_RET(PopStyleColor, count)
END_IMGUI_FUNC
//    IMGUI_API void          PushStyleVar(ImGuiStyleVar idx, float val);                     // modify a style float variable. always use this if you modify the style after NewFrame().
IMGUI_FUNCTION(PushStyleVar)
INT_ARG(idx)
NUMBER_ARG(val)
CALL_FUNCTION_NO_RET(PushStyleVar, idx, val)
ADD_END_STACK(3)
END_IMGUI_FUNC
//    IMGUI_API void          PushStyleVar(ImGuiStyleVar idx, const ImVec2& val);             // modify a style ImVec2 variable. always use this if you modify the style after NewFrame().
IMGUI_FUNCTION(PushStyleVar_2)
INT_ARG(idx)
IM_VEC_2_ARG(val)
CALL_FUNCTION_NO_RET(PushStyleVar, idx, val)
ADD_END_STACK(3)
END_IMGUI_FUNC
//    IMGUI_API void          PopStyleVar(int count = 1);
IMGUI_FUNCTION(PopStyleVar)
OPTIONAL_INT_ARG(count, 1)
CALL_FUNCTION_NO_RET(PopStyleVar, count)
POP_END_STACK(3)
END_IMGUI_FUNC
//    IMGUI_API void          PushAllowKeyboardFocus(bool allow_keyboard_focus);              // == tab stop enable. Allow focusing using TAB/Shift-TAB, enabled by default but you can disable it for certain widgets
IMGUI_FUNCTION(PushAllowKeyboardFocus)
BOOL_ARG(allow_keyboard_focus)
CALL_FUNCTION_NO_RET(PushAllowKeyboardFocus, allow_keyboard_focus)
END_IMGUI_FUNC
//    IMGUI_API void          PopAllowKeyboardFocus();
IMGUI_FUNCTION(PopAllowKeyboardFocus)
CALL_FUNCTION_NO_RET(PopAllowKeyboardFocus)
END_IMGUI_FUNC
//    IMGUI_API void          PushButtonRepeat(bool repeat);                                  // in 'repeat' mode, Button*() functions return repeated true in a typematic manner (using io.KeyRepeatDelay/io.KeyRepeatRate setting). Note that you can call IsItemActive() after any Button() to tell if the button is held in the current frame.
IMGUI_FUNCTION(PushButtonRepeat)
BOOL_ARG(repeat)
CALL_FUNCTION_NO_RET(PushButtonRepeat, repeat)
END_IMGUI_FUNC
//    IMGUI_API void          PopButtonRepeat();
IMGUI_FUNCTION(PopButtonRepeat)
CALL_FUNCTION_NO_RET(PopButtonRepeat)
END_IMGUI_FUNC
//    IMGUI_API void          PushItemWidth(float item_width);                                // push width of items for common large "item+label" widgets. >0.0f: width in pixels, <0.0f align xx pixels to the right of window (so -FLT_MIN always align width to the right side).
IMGUI_FUNCTION(PushItemWidth)
NUMBER_ARG(item_width)
CALL_FUNCTION_NO_RET(PushItemWidth, item_width)
END_IMGUI_FUNC
//    IMGUI_API void          PopItemWidth();
IMGUI_FUNCTION(PopItemWidth)
CALL_FUNCTION_NO_RET(PopItemWidth)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextItemWidth(float item_width);                             // set width of the _next_ common large "item+label" widget. >0.0f: width in pixels, <0.0f align xx pixels to the right of window (so -FLT_MIN always align width to the right side)
IMGUI_FUNCTION(SetNextItemWidth)
NUMBER_ARG(item_width)
CALL_FUNCTION_NO_RET(SetNextItemWidth, item_width)
END_IMGUI_FUNC
//    IMGUI_API float         CalcItemWidth();                                                // width of item given pushed settings and current cursor position. NOT necessarily the width of last item unlike most 'Item' functions.
IMGUI_FUNCTION(CalcItemWidth)
CALL_FUNCTION(CalcItemWidth, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API void          PushTextWrapPos(float wrap_local_pos_x = 0.0f);                 // push word-wrapping position for Text*() commands. < 0.0f: no wrapping; 0.0f: wrap to end of window (or column); > 0.0f: wrap at 'wrap_pos_x' position in window local space
IMGUI_FUNCTION(PushTextWrapPos)
OPTIONAL_NUMBER_ARG(wrap_local_pos_x, 0.0f)
CALL_FUNCTION_NO_RET(PushTextWrapPos, wrap_local_pos_x)
END_IMGUI_FUNC
//    IMGUI_API void          PopTextWrapPos();
IMGUI_FUNCTION(PopTextWrapPos)
CALL_FUNCTION_NO_RET(PopTextWrapPos)
END_IMGUI_FUNC
//    IMGUI_API ImFont*       GetFont();                                                      // get current font
// Unsupported return type ImFont*
//    IMGUI_API float         GetFontSize();                                                  // get current font size (= height in pixels) of current font with current scale applied
IMGUI_FUNCTION(GetFontSize)
CALL_FUNCTION(GetFontSize, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetFontTexUvWhitePixel();                                       // get UV coordinate for a while pixel, useful to draw custom shapes via the ImDrawList API
IMGUI_FUNCTION(GetFontTexUvWhitePixel)
CALL_FUNCTION(GetFontTexUvWhitePixel, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API ImU32         GetColorU32(ImGuiCol idx, float alpha_mul = 1.0f);              // retrieve given style color with style alpha applied and optional extra alpha multiplier, packed as a 32-bit value suitable for ImDrawList
IMGUI_FUNCTION(GetColorU32)
INT_ARG(idx)
OPTIONAL_NUMBER_ARG(alpha_mul, 1.0f)
CALL_FUNCTION(GetColorU32, unsigned int, idx, alpha_mul)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API ImU32         GetColorU32(const ImVec4& col);                                 // retrieve given color with style alpha applied, packed as a 32-bit value suitable for ImDrawList
IMGUI_FUNCTION(GetColorU32_1)
IM_VEC_4_ARG(col)
CALL_FUNCTION(GetColorU32, unsigned int, col)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API ImU32         GetColorU32(ImU32 col);                                         // retrieve given color with style alpha applied, packed as a 32-bit value suitable for ImDrawList
IMGUI_FUNCTION(GetColorU32_1_1)
UINT_ARG(col)
CALL_FUNCTION(GetColorU32, unsigned int, col)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API const ImVec4& GetStyleColorVec4(ImGuiCol idx);                                // retrieve style color as stored in ImGuiStyle structure. use to feed back into PushStyleColor(), otherwise use GetColorU32() to get style color with style alpha baked in.
// Unsupported return type const
//    IMGUI_API void          Separator();                                                    // separator, generally horizontal. inside a menu bar or in horizontal layout mode, this becomes a vertical separator.
IMGUI_FUNCTION(Separator)
CALL_FUNCTION_NO_RET(Separator)
END_IMGUI_FUNC
//    IMGUI_API void          SameLine(float offset_from_start_x=0.0f, float spacing=-1.0f);  // call between widgets or groups to layout them horizontally. X position given in window coordinates.
IMGUI_FUNCTION(SameLine)
OPTIONAL_NUMBER_ARG(offset_from_start_x, 0.0f)
OPTIONAL_NUMBER_ARG(spacing, -1.0f)
CALL_FUNCTION_NO_RET(SameLine, offset_from_start_x, spacing)
END_IMGUI_FUNC
//    IMGUI_API void          NewLine();                                                      // undo a SameLine() or force a new line when in a horizontal-layout context.
IMGUI_FUNCTION(NewLine)
CALL_FUNCTION_NO_RET(NewLine)
END_IMGUI_FUNC
//    IMGUI_API void          Spacing();                                                      // add vertical spacing.
IMGUI_FUNCTION(Spacing)
CALL_FUNCTION_NO_RET(Spacing)
END_IMGUI_FUNC
//    IMGUI_API void          Dummy(const ImVec2& size);                                      // add a dummy item of given size. unlike InvisibleButton(), Dummy() won't take the mouse click or be navigable into.
IMGUI_FUNCTION(Dummy)
IM_VEC_2_ARG(size)
CALL_FUNCTION_NO_RET(Dummy, size)
END_IMGUI_FUNC
//    IMGUI_API void          Indent(float indent_w = 0.0f);                                  // move content position toward the right, by indent_w, or style.IndentSpacing if indent_w <= 0
IMGUI_FUNCTION(Indent)
OPTIONAL_NUMBER_ARG(indent_w, 0.0f)
CALL_FUNCTION_NO_RET(Indent, indent_w)
END_IMGUI_FUNC
//    IMGUI_API void          Unindent(float indent_w = 0.0f);                                // move content position back to the left, by indent_w, or style.IndentSpacing if indent_w <= 0
IMGUI_FUNCTION(Unindent)
OPTIONAL_NUMBER_ARG(indent_w, 0.0f)
CALL_FUNCTION_NO_RET(Unindent, indent_w)
END_IMGUI_FUNC
//    IMGUI_API void          BeginGroup();                                                   // lock horizontal starting position
IMGUI_FUNCTION(BeginGroup)
CALL_FUNCTION_NO_RET(BeginGroup)
ADD_END_STACK(4)
END_IMGUI_FUNC
//    IMGUI_API void          EndGroup();                                                     // unlock horizontal starting position + capture the whole group bounding box into one "item" (so you can use IsItemHovered() or layout primitives such as SameLine() on whole group, etc.)
IMGUI_FUNCTION(EndGroup)
CALL_FUNCTION_NO_RET(EndGroup)
POP_END_STACK(4)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetCursorPos();                                                 // cursor position in window coordinates (relative to window position)
IMGUI_FUNCTION(GetCursorPos)
CALL_FUNCTION(GetCursorPos, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API float         GetCursorPosX();                                                //   (some functions are using window-relative coordinates, such as: GetCursorPos, GetCursorStartPos, GetContentRegionMax, GetWindowContentRegion* etc.
IMGUI_FUNCTION(GetCursorPosX)
CALL_FUNCTION(GetCursorPosX, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API float         GetCursorPosY();                                                //    other functions such as GetCursorScreenPos or everything in ImDrawList::
IMGUI_FUNCTION(GetCursorPosY)
CALL_FUNCTION(GetCursorPosY, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API void          SetCursorPos(const ImVec2& local_pos);                          //    are using the main, absolute coordinate system.
IMGUI_FUNCTION(SetCursorPos)
IM_VEC_2_ARG(local_pos)
CALL_FUNCTION_NO_RET(SetCursorPos, local_pos)
END_IMGUI_FUNC
//    IMGUI_API void          SetCursorPosX(float local_x);                                   //    GetWindowPos() + GetCursorPos() == GetCursorScreenPos() etc.)
IMGUI_FUNCTION(SetCursorPosX)
NUMBER_ARG(local_x)
CALL_FUNCTION_NO_RET(SetCursorPosX, local_x)
END_IMGUI_FUNC
//    IMGUI_API void          SetCursorPosY(float local_y);                                   //
IMGUI_FUNCTION(SetCursorPosY)
NUMBER_ARG(local_y)
CALL_FUNCTION_NO_RET(SetCursorPosY, local_y)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetCursorStartPos();                                            // initial cursor position in window coordinates
IMGUI_FUNCTION(GetCursorStartPos)
CALL_FUNCTION(GetCursorStartPos, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetCursorScreenPos();                                           // cursor position in absolute coordinates (useful to work with ImDrawList API). generally top-left == GetMainViewport()->Pos == (0,0) in single viewport mode, and bottom-right == GetMainViewport()->Pos+Size == io.DisplaySize in single-viewport mode.
IMGUI_FUNCTION(GetCursorScreenPos)
CALL_FUNCTION(GetCursorScreenPos, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API void          SetCursorScreenPos(const ImVec2& pos);                          // cursor position in absolute coordinates
IMGUI_FUNCTION(SetCursorScreenPos)
IM_VEC_2_ARG(pos)
CALL_FUNCTION_NO_RET(SetCursorScreenPos, pos)
END_IMGUI_FUNC
//    IMGUI_API void          AlignTextToFramePadding();                                      // vertically align upcoming text baseline to FramePadding.y so that it will align properly to regularly framed items (call if you have text on a line before a framed item)
IMGUI_FUNCTION(AlignTextToFramePadding)
CALL_FUNCTION_NO_RET(AlignTextToFramePadding)
END_IMGUI_FUNC
//    IMGUI_API float         GetTextLineHeight();                                            // ~ FontSize
IMGUI_FUNCTION(GetTextLineHeight)
CALL_FUNCTION(GetTextLineHeight, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API float         GetTextLineHeightWithSpacing();                                 // ~ FontSize + style.ItemSpacing.y (distance in pixels between 2 consecutive lines of text)
IMGUI_FUNCTION(GetTextLineHeightWithSpacing)
CALL_FUNCTION(GetTextLineHeightWithSpacing, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API float         GetFrameHeight();                                               // ~ FontSize + style.FramePadding.y * 2
IMGUI_FUNCTION(GetFrameHeight)
CALL_FUNCTION(GetFrameHeight, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API float         GetFrameHeightWithSpacing();                                    // ~ FontSize + style.FramePadding.y * 2 + style.ItemSpacing.y (distance in pixels between 2 consecutive lines of framed widgets)
IMGUI_FUNCTION(GetFrameHeightWithSpacing)
CALL_FUNCTION(GetFrameHeightWithSpacing, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API void          PushID(const char* str_id);                                     // push string into the ID stack (will hash string).
IMGUI_FUNCTION(PushID)
LABEL_ARG(str_id)
CALL_FUNCTION_NO_RET(PushID, str_id)
END_IMGUI_FUNC
//    IMGUI_API void          PushID(const char* str_id_begin, const char* str_id_end);       // push string into the ID stack (will hash string).
IMGUI_FUNCTION(PushID_2)
LABEL_ARG(str_id_begin)
LABEL_ARG(str_id_end)
CALL_FUNCTION_NO_RET(PushID, str_id_begin, str_id_end)
END_IMGUI_FUNC
//    IMGUI_API void          PushID(const void* ptr_id);                                     // push pointer into the ID stack (will hash pointer).
// Unsupported arg type const void* ptr_id
//    IMGUI_API void          PushID(int int_id);                                             // push integer into the ID stack (will hash integer).
IMGUI_FUNCTION(PushID_1)
INT_ARG(int_id)
CALL_FUNCTION_NO_RET(PushID, int_id)
END_IMGUI_FUNC
//    IMGUI_API void          PopID();                                                        // pop from the ID stack.
IMGUI_FUNCTION(PopID)
CALL_FUNCTION_NO_RET(PopID)
END_IMGUI_FUNC
//    IMGUI_API ImGuiID       GetID(const char* str_id);                                      // calculate unique ID (hash of whole ID stack + given parameter). e.g. if you want to query into ImGuiStorage yourself
IMGUI_FUNCTION(GetID)
LABEL_ARG(str_id)
CALL_FUNCTION(GetID, unsigned int, str_id)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API ImGuiID       GetID(const char* str_id_begin, const char* str_id_end);
IMGUI_FUNCTION(GetID_2)
LABEL_ARG(str_id_begin)
LABEL_ARG(str_id_end)
CALL_FUNCTION(GetID, unsigned int, str_id_begin, str_id_end)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API ImGuiID       GetID(const void* ptr_id);
// Unsupported arg type const void* ptr_id
//    IMGUI_API void          TextUnformatted(const char* text, const char* text_end = NULL); // raw text without formatting. Roughly equivalent to Text("%s", text) but: A) doesn't require null terminated string if 'text_end' is specified, B) it's faster, no memory copy is done, no buffer size limits, recommended for long chunks of text.
IMGUI_FUNCTION(TextUnformatted)
LABEL_ARG(text)
OPTIONAL_LABEL_ARG(text_end)
CALL_FUNCTION_NO_RET(TextUnformatted, text, text_end)
END_IMGUI_FUNC
//    IMGUI_API void          Text(const char* fmt, ...)                                      IM_FMTARGS(1); // formatted text
// Unsupported arg type  ...)                                      IM_FMTARGS(1
//    IMGUI_API void          TextV(const char* fmt, va_list args)                            IM_FMTLIST(1);
// Unsupported arg type  va_list args)                            IM_FMTLIST(1
//    IMGUI_API void          TextColored(const ImVec4& col, const char* fmt, ...)            IM_FMTARGS(2); // shortcut for PushStyleColor(ImGuiCol_Text, col); Text(fmt, ...); PopStyleColor();
// Unsupported arg type  ...)            IM_FMTARGS(2
//    IMGUI_API void          TextColoredV(const ImVec4& col, const char* fmt, va_list args)  IM_FMTLIST(2);
// Unsupported arg type  va_list args)  IM_FMTLIST(2
//    IMGUI_API void          TextDisabled(const char* fmt, ...)                              IM_FMTARGS(1); // shortcut for PushStyleColor(ImGuiCol_Text, style.Colors[ImGuiCol_TextDisabled]); Text(fmt, ...); PopStyleColor();
// Unsupported arg type  ...)                              IM_FMTARGS(1
//    IMGUI_API void          TextDisabledV(const char* fmt, va_list args)                    IM_FMTLIST(1);
// Unsupported arg type  va_list args)                    IM_FMTLIST(1
//    IMGUI_API void          TextWrapped(const char* fmt, ...)                               IM_FMTARGS(1); // shortcut for PushTextWrapPos(0.0f); Text(fmt, ...); PopTextWrapPos();. Note that this won't work on an auto-resizing window if there's no other widgets to extend the window width, yoy may need to set a size using SetNextWindowSize().
// Unsupported arg type  ...)                               IM_FMTARGS(1
//    IMGUI_API void          TextWrappedV(const char* fmt, va_list args)                     IM_FMTLIST(1);
// Unsupported arg type  va_list args)                     IM_FMTLIST(1
//    IMGUI_API void          LabelText(const char* label, const char* fmt, ...)              IM_FMTARGS(2); // display text+label aligned the same way as value+label widgets
// Unsupported arg type  ...)              IM_FMTARGS(2
//    IMGUI_API void          LabelTextV(const char* label, const char* fmt, va_list args)    IM_FMTLIST(2);
// Unsupported arg type  va_list args)    IM_FMTLIST(2
//    IMGUI_API void          BulletText(const char* fmt, ...)                                IM_FMTARGS(1); // shortcut for Bullet()+Text()
// Unsupported arg type  ...)                                IM_FMTARGS(1
//    IMGUI_API void          BulletTextV(const char* fmt, va_list args)                      IM_FMTLIST(1);
// Unsupported arg type  va_list args)                      IM_FMTLIST(1
//    IMGUI_API bool          Button(const char* label, const ImVec2& size = ImVec2 0  0);   // button
IMGUI_FUNCTION(Button)
LABEL_ARG(label)
OPTIONAL_IM_VEC_2_ARG(size, 0, 0)
CALL_FUNCTION(Button, bool, label, size)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          SmallButton(const char* label);                                 // button with FramePadding=(0,0) to easily embed within text
IMGUI_FUNCTION(SmallButton)
LABEL_ARG(label)
CALL_FUNCTION(SmallButton, bool, label)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          InvisibleButton(const char* str_id, const ImVec2& size, ImGuiButtonFlags flags = 0); // flexible button behavior without the visuals, frequently useful to build custom behaviors using the public api (along with IsItemActive, IsItemHovered, etc.)
IMGUI_FUNCTION(InvisibleButton)
LABEL_ARG(str_id)
IM_VEC_2_ARG(size)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(InvisibleButton, bool, str_id, size, flags)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          ArrowButton(const char* str_id, ImGuiDir dir);                  // square button with an arrow shape
IMGUI_FUNCTION(ArrowButton)
LABEL_ARG(str_id)
INT_ARG(dir)
CALL_FUNCTION(ArrowButton, bool, str_id, dir)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          Checkbox(const char* label, bool* v);
IMGUI_FUNCTION(Checkbox)
LABEL_ARG(label)
BOOL_POINTER_ARG(v)
CALL_FUNCTION(Checkbox, bool, label, v)
PUSH_BOOL(ret)
END_BOOL_POINTER(v)
END_IMGUI_FUNC
//    IMGUI_API bool          CheckboxFlags(const char* label, int* flags, int flags_value);
IMGUI_FUNCTION(CheckboxFlags)
LABEL_ARG(label)
INT_POINTER_ARG(flags)
INT_ARG(flags_value)
CALL_FUNCTION(CheckboxFlags, bool, label, flags, flags_value)
PUSH_BOOL(ret)
END_INT_POINTER(flags)
END_IMGUI_FUNC
//    IMGUI_API bool          CheckboxFlags(const char* label, unsigned int* flags, unsigned int flags_value);
IMGUI_FUNCTION(CheckboxFlags_3)
LABEL_ARG(label)
UINT_POINTER_ARG(flags)
UINT_ARG(flags_value)
CALL_FUNCTION(CheckboxFlags, bool, label, flags, flags_value)
PUSH_BOOL(ret)
END_UINT_POINTER(flags)
END_IMGUI_FUNC
//    IMGUI_API bool          RadioButton(const char* label, bool active);                    // use with e.g. if (RadioButton("one", my_value==1)) { my_value = 1; }
IMGUI_FUNCTION(RadioButton)
LABEL_ARG(label)
BOOL_ARG(active)
CALL_FUNCTION(RadioButton, bool, label, active)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          RadioButton(const char* label, int* v, int v_button);           // shortcut to handle the above pattern when value is an integer
IMGUI_FUNCTION(RadioButton_3)
LABEL_ARG(label)
INT_POINTER_ARG(v)
INT_ARG(v_button)
CALL_FUNCTION(RadioButton, bool, label, v, v_button)
PUSH_BOOL(ret)
END_INT_POINTER(v)
END_IMGUI_FUNC
//    IMGUI_API void          ProgressBar(float fraction, const ImVec2& size_arg = ImVec2 -FLT_MIN  0, const char* overlay = NULL);
IMGUI_FUNCTION(ProgressBar)
NUMBER_ARG(fraction)
OPTIONAL_IM_VEC_2_ARG(size_arg, -FLT_MIN, 0)
OPTIONAL_LABEL_ARG(overlay)
CALL_FUNCTION_NO_RET(ProgressBar, fraction, size_arg, overlay)
END_IMGUI_FUNC
//    IMGUI_API void          Bullet();                                                       // draw a small circle + keep the cursor on the same line. advance cursor x position by GetTreeNodeToLabelSpacing(), same distance that TreeNode() uses
IMGUI_FUNCTION(Bullet)
CALL_FUNCTION_NO_RET(Bullet)
END_IMGUI_FUNC
//    IMGUI_API void          Image(ImTextureID user_texture_id, const ImVec2& size, const ImVec2& uv0 = ImVec2 0  0, const ImVec2& uv1 = ImVec2 1  1, const ImVec4& tint_col = ImVec4 1  1  1  1, const ImVec4& border_col = ImVec4 0  0  0  0);
IMGUI_FUNCTION(Image)
IM_TEXTURE_ID_ARG(user_texture_id)
IM_VEC_2_ARG(size)
OPTIONAL_IM_VEC_2_ARG(uv0, 0, 0)
OPTIONAL_IM_VEC_2_ARG(uv1, 1, 1)
OPTIONAL_IM_VEC_4_ARG(tint_col, 1, 1, 1, 1)
OPTIONAL_IM_VEC_4_ARG(border_col, 0, 0, 0, 0)
CALL_FUNCTION_NO_RET(Image, user_texture_id, size, uv0, uv1, tint_col, border_col)
END_IMGUI_FUNC
//    IMGUI_API bool          ImageButton(const char* str_id, ImTextureID user_texture_id, const ImVec2& size, const ImVec2& uv0 = ImVec2 0  0, const ImVec2& uv1 = ImVec2 1  1, const ImVec4& bg_col = ImVec4 0  0  0  0, const ImVec4& tint_col = ImVec4 1  1  1  1);
IMGUI_FUNCTION(ImageButton)
LABEL_ARG(str_id)
IM_TEXTURE_ID_ARG(user_texture_id)
IM_VEC_2_ARG(size)
OPTIONAL_IM_VEC_2_ARG(uv0, 0, 0)
OPTIONAL_IM_VEC_2_ARG(uv1, 1, 1)
OPTIONAL_IM_VEC_4_ARG(bg_col, 0, 0, 0, 0)
OPTIONAL_IM_VEC_4_ARG(tint_col, 1, 1, 1, 1)
CALL_FUNCTION(ImageButton, bool, str_id, user_texture_id, size, uv0, uv1, bg_col, tint_col)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginCombo(const char* label, const char* preview_value, ImGuiComboFlags flags = 0);
IMGUI_FUNCTION(BeginCombo)
LABEL_ARG(label)
LABEL_ARG(preview_value)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(BeginCombo, bool, label, preview_value, flags)
IF_RET_ADD_END_STACK(5)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          EndCombo(); // only call EndCombo() if BeginCombo() returns true!
IMGUI_FUNCTION(EndCombo)
CALL_FUNCTION_NO_RET(EndCombo)
POP_END_STACK(5)
END_IMGUI_FUNC
//    IMGUI_API bool          Combo(const char* label, int* current_item, const char* const items[], int items_count, int popup_max_height_in_items = -1);
// Unsupported arg type  const char* const items[]
//    IMGUI_API bool          Combo(const char* label, int* current_item, const char* items_separated_by_zeros, int popup_max_height_in_items = -1);      // Separate items with \0 within a string, end item-list with \0\0. e.g. "One\0Two\0Three\0"
IMGUI_FUNCTION(Combo)
LABEL_ARG(label)
INT_POINTER_ARG(current_item)
LABEL_ARG(items_separated_by_zeros)
OPTIONAL_INT_ARG(popup_max_height_in_items, -1)
CALL_FUNCTION(Combo, bool, label, current_item, items_separated_by_zeros, popup_max_height_in_items)
PUSH_BOOL(ret)
END_INT_POINTER(current_item)
END_IMGUI_FUNC
//    IMGUI_API bool          Combo(const char* label, int* current_item, bool(*items_getter)(void* data, int idx, const char** out_text), void* data, int items_count, int popup_max_height_in_items = -1);
// Unsupported arg type  bool(*items_getter)(void* data
// Unsupported arg type  const char** out_text)
// Unsupported arg type  void* data
//    IMGUI_API bool          DragFloat(const char* label, float* v, float v_speed = 1.0f, float v_min = 0.0f, float v_max = 0.0f, const char* format = "%.3f", ImGuiSliderFlags flags = 0);     // If v_min >= v_max we have no bound
IMGUI_FUNCTION(DragFloat)
LABEL_ARG(label)
FLOAT_POINTER_ARG(v)
OPTIONAL_NUMBER_ARG(v_speed, 1.0f)
OPTIONAL_NUMBER_ARG(v_min, 0.0f)
OPTIONAL_NUMBER_ARG(v_max, 0.0f)
LABEL_ARG(format)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(DragFloat, bool, label, v, v_speed, v_min, v_max, format, flags)
PUSH_BOOL(ret)
END_FLOAT_POINTER(v)
END_IMGUI_FUNC
//    IMGUI_API bool          DragFloat2(const char* label, float v[2], float v_speed = 1.0f, float v_min = 0.0f, float v_max = 0.0f, const char* format = "%.3f", ImGuiSliderFlags flags = 0);
// Unsupported arg type  float v[2]
//    IMGUI_API bool          DragFloat3(const char* label, float v[3], float v_speed = 1.0f, float v_min = 0.0f, float v_max = 0.0f, const char* format = "%.3f", ImGuiSliderFlags flags = 0);
// Unsupported arg type  float v[3]
//    IMGUI_API bool          DragFloat4(const char* label, float v[4], float v_speed = 1.0f, float v_min = 0.0f, float v_max = 0.0f, const char* format = "%.3f", ImGuiSliderFlags flags = 0);
// Unsupported arg type  float v[4]
//    IMGUI_API bool          DragFloatRange2(const char* label, float* v_current_min, float* v_current_max, float v_speed = 1.0f, float v_min = 0.0f, float v_max = 0.0f, const char* format = "%.3f", const char* format_max = NULL, ImGuiSliderFlags flags = 0);
IMGUI_FUNCTION(DragFloatRange2)
LABEL_ARG(label)
FLOAT_POINTER_ARG(v_current_min)
FLOAT_POINTER_ARG(v_current_max)
OPTIONAL_NUMBER_ARG(v_speed, 1.0f)
OPTIONAL_NUMBER_ARG(v_min, 0.0f)
OPTIONAL_NUMBER_ARG(v_max, 0.0f)
LABEL_ARG(format)
OPTIONAL_LABEL_ARG(format_max)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(DragFloatRange2, bool, label, v_current_min, v_current_max, v_speed, v_min, v_max, format, format_max, flags)
PUSH_BOOL(ret)
END_FLOAT_POINTER(v_current_min)
END_FLOAT_POINTER(v_current_max)
END_IMGUI_FUNC
//    IMGUI_API bool          DragInt(const char* label, int* v, float v_speed = 1.0f, int v_min = 0, int v_max = 0, const char* format = "%d", ImGuiSliderFlags flags = 0);  // If v_min >= v_max we have no bound
IMGUI_FUNCTION(DragInt)
LABEL_ARG(label)
INT_POINTER_ARG(v)
OPTIONAL_NUMBER_ARG(v_speed, 1.0f)
OPTIONAL_INT_ARG(v_min, 0)
OPTIONAL_INT_ARG(v_max, 0)
LABEL_ARG(format)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(DragInt, bool, label, v, v_speed, v_min, v_max, format, flags)
PUSH_BOOL(ret)
END_INT_POINTER(v)
END_IMGUI_FUNC
//    IMGUI_API bool          DragInt2(const char* label, int v[2], float v_speed = 1.0f, int v_min = 0, int v_max = 0, const char* format = "%d", ImGuiSliderFlags flags = 0);
// Unsupported arg type  int v[2]
//    IMGUI_API bool          DragInt3(const char* label, int v[3], float v_speed = 1.0f, int v_min = 0, int v_max = 0, const char* format = "%d", ImGuiSliderFlags flags = 0);
// Unsupported arg type  int v[3]
//    IMGUI_API bool          DragInt4(const char* label, int v[4], float v_speed = 1.0f, int v_min = 0, int v_max = 0, const char* format = "%d", ImGuiSliderFlags flags = 0);
// Unsupported arg type  int v[4]
//    IMGUI_API bool          DragIntRange2(const char* label, int* v_current_min, int* v_current_max, float v_speed = 1.0f, int v_min = 0, int v_max = 0, const char* format = "%d", const char* format_max = NULL, ImGuiSliderFlags flags = 0);
IMGUI_FUNCTION(DragIntRange2)
LABEL_ARG(label)
INT_POINTER_ARG(v_current_min)
INT_POINTER_ARG(v_current_max)
OPTIONAL_NUMBER_ARG(v_speed, 1.0f)
OPTIONAL_INT_ARG(v_min, 0)
OPTIONAL_INT_ARG(v_max, 0)
LABEL_ARG(format)
OPTIONAL_LABEL_ARG(format_max)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(DragIntRange2, bool, label, v_current_min, v_current_max, v_speed, v_min, v_max, format, format_max, flags)
PUSH_BOOL(ret)
END_INT_POINTER(v_current_min)
END_INT_POINTER(v_current_max)
END_IMGUI_FUNC
//    IMGUI_API bool          DragScalar(const char* label, ImGuiDataType data_type, void* p_data, float v_speed = 1.0f, const void* p_min = NULL, const void* p_max = NULL, const char* format = NULL, ImGuiSliderFlags flags = 0);
// Unsupported arg type  void* p_data
// Unsupported arg type  const void* p_min = NULL
// Unsupported arg type  const void* p_max = NULL
//    IMGUI_API bool          DragScalarN(const char* label, ImGuiDataType data_type, void* p_data, int components, float v_speed = 1.0f, const void* p_min = NULL, const void* p_max = NULL, const char* format = NULL, ImGuiSliderFlags flags = 0);
// Unsupported arg type  void* p_data
// Unsupported arg type  const void* p_min = NULL
// Unsupported arg type  const void* p_max = NULL
//    IMGUI_API bool          SliderFloat(const char* label, float* v, float v_min, float v_max, const char* format = "%.3f", ImGuiSliderFlags flags = 0);     // adjust format to decorate the value with a prefix or a suffix for in-slider labels or unit display.
IMGUI_FUNCTION(SliderFloat)
LABEL_ARG(label)
FLOAT_POINTER_ARG(v)
NUMBER_ARG(v_min)
NUMBER_ARG(v_max)
LABEL_ARG(format)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(SliderFloat, bool, label, v, v_min, v_max, format, flags)
PUSH_BOOL(ret)
END_FLOAT_POINTER(v)
END_IMGUI_FUNC
//    IMGUI_API bool          SliderFloat2(const char* label, float v[2], float v_min, float v_max, const char* format = "%.3f", ImGuiSliderFlags flags = 0);
// Unsupported arg type  float v[2]
//    IMGUI_API bool          SliderFloat3(const char* label, float v[3], float v_min, float v_max, const char* format = "%.3f", ImGuiSliderFlags flags = 0);
// Unsupported arg type  float v[3]
//    IMGUI_API bool          SliderFloat4(const char* label, float v[4], float v_min, float v_max, const char* format = "%.3f", ImGuiSliderFlags flags = 0);
// Unsupported arg type  float v[4]
//    IMGUI_API bool          SliderAngle(const char* label, float* v_rad, float v_degrees_min = -360.0f, float v_degrees_max = +360.0f, const char* format = "%.0f deg", ImGuiSliderFlags flags = 0);
IMGUI_FUNCTION(SliderAngle)
LABEL_ARG(label)
FLOAT_POINTER_ARG(v_rad)
OPTIONAL_NUMBER_ARG(v_degrees_min, -360.0f)
OPTIONAL_NUMBER_ARG(v_degrees_max, +360.0f)
LABEL_ARG(format)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(SliderAngle, bool, label, v_rad, v_degrees_min, v_degrees_max, format, flags)
PUSH_BOOL(ret)
END_FLOAT_POINTER(v_rad)
END_IMGUI_FUNC
//    IMGUI_API bool          SliderInt(const char* label, int* v, int v_min, int v_max, const char* format = "%d", ImGuiSliderFlags flags = 0);
IMGUI_FUNCTION(SliderInt)
LABEL_ARG(label)
INT_POINTER_ARG(v)
INT_ARG(v_min)
INT_ARG(v_max)
LABEL_ARG(format)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(SliderInt, bool, label, v, v_min, v_max, format, flags)
PUSH_BOOL(ret)
END_INT_POINTER(v)
END_IMGUI_FUNC
//    IMGUI_API bool          SliderInt2(const char* label, int v[2], int v_min, int v_max, const char* format = "%d", ImGuiSliderFlags flags = 0);
// Unsupported arg type  int v[2]
//    IMGUI_API bool          SliderInt3(const char* label, int v[3], int v_min, int v_max, const char* format = "%d", ImGuiSliderFlags flags = 0);
// Unsupported arg type  int v[3]
//    IMGUI_API bool          SliderInt4(const char* label, int v[4], int v_min, int v_max, const char* format = "%d", ImGuiSliderFlags flags = 0);
// Unsupported arg type  int v[4]
//    IMGUI_API bool          SliderScalar(const char* label, ImGuiDataType data_type, void* p_data, const void* p_min, const void* p_max, const char* format = NULL, ImGuiSliderFlags flags = 0);
// Unsupported arg type  void* p_data
// Unsupported arg type  const void* p_min
// Unsupported arg type  const void* p_max
//    IMGUI_API bool          SliderScalarN(const char* label, ImGuiDataType data_type, void* p_data, int components, const void* p_min, const void* p_max, const char* format = NULL, ImGuiSliderFlags flags = 0);
// Unsupported arg type  void* p_data
// Unsupported arg type  const void* p_min
// Unsupported arg type  const void* p_max
//    IMGUI_API bool          VSliderFloat(const char* label, const ImVec2& size, float* v, float v_min, float v_max, const char* format = "%.3f", ImGuiSliderFlags flags = 0);
IMGUI_FUNCTION(VSliderFloat)
LABEL_ARG(label)
IM_VEC_2_ARG(size)
FLOAT_POINTER_ARG(v)
NUMBER_ARG(v_min)
NUMBER_ARG(v_max)
LABEL_ARG(format)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(VSliderFloat, bool, label, size, v, v_min, v_max, format, flags)
PUSH_BOOL(ret)
END_FLOAT_POINTER(v)
END_IMGUI_FUNC
//    IMGUI_API bool          VSliderInt(const char* label, const ImVec2& size, int* v, int v_min, int v_max, const char* format = "%d", ImGuiSliderFlags flags = 0);
IMGUI_FUNCTION(VSliderInt)
LABEL_ARG(label)
IM_VEC_2_ARG(size)
INT_POINTER_ARG(v)
INT_ARG(v_min)
INT_ARG(v_max)
LABEL_ARG(format)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(VSliderInt, bool, label, size, v, v_min, v_max, format, flags)
PUSH_BOOL(ret)
END_INT_POINTER(v)
END_IMGUI_FUNC
//    IMGUI_API bool          VSliderScalar(const char* label, const ImVec2& size, ImGuiDataType data_type, void* p_data, const void* p_min, const void* p_max, const char* format = NULL, ImGuiSliderFlags flags = 0);
// Unsupported arg type  void* p_data
// Unsupported arg type  const void* p_min
// Unsupported arg type  const void* p_max
//    IMGUI_API bool          InputText(const char* label, char* buf, size_t buf_size, ImGuiInputTextFlags flags = 0, ImGuiInputTextCallback callback = NULL, void* user_data = NULL);
// Unsupported arg type  char* buf
// Unsupported arg type  size_t buf_size
// Unsupported arg type  ImGuiInputTextCallback callback = NULL
// Unsupported arg type  void* user_data = NULL
//    IMGUI_API bool          InputTextMultiline(const char* label, char* buf, size_t buf_size, const ImVec2& size = ImVec2 0  0, ImGuiInputTextFlags flags = 0, ImGuiInputTextCallback callback = NULL, void* user_data = NULL);
// Unsupported arg type  char* buf
// Unsupported arg type  size_t buf_size
// Unsupported arg type  ImGuiInputTextCallback callback = NULL
// Unsupported arg type  void* user_data = NULL
//    IMGUI_API bool          InputTextWithHint(const char* label, const char* hint, char* buf, size_t buf_size, ImGuiInputTextFlags flags = 0, ImGuiInputTextCallback callback = NULL, void* user_data = NULL);
// Unsupported arg type  char* buf
// Unsupported arg type  size_t buf_size
// Unsupported arg type  ImGuiInputTextCallback callback = NULL
// Unsupported arg type  void* user_data = NULL
//    IMGUI_API bool          InputFloat(const char* label, float* v, float step = 0.0f, float step_fast = 0.0f, const char* format = "%.3f", ImGuiInputTextFlags flags = 0);
IMGUI_FUNCTION(InputFloat)
LABEL_ARG(label)
FLOAT_POINTER_ARG(v)
OPTIONAL_NUMBER_ARG(step, 0.0f)
OPTIONAL_NUMBER_ARG(step_fast, 0.0f)
LABEL_ARG(format)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(InputFloat, bool, label, v, step, step_fast, format, flags)
PUSH_BOOL(ret)
END_FLOAT_POINTER(v)
END_IMGUI_FUNC
//    IMGUI_API bool          InputFloat2(const char* label, float v[2], const char* format = "%.3f", ImGuiInputTextFlags flags = 0);
// Unsupported arg type  float v[2]
//    IMGUI_API bool          InputFloat3(const char* label, float v[3], const char* format = "%.3f", ImGuiInputTextFlags flags = 0);
// Unsupported arg type  float v[3]
//    IMGUI_API bool          InputFloat4(const char* label, float v[4], const char* format = "%.3f", ImGuiInputTextFlags flags = 0);
// Unsupported arg type  float v[4]
//    IMGUI_API bool          InputInt(const char* label, int* v, int step = 1, int step_fast = 100, ImGuiInputTextFlags flags = 0);
IMGUI_FUNCTION(InputInt)
LABEL_ARG(label)
INT_POINTER_ARG(v)
OPTIONAL_INT_ARG(step, 1)
OPTIONAL_INT_ARG(step_fast, 100)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(InputInt, bool, label, v, step, step_fast, flags)
PUSH_BOOL(ret)
END_INT_POINTER(v)
END_IMGUI_FUNC
//    IMGUI_API bool          InputInt2(const char* label, int v[2], ImGuiInputTextFlags flags = 0);
// Unsupported arg type  int v[2]
//    IMGUI_API bool          InputInt3(const char* label, int v[3], ImGuiInputTextFlags flags = 0);
// Unsupported arg type  int v[3]
//    IMGUI_API bool          InputInt4(const char* label, int v[4], ImGuiInputTextFlags flags = 0);
// Unsupported arg type  int v[4]
//    IMGUI_API bool          InputDouble(const char* label, double* v, double step = 0.0, double step_fast = 0.0, const char* format = "%.6f", ImGuiInputTextFlags flags = 0);
// Unsupported arg type  double* v
// Unsupported arg type  double step = 0.0
// Unsupported arg type  double step_fast = 0.0
//    IMGUI_API bool          InputScalar(const char* label, ImGuiDataType data_type, void* p_data, const void* p_step = NULL, const void* p_step_fast = NULL, const char* format = NULL, ImGuiInputTextFlags flags = 0);
// Unsupported arg type  void* p_data
// Unsupported arg type  const void* p_step = NULL
// Unsupported arg type  const void* p_step_fast = NULL
//    IMGUI_API bool          InputScalarN(const char* label, ImGuiDataType data_type, void* p_data, int components, const void* p_step = NULL, const void* p_step_fast = NULL, const char* format = NULL, ImGuiInputTextFlags flags = 0);
// Unsupported arg type  void* p_data
// Unsupported arg type  const void* p_step = NULL
// Unsupported arg type  const void* p_step_fast = NULL
//    IMGUI_API bool          ColorEdit3(const char* label, float col[3], ImGuiColorEditFlags flags = 0);
// Unsupported arg type  float col[3]
//    IMGUI_API bool          ColorEdit4(const char* label, float col[4], ImGuiColorEditFlags flags = 0);
// Unsupported arg type  float col[4]
//    IMGUI_API bool          ColorPicker3(const char* label, float col[3], ImGuiColorEditFlags flags = 0);
// Unsupported arg type  float col[3]
//    IMGUI_API bool          ColorPicker4(const char* label, float col[4], ImGuiColorEditFlags flags = 0, const float* ref_col = NULL);
// Unsupported arg type  float col[4]
// Unsupported arg type  const float* ref_col = NULL
//    IMGUI_API bool          ColorButton(const char* desc_id, const ImVec4& col, ImGuiColorEditFlags flags = 0, const ImVec2& size = ImVec2 0  0); // display a color square/button, hover for details, return true when pressed.
IMGUI_FUNCTION(ColorButton)
LABEL_ARG(desc_id)
IM_VEC_4_ARG(col)
OPTIONAL_INT_ARG(flags, 0)
OPTIONAL_IM_VEC_2_ARG(size, 0, 0)
CALL_FUNCTION(ColorButton, bool, desc_id, col, flags, size)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          SetColorEditOptions(ImGuiColorEditFlags flags);                     // initialize current options (generally on application startup) if you want to select a default format, picker type, etc. User will be able to change many settings, unless you pass the _NoOptions flag to your calls.
IMGUI_FUNCTION(SetColorEditOptions)
INT_ARG(flags)
CALL_FUNCTION_NO_RET(SetColorEditOptions, flags)
END_IMGUI_FUNC
//    IMGUI_API bool          TreeNode(const char* label);
IMGUI_FUNCTION(TreeNode)
LABEL_ARG(label)
CALL_FUNCTION(TreeNode, bool, label)
IF_RET_ADD_END_STACK(6)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          TreeNode(const char* str_id, const char* fmt, ...) IM_FMTARGS(2);   // helper variation to easily decorelate the id from the displayed string. Read the FAQ about why and how to use ID. to align arbitrary text at the same level as a TreeNode() you can use Bullet().
// Unsupported arg type  ...) IM_FMTARGS(2
//    IMGUI_API bool          TreeNode(const void* ptr_id, const char* fmt, ...) IM_FMTARGS(2);   // "
// Unsupported arg type const void* ptr_id
// Unsupported arg type  ...) IM_FMTARGS(2
//    IMGUI_API bool          TreeNodeV(const char* str_id, const char* fmt, va_list args) IM_FMTLIST(2);
// Unsupported arg type  va_list args) IM_FMTLIST(2
//    IMGUI_API bool          TreeNodeV(const void* ptr_id, const char* fmt, va_list args) IM_FMTLIST(2);
// Unsupported arg type const void* ptr_id
// Unsupported arg type  va_list args) IM_FMTLIST(2
//    IMGUI_API bool          TreeNodeEx(const char* label, ImGuiTreeNodeFlags flags = 0);
IMGUI_FUNCTION(TreeNodeEx)
LABEL_ARG(label)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(TreeNodeEx, bool, label, flags)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          TreeNodeEx(const char* str_id, ImGuiTreeNodeFlags flags, const char* fmt, ...) IM_FMTARGS(3);
// Unsupported arg type  ...) IM_FMTARGS(3
//    IMGUI_API bool          TreeNodeEx(const void* ptr_id, ImGuiTreeNodeFlags flags, const char* fmt, ...) IM_FMTARGS(3);
// Unsupported arg type const void* ptr_id
// Unsupported arg type  ...) IM_FMTARGS(3
//    IMGUI_API bool          TreeNodeExV(const char* str_id, ImGuiTreeNodeFlags flags, const char* fmt, va_list args) IM_FMTLIST(3);
// Unsupported arg type  va_list args) IM_FMTLIST(3
//    IMGUI_API bool          TreeNodeExV(const void* ptr_id, ImGuiTreeNodeFlags flags, const char* fmt, va_list args) IM_FMTLIST(3);
// Unsupported arg type const void* ptr_id
// Unsupported arg type  va_list args) IM_FMTLIST(3
//    IMGUI_API void          TreePush(const char* str_id);                                       // ~ Indent()+PushId(). Already called by TreeNode() when returning true, but you can call TreePush/TreePop yourself if desired.
IMGUI_FUNCTION(TreePush)
LABEL_ARG(str_id)
CALL_FUNCTION_NO_RET(TreePush, str_id)
ADD_END_STACK(6)
END_IMGUI_FUNC
//    IMGUI_API void          TreePush(const void* ptr_id);                                       // "
// Unsupported arg type const void* ptr_id
//    IMGUI_API void          TreePop();                                                          // ~ Unindent()+PopId()
IMGUI_FUNCTION(TreePop)
CALL_FUNCTION_NO_RET(TreePop)
POP_END_STACK(6)
END_IMGUI_FUNC
//    IMGUI_API float         GetTreeNodeToLabelSpacing();                                        // horizontal distance preceding label when using TreeNode*() or Bullet() == (g.FontSize + style.FramePadding.x*2) for a regular unframed TreeNode
IMGUI_FUNCTION(GetTreeNodeToLabelSpacing)
CALL_FUNCTION(GetTreeNodeToLabelSpacing, float)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          CollapsingHeader(const char* label, ImGuiTreeNodeFlags flags = 0);  // if returning 'true' the header is open. doesn't indent nor push on ID stack. user doesn't have to call TreePop().
IMGUI_FUNCTION(CollapsingHeader)
LABEL_ARG(label)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(CollapsingHeader, bool, label, flags)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          CollapsingHeader(const char* label, bool* p_visible, ImGuiTreeNodeFlags flags = 0); // when 'p_visible != NULL': if '*p_visible==true' display an additional small close button on upper right of the header which will set the bool to false when clicked, if '*p_visible==false' don't display the header.
IMGUI_FUNCTION(CollapsingHeader_3)
LABEL_ARG(label)
BOOL_POINTER_ARG(p_visible)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(CollapsingHeader, bool, label, p_visible, flags)
PUSH_BOOL(ret)
END_BOOL_POINTER(p_visible)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextItemOpen(bool is_open, ImGuiCond cond = 0);                  // set next TreeNode/CollapsingHeader open state.
IMGUI_FUNCTION(SetNextItemOpen)
BOOL_ARG(is_open)
OPTIONAL_INT_ARG(cond, 0)
CALL_FUNCTION_NO_RET(SetNextItemOpen, is_open, cond)
END_IMGUI_FUNC
//    IMGUI_API bool          Selectable(const char* label, bool selected = false, ImGuiSelectableFlags flags = 0, const ImVec2& size = ImVec2 0  0); // "bool selected" carry the selection state (read-only). Selectable() is clicked is returns true so you can modify your selection state. size.x==0.0: use remaining width, size.x>0.0: specify width. size.y==0.0: use label height, size.y>0.0: specify height
IMGUI_FUNCTION(Selectable)
LABEL_ARG(label)
OPTIONAL_BOOL_ARG(selected, false)
OPTIONAL_INT_ARG(flags, 0)
OPTIONAL_IM_VEC_2_ARG(size, 0, 0)
CALL_FUNCTION(Selectable, bool, label, selected, flags, size)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          Selectable(const char* label, bool* p_selected, ImGuiSelectableFlags flags = 0, const ImVec2& size = ImVec2 0  0);      // "bool* p_selected" point to the selection state (read-write), as a convenient helper.
IMGUI_FUNCTION(Selectable_4)
LABEL_ARG(label)
BOOL_POINTER_ARG(p_selected)
OPTIONAL_INT_ARG(flags, 0)
OPTIONAL_IM_VEC_2_ARG(size, 0, 0)
CALL_FUNCTION(Selectable, bool, label, p_selected, flags, size)
PUSH_BOOL(ret)
END_BOOL_POINTER(p_selected)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginListBox(const char* label, const ImVec2& size = ImVec2 0  0); // open a framed scrolling region
IMGUI_FUNCTION(BeginListBox)
LABEL_ARG(label)
OPTIONAL_IM_VEC_2_ARG(size, 0, 0)
CALL_FUNCTION(BeginListBox, bool, label, size)
IF_RET_ADD_END_STACK(7)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          EndListBox();                                                       // only call EndListBox() if BeginListBox() returned true!
IMGUI_FUNCTION(EndListBox)
CALL_FUNCTION_NO_RET(EndListBox)
POP_END_STACK(7)
END_IMGUI_FUNC
//    IMGUI_API bool          ListBox(const char* label, int* current_item, const char* const items[], int items_count, int height_in_items = -1);
// Unsupported arg type  const char* const items[]
//    IMGUI_API bool          ListBox(const char* label, int* current_item, bool (*items_getter)(void* data, int idx, const char** out_text), void* data, int items_count, int height_in_items = -1);
// Unsupported arg type  bool (*items_getter)(void* data
// Unsupported arg type  const char** out_text)
// Unsupported arg type  void* data
//    IMGUI_API void          PlotLines(const char* label, const float* values, int values_count, int values_offset = 0, const char* overlay_text = NULL, float scale_min = FLT_MAX, float scale_max = FLT_MAX, ImVec2 graph_size = ImVec2 0  0, int stride = sizeof(float));
// Unsupported arg type  const float* values
// Unsupported arg type  ImVec2 graph_size = ImVec2 0  0
//    IMGUI_API void          PlotLines(const char* label, float(*values_getter)(void* data, int idx), void* data, int values_count, int values_offset = 0, const char* overlay_text = NULL, float scale_min = FLT_MAX, float scale_max = FLT_MAX, ImVec2 graph_size = ImVec2 0  0);
// Unsupported arg type  float(*values_getter)(void* data
// Unsupported arg type  void* data
// Unsupported arg type  ImVec2 graph_size = ImVec2 0  0
//    IMGUI_API void          PlotHistogram(const char* label, const float* values, int values_count, int values_offset = 0, const char* overlay_text = NULL, float scale_min = FLT_MAX, float scale_max = FLT_MAX, ImVec2 graph_size = ImVec2 0  0, int stride = sizeof(float));
// Unsupported arg type  const float* values
// Unsupported arg type  ImVec2 graph_size = ImVec2 0  0
//    IMGUI_API void          PlotHistogram(const char* label, float(*values_getter)(void* data, int idx), void* data, int values_count, int values_offset = 0, const char* overlay_text = NULL, float scale_min = FLT_MAX, float scale_max = FLT_MAX, ImVec2 graph_size = ImVec2 0  0);
// Unsupported arg type  float(*values_getter)(void* data
// Unsupported arg type  void* data
// Unsupported arg type  ImVec2 graph_size = ImVec2 0  0
//    IMGUI_API void          Value(const char* prefix, bool b);
IMGUI_FUNCTION(Value)
LABEL_ARG(prefix)
BOOL_ARG(b)
CALL_FUNCTION_NO_RET(Value, prefix, b)
END_IMGUI_FUNC
//    IMGUI_API void          Value(const char* prefix, int v);
IMGUI_FUNCTION(Value_2)
LABEL_ARG(prefix)
INT_ARG(v)
CALL_FUNCTION_NO_RET(Value, prefix, v)
END_IMGUI_FUNC
//    IMGUI_API void          Value(const char* prefix, unsigned int v);
IMGUI_FUNCTION(Value_2_2)
LABEL_ARG(prefix)
UINT_ARG(v)
CALL_FUNCTION_NO_RET(Value, prefix, v)
END_IMGUI_FUNC
//    IMGUI_API void          Value(const char* prefix, float v, const char* float_format = NULL);
IMGUI_FUNCTION(Value_3)
LABEL_ARG(prefix)
NUMBER_ARG(v)
OPTIONAL_LABEL_ARG(float_format)
CALL_FUNCTION_NO_RET(Value, prefix, v, float_format)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginMenuBar();                                                     // append to menu-bar of current window (requires ImGuiWindowFlags_MenuBar flag set on parent window).
IMGUI_FUNCTION(BeginMenuBar)
CALL_FUNCTION(BeginMenuBar, bool)
IF_RET_ADD_END_STACK(8)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          EndMenuBar();                                                       // only call EndMenuBar() if BeginMenuBar() returns true!
IMGUI_FUNCTION(EndMenuBar)
CALL_FUNCTION_NO_RET(EndMenuBar)
POP_END_STACK(8)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginMainMenuBar();                                                 // create and append to a full screen menu-bar.
IMGUI_FUNCTION(BeginMainMenuBar)
CALL_FUNCTION(BeginMainMenuBar, bool)
IF_RET_ADD_END_STACK(9)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          EndMainMenuBar();                                                   // only call EndMainMenuBar() if BeginMainMenuBar() returns true!
IMGUI_FUNCTION(EndMainMenuBar)
CALL_FUNCTION_NO_RET(EndMainMenuBar)
POP_END_STACK(9)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginMenu(const char* label, bool enabled = true);                  // create a sub-menu entry. only call EndMenu() if this returns true!
IMGUI_FUNCTION(BeginMenu)
LABEL_ARG(label)
OPTIONAL_BOOL_ARG(enabled, true)
CALL_FUNCTION(BeginMenu, bool, label, enabled)
IF_RET_ADD_END_STACK(10)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          EndMenu();                                                          // only call EndMenu() if BeginMenu() returns true!
IMGUI_FUNCTION(EndMenu)
CALL_FUNCTION_NO_RET(EndMenu)
POP_END_STACK(10)
END_IMGUI_FUNC
//    IMGUI_API bool          MenuItem(const char* label, const char* shortcut = NULL, bool selected = false, bool enabled = true);  // return true when activated.
IMGUI_FUNCTION(MenuItem)
LABEL_ARG(label)
OPTIONAL_LABEL_ARG(shortcut)
OPTIONAL_BOOL_ARG(selected, false)
OPTIONAL_BOOL_ARG(enabled, true)
CALL_FUNCTION(MenuItem, bool, label, shortcut, selected, enabled)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          MenuItem(const char* label, const char* shortcut, bool* p_selected, bool enabled = true);              // return true when activated + toggle (*p_selected) if p_selected != NULL
IMGUI_FUNCTION(MenuItem_4)
LABEL_ARG(label)
LABEL_ARG(shortcut)
BOOL_POINTER_ARG(p_selected)
OPTIONAL_BOOL_ARG(enabled, true)
CALL_FUNCTION(MenuItem, bool, label, shortcut, p_selected, enabled)
PUSH_BOOL(ret)
END_BOOL_POINTER(p_selected)
END_IMGUI_FUNC
//    IMGUI_API void          BeginTooltip();                                                     // begin/append a tooltip window. to create full-featured tooltip (with any kind of items).
IMGUI_FUNCTION(BeginTooltip)
CALL_FUNCTION_NO_RET(BeginTooltip)
ADD_END_STACK(11)
END_IMGUI_FUNC
//    IMGUI_API void          EndTooltip();
IMGUI_FUNCTION(EndTooltip)
CALL_FUNCTION_NO_RET(EndTooltip)
POP_END_STACK(11)
END_IMGUI_FUNC
//    IMGUI_API void          SetTooltip(const char* fmt, ...) IM_FMTARGS(1);                     // set a text-only tooltip, typically use with ImGui::IsItemHovered(). override any previous call to SetTooltip().
// Unsupported arg type  ...) IM_FMTARGS(1
//    IMGUI_API void          SetTooltipV(const char* fmt, va_list args) IM_FMTLIST(1);
// Unsupported arg type  va_list args) IM_FMTLIST(1
//    IMGUI_API bool          BeginPopup(const char* str_id, ImGuiWindowFlags flags = 0);                         // return true if the popup is open, and you can start outputting to it.
IMGUI_FUNCTION(BeginPopup)
LABEL_ARG(str_id)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(BeginPopup, bool, str_id, flags)
IF_RET_ADD_END_STACK(12)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginPopupModal(const char* name, bool* p_open = NULL, ImGuiWindowFlags flags = 0); // return true if the modal is open, and you can start outputting to it.
IMGUI_FUNCTION(BeginPopupModal)
LABEL_ARG(name)
OPTIONAL_BOOL_POINTER_ARG(p_open)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(BeginPopupModal, bool, name, p_open, flags)
IF_RET_ADD_END_STACK(12)
PUSH_BOOL(ret)
END_BOOL_POINTER(p_open)
END_IMGUI_FUNC
//    IMGUI_API void          EndPopup();                                                                         // only call EndPopup() if BeginPopupXXX() returns true!
IMGUI_FUNCTION(EndPopup)
CALL_FUNCTION_NO_RET(EndPopup)
POP_END_STACK(12)
END_IMGUI_FUNC
//    IMGUI_API void          OpenPopup(const char* str_id, ImGuiPopupFlags popup_flags = 0);                     // call to mark popup as open (don't call every frame!).
IMGUI_FUNCTION(OpenPopup)
LABEL_ARG(str_id)
OPTIONAL_INT_ARG(popup_flags, 0)
CALL_FUNCTION_NO_RET(OpenPopup, str_id, popup_flags)
END_IMGUI_FUNC
//    IMGUI_API void          OpenPopup(ImGuiID id, ImGuiPopupFlags popup_flags = 0);                             // id overload to facilitate calling from nested stacks
IMGUI_FUNCTION(OpenPopup_2)
UINT_ARG(id)
OPTIONAL_INT_ARG(popup_flags, 0)
CALL_FUNCTION_NO_RET(OpenPopup, id, popup_flags)
END_IMGUI_FUNC
//    IMGUI_API void          OpenPopupOnItemClick(const char* str_id = NULL, ImGuiPopupFlags popup_flags = 1);   // helper to open popup when clicked on last item. Default to ImGuiPopupFlags_MouseButtonRight == 1. (note: actually triggers on the mouse _released_ event to be consistent with popup behaviors)
IMGUI_FUNCTION(OpenPopupOnItemClick)
OPTIONAL_LABEL_ARG(str_id)
OPTIONAL_INT_ARG(popup_flags, 1)
CALL_FUNCTION_NO_RET(OpenPopupOnItemClick, str_id, popup_flags)
END_IMGUI_FUNC
//    IMGUI_API void          CloseCurrentPopup();                                                                // manually close the popup we have begin-ed into.
IMGUI_FUNCTION(CloseCurrentPopup)
CALL_FUNCTION_NO_RET(CloseCurrentPopup)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginPopupContextItem(const char* str_id = NULL, ImGuiPopupFlags popup_flags = 1);  // open+begin popup when clicked on last item. Use str_id==NULL to associate the popup to previous item. If you want to use that on a non-interactive item such as Text() you need to pass in an explicit ID here. read comments in .cpp!
IMGUI_FUNCTION(BeginPopupContextItem)
OPTIONAL_LABEL_ARG(str_id)
OPTIONAL_INT_ARG(popup_flags, 1)
CALL_FUNCTION(BeginPopupContextItem, bool, str_id, popup_flags)
IF_RET_ADD_END_STACK(12)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginPopupContextWindow(const char* str_id = NULL, ImGuiPopupFlags popup_flags = 1);// open+begin popup when clicked on current window.
IMGUI_FUNCTION(BeginPopupContextWindow)
OPTIONAL_LABEL_ARG(str_id)
OPTIONAL_INT_ARG(popup_flags, 1)
CALL_FUNCTION(BeginPopupContextWindow, bool, str_id, popup_flags)
IF_RET_ADD_END_STACK(12)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginPopupContextVoid(const char* str_id = NULL, ImGuiPopupFlags popup_flags = 1);  // open+begin popup when clicked in void (where there are no windows).
IMGUI_FUNCTION(BeginPopupContextVoid)
OPTIONAL_LABEL_ARG(str_id)
OPTIONAL_INT_ARG(popup_flags, 1)
CALL_FUNCTION(BeginPopupContextVoid, bool, str_id, popup_flags)
IF_RET_ADD_END_STACK(12)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsPopupOpen(const char* str_id, ImGuiPopupFlags flags = 0);                         // return true if the popup is open.
IMGUI_FUNCTION(IsPopupOpen)
LABEL_ARG(str_id)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(IsPopupOpen, bool, str_id, flags)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginTable(const char* str_id, int column, ImGuiTableFlags flags = 0, const ImVec2& outer_size = ImVec2 0.0f  0.0f, float inner_width = 0.0f);
IMGUI_FUNCTION(BeginTable)
LABEL_ARG(str_id)
INT_ARG(column)
OPTIONAL_INT_ARG(flags, 0)
OPTIONAL_IM_VEC_2_ARG(outer_size, 0.0f, 0.0f)
OPTIONAL_NUMBER_ARG(inner_width, 0.0f)
CALL_FUNCTION(BeginTable, bool, str_id, column, flags, outer_size, inner_width)
IF_RET_ADD_END_STACK(13)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          EndTable();                                         // only call EndTable() if BeginTable() returns true!
IMGUI_FUNCTION(EndTable)
CALL_FUNCTION_NO_RET(EndTable)
POP_END_STACK(13)
END_IMGUI_FUNC
//    IMGUI_API void          TableNextRow(ImGuiTableRowFlags row_flags = 0, float min_row_height = 0.0f); // append into the first cell of a new row.
IMGUI_FUNCTION(TableNextRow)
OPTIONAL_INT_ARG(row_flags, 0)
OPTIONAL_NUMBER_ARG(min_row_height, 0.0f)
CALL_FUNCTION_NO_RET(TableNextRow, row_flags, min_row_height)
END_IMGUI_FUNC
//    IMGUI_API bool          TableNextColumn();                                  // append into the next column (or first column of next row if currently in last column). Return true when column is visible.
IMGUI_FUNCTION(TableNextColumn)
CALL_FUNCTION(TableNextColumn, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          TableSetColumnIndex(int column_n);                  // append into the specified column. Return true when column is visible.
IMGUI_FUNCTION(TableSetColumnIndex)
INT_ARG(column_n)
CALL_FUNCTION(TableSetColumnIndex, bool, column_n)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          TableSetupColumn(const char* label, ImGuiTableColumnFlags flags = 0, float init_width_or_weight = 0.0f, ImGuiID user_id = 0);
IMGUI_FUNCTION(TableSetupColumn)
LABEL_ARG(label)
OPTIONAL_INT_ARG(flags, 0)
OPTIONAL_NUMBER_ARG(init_width_or_weight, 0.0f)
OPTIONAL_UINT_ARG(user_id, 0)
CALL_FUNCTION_NO_RET(TableSetupColumn, label, flags, init_width_or_weight, user_id)
END_IMGUI_FUNC
//    IMGUI_API void          TableSetupScrollFreeze(int cols, int rows);         // lock columns/rows so they stay visible when scrolled.
IMGUI_FUNCTION(TableSetupScrollFreeze)
INT_ARG(cols)
INT_ARG(rows)
CALL_FUNCTION_NO_RET(TableSetupScrollFreeze, cols, rows)
END_IMGUI_FUNC
//    IMGUI_API void          TableHeadersRow();                                  // submit all headers cells based on data provided to TableSetupColumn() + submit context menu
IMGUI_FUNCTION(TableHeadersRow)
CALL_FUNCTION_NO_RET(TableHeadersRow)
END_IMGUI_FUNC
//    IMGUI_API void          TableHeader(const char* label);                     // submit one header cell manually (rarely used)
IMGUI_FUNCTION(TableHeader)
LABEL_ARG(label)
CALL_FUNCTION_NO_RET(TableHeader, label)
END_IMGUI_FUNC
//    IMGUI_API ImGuiTableSortSpecs*  TableGetSortSpecs();                        // get latest sort specs for the table (NULL if not sorting).  Lifetime: don't hold on this pointer over multiple frames or past any subsequent call to BeginTable().
// Unsupported return type ImGuiTableSortSpecs*
//    IMGUI_API int                   TableGetColumnCount();                      // return number of columns (value passed to BeginTable)
// Unsupported return type int
//    IMGUI_API int                   TableGetColumnIndex();                      // return current column index.
// Unsupported return type int
//    IMGUI_API int                   TableGetRowIndex();                         // return current row index.
// Unsupported return type int
//    IMGUI_API const char*           TableGetColumnName(int column_n = -1);      // return "" if column didn't have a name declared by TableSetupColumn(). Pass -1 to use current column.
IMGUI_FUNCTION(TableGetColumnName)
OPTIONAL_INT_ARG(column_n, -1)
CALL_FUNCTION(TableGetColumnName, const char*, column_n)
PUSH_STRING(ret)
END_IMGUI_FUNC
//    IMGUI_API ImGuiTableColumnFlags TableGetColumnFlags(int column_n = -1);     // return column flags so you can query their Enabled/Visible/Sorted/Hovered status flags. Pass -1 to use current column.
// Unsupported return type ImGuiTableColumnFlags
//    IMGUI_API void                  TableSetColumnEnabled(int column_n, bool v);// change user accessible enabled/disabled state of a column. Set to false to hide the column. User can use the context menu to change this themselves (right-click in headers, or right-click in columns body with ImGuiTableFlags_ContextMenuInBody)
IMGUI_FUNCTION(TableSetColumnEnabled)
INT_ARG(column_n)
BOOL_ARG(v)
CALL_FUNCTION_NO_RET(TableSetColumnEnabled, column_n, v)
END_IMGUI_FUNC
//    IMGUI_API void                  TableSetBgColor(ImGuiTableBgTarget target, ImU32 color, int column_n = -1);  // change the color of a cell, row, or column. See ImGuiTableBgTarget_ flags for details.
IMGUI_FUNCTION(TableSetBgColor)
INT_ARG(target)
UINT_ARG(color)
OPTIONAL_INT_ARG(column_n, -1)
CALL_FUNCTION_NO_RET(TableSetBgColor, target, color, column_n)
END_IMGUI_FUNC
//    IMGUI_API void          Columns(int count = 1, const char* id = NULL, bool border = true);
IMGUI_FUNCTION(Columns)
OPTIONAL_INT_ARG(count, 1)
OPTIONAL_LABEL_ARG(id)
OPTIONAL_BOOL_ARG(border, true)
CALL_FUNCTION_NO_RET(Columns, count, id, border)
END_IMGUI_FUNC
//    IMGUI_API void          NextColumn();                                                       // next column, defaults to current row or next row if the current row is finished
IMGUI_FUNCTION(NextColumn)
CALL_FUNCTION_NO_RET(NextColumn)
END_IMGUI_FUNC
//    IMGUI_API int           GetColumnIndex();                                                   // get current column index
// Unsupported return type int
//    IMGUI_API float         GetColumnWidth(int column_index = -1);                              // get column width (in pixels). pass -1 to use current column
IMGUI_FUNCTION(GetColumnWidth)
OPTIONAL_INT_ARG(column_index, -1)
CALL_FUNCTION(GetColumnWidth, float, column_index)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API void          SetColumnWidth(int column_index, float width);                      // set column width (in pixels). pass -1 to use current column
IMGUI_FUNCTION(SetColumnWidth)
INT_ARG(column_index)
NUMBER_ARG(width)
CALL_FUNCTION_NO_RET(SetColumnWidth, column_index, width)
END_IMGUI_FUNC
//    IMGUI_API float         GetColumnOffset(int column_index = -1);                             // get position of column line (in pixels, from the left side of the contents region). pass -1 to use current column, otherwise 0..GetColumnsCount() inclusive. column 0 is typically 0.0f
IMGUI_FUNCTION(GetColumnOffset)
OPTIONAL_INT_ARG(column_index, -1)
CALL_FUNCTION(GetColumnOffset, float, column_index)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API void          SetColumnOffset(int column_index, float offset_x);                  // set position of column line (in pixels, from the left side of the contents region). pass -1 to use current column
IMGUI_FUNCTION(SetColumnOffset)
INT_ARG(column_index)
NUMBER_ARG(offset_x)
CALL_FUNCTION_NO_RET(SetColumnOffset, column_index, offset_x)
END_IMGUI_FUNC
//    IMGUI_API int           GetColumnsCount();
// Unsupported return type int
//    IMGUI_API bool          BeginTabBar(const char* str_id, ImGuiTabBarFlags flags = 0);        // create and append into a TabBar
IMGUI_FUNCTION(BeginTabBar)
LABEL_ARG(str_id)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(BeginTabBar, bool, str_id, flags)
IF_RET_ADD_END_STACK(14)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          EndTabBar();                                                        // only call EndTabBar() if BeginTabBar() returns true!
IMGUI_FUNCTION(EndTabBar)
CALL_FUNCTION_NO_RET(EndTabBar)
POP_END_STACK(14)
END_IMGUI_FUNC
//    IMGUI_API bool          BeginTabItem(const char* label, bool* p_open = NULL, ImGuiTabItemFlags flags = 0); // create a Tab. Returns true if the Tab is selected.
IMGUI_FUNCTION(BeginTabItem)
LABEL_ARG(label)
OPTIONAL_BOOL_POINTER_ARG(p_open)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(BeginTabItem, bool, label, p_open, flags)
IF_RET_ADD_END_STACK(15)
PUSH_BOOL(ret)
END_BOOL_POINTER(p_open)
END_IMGUI_FUNC
//    IMGUI_API void          EndTabItem();                                                       // only call EndTabItem() if BeginTabItem() returns true!
IMGUI_FUNCTION(EndTabItem)
CALL_FUNCTION_NO_RET(EndTabItem)
POP_END_STACK(15)
END_IMGUI_FUNC
//    IMGUI_API bool          TabItemButton(const char* label, ImGuiTabItemFlags flags = 0);      // create a Tab behaving like a button. return true when clicked. cannot be selected in the tab bar.
IMGUI_FUNCTION(TabItemButton)
LABEL_ARG(label)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(TabItemButton, bool, label, flags)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          SetTabItemClosed(const char* tab_or_docked_window_label);           // notify TabBar or Docking system of a closed tab/window ahead (useful to reduce visual flicker on reorderable tab bars). For tab-bar: call after BeginTabBar() and before Tab submissions. Otherwise call with a window name.
IMGUI_FUNCTION(SetTabItemClosed)
LABEL_ARG(tab_or_docked_window_label)
CALL_FUNCTION_NO_RET(SetTabItemClosed, tab_or_docked_window_label)
END_IMGUI_FUNC
//    IMGUI_API ImGuiID       DockSpace(ImGuiID id, const ImVec2& size = ImVec2 0  0, ImGuiDockNodeFlags flags = 0, const ImGuiWindowClass* window_class = NULL);
// Unsupported arg type  const ImGuiWindowClass* window_class = NULL
//    IMGUI_API ImGuiID       DockSpaceOverViewport(const ImGuiViewport* viewport = NULL, ImGuiDockNodeFlags flags = 0, const ImGuiWindowClass* window_class = NULL);
// Unsupported arg type const ImGuiViewport* viewport = NULL
// Unsupported arg type  const ImGuiWindowClass* window_class = NULL
//    IMGUI_API void          SetNextWindowDockID(ImGuiID dock_id, ImGuiCond cond = 0);           // set next window dock id
IMGUI_FUNCTION(SetNextWindowDockID)
UINT_ARG(dock_id)
OPTIONAL_INT_ARG(cond, 0)
CALL_FUNCTION_NO_RET(SetNextWindowDockID, dock_id, cond)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextWindowClass(const ImGuiWindowClass* window_class);           // set next window class (control docking compatibility + provide hints to platform backend via custom viewport flags and platform parent/child relationship)
// Unsupported arg type const ImGuiWindowClass* window_class
//    IMGUI_API ImGuiID       GetWindowDockID();
IMGUI_FUNCTION(GetWindowDockID)
CALL_FUNCTION(GetWindowDockID, unsigned int)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsWindowDocked();                                                   // is current window docked into another window?
IMGUI_FUNCTION(IsWindowDocked)
CALL_FUNCTION(IsWindowDocked, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          LogToTTY(int auto_open_depth = -1);                                 // start logging to tty (stdout)
IMGUI_FUNCTION(LogToTTY)
OPTIONAL_INT_ARG(auto_open_depth, -1)
CALL_FUNCTION_NO_RET(LogToTTY, auto_open_depth)
END_IMGUI_FUNC
//    IMGUI_API void          LogToFile(int auto_open_depth = -1, const char* filename = NULL);   // start logging to file
IMGUI_FUNCTION(LogToFile)
OPTIONAL_INT_ARG(auto_open_depth, -1)
OPTIONAL_LABEL_ARG(filename)
CALL_FUNCTION_NO_RET(LogToFile, auto_open_depth, filename)
END_IMGUI_FUNC
//    IMGUI_API void          LogToClipboard(int auto_open_depth = -1);                           // start logging to OS clipboard
IMGUI_FUNCTION(LogToClipboard)
OPTIONAL_INT_ARG(auto_open_depth, -1)
CALL_FUNCTION_NO_RET(LogToClipboard, auto_open_depth)
END_IMGUI_FUNC
//    IMGUI_API void          LogFinish();                                                        // stop logging (close file, etc.)
IMGUI_FUNCTION(LogFinish)
CALL_FUNCTION_NO_RET(LogFinish)
END_IMGUI_FUNC
//    IMGUI_API void          LogButtons();                                                       // helper to display buttons for logging to tty/file/clipboard
IMGUI_FUNCTION(LogButtons)
CALL_FUNCTION_NO_RET(LogButtons)
END_IMGUI_FUNC
//    IMGUI_API void          LogText(const char* fmt, ...) IM_FMTARGS(1);                        // pass text data straight to log (without being displayed)
// Unsupported arg type  ...) IM_FMTARGS(1
//    IMGUI_API void          LogTextV(const char* fmt, va_list args) IM_FMTLIST(1);
// Unsupported arg type  va_list args) IM_FMTLIST(1
//    IMGUI_API bool          BeginDragDropSource(ImGuiDragDropFlags flags = 0);                                      // call after submitting an item which may be dragged. when this return true, you can call SetDragDropPayload() + EndDragDropSource()
IMGUI_FUNCTION(BeginDragDropSource)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(BeginDragDropSource, bool, flags)
IF_RET_ADD_END_STACK(16)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          SetDragDropPayload(const char* type, const void* data, size_t sz, ImGuiCond cond = 0);  // type is a user defined string of maximum 32 characters. Strings starting with '_' are reserved for dear imgui internal types. Data is copied and held by imgui. Return true when payload has been accepted.
// Unsupported arg type  const void* data
// Unsupported arg type  size_t sz
//    IMGUI_API void          EndDragDropSource();                                                                    // only call EndDragDropSource() if BeginDragDropSource() returns true!
IMGUI_FUNCTION(EndDragDropSource)
CALL_FUNCTION_NO_RET(EndDragDropSource)
POP_END_STACK(16)
END_IMGUI_FUNC
//    IMGUI_API bool                  BeginDragDropTarget();                                                          // call after submitting an item that may receive a payload. If this returns true, you can call AcceptDragDropPayload() + EndDragDropTarget()
IMGUI_FUNCTION(BeginDragDropTarget)
CALL_FUNCTION(BeginDragDropTarget, bool)
IF_RET_ADD_END_STACK(17)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API const ImGuiPayload*   AcceptDragDropPayload(const char* type, ImGuiDragDropFlags flags = 0);          // accept contents of a given type. If ImGuiDragDropFlags_AcceptBeforeDelivery is set you can peek into the payload before the mouse button is released.
// Unsupported return type const
//    IMGUI_API void                  EndDragDropTarget();                                                            // only call EndDragDropTarget() if BeginDragDropTarget() returns true!
IMGUI_FUNCTION(EndDragDropTarget)
CALL_FUNCTION_NO_RET(EndDragDropTarget)
POP_END_STACK(17)
END_IMGUI_FUNC
//    IMGUI_API const ImGuiPayload*   GetDragDropPayload();                                                           // peek directly into the current payload from anywhere. may return NULL. use ImGuiPayload::IsDataType() to test for the payload type.
// Unsupported return type const
//    IMGUI_API void          BeginDisabled(bool disabled = true);
IMGUI_FUNCTION(BeginDisabled)
OPTIONAL_BOOL_ARG(disabled, true)
CALL_FUNCTION_NO_RET(BeginDisabled, disabled)
ADD_END_STACK(18)
END_IMGUI_FUNC
//    IMGUI_API void          EndDisabled();
IMGUI_FUNCTION(EndDisabled)
CALL_FUNCTION_NO_RET(EndDisabled)
POP_END_STACK(18)
END_IMGUI_FUNC
//    IMGUI_API void          PushClipRect(const ImVec2& clip_rect_min, const ImVec2& clip_rect_max, bool intersect_with_current_clip_rect);
IMGUI_FUNCTION(PushClipRect)
IM_VEC_2_ARG(clip_rect_min)
IM_VEC_2_ARG(clip_rect_max)
BOOL_ARG(intersect_with_current_clip_rect)
CALL_FUNCTION_NO_RET(PushClipRect, clip_rect_min, clip_rect_max, intersect_with_current_clip_rect)
END_IMGUI_FUNC
//    IMGUI_API void          PopClipRect();
IMGUI_FUNCTION(PopClipRect)
CALL_FUNCTION_NO_RET(PopClipRect)
END_IMGUI_FUNC
//    IMGUI_API void          SetItemDefaultFocus();                                              // make last item the default focused item of a window.
IMGUI_FUNCTION(SetItemDefaultFocus)
CALL_FUNCTION_NO_RET(SetItemDefaultFocus)
END_IMGUI_FUNC
//    IMGUI_API void          SetKeyboardFocusHere(int offset = 0);                               // focus keyboard on the next widget. Use positive 'offset' to access sub components of a multiple component widget. Use -1 to access previous widget.
IMGUI_FUNCTION(SetKeyboardFocusHere)
OPTIONAL_INT_ARG(offset, 0)
CALL_FUNCTION_NO_RET(SetKeyboardFocusHere, offset)
END_IMGUI_FUNC
//    IMGUI_API bool          IsItemHovered(ImGuiHoveredFlags flags = 0);                         // is the last item hovered? (and usable, aka not blocked by a popup, etc.). See ImGuiHoveredFlags for more options.
IMGUI_FUNCTION(IsItemHovered)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(IsItemHovered, bool, flags)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsItemActive();                                                     // is the last item active? (e.g. button being held, text field being edited. This will continuously return true while holding mouse button on an item. Items that don't interact will always return false)
IMGUI_FUNCTION(IsItemActive)
CALL_FUNCTION(IsItemActive, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsItemFocused();                                                    // is the last item focused for keyboard/gamepad navigation?
IMGUI_FUNCTION(IsItemFocused)
CALL_FUNCTION(IsItemFocused, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsItemClicked(ImGuiMouseButton mouse_button = 0);                   // is the last item hovered and mouse clicked on? (**)  == IsMouseClicked(mouse_button) && IsItemHovered()Important. (**) this is NOT equivalent to the behavior of e.g. Button(). Read comments in function definition.
IMGUI_FUNCTION(IsItemClicked)
OPTIONAL_INT_ARG(mouse_button, 0)
CALL_FUNCTION(IsItemClicked, bool, mouse_button)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsItemVisible();                                                    // is the last item visible? (items may be out of sight because of clipping/scrolling)
IMGUI_FUNCTION(IsItemVisible)
CALL_FUNCTION(IsItemVisible, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsItemEdited();                                                     // did the last item modify its underlying value this frame? or was pressed? This is generally the same as the "bool" return value of many widgets.
IMGUI_FUNCTION(IsItemEdited)
CALL_FUNCTION(IsItemEdited, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsItemActivated();                                                  // was the last item just made active (item was previously inactive).
IMGUI_FUNCTION(IsItemActivated)
CALL_FUNCTION(IsItemActivated, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsItemDeactivated();                                                // was the last item just made inactive (item was previously active). Useful for Undo/Redo patterns with widgets that require continuous editing.
IMGUI_FUNCTION(IsItemDeactivated)
CALL_FUNCTION(IsItemDeactivated, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsItemDeactivatedAfterEdit();                                       // was the last item just made inactive and made a value change when it was active? (e.g. Slider/Drag moved). Useful for Undo/Redo patterns with widgets that require continuous editing. Note that you may get false positives (some widgets such as Combo()/ListBox()/Selectable() will return true even when clicking an already selected item).
IMGUI_FUNCTION(IsItemDeactivatedAfterEdit)
CALL_FUNCTION(IsItemDeactivatedAfterEdit, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsItemToggledOpen();                                                // was the last item open state toggled? set by TreeNode().
IMGUI_FUNCTION(IsItemToggledOpen)
CALL_FUNCTION(IsItemToggledOpen, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsAnyItemHovered();                                                 // is any item hovered?
IMGUI_FUNCTION(IsAnyItemHovered)
CALL_FUNCTION(IsAnyItemHovered, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsAnyItemActive();                                                  // is any item active?
IMGUI_FUNCTION(IsAnyItemActive)
CALL_FUNCTION(IsAnyItemActive, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsAnyItemFocused();                                                 // is any item focused?
IMGUI_FUNCTION(IsAnyItemFocused)
CALL_FUNCTION(IsAnyItemFocused, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetItemRectMin();                                                   // get upper-left bounding rectangle of the last item (screen space)
IMGUI_FUNCTION(GetItemRectMin)
CALL_FUNCTION(GetItemRectMin, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetItemRectMax();                                                   // get lower-right bounding rectangle of the last item (screen space)
IMGUI_FUNCTION(GetItemRectMax)
CALL_FUNCTION(GetItemRectMax, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetItemRectSize();                                                  // get size of last item
IMGUI_FUNCTION(GetItemRectSize)
CALL_FUNCTION(GetItemRectSize, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API void          SetItemAllowOverlap();                                              // allow last item to be overlapped by a subsequent item. sometimes useful with invisible buttons, selectables, etc. to catch unused area.
IMGUI_FUNCTION(SetItemAllowOverlap)
CALL_FUNCTION_NO_RET(SetItemAllowOverlap)
END_IMGUI_FUNC
//    IMGUI_API ImGuiViewport* GetMainViewport();                                                 // return primary/default viewport. This can never be NULL.
// Unsupported return type ImGuiViewport*
//    IMGUI_API ImDrawList*   GetBackgroundDrawList();                                            // get background draw list for the viewport associated to the current window. this draw list will be the first rendering one. Useful to quickly draw shapes/text behind dear imgui contents.
// Unsupported return type ImDrawList*
//    IMGUI_API ImDrawList*   GetForegroundDrawList();                                            // get foreground draw list for the viewport associated to the current window. this draw list will be the last rendered one. Useful to quickly draw shapes/text over dear imgui contents.
// Unsupported return type ImDrawList*
//    IMGUI_API ImDrawList*   GetBackgroundDrawList(ImGuiViewport* viewport);                     // get background draw list for the given viewport. this draw list will be the first rendering one. Useful to quickly draw shapes/text behind dear imgui contents.
// Unsupported return type ImDrawList*
// Unsupported arg type ImGuiViewport* viewport
//    IMGUI_API ImDrawList*   GetForegroundDrawList(ImGuiViewport* viewport);                     // get foreground draw list for the given viewport. this draw list will be the last rendered one. Useful to quickly draw shapes/text over dear imgui contents.
// Unsupported return type ImDrawList*
// Unsupported arg type ImGuiViewport* viewport
//    IMGUI_API bool          IsRectVisible(const ImVec2& size);                                  // test if rectangle (of given size, starting from cursor position) is visible / not clipped.
IMGUI_FUNCTION(IsRectVisible)
IM_VEC_2_ARG(size)
CALL_FUNCTION(IsRectVisible, bool, size)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsRectVisible(const ImVec2& rect_min, const ImVec2& rect_max);      // test if rectangle (in screen space) is visible / not clipped. to perform coarse clipping on user's side.
IMGUI_FUNCTION(IsRectVisible_2)
IM_VEC_2_ARG(rect_min)
IM_VEC_2_ARG(rect_max)
CALL_FUNCTION(IsRectVisible, bool, rect_min, rect_max)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API double        GetTime();                                                          // get global imgui time. incremented by io.DeltaTime every frame.
// Unsupported return type double
//    IMGUI_API int           GetFrameCount();                                                    // get global imgui frame count. incremented by 1 every frame.
// Unsupported return type int
//    IMGUI_API ImDrawListSharedData* GetDrawListSharedData();                                    // you may use this when creating your own ImDrawList instances.
// Unsupported return type ImDrawListSharedData*
//    IMGUI_API const char*   GetStyleColorName(ImGuiCol idx);                                    // get a string corresponding to the enum value (for display, saving, etc.).
IMGUI_FUNCTION(GetStyleColorName)
INT_ARG(idx)
CALL_FUNCTION(GetStyleColorName, const char*, idx)
PUSH_STRING(ret)
END_IMGUI_FUNC
//    IMGUI_API void          SetStateStorage(ImGuiStorage* storage);                             // replace current window storage with our own (if you want to manipulate it yourself, typically clear subsection of it)
// Unsupported arg type ImGuiStorage* storage
//    IMGUI_API ImGuiStorage* GetStateStorage();
// Unsupported return type ImGuiStorage*
//    IMGUI_API bool          BeginChildFrame(ImGuiID id, const ImVec2& size, ImGuiWindowFlags flags = 0); // helper to create a child window / scrolling region that looks like a normal widget frame
IMGUI_FUNCTION(BeginChildFrame)
UINT_ARG(id)
IM_VEC_2_ARG(size)
OPTIONAL_INT_ARG(flags, 0)
CALL_FUNCTION(BeginChildFrame, bool, id, size, flags)
IF_RET_ADD_END_STACK(19)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API void          EndChildFrame();                                                    // always call EndChildFrame() regardless of BeginChildFrame() return values (which indicates a collapsed/clipped window)
IMGUI_FUNCTION(EndChildFrame)
CALL_FUNCTION_NO_RET(EndChildFrame)
POP_END_STACK(19)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        CalcTextSize(const char* text, const char* text_end = NULL, bool hide_text_after_double_hash = false, float wrap_width = -1.0f);
IMGUI_FUNCTION(CalcTextSize)
LABEL_ARG(text)
OPTIONAL_LABEL_ARG(text_end)
OPTIONAL_BOOL_ARG(hide_text_after_double_hash, false)
OPTIONAL_NUMBER_ARG(wrap_width, -1.0f)
CALL_FUNCTION(CalcTextSize, ImVec2, text, text_end, hide_text_after_double_hash, wrap_width)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API ImVec4        ColorConvertU32ToFloat4(ImU32 in);
// Unsupported return type ImVec4
//    IMGUI_API ImU32         ColorConvertFloat4ToU32(const ImVec4& in);
IMGUI_FUNCTION(ColorConvertFloat4ToU32)
IM_VEC_4_ARG(in)
CALL_FUNCTION(ColorConvertFloat4ToU32, unsigned int, in)
PUSH_NUMBER(ret)
END_IMGUI_FUNC
//    IMGUI_API void          ColorConvertRGBtoHSV(float r, float g, float b, float& out_h, float& out_s, float& out_v);
// Unsupported arg type  float& out_h
// Unsupported arg type  float& out_s
// Unsupported arg type  float& out_v
//    IMGUI_API void          ColorConvertHSVtoRGB(float h, float s, float v, float& out_r, float& out_g, float& out_b);
// Unsupported arg type  float& out_r
// Unsupported arg type  float& out_g
// Unsupported arg type  float& out_b
//    IMGUI_API bool          IsKeyDown(ImGuiKey key);                                            // is key being held.
// Unsupported arg type ImGuiKey key
//    IMGUI_API bool          IsKeyPressed(ImGuiKey key, bool repeat = true);                     // was key pressed (went from !Down to Down)? if repeat=true, uses io.KeyRepeatDelay / KeyRepeatRate
// Unsupported arg type ImGuiKey key
//    IMGUI_API bool          IsKeyReleased(ImGuiKey key);                                        // was key released (went from Down to !Down)?
// Unsupported arg type ImGuiKey key
//    IMGUI_API int           GetKeyPressedAmount(ImGuiKey key, float repeat_delay, float rate);  // uses provided repeat rate/delay. return a count, most often 0 or 1 but might be >1 if RepeatRate is small enough that DeltaTime > RepeatRate
// Unsupported return type int
// Unsupported arg type ImGuiKey key
//    IMGUI_API const char*   GetKeyName(ImGuiKey key);                                           // [DEBUG] returns English name of the key. Those names a provided for debugging purpose and are not meant to be saved persistently not compared.
// Unsupported arg type ImGuiKey key
//    IMGUI_API void          SetNextFrameWantCaptureKeyboard(bool want_capture_keyboard);        // Override io.WantCaptureKeyboard flag next frame (said flag is left for your application to handle, typically when true it instructs your app to ignore inputs). e.g. force capture keyboard when your widget is being hovered. This is equivalent to setting "io.WantCaptureKeyboard = want_capture_keyboard"; after the next NewFrame() call.
IMGUI_FUNCTION(SetNextFrameWantCaptureKeyboard)
BOOL_ARG(want_capture_keyboard)
CALL_FUNCTION_NO_RET(SetNextFrameWantCaptureKeyboard, want_capture_keyboard)
END_IMGUI_FUNC
//    IMGUI_API bool          IsMouseDown(ImGuiMouseButton button);                               // is mouse button held?
IMGUI_FUNCTION(IsMouseDown)
INT_ARG(button)
CALL_FUNCTION(IsMouseDown, bool, button)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsMouseClicked(ImGuiMouseButton button, bool repeat = false);       // did mouse button clicked? (went from !Down to Down). Same as GetMouseClickedCount() == 1.
IMGUI_FUNCTION(IsMouseClicked)
INT_ARG(button)
OPTIONAL_BOOL_ARG(repeat, false)
CALL_FUNCTION(IsMouseClicked, bool, button, repeat)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsMouseReleased(ImGuiMouseButton button);                           // did mouse button released? (went from Down to !Down)
IMGUI_FUNCTION(IsMouseReleased)
INT_ARG(button)
CALL_FUNCTION(IsMouseReleased, bool, button)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsMouseDoubleClicked(ImGuiMouseButton button);                      // did mouse button double-clicked? Same as GetMouseClickedCount() == 2. (note that a double-click will also report IsMouseClicked() == true)
IMGUI_FUNCTION(IsMouseDoubleClicked)
INT_ARG(button)
CALL_FUNCTION(IsMouseDoubleClicked, bool, button)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API int           GetMouseClickedCount(ImGuiMouseButton button);                      // return the number of successive mouse-clicks at the time where a click happen (otherwise 0).
// Unsupported return type int
//    IMGUI_API bool          IsMouseHoveringRect(const ImVec2& r_min, const ImVec2& r_max, bool clip = true);// is mouse hovering given bounding rect (in screen space). clipped by current clipping settings, but disregarding of other consideration of focus/window ordering/popup-block.
IMGUI_FUNCTION(IsMouseHoveringRect)
IM_VEC_2_ARG(r_min)
IM_VEC_2_ARG(r_max)
OPTIONAL_BOOL_ARG(clip, true)
CALL_FUNCTION(IsMouseHoveringRect, bool, r_min, r_max, clip)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API bool          IsMousePosValid(const ImVec2* mouse_pos = NULL);                    // by convention we use (-FLT_MAX,-FLT_MAX) to denote that there is no mouse available
// Unsupported arg type const ImVec2* mouse_pos = NULL
//    IMGUI_API bool          IsAnyMouseDown();                                                   // [WILL OBSOLETE] is any mouse button held? This was designed for backends, but prefer having backend maintain a mask of held mouse buttons, because upcoming input queue system will make this invalid.
IMGUI_FUNCTION(IsAnyMouseDown)
CALL_FUNCTION(IsAnyMouseDown, bool)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetMousePos();                                                      // shortcut to ImGui::GetIO().MousePos provided by user, to be consistent with other calls
IMGUI_FUNCTION(GetMousePos)
CALL_FUNCTION(GetMousePos, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetMousePosOnOpeningCurrentPopup();                                 // retrieve mouse position at the time of opening popup we have BeginPopup() into (helper to avoid user backing that value themselves)
IMGUI_FUNCTION(GetMousePosOnOpeningCurrentPopup)
CALL_FUNCTION(GetMousePosOnOpeningCurrentPopup, ImVec2)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API bool          IsMouseDragging(ImGuiMouseButton button, float lock_threshold = -1.0f);         // is mouse dragging? (if lock_threshold < -1.0f, uses io.MouseDraggingThreshold)
IMGUI_FUNCTION(IsMouseDragging)
INT_ARG(button)
OPTIONAL_NUMBER_ARG(lock_threshold, -1.0f)
CALL_FUNCTION(IsMouseDragging, bool, button, lock_threshold)
PUSH_BOOL(ret)
END_IMGUI_FUNC
//    IMGUI_API ImVec2        GetMouseDragDelta(ImGuiMouseButton button = 0, float lock_threshold = -1.0f);   // return the delta from the initial clicking position while the mouse button is pressed or was just released. This is locked and return 0.0f until the mouse moves past a distance threshold at least once (if lock_threshold < -1.0f, uses io.MouseDraggingThreshold)
IMGUI_FUNCTION(GetMouseDragDelta)
OPTIONAL_INT_ARG(button, 0)
OPTIONAL_NUMBER_ARG(lock_threshold, -1.0f)
CALL_FUNCTION(GetMouseDragDelta, ImVec2, button, lock_threshold)
PUSH_NUMBER(ret.x)
PUSH_NUMBER(ret.y)
END_IMGUI_FUNC
//    IMGUI_API void          ResetMouseDragDelta(ImGuiMouseButton button = 0);                   //
IMGUI_FUNCTION(ResetMouseDragDelta)
OPTIONAL_INT_ARG(button, 0)
CALL_FUNCTION_NO_RET(ResetMouseDragDelta, button)
END_IMGUI_FUNC
//    IMGUI_API ImGuiMouseCursor GetMouseCursor();                                                // get desired mouse cursor shape. Important: reset in ImGui::NewFrame(), this is updated during the frame. valid before Render(). If you use software rendering by setting io.MouseDrawCursor ImGui will render those for you
// Unsupported return type ImGuiMouseCursor
//    IMGUI_API void          SetMouseCursor(ImGuiMouseCursor cursor_type);                       // set desired mouse cursor shape
IMGUI_FUNCTION(SetMouseCursor)
INT_ARG(cursor_type)
CALL_FUNCTION_NO_RET(SetMouseCursor, cursor_type)
END_IMGUI_FUNC
//    IMGUI_API void          SetNextFrameWantCaptureMouse(bool want_capture_mouse);              // Override io.WantCaptureMouse flag next frame (said flag is left for your application to handle, typical when true it instucts your app to ignore inputs). This is equivalent to setting "io.WantCaptureMouse = want_capture_mouse;" after the next NewFrame() call.
IMGUI_FUNCTION(SetNextFrameWantCaptureMouse)
BOOL_ARG(want_capture_mouse)
CALL_FUNCTION_NO_RET(SetNextFrameWantCaptureMouse, want_capture_mouse)
END_IMGUI_FUNC
//    IMGUI_API const char*   GetClipboardText();
IMGUI_FUNCTION(GetClipboardText)
CALL_FUNCTION(GetClipboardText, const char*)
PUSH_STRING(ret)
END_IMGUI_FUNC
//    IMGUI_API void          SetClipboardText(const char* text);
IMGUI_FUNCTION(SetClipboardText)
LABEL_ARG(text)
CALL_FUNCTION_NO_RET(SetClipboardText, text)
END_IMGUI_FUNC
//    IMGUI_API void          LoadIniSettingsFromDisk(const char* ini_filename);                  // call after CreateContext() and before the first call to NewFrame(). NewFrame() automatically calls LoadIniSettingsFromDisk(io.IniFilename).
IMGUI_FUNCTION(LoadIniSettingsFromDisk)
LABEL_ARG(ini_filename)
CALL_FUNCTION_NO_RET(LoadIniSettingsFromDisk, ini_filename)
END_IMGUI_FUNC
//    IMGUI_API void          LoadIniSettingsFromMemory(const char* ini_data, size_t ini_size=0); // call after CreateContext() and before the first call to NewFrame() to provide .ini data from your own data source.
// Unsupported arg type  size_t ini_size=0
//    IMGUI_API void          SaveIniSettingsToDisk(const char* ini_filename);                    // this is automatically called (if io.IniFilename is not empty) a few seconds after any modification that should be reflected in the .ini file (and also by DestroyContext).
IMGUI_FUNCTION(SaveIniSettingsToDisk)
LABEL_ARG(ini_filename)
CALL_FUNCTION_NO_RET(SaveIniSettingsToDisk, ini_filename)
END_IMGUI_FUNC
//    IMGUI_API const char*   SaveIniSettingsToMemory(size_t* out_ini_size = NULL);               // return a zero-terminated string with the .ini data which you can save by your own mean. call when io.WantSaveIniSettings is set, then save data by your own mean and clear io.WantSaveIniSettings.
// Unsupported arg type size_t* out_ini_size = NULL
//    IMGUI_API void          DebugTextEncoding(const char* text);
IMGUI_FUNCTION(DebugTextEncoding)
LABEL_ARG(text)
CALL_FUNCTION_NO_RET(DebugTextEncoding, text)
END_IMGUI_FUNC
//    IMGUI_API bool          DebugCheckVersionAndDataLayout(const char* version_str, size_t sz_io, size_t sz_style, size_t sz_vec2, size_t sz_vec4, size_t sz_drawvert, size_t sz_drawidx); // This is called by IMGUI_CHECKVERSION() macro.
// Unsupported arg type  size_t sz_io
// Unsupported arg type  size_t sz_style
// Unsupported arg type  size_t sz_vec2
// Unsupported arg type  size_t sz_vec4
// Unsupported arg type  size_t sz_drawvert
// Unsupported arg type  size_t sz_drawidx
//    IMGUI_API void          SetAllocatorFunctions(ImGuiMemAllocFunc alloc_func, ImGuiMemFreeFunc free_func, void* user_data = NULL);
// Unsupported arg type ImGuiMemAllocFunc alloc_func
// Unsupported arg type  ImGuiMemFreeFunc free_func
// Unsupported arg type  void* user_data = NULL
//    IMGUI_API void          GetAllocatorFunctions(ImGuiMemAllocFunc* p_alloc_func, ImGuiMemFreeFunc* p_free_func, void** p_user_data);
// Unsupported arg type ImGuiMemAllocFunc* p_alloc_func
// Unsupported arg type  ImGuiMemFreeFunc* p_free_func
// Unsupported arg type  void** p_user_data
//    IMGUI_API void*         MemAlloc(size_t size);
// Unsupported return type void*
// Unsupported arg type size_t size
//    IMGUI_API void          MemFree(void* ptr);
// Unsupported arg type void* ptr
//    IMGUI_API ImGuiPlatformIO&  GetPlatformIO();                                                // platform/renderer functions, for backend to setup + viewports list.
// Unsupported return type ImGuiPlatformIO&
//    IMGUI_API void              UpdatePlatformWindows();                                        // call in main loop. will call CreateWindow/ResizeWindow/etc. platform functions for each secondary viewport, and DestroyWindow for each inactive viewport.
IMGUI_FUNCTION(UpdatePlatformWindows)
CALL_FUNCTION_NO_RET(UpdatePlatformWindows)
END_IMGUI_FUNC
//    IMGUI_API void              RenderPlatformWindowsDefault(void* platform_render_arg = NULL, void* renderer_render_arg = NULL); // call in main loop. will call RenderWindow/SwapBuffers platform functions for each secondary viewport which doesn't have the ImGuiViewportFlags_Minimized flag set. May be reimplemented by user for custom rendering needs.
// Unsupported arg type void* platform_render_arg = NULL
// Unsupported arg type  void* renderer_render_arg = NULL
//    IMGUI_API void              DestroyPlatformWindows();                                       // call DestroyWindow platform functions for all viewports. call from backend Shutdown() if you need to close platform windows before imgui shutdown. otherwise will be called by DestroyContext().
IMGUI_FUNCTION(DestroyPlatformWindows)
CALL_FUNCTION_NO_RET(DestroyPlatformWindows)
END_IMGUI_FUNC
//    IMGUI_API ImGuiViewport*    FindViewportByID(ImGuiID id);                                   // this is a helper for backends.
// Unsupported return type ImGuiViewport*
//    IMGUI_API ImGuiViewport*    FindViewportByPlatformHandle(void* platform_handle);            // this is a helper for backends. the type platform_handle is decided by the backend (e.g. HWND, MyWindow*, GLFWwindow* etc.)
// Unsupported return type ImGuiViewport*
// Unsupported arg type void* platform_handle
END_STACK_START
END_STACK_OPTION(0, EndFrame)
END_STACK_OPTION(1, End)
END_STACK_OPTION(2, EndChild)
END_STACK_OPTION(3, PopStyleVar)
END_STACK_OPTION(4, EndGroup)
END_STACK_OPTION(5, EndCombo)
END_STACK_OPTION(6, TreePop)
END_STACK_OPTION(7, EndListBox)
END_STACK_OPTION(8, EndMenuBar)
END_STACK_OPTION(9, EndMainMenuBar)
END_STACK_OPTION(10, EndMenu)
END_STACK_OPTION(11, EndTooltip)
END_STACK_OPTION(12, EndPopup)
END_STACK_OPTION(13, EndTable)
END_STACK_OPTION(14, EndTabBar)
END_STACK_OPTION(15, EndTabItem)
END_STACK_OPTION(16, EndDragDropSource)
END_STACK_OPTION(17, EndDragDropTarget)
END_STACK_OPTION(18, EndDisabled)
END_STACK_OPTION(19, EndChildFrame)
END_STACK_END
//enum ImGuiWindowFlags_

START_ENUM(WindowFlags)
//    ImGuiWindowFlags_None                   = 0,
MAKE_ENUM(ImGuiWindowFlags_None,None)
//    ImGuiWindowFlags_NoTitleBar             = 1 << 0,   // Disable title-bar
MAKE_ENUM(ImGuiWindowFlags_NoTitleBar,NoTitleBar)
//    ImGuiWindowFlags_NoResize               = 1 << 1,   // Disable user resizing with the lower-right grip
MAKE_ENUM(ImGuiWindowFlags_NoResize,NoResize)
//    ImGuiWindowFlags_NoMove                 = 1 << 2,   // Disable user moving the window
MAKE_ENUM(ImGuiWindowFlags_NoMove,NoMove)
//    ImGuiWindowFlags_NoScrollbar            = 1 << 3,   // Disable scrollbars (window can still scroll with mouse or programmatically)
MAKE_ENUM(ImGuiWindowFlags_NoScrollbar,NoScrollbar)
//    ImGuiWindowFlags_NoScrollWithMouse      = 1 << 4,   // Disable user vertically scrolling with mouse wheel. On child window, mouse wheel will be forwarded to the parent unless NoScrollbar is also set.
MAKE_ENUM(ImGuiWindowFlags_NoScrollWithMouse,NoScrollWithMouse)
//    ImGuiWindowFlags_NoCollapse             = 1 << 5,   // Disable user collapsing window by double-clicking on it. Also referred to as Window Menu Button (e.g. within a docking node).
MAKE_ENUM(ImGuiWindowFlags_NoCollapse,NoCollapse)
//    ImGuiWindowFlags_AlwaysAutoResize       = 1 << 6,   // Resize every window to its content every frame
MAKE_ENUM(ImGuiWindowFlags_AlwaysAutoResize,AlwaysAutoResize)
//    ImGuiWindowFlags_NoBackground           = 1 << 7,   // Disable drawing background color (WindowBg, etc.) and outside border. Similar as using SetNextWindowBgAlpha(0.0f).
MAKE_ENUM(ImGuiWindowFlags_NoBackground,NoBackground)
//    ImGuiWindowFlags_NoSavedSettings        = 1 << 8,   // Never load/save settings in .ini file
MAKE_ENUM(ImGuiWindowFlags_NoSavedSettings,NoSavedSettings)
//    ImGuiWindowFlags_NoMouseInputs          = 1 << 9,   // Disable catching mouse, hovering test with pass through.
MAKE_ENUM(ImGuiWindowFlags_NoMouseInputs,NoMouseInputs)
//    ImGuiWindowFlags_MenuBar                = 1 << 10,  // Has a menu-bar
MAKE_ENUM(ImGuiWindowFlags_MenuBar,MenuBar)
//    ImGuiWindowFlags_HorizontalScrollbar    = 1 << 11,  // Allow horizontal scrollbar to appear (off by default). You may use SetNextWindowContentSize(ImVec2(width,0.0f)); prior to calling Begin() to specify width. Read code in imgui_demo in the "Horizontal Scrolling" section.
MAKE_ENUM(ImGuiWindowFlags_HorizontalScrollbar,HorizontalScrollbar)
//    ImGuiWindowFlags_NoFocusOnAppearing     = 1 << 12,  // Disable taking focus when transitioning from hidden to visible state
MAKE_ENUM(ImGuiWindowFlags_NoFocusOnAppearing,NoFocusOnAppearing)
//    ImGuiWindowFlags_NoBringToFrontOnFocus  = 1 << 13,  // Disable bringing window to front when taking focus (e.g. clicking on it or programmatically giving it focus)
MAKE_ENUM(ImGuiWindowFlags_NoBringToFrontOnFocus,NoBringToFrontOnFocus)
//    ImGuiWindowFlags_AlwaysVerticalScrollbar= 1 << 14,  // Always show vertical scrollbar (even if ContentSize.y < Size.y)
MAKE_ENUM(ImGuiWindowFlags_AlwaysVerticalScrollbar,AlwaysVerticalScrollbar)
//    ImGuiWindowFlags_AlwaysHorizontalScrollbar=1<< 15,  // Always show horizontal scrollbar (even if ContentSize.x < Size.x)
MAKE_ENUM(ImGuiWindowFlags_AlwaysHorizontalScrollbar,AlwaysHorizontalScrollbar)
//    ImGuiWindowFlags_AlwaysUseWindowPadding = 1 << 16,  // Ensure child windows without border uses style.WindowPadding (ignored by default for non-bordered child windows, because more convenient)
MAKE_ENUM(ImGuiWindowFlags_AlwaysUseWindowPadding,AlwaysUseWindowPadding)
//    ImGuiWindowFlags_NoNavInputs            = 1 << 18,  // No gamepad/keyboard navigation within the window
MAKE_ENUM(ImGuiWindowFlags_NoNavInputs,NoNavInputs)
//    ImGuiWindowFlags_NoNavFocus             = 1 << 19,  // No focusing toward this window with gamepad/keyboard navigation (e.g. skipped by CTRL+TAB)
MAKE_ENUM(ImGuiWindowFlags_NoNavFocus,NoNavFocus)
//    ImGuiWindowFlags_UnsavedDocument        = 1 << 20,  // Display a dot next to the title. When used in a tab/docking context, tab is selected when clicking the X + closure is not assumed (will wait for user to stop submitting the tab). Otherwise closure is assumed when pressing the X, so if you keep submitting the tab may reappear at end of tab bar.
MAKE_ENUM(ImGuiWindowFlags_UnsavedDocument,UnsavedDocument)
//    ImGuiWindowFlags_NoDocking              = 1 << 21,  // Disable docking of this window
MAKE_ENUM(ImGuiWindowFlags_NoDocking,NoDocking)
//    ImGuiWindowFlags_NoNav                  = ImGuiWindowFlags_NoNavInputs | ImGuiWindowFlags_NoNavFocus,
MAKE_ENUM(ImGuiWindowFlags_NoNav,NoNav)
//    ImGuiWindowFlags_NoDecoration           = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse,
MAKE_ENUM(ImGuiWindowFlags_NoDecoration,NoDecoration)
//    ImGuiWindowFlags_NoInputs               = ImGuiWindowFlags_NoMouseInputs | ImGuiWindowFlags_NoNavInputs | ImGuiWindowFlags_NoNavFocus,
MAKE_ENUM(ImGuiWindowFlags_NoInputs,NoInputs)
//    ImGuiWindowFlags_NavFlattened           = 1 << 23,  // [BETA] On child window: allow gamepad/keyboard navigation to cross over parent border to this child or between sibling child windows.
MAKE_ENUM(ImGuiWindowFlags_NavFlattened,NavFlattened)
//    ImGuiWindowFlags_ChildWindow            = 1 << 24,  // Don't use! For internal use by BeginChild()
MAKE_ENUM(ImGuiWindowFlags_ChildWindow,ChildWindow)
//    ImGuiWindowFlags_Tooltip                = 1 << 25,  // Don't use! For internal use by BeginTooltip()
MAKE_ENUM(ImGuiWindowFlags_Tooltip,Tooltip)
//    ImGuiWindowFlags_Popup                  = 1 << 26,  // Don't use! For internal use by BeginPopup()
MAKE_ENUM(ImGuiWindowFlags_Popup,Popup)
//    ImGuiWindowFlags_Modal                  = 1 << 27,  // Don't use! For internal use by BeginPopupModal()
MAKE_ENUM(ImGuiWindowFlags_Modal,Modal)
//    ImGuiWindowFlags_ChildMenu              = 1 << 28,  // Don't use! For internal use by BeginMenu()
MAKE_ENUM(ImGuiWindowFlags_ChildMenu,ChildMenu)
//    ImGuiWindowFlags_DockNodeHost           = 1 << 29,  // Don't use! For internal use by Begin()/NewFrame()
MAKE_ENUM(ImGuiWindowFlags_DockNodeHost,DockNodeHost)
END_ENUM(WindowFlags)
//enum ImGuiInputTextFlags_

START_ENUM(InputTextFlags)
//    ImGuiInputTextFlags_None                = 0,
MAKE_ENUM(ImGuiInputTextFlags_None,None)
//    ImGuiInputTextFlags_CharsDecimal        = 1 << 0,   // Allow 0123456789.+-*/
MAKE_ENUM(ImGuiInputTextFlags_CharsDecimal,CharsDecimal)
//    ImGuiInputTextFlags_CharsHexadecimal    = 1 << 1,   // Allow 0123456789ABCDEFabcdef
MAKE_ENUM(ImGuiInputTextFlags_CharsHexadecimal,CharsHexadecimal)
//    ImGuiInputTextFlags_CharsUppercase      = 1 << 2,   // Turn a..z into A..Z
MAKE_ENUM(ImGuiInputTextFlags_CharsUppercase,CharsUppercase)
//    ImGuiInputTextFlags_CharsNoBlank        = 1 << 3,   // Filter out spaces, tabs
MAKE_ENUM(ImGuiInputTextFlags_CharsNoBlank,CharsNoBlank)
//    ImGuiInputTextFlags_AutoSelectAll       = 1 << 4,   // Select entire text when first taking mouse focus
MAKE_ENUM(ImGuiInputTextFlags_AutoSelectAll,AutoSelectAll)
//    ImGuiInputTextFlags_EnterReturnsTrue    = 1 << 5,   // Return 'true' when Enter is pressed (as opposed to every time the value was modified). Consider looking at the IsItemDeactivatedAfterEdit() function.
MAKE_ENUM(ImGuiInputTextFlags_EnterReturnsTrue,EnterReturnsTrue)
//    ImGuiInputTextFlags_CallbackCompletion  = 1 << 6,   // Callback on pressing TAB (for completion handling)
MAKE_ENUM(ImGuiInputTextFlags_CallbackCompletion,CallbackCompletion)
//    ImGuiInputTextFlags_CallbackHistory     = 1 << 7,   // Callback on pressing Up/Down arrows (for history handling)
MAKE_ENUM(ImGuiInputTextFlags_CallbackHistory,CallbackHistory)
//    ImGuiInputTextFlags_CallbackAlways      = 1 << 8,   // Callback on each iteration. User code may query cursor position, modify text buffer.
MAKE_ENUM(ImGuiInputTextFlags_CallbackAlways,CallbackAlways)
//    ImGuiInputTextFlags_CallbackCharFilter  = 1 << 9,   // Callback on character inputs to replace or discard them. Modify 'EventChar' to replace or discard, or return 1 in callback to discard.
MAKE_ENUM(ImGuiInputTextFlags_CallbackCharFilter,CallbackCharFilter)
//    ImGuiInputTextFlags_AllowTabInput       = 1 << 10,  // Pressing TAB input a '\t' character into the text field
MAKE_ENUM(ImGuiInputTextFlags_AllowTabInput,AllowTabInput)
//    ImGuiInputTextFlags_CtrlEnterForNewLine = 1 << 11,  // In multi-line mode, unfocus with Enter, add new line with Ctrl+Enter (default is opposite: unfocus with Ctrl+Enter, add line with Enter).
MAKE_ENUM(ImGuiInputTextFlags_CtrlEnterForNewLine,CtrlEnterForNewLine)
//    ImGuiInputTextFlags_NoHorizontalScroll  = 1 << 12,  // Disable following the cursor horizontally
MAKE_ENUM(ImGuiInputTextFlags_NoHorizontalScroll,NoHorizontalScroll)
//    ImGuiInputTextFlags_AlwaysOverwrite     = 1 << 13,  // Overwrite mode
MAKE_ENUM(ImGuiInputTextFlags_AlwaysOverwrite,AlwaysOverwrite)
//    ImGuiInputTextFlags_ReadOnly            = 1 << 14,  // Read-only mode
MAKE_ENUM(ImGuiInputTextFlags_ReadOnly,ReadOnly)
//    ImGuiInputTextFlags_Password            = 1 << 15,  // Password mode, display all characters as '*'
MAKE_ENUM(ImGuiInputTextFlags_Password,Password)
//    ImGuiInputTextFlags_NoUndoRedo          = 1 << 16,  // Disable undo/redo. Note that input text owns the text data while active, if you want to provide your own undo/redo stack you need e.g. to call ClearActiveID().
MAKE_ENUM(ImGuiInputTextFlags_NoUndoRedo,NoUndoRedo)
//    ImGuiInputTextFlags_CharsScientific     = 1 << 17,  // Allow 0123456789.+-*/eE (Scientific notation input)
MAKE_ENUM(ImGuiInputTextFlags_CharsScientific,CharsScientific)
//    ImGuiInputTextFlags_CallbackResize      = 1 << 18,  // Callback on buffer capacity changes request (beyond 'buf_size' parameter value), allowing the string to grow. Notify when the string wants to be resized (for string types which hold a cache of their Size). You will be provided a new BufSize in the callback and NEED to honor it. (see misc/cpp/imgui_stdlib.h for an example of using this)
MAKE_ENUM(ImGuiInputTextFlags_CallbackResize,CallbackResize)
//    ImGuiInputTextFlags_CallbackEdit        = 1 << 19,  // Callback on any edit (note that InputText() already returns true on edit, the callback is useful mainly to manipulate the underlying buffer while focus is active)
MAKE_ENUM(ImGuiInputTextFlags_CallbackEdit,CallbackEdit)
//    ImGuiInputTextFlags_EscapeClearsAll     = 1 << 20,  // Escape key clears content if not empty, and deactivate otherwise (constrast to default behavior of Escape to revert)
MAKE_ENUM(ImGuiInputTextFlags_EscapeClearsAll,EscapeClearsAll)
//    ImGuiInputTextFlags_AlwaysInsertMode    = ImGuiInputTextFlags_AlwaysOverwrite   // [renamed in 1.82] name was not matching behavior
MAKE_ENUM(ImGuiInputTextFlags_AlwaysInsertMode,AlwaysInsertMode)
END_ENUM(InputTextFlags)
//enum ImGuiTreeNodeFlags_

START_ENUM(TreeNodeFlags)
//    ImGuiTreeNodeFlags_None                 = 0,
MAKE_ENUM(ImGuiTreeNodeFlags_None,None)
//    ImGuiTreeNodeFlags_Selected             = 1 << 0,   // Draw as selected
MAKE_ENUM(ImGuiTreeNodeFlags_Selected,Selected)
//    ImGuiTreeNodeFlags_Framed               = 1 << 1,   // Draw frame with background (e.g. for CollapsingHeader)
MAKE_ENUM(ImGuiTreeNodeFlags_Framed,Framed)
//    ImGuiTreeNodeFlags_AllowItemOverlap     = 1 << 2,   // Hit testing to allow subsequent widgets to overlap this one
MAKE_ENUM(ImGuiTreeNodeFlags_AllowItemOverlap,AllowItemOverlap)
//    ImGuiTreeNodeFlags_NoTreePushOnOpen     = 1 << 3,   // Don't do a TreePush() when open (e.g. for CollapsingHeader) = no extra indent nor pushing on ID stack
MAKE_ENUM(ImGuiTreeNodeFlags_NoTreePushOnOpen,NoTreePushOnOpen)
//    ImGuiTreeNodeFlags_NoAutoOpenOnLog      = 1 << 4,   // Don't automatically and temporarily open node when Logging is active (by default logging will automatically open tree nodes)
MAKE_ENUM(ImGuiTreeNodeFlags_NoAutoOpenOnLog,NoAutoOpenOnLog)
//    ImGuiTreeNodeFlags_DefaultOpen          = 1 << 5,   // Default node to be open
MAKE_ENUM(ImGuiTreeNodeFlags_DefaultOpen,DefaultOpen)
//    ImGuiTreeNodeFlags_OpenOnDoubleClick    = 1 << 6,   // Need double-click to open node
MAKE_ENUM(ImGuiTreeNodeFlags_OpenOnDoubleClick,OpenOnDoubleClick)
//    ImGuiTreeNodeFlags_OpenOnArrow          = 1 << 7,   // Only open when clicking on the arrow part. If ImGuiTreeNodeFlags_OpenOnDoubleClick is also set, single-click arrow or double-click all box to open.
MAKE_ENUM(ImGuiTreeNodeFlags_OpenOnArrow,OpenOnArrow)
//    ImGuiTreeNodeFlags_Leaf                 = 1 << 8,   // No collapsing, no arrow (use as a convenience for leaf nodes).
MAKE_ENUM(ImGuiTreeNodeFlags_Leaf,Leaf)
//    ImGuiTreeNodeFlags_Bullet               = 1 << 9,   // Display a bullet instead of arrow
MAKE_ENUM(ImGuiTreeNodeFlags_Bullet,Bullet)
//    ImGuiTreeNodeFlags_FramePadding         = 1 << 10,  // Use FramePadding (even for an unframed text node) to vertically align text baseline to regular widget height. Equivalent to calling AlignTextToFramePadding().
MAKE_ENUM(ImGuiTreeNodeFlags_FramePadding,FramePadding)
//    ImGuiTreeNodeFlags_SpanAvailWidth       = 1 << 11,  // Extend hit box to the right-most edge, even if not framed. This is not the default in order to allow adding other items on the same line. In the future we may refactor the hit system to be front-to-back, allowing natural overlaps and then this can become the default.
MAKE_ENUM(ImGuiTreeNodeFlags_SpanAvailWidth,SpanAvailWidth)
//    ImGuiTreeNodeFlags_SpanFullWidth        = 1 << 12,  // Extend hit box to the left-most and right-most edges (bypass the indented area).
MAKE_ENUM(ImGuiTreeNodeFlags_SpanFullWidth,SpanFullWidth)
//    ImGuiTreeNodeFlags_NavLeftJumpsBackHere = 1 << 13,  // (WIP) Nav: left direction may move to this TreeNode() from any of its child (items submitted between TreeNode and TreePop)
MAKE_ENUM(ImGuiTreeNodeFlags_NavLeftJumpsBackHere,NavLeftJumpsBackHere)
//    ImGuiTreeNodeFlags_CollapsingHeader     = ImGuiTreeNodeFlags_Framed | ImGuiTreeNodeFlags_NoTreePushOnOpen | ImGuiTreeNodeFlags_NoAutoOpenOnLog,
MAKE_ENUM(ImGuiTreeNodeFlags_CollapsingHeader,CollapsingHeader)
END_ENUM(TreeNodeFlags)
//enum ImGuiPopupFlags_

START_ENUM(PopupFlags)
//    ImGuiPopupFlags_None                    = 0,
MAKE_ENUM(ImGuiPopupFlags_None,None)
//    ImGuiPopupFlags_MouseButtonLeft         = 0,        // For BeginPopupContext*(): open on Left Mouse release. Guaranteed to always be == 0 (same as ImGuiMouseButton_Left)
MAKE_ENUM(ImGuiPopupFlags_MouseButtonLeft,MouseButtonLeft)
//    ImGuiPopupFlags_MouseButtonRight        = 1,        // For BeginPopupContext*(): open on Right Mouse release. Guaranteed to always be == 1 (same as ImGuiMouseButton_Right)
MAKE_ENUM(ImGuiPopupFlags_MouseButtonRight,MouseButtonRight)
//    ImGuiPopupFlags_MouseButtonMiddle       = 2,        // For BeginPopupContext*(): open on Middle Mouse release. Guaranteed to always be == 2 (same as ImGuiMouseButton_Middle)
MAKE_ENUM(ImGuiPopupFlags_MouseButtonMiddle,MouseButtonMiddle)
//    ImGuiPopupFlags_NoOpenOverExistingPopup = 1 << 5,   // For OpenPopup*(), BeginPopupContext*(): don't open if there's already a popup at the same level of the popup stack
MAKE_ENUM(ImGuiPopupFlags_NoOpenOverExistingPopup,NoOpenOverExistingPopup)
//    ImGuiPopupFlags_NoOpenOverItems         = 1 << 6,   // For BeginPopupContextWindow(): don't return true when hovering items, only when hovering empty space
MAKE_ENUM(ImGuiPopupFlags_NoOpenOverItems,NoOpenOverItems)
//    ImGuiPopupFlags_AnyPopupId              = 1 << 7,   // For IsPopupOpen(): ignore the ImGuiID parameter and test for any popup.
MAKE_ENUM(ImGuiPopupFlags_AnyPopupId,AnyPopupId)
//    ImGuiPopupFlags_AnyPopupLevel           = 1 << 8,   // For IsPopupOpen(): search/test at any level of the popup stack (default test in the current level)
MAKE_ENUM(ImGuiPopupFlags_AnyPopupLevel,AnyPopupLevel)
//    ImGuiPopupFlags_AnyPopup                = ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel,
MAKE_ENUM(ImGuiPopupFlags_AnyPopup,AnyPopup)
END_ENUM(PopupFlags)
//enum ImGuiSelectableFlags_

START_ENUM(SelectableFlags)
//    ImGuiSelectableFlags_None               = 0,
MAKE_ENUM(ImGuiSelectableFlags_None,None)
//    ImGuiSelectableFlags_DontClosePopups    = 1 << 0,   // Clicking this doesn't close parent popup window
MAKE_ENUM(ImGuiSelectableFlags_DontClosePopups,DontClosePopups)
//    ImGuiSelectableFlags_SpanAllColumns     = 1 << 1,   // Selectable frame can span all columns (text will still fit in current column)
MAKE_ENUM(ImGuiSelectableFlags_SpanAllColumns,SpanAllColumns)
//    ImGuiSelectableFlags_AllowDoubleClick   = 1 << 2,   // Generate press events on double clicks too
MAKE_ENUM(ImGuiSelectableFlags_AllowDoubleClick,AllowDoubleClick)
//    ImGuiSelectableFlags_Disabled           = 1 << 3,   // Cannot be selected, display grayed out text
MAKE_ENUM(ImGuiSelectableFlags_Disabled,Disabled)
//    ImGuiSelectableFlags_AllowItemOverlap   = 1 << 4,   // (WIP) Hit testing to allow subsequent widgets to overlap this one
MAKE_ENUM(ImGuiSelectableFlags_AllowItemOverlap,AllowItemOverlap)
END_ENUM(SelectableFlags)
//enum ImGuiComboFlags_

START_ENUM(ComboFlags)
//    ImGuiComboFlags_None                    = 0,
MAKE_ENUM(ImGuiComboFlags_None,None)
//    ImGuiComboFlags_PopupAlignLeft          = 1 << 0,   // Align the popup toward the left by default
MAKE_ENUM(ImGuiComboFlags_PopupAlignLeft,PopupAlignLeft)
//    ImGuiComboFlags_HeightSmall             = 1 << 1,   // Max ~4 items visible. Tip: If you want your combo popup to be a specific size you can use SetNextWindowSizeConstraints() prior to calling BeginCombo()
MAKE_ENUM(ImGuiComboFlags_HeightSmall,HeightSmall)
//    ImGuiComboFlags_HeightRegular           = 1 << 2,   // Max ~8 items visible (default)
MAKE_ENUM(ImGuiComboFlags_HeightRegular,HeightRegular)
//    ImGuiComboFlags_HeightLarge             = 1 << 3,   // Max ~20 items visible
MAKE_ENUM(ImGuiComboFlags_HeightLarge,HeightLarge)
//    ImGuiComboFlags_HeightLargest           = 1 << 4,   // As many fitting items as possible
MAKE_ENUM(ImGuiComboFlags_HeightLargest,HeightLargest)
//    ImGuiComboFlags_NoArrowButton           = 1 << 5,   // Display on the preview box without the square arrow button
MAKE_ENUM(ImGuiComboFlags_NoArrowButton,NoArrowButton)
//    ImGuiComboFlags_NoPreview               = 1 << 6,   // Display only a square arrow button
MAKE_ENUM(ImGuiComboFlags_NoPreview,NoPreview)
END_ENUM(ComboFlags)
//enum ImGuiTabBarFlags_

START_ENUM(TabBarFlags)
//    ImGuiTabBarFlags_None                           = 0,
MAKE_ENUM(ImGuiTabBarFlags_None,None)
//    ImGuiTabBarFlags_Reorderable                    = 1 << 0,   // Allow manually dragging tabs to re-order them + New tabs are appended at the end of list
MAKE_ENUM(ImGuiTabBarFlags_Reorderable,Reorderable)
//    ImGuiTabBarFlags_AutoSelectNewTabs              = 1 << 1,   // Automatically select new tabs when they appear
MAKE_ENUM(ImGuiTabBarFlags_AutoSelectNewTabs,AutoSelectNewTabs)
//    ImGuiTabBarFlags_TabListPopupButton             = 1 << 2,   // Disable buttons to open the tab list popup
MAKE_ENUM(ImGuiTabBarFlags_TabListPopupButton,TabListPopupButton)
//    ImGuiTabBarFlags_NoCloseWithMiddleMouseButton   = 1 << 3,   // Disable behavior of closing tabs (that are submitted with p_open != NULL) with middle mouse button. You can still repro this behavior on user's side with if (IsItemHovered() && IsMouseClicked(2)) *p_open = false.
MAKE_ENUM(ImGuiTabBarFlags_NoCloseWithMiddleMouseButton,NoCloseWithMiddleMouseButton)
//    ImGuiTabBarFlags_NoTabListScrollingButtons      = 1 << 4,   // Disable scrolling buttons (apply when fitting policy is ImGuiTabBarFlags_FittingPolicyScroll)
MAKE_ENUM(ImGuiTabBarFlags_NoTabListScrollingButtons,NoTabListScrollingButtons)
//    ImGuiTabBarFlags_NoTooltip                      = 1 << 5,   // Disable tooltips when hovering a tab
MAKE_ENUM(ImGuiTabBarFlags_NoTooltip,NoTooltip)
//    ImGuiTabBarFlags_FittingPolicyResizeDown        = 1 << 6,   // Resize tabs when they don't fit
MAKE_ENUM(ImGuiTabBarFlags_FittingPolicyResizeDown,FittingPolicyResizeDown)
//    ImGuiTabBarFlags_FittingPolicyScroll            = 1 << 7,   // Add scroll buttons when tabs don't fit
MAKE_ENUM(ImGuiTabBarFlags_FittingPolicyScroll,FittingPolicyScroll)
END_ENUM(TabBarFlags)
//enum ImGuiTabItemFlags_

START_ENUM(TabItemFlags)
//    ImGuiTabItemFlags_None                          = 0,
MAKE_ENUM(ImGuiTabItemFlags_None,None)
//    ImGuiTabItemFlags_UnsavedDocument               = 1 << 0,   // Display a dot next to the title + tab is selected when clicking the X + closure is not assumed (will wait for user to stop submitting the tab). Otherwise closure is assumed when pressing the X, so if you keep submitting the tab may reappear at end of tab bar.
MAKE_ENUM(ImGuiTabItemFlags_UnsavedDocument,UnsavedDocument)
//    ImGuiTabItemFlags_SetSelected                   = 1 << 1,   // Trigger flag to programmatically make the tab selected when calling BeginTabItem()
MAKE_ENUM(ImGuiTabItemFlags_SetSelected,SetSelected)
//    ImGuiTabItemFlags_NoCloseWithMiddleMouseButton  = 1 << 2,   // Disable behavior of closing tabs (that are submitted with p_open != NULL) with middle mouse button. You can still repro this behavior on user's side with if (IsItemHovered() && IsMouseClicked(2)) *p_open = false.
MAKE_ENUM(ImGuiTabItemFlags_NoCloseWithMiddleMouseButton,NoCloseWithMiddleMouseButton)
//    ImGuiTabItemFlags_NoPushId                      = 1 << 3,   // Don't call PushID(tab->ID)/PopID() on BeginTabItem()/EndTabItem()
MAKE_ENUM(ImGuiTabItemFlags_NoPushId,NoPushId)
//    ImGuiTabItemFlags_NoTooltip                     = 1 << 4,   // Disable tooltip for the given tab
MAKE_ENUM(ImGuiTabItemFlags_NoTooltip,NoTooltip)
//    ImGuiTabItemFlags_NoReorder                     = 1 << 5,   // Disable reordering this tab or having another tab cross over this tab
MAKE_ENUM(ImGuiTabItemFlags_NoReorder,NoReorder)
//    ImGuiTabItemFlags_Leading                       = 1 << 6,   // Enforce the tab position to the left of the tab bar (after the tab list popup button)
MAKE_ENUM(ImGuiTabItemFlags_Leading,Leading)
//    ImGuiTabItemFlags_Trailing                      = 1 << 7,   // Enforce the tab position to the right of the tab bar (before the scrolling buttons)
MAKE_ENUM(ImGuiTabItemFlags_Trailing,Trailing)
END_ENUM(TabItemFlags)
//enum ImGuiTableFlags_

START_ENUM(TableFlags)
//    ImGuiTableFlags_None                       = 0,
MAKE_ENUM(ImGuiTableFlags_None,None)
//    ImGuiTableFlags_Resizable                  = 1 << 0,   // Enable resizing columns.
MAKE_ENUM(ImGuiTableFlags_Resizable,Resizable)
//    ImGuiTableFlags_Reorderable                = 1 << 1,   // Enable reordering columns in header row (need calling TableSetupColumn() + TableHeadersRow() to display headers)
MAKE_ENUM(ImGuiTableFlags_Reorderable,Reorderable)
//    ImGuiTableFlags_Hideable                   = 1 << 2,   // Enable hiding/disabling columns in context menu.
MAKE_ENUM(ImGuiTableFlags_Hideable,Hideable)
//    ImGuiTableFlags_Sortable                   = 1 << 3,   // Enable sorting. Call TableGetSortSpecs() to obtain sort specs. Also see ImGuiTableFlags_SortMulti and ImGuiTableFlags_SortTristate.
MAKE_ENUM(ImGuiTableFlags_Sortable,Sortable)
//    ImGuiTableFlags_NoSavedSettings            = 1 << 4,   // Disable persisting columns order, width and sort settings in the .ini file.
MAKE_ENUM(ImGuiTableFlags_NoSavedSettings,NoSavedSettings)
//    ImGuiTableFlags_ContextMenuInBody          = 1 << 5,   // Right-click on columns body/contents will display table context menu. By default it is available in TableHeadersRow().
MAKE_ENUM(ImGuiTableFlags_ContextMenuInBody,ContextMenuInBody)
//    ImGuiTableFlags_RowBg                      = 1 << 6,   // Set each RowBg color with ImGuiCol_TableRowBg or ImGuiCol_TableRowBgAlt (equivalent of calling TableSetBgColor with ImGuiTableBgFlags_RowBg0 on each row manually)
MAKE_ENUM(ImGuiTableFlags_RowBg,RowBg)
//    ImGuiTableFlags_BordersInnerH              = 1 << 7,   // Draw horizontal borders between rows.
MAKE_ENUM(ImGuiTableFlags_BordersInnerH,BordersInnerH)
//    ImGuiTableFlags_BordersOuterH              = 1 << 8,   // Draw horizontal borders at the top and bottom.
MAKE_ENUM(ImGuiTableFlags_BordersOuterH,BordersOuterH)
//    ImGuiTableFlags_BordersInnerV              = 1 << 9,   // Draw vertical borders between columns.
MAKE_ENUM(ImGuiTableFlags_BordersInnerV,BordersInnerV)
//    ImGuiTableFlags_BordersOuterV              = 1 << 10,  // Draw vertical borders on the left and right sides.
MAKE_ENUM(ImGuiTableFlags_BordersOuterV,BordersOuterV)
//    ImGuiTableFlags_BordersH                   = ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_BordersOuterH, // Draw horizontal borders.
MAKE_ENUM(ImGuiTableFlags_BordersH,BordersH)
//    ImGuiTableFlags_BordersV                   = ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_BordersOuterV, // Draw vertical borders.
MAKE_ENUM(ImGuiTableFlags_BordersV,BordersV)
//    ImGuiTableFlags_BordersInner               = ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_BordersInnerH, // Draw inner borders.
MAKE_ENUM(ImGuiTableFlags_BordersInner,BordersInner)
//    ImGuiTableFlags_BordersOuter               = ImGuiTableFlags_BordersOuterV | ImGuiTableFlags_BordersOuterH, // Draw outer borders.
MAKE_ENUM(ImGuiTableFlags_BordersOuter,BordersOuter)
//    ImGuiTableFlags_Borders                    = ImGuiTableFlags_BordersInner | ImGuiTableFlags_BordersOuter,   // Draw all borders.
MAKE_ENUM(ImGuiTableFlags_Borders,Borders)
//    ImGuiTableFlags_NoBordersInBody            = 1 << 11,  // [ALPHA] Disable vertical borders in columns Body (borders will always appear in Headers). -> May move to style
MAKE_ENUM(ImGuiTableFlags_NoBordersInBody,NoBordersInBody)
//    ImGuiTableFlags_NoBordersInBodyUntilResize = 1 << 12,  // [ALPHA] Disable vertical borders in columns Body until hovered for resize (borders will always appear in Headers). -> May move to style
MAKE_ENUM(ImGuiTableFlags_NoBordersInBodyUntilResize,NoBordersInBodyUntilResize)
//    ImGuiTableFlags_SizingFixedFit             = 1 << 13,  // Columns default to _WidthFixed or _WidthAuto (if resizable or not resizable), matching contents width.
MAKE_ENUM(ImGuiTableFlags_SizingFixedFit,SizingFixedFit)
//    ImGuiTableFlags_SizingFixedSame            = 2 << 13,  // Columns default to _WidthFixed or _WidthAuto (if resizable or not resizable), matching the maximum contents width of all columns. Implicitly enable ImGuiTableFlags_NoKeepColumnsVisible.
MAKE_ENUM(ImGuiTableFlags_SizingFixedSame,SizingFixedSame)
//    ImGuiTableFlags_SizingStretchProp          = 3 << 13,  // Columns default to _WidthStretch with default weights proportional to each columns contents widths.
MAKE_ENUM(ImGuiTableFlags_SizingStretchProp,SizingStretchProp)
//    ImGuiTableFlags_SizingStretchSame          = 4 << 13,  // Columns default to _WidthStretch with default weights all equal, unless overridden by TableSetupColumn().
MAKE_ENUM(ImGuiTableFlags_SizingStretchSame,SizingStretchSame)
//    ImGuiTableFlags_NoHostExtendX              = 1 << 16,  // Make outer width auto-fit to columns, overriding outer_size.x value. Only available when ScrollX/ScrollY are disabled and Stretch columns are not used.
MAKE_ENUM(ImGuiTableFlags_NoHostExtendX,NoHostExtendX)
//    ImGuiTableFlags_NoHostExtendY              = 1 << 17,  // Make outer height stop exactly at outer_size.y (prevent auto-extending table past the limit). Only available when ScrollX/ScrollY are disabled. Data below the limit will be clipped and not visible.
MAKE_ENUM(ImGuiTableFlags_NoHostExtendY,NoHostExtendY)
//    ImGuiTableFlags_NoKeepColumnsVisible       = 1 << 18,  // Disable keeping column always minimally visible when ScrollX is off and table gets too small. Not recommended if columns are resizable.
MAKE_ENUM(ImGuiTableFlags_NoKeepColumnsVisible,NoKeepColumnsVisible)
//    ImGuiTableFlags_PreciseWidths              = 1 << 19,  // Disable distributing remainder width to stretched columns (width allocation on a 100-wide table with 3 columns: Without this flag: 33,33,34. With this flag: 33,33,33). With larger number of columns, resizing will appear to be less smooth.
MAKE_ENUM(ImGuiTableFlags_PreciseWidths,PreciseWidths)
//    ImGuiTableFlags_NoClip                     = 1 << 20,  // Disable clipping rectangle for every individual columns (reduce draw command count, items will be able to overflow into other columns). Generally incompatible with TableSetupScrollFreeze().
MAKE_ENUM(ImGuiTableFlags_NoClip,NoClip)
//    ImGuiTableFlags_PadOuterX                  = 1 << 21,  // Default if BordersOuterV is on. Enable outermost padding. Generally desirable if you have headers.
MAKE_ENUM(ImGuiTableFlags_PadOuterX,PadOuterX)
//    ImGuiTableFlags_NoPadOuterX                = 1 << 22,  // Default if BordersOuterV is off. Disable outermost padding.
MAKE_ENUM(ImGuiTableFlags_NoPadOuterX,NoPadOuterX)
//    ImGuiTableFlags_NoPadInnerX                = 1 << 23,  // Disable inner padding between columns (double inner padding if BordersOuterV is on, single inner padding if BordersOuterV is off).
MAKE_ENUM(ImGuiTableFlags_NoPadInnerX,NoPadInnerX)
//    ImGuiTableFlags_ScrollX                    = 1 << 24,  // Enable horizontal scrolling. Require 'outer_size' parameter of BeginTable() to specify the container size. Changes default sizing policy. Because this creates a child window, ScrollY is currently generally recommended when using ScrollX.
MAKE_ENUM(ImGuiTableFlags_ScrollX,ScrollX)
//    ImGuiTableFlags_ScrollY                    = 1 << 25,  // Enable vertical scrolling. Require 'outer_size' parameter of BeginTable() to specify the container size.
MAKE_ENUM(ImGuiTableFlags_ScrollY,ScrollY)
//    ImGuiTableFlags_SortMulti                  = 1 << 26,  // Hold shift when clicking headers to sort on multiple column. TableGetSortSpecs() may return specs where (SpecsCount > 1).
MAKE_ENUM(ImGuiTableFlags_SortMulti,SortMulti)
//    ImGuiTableFlags_SortTristate               = 1 << 27,  // Allow no sorting, disable default sorting. TableGetSortSpecs() may return specs where (SpecsCount == 0).
MAKE_ENUM(ImGuiTableFlags_SortTristate,SortTristate)
END_ENUM(TableFlags)
//enum ImGuiTableColumnFlags_

START_ENUM(TableColumnFlags)
//    ImGuiTableColumnFlags_None                  = 0,
MAKE_ENUM(ImGuiTableColumnFlags_None,None)
//    ImGuiTableColumnFlags_Disabled              = 1 << 0,   // Overriding/master disable flag: hide column, won't show in context menu (unlike calling TableSetColumnEnabled() which manipulates the user accessible state)
MAKE_ENUM(ImGuiTableColumnFlags_Disabled,Disabled)
//    ImGuiTableColumnFlags_DefaultHide           = 1 << 1,   // Default as a hidden/disabled column.
MAKE_ENUM(ImGuiTableColumnFlags_DefaultHide,DefaultHide)
//    ImGuiTableColumnFlags_DefaultSort           = 1 << 2,   // Default as a sorting column.
MAKE_ENUM(ImGuiTableColumnFlags_DefaultSort,DefaultSort)
//    ImGuiTableColumnFlags_WidthStretch          = 1 << 3,   // Column will stretch. Preferable with horizontal scrolling disabled (default if table sizing policy is _SizingStretchSame or _SizingStretchProp).
MAKE_ENUM(ImGuiTableColumnFlags_WidthStretch,WidthStretch)
//    ImGuiTableColumnFlags_WidthFixed            = 1 << 4,   // Column will not stretch. Preferable with horizontal scrolling enabled (default if table sizing policy is _SizingFixedFit and table is resizable).
MAKE_ENUM(ImGuiTableColumnFlags_WidthFixed,WidthFixed)
//    ImGuiTableColumnFlags_NoResize              = 1 << 5,   // Disable manual resizing.
MAKE_ENUM(ImGuiTableColumnFlags_NoResize,NoResize)
//    ImGuiTableColumnFlags_NoReorder             = 1 << 6,   // Disable manual reordering this column, this will also prevent other columns from crossing over this column.
MAKE_ENUM(ImGuiTableColumnFlags_NoReorder,NoReorder)
//    ImGuiTableColumnFlags_NoHide                = 1 << 7,   // Disable ability to hide/disable this column.
MAKE_ENUM(ImGuiTableColumnFlags_NoHide,NoHide)
//    ImGuiTableColumnFlags_NoClip                = 1 << 8,   // Disable clipping for this column (all NoClip columns will render in a same draw command).
MAKE_ENUM(ImGuiTableColumnFlags_NoClip,NoClip)
//    ImGuiTableColumnFlags_NoSort                = 1 << 9,   // Disable ability to sort on this field (even if ImGuiTableFlags_Sortable is set on the table).
MAKE_ENUM(ImGuiTableColumnFlags_NoSort,NoSort)
//    ImGuiTableColumnFlags_NoSortAscending       = 1 << 10,  // Disable ability to sort in the ascending direction.
MAKE_ENUM(ImGuiTableColumnFlags_NoSortAscending,NoSortAscending)
//    ImGuiTableColumnFlags_NoSortDescending      = 1 << 11,  // Disable ability to sort in the descending direction.
MAKE_ENUM(ImGuiTableColumnFlags_NoSortDescending,NoSortDescending)
//    ImGuiTableColumnFlags_NoHeaderLabel         = 1 << 12,  // TableHeadersRow() will not submit label for this column. Convenient for some small columns. Name will still appear in context menu.
MAKE_ENUM(ImGuiTableColumnFlags_NoHeaderLabel,NoHeaderLabel)
//    ImGuiTableColumnFlags_NoHeaderWidth         = 1 << 13,  // Disable header text width contribution to automatic column width.
MAKE_ENUM(ImGuiTableColumnFlags_NoHeaderWidth,NoHeaderWidth)
//    ImGuiTableColumnFlags_PreferSortAscending   = 1 << 14,  // Make the initial sort direction Ascending when first sorting on this column (default).
MAKE_ENUM(ImGuiTableColumnFlags_PreferSortAscending,PreferSortAscending)
//    ImGuiTableColumnFlags_PreferSortDescending  = 1 << 15,  // Make the initial sort direction Descending when first sorting on this column.
MAKE_ENUM(ImGuiTableColumnFlags_PreferSortDescending,PreferSortDescending)
//    ImGuiTableColumnFlags_IndentEnable          = 1 << 16,  // Use current Indent value when entering cell (default for column 0).
MAKE_ENUM(ImGuiTableColumnFlags_IndentEnable,IndentEnable)
//    ImGuiTableColumnFlags_IndentDisable         = 1 << 17,  // Ignore current Indent value when entering cell (default for columns > 0). Indentation changes _within_ the cell will still be honored.
MAKE_ENUM(ImGuiTableColumnFlags_IndentDisable,IndentDisable)
//    ImGuiTableColumnFlags_IsEnabled             = 1 << 24,  // Status: is enabled == not hidden by user/api (referred to as "Hide" in _DefaultHide and _NoHide) flags.
MAKE_ENUM(ImGuiTableColumnFlags_IsEnabled,IsEnabled)
//    ImGuiTableColumnFlags_IsVisible             = 1 << 25,  // Status: is visible == is enabled AND not clipped by scrolling.
MAKE_ENUM(ImGuiTableColumnFlags_IsVisible,IsVisible)
//    ImGuiTableColumnFlags_IsSorted              = 1 << 26,  // Status: is currently part of the sort specs
MAKE_ENUM(ImGuiTableColumnFlags_IsSorted,IsSorted)
//    ImGuiTableColumnFlags_IsHovered             = 1 << 27,  // Status: is hovered by mouse
MAKE_ENUM(ImGuiTableColumnFlags_IsHovered,IsHovered)
END_ENUM(TableColumnFlags)
//enum ImGuiTableRowFlags_

START_ENUM(TableRowFlags)
//    ImGuiTableRowFlags_None                     = 0,
MAKE_ENUM(ImGuiTableRowFlags_None,None)
//    ImGuiTableRowFlags_Headers                  = 1 << 0,   // Identify header row (set default background color + width of its contents accounted differently for auto column width)
MAKE_ENUM(ImGuiTableRowFlags_Headers,Headers)
END_ENUM(TableRowFlags)
//enum ImGuiTableBgTarget_

START_ENUM(TableBgTarget)
//    ImGuiTableBgTarget_None                     = 0,
MAKE_ENUM(ImGuiTableBgTarget_None,None)
//    ImGuiTableBgTarget_RowBg0                   = 1,        // Set row background color 0 (generally used for background, automatically set when ImGuiTableFlags_RowBg is used)
MAKE_ENUM(ImGuiTableBgTarget_RowBg0,RowBg0)
//    ImGuiTableBgTarget_RowBg1                   = 2,        // Set row background color 1 (generally used for selection marking)
MAKE_ENUM(ImGuiTableBgTarget_RowBg1,RowBg1)
//    ImGuiTableBgTarget_CellBg                   = 3,        // Set cell background color (top-most color)
MAKE_ENUM(ImGuiTableBgTarget_CellBg,CellBg)
END_ENUM(TableBgTarget)
//enum ImGuiFocusedFlags_

START_ENUM(FocusedFlags)
//    ImGuiFocusedFlags_None                          = 0,
MAKE_ENUM(ImGuiFocusedFlags_None,None)
//    ImGuiFocusedFlags_ChildWindows                  = 1 << 0,   // Return true if any children of the window is focused
MAKE_ENUM(ImGuiFocusedFlags_ChildWindows,ChildWindows)
//    ImGuiFocusedFlags_RootWindow                    = 1 << 1,   // Test from root window (top most parent of the current hierarchy)
MAKE_ENUM(ImGuiFocusedFlags_RootWindow,RootWindow)
//    ImGuiFocusedFlags_AnyWindow                     = 1 << 2,   // Return true if any window is focused. Important: If you are trying to tell how to dispatch your low-level inputs, do NOT use this. Use 'io.WantCaptureMouse' instead! Please read the FAQ!
MAKE_ENUM(ImGuiFocusedFlags_AnyWindow,AnyWindow)
//    ImGuiFocusedFlags_NoPopupHierarchy              = 1 << 3,   // Do not consider popup hierarchy (do not treat popup emitter as parent of popup) (when used with _ChildWindows or _RootWindow)
MAKE_ENUM(ImGuiFocusedFlags_NoPopupHierarchy,NoPopupHierarchy)
//    ImGuiFocusedFlags_DockHierarchy                 = 1 << 4,   // Consider docking hierarchy (treat dockspace host as parent of docked window) (when used with _ChildWindows or _RootWindow)
MAKE_ENUM(ImGuiFocusedFlags_DockHierarchy,DockHierarchy)
//    ImGuiFocusedFlags_RootAndChildWindows           = ImGuiFocusedFlags_RootWindow | ImGuiFocusedFlags_ChildWindows,
MAKE_ENUM(ImGuiFocusedFlags_RootAndChildWindows,RootAndChildWindows)
END_ENUM(FocusedFlags)
//enum ImGuiHoveredFlags_

START_ENUM(HoveredFlags)
//    ImGuiHoveredFlags_None                          = 0,        // Return true if directly over the item/window, not obstructed by another window, not obstructed by an active popup or modal blocking inputs under them.
MAKE_ENUM(ImGuiHoveredFlags_None,None)
//    ImGuiHoveredFlags_ChildWindows                  = 1 << 0,   // IsWindowHovered() only: Return true if any children of the window is hovered
MAKE_ENUM(ImGuiHoveredFlags_ChildWindows,ChildWindows)
//    ImGuiHoveredFlags_RootWindow                    = 1 << 1,   // IsWindowHovered() only: Test from root window (top most parent of the current hierarchy)
MAKE_ENUM(ImGuiHoveredFlags_RootWindow,RootWindow)
//    ImGuiHoveredFlags_AnyWindow                     = 1 << 2,   // IsWindowHovered() only: Return true if any window is hovered
MAKE_ENUM(ImGuiHoveredFlags_AnyWindow,AnyWindow)
//    ImGuiHoveredFlags_NoPopupHierarchy              = 1 << 3,   // IsWindowHovered() only: Do not consider popup hierarchy (do not treat popup emitter as parent of popup) (when used with _ChildWindows or _RootWindow)
MAKE_ENUM(ImGuiHoveredFlags_NoPopupHierarchy,NoPopupHierarchy)
//    ImGuiHoveredFlags_DockHierarchy                 = 1 << 4,   // IsWindowHovered() only: Consider docking hierarchy (treat dockspace host as parent of docked window) (when used with _ChildWindows or _RootWindow)
MAKE_ENUM(ImGuiHoveredFlags_DockHierarchy,DockHierarchy)
//    ImGuiHoveredFlags_AllowWhenBlockedByPopup       = 1 << 5,   // Return true even if a popup window is normally blocking access to this item/window
MAKE_ENUM(ImGuiHoveredFlags_AllowWhenBlockedByPopup,AllowWhenBlockedByPopup)
//    ImGuiHoveredFlags_AllowWhenBlockedByActiveItem  = 1 << 7,   // Return true even if an active item is blocking access to this item/window. Useful for Drag and Drop patterns.
MAKE_ENUM(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem,AllowWhenBlockedByActiveItem)
//    ImGuiHoveredFlags_AllowWhenOverlapped           = 1 << 8,   // IsItemHovered() only: Return true even if the position is obstructed or overlapped by another window
MAKE_ENUM(ImGuiHoveredFlags_AllowWhenOverlapped,AllowWhenOverlapped)
//    ImGuiHoveredFlags_AllowWhenDisabled             = 1 << 9,   // IsItemHovered() only: Return true even if the item is disabled
MAKE_ENUM(ImGuiHoveredFlags_AllowWhenDisabled,AllowWhenDisabled)
//    ImGuiHoveredFlags_NoNavOverride                 = 1 << 10,  // Disable using gamepad/keyboard navigation state when active, always query mouse.
MAKE_ENUM(ImGuiHoveredFlags_NoNavOverride,NoNavOverride)
//    ImGuiHoveredFlags_RectOnly                      = ImGuiHoveredFlags_AllowWhenBlockedByPopup | ImGuiHoveredFlags_AllowWhenBlockedByActiveItem | ImGuiHoveredFlags_AllowWhenOverlapped,
MAKE_ENUM(ImGuiHoveredFlags_RectOnly,RectOnly)
//    ImGuiHoveredFlags_RootAndChildWindows           = ImGuiHoveredFlags_RootWindow | ImGuiHoveredFlags_ChildWindows,
MAKE_ENUM(ImGuiHoveredFlags_RootAndChildWindows,RootAndChildWindows)
//    ImGuiHoveredFlags_DelayNormal                   = 1 << 11,  // Return true after io.HoverDelayNormal elapsed (~0.30 sec)
MAKE_ENUM(ImGuiHoveredFlags_DelayNormal,DelayNormal)
//    ImGuiHoveredFlags_DelayShort                    = 1 << 12,  // Return true after io.HoverDelayShort elapsed (~0.10 sec)
MAKE_ENUM(ImGuiHoveredFlags_DelayShort,DelayShort)
//    ImGuiHoveredFlags_NoSharedDelay                 = 1 << 13,  // Disable shared delay system where moving from one item to the next keeps the previous timer for a short time (standard for tooltips with long delays)
MAKE_ENUM(ImGuiHoveredFlags_NoSharedDelay,NoSharedDelay)
END_ENUM(HoveredFlags)
//enum ImGuiDockNodeFlags_

START_ENUM(DockNodeFlags)
//    ImGuiDockNodeFlags_None                         = 0,
MAKE_ENUM(ImGuiDockNodeFlags_None,None)
//    ImGuiDockNodeFlags_KeepAliveOnly                = 1 << 0,   // Shared       // Don't display the dockspace node but keep it alive. Windows docked into this dockspace node won't be undocked.
MAKE_ENUM(ImGuiDockNodeFlags_KeepAliveOnly,KeepAliveOnly)
//    ImGuiDockNodeFlags_NoDockingInCentralNode       = 1 << 2,   // Shared       // Disable docking inside the Central Node, which will be always kept empty.
MAKE_ENUM(ImGuiDockNodeFlags_NoDockingInCentralNode,NoDockingInCentralNode)
//    ImGuiDockNodeFlags_PassthruCentralNode          = 1 << 3,   // Shared       // Enable passthru dockspace: 1) DockSpace() will render a ImGuiCol_WindowBg background covering everything excepted the Central Node when empty. Meaning the host window should probably use SetNextWindowBgAlpha(0.0f) prior to Begin() when using this. 2) When Central Node is empty: let inputs pass-through + won't display a DockingEmptyBg background. See demo for details.
MAKE_ENUM(ImGuiDockNodeFlags_PassthruCentralNode,PassthruCentralNode)
//    ImGuiDockNodeFlags_NoSplit                      = 1 << 4,   // Shared/Local // Disable splitting the node into smaller nodes. Useful e.g. when embedding dockspaces into a main root one (the root one may have splitting disabled to reduce confusion). Note: when turned off, existing splits will be preserved.
MAKE_ENUM(ImGuiDockNodeFlags_NoSplit,NoSplit)
//    ImGuiDockNodeFlags_NoResize                     = 1 << 5,   // Shared/Local // Disable resizing node using the splitter/separators. Useful with programmatically setup dockspaces.
MAKE_ENUM(ImGuiDockNodeFlags_NoResize,NoResize)
//    ImGuiDockNodeFlags_AutoHideTabBar               = 1 << 6,   // Shared/Local // Tab bar will automatically hide when there is a single window in the dock node.
MAKE_ENUM(ImGuiDockNodeFlags_AutoHideTabBar,AutoHideTabBar)
END_ENUM(DockNodeFlags)
//enum ImGuiDragDropFlags_

START_ENUM(DragDropFlags)
//    ImGuiDragDropFlags_None                         = 0,
MAKE_ENUM(ImGuiDragDropFlags_None,None)
//    ImGuiDragDropFlags_SourceNoPreviewTooltip       = 1 << 0,   // By default, a successful call to BeginDragDropSource opens a tooltip so you can display a preview or description of the source contents. This flag disables this behavior.
MAKE_ENUM(ImGuiDragDropFlags_SourceNoPreviewTooltip,SourceNoPreviewTooltip)
//    ImGuiDragDropFlags_SourceNoDisableHover         = 1 << 1,   // By default, when dragging we clear data so that IsItemHovered() will return false, to avoid subsequent user code submitting tooltips. This flag disables this behavior so you can still call IsItemHovered() on the source item.
MAKE_ENUM(ImGuiDragDropFlags_SourceNoDisableHover,SourceNoDisableHover)
//    ImGuiDragDropFlags_SourceNoHoldToOpenOthers     = 1 << 2,   // Disable the behavior that allows to open tree nodes and collapsing header by holding over them while dragging a source item.
MAKE_ENUM(ImGuiDragDropFlags_SourceNoHoldToOpenOthers,SourceNoHoldToOpenOthers)
//    ImGuiDragDropFlags_SourceAllowNullID            = 1 << 3,   // Allow items such as Text(), Image() that have no unique identifier to be used as drag source, by manufacturing a temporary identifier based on their window-relative position. This is extremely unusual within the dear imgui ecosystem and so we made it explicit.
MAKE_ENUM(ImGuiDragDropFlags_SourceAllowNullID,SourceAllowNullID)
//    ImGuiDragDropFlags_SourceExtern                 = 1 << 4,   // External source (from outside of dear imgui), won't attempt to read current item/window info. Will always return true. Only one Extern source can be active simultaneously.
MAKE_ENUM(ImGuiDragDropFlags_SourceExtern,SourceExtern)
//    ImGuiDragDropFlags_SourceAutoExpirePayload      = 1 << 5,   // Automatically expire the payload if the source cease to be submitted (otherwise payloads are persisting while being dragged)
MAKE_ENUM(ImGuiDragDropFlags_SourceAutoExpirePayload,SourceAutoExpirePayload)
//    ImGuiDragDropFlags_AcceptBeforeDelivery         = 1 << 10,  // AcceptDragDropPayload() will returns true even before the mouse button is released. You can then call IsDelivery() to test if the payload needs to be delivered.
MAKE_ENUM(ImGuiDragDropFlags_AcceptBeforeDelivery,AcceptBeforeDelivery)
//    ImGuiDragDropFlags_AcceptNoDrawDefaultRect      = 1 << 11,  // Do not draw the default highlight rectangle when hovering over target.
MAKE_ENUM(ImGuiDragDropFlags_AcceptNoDrawDefaultRect,AcceptNoDrawDefaultRect)
//    ImGuiDragDropFlags_AcceptNoPreviewTooltip       = 1 << 12,  // Request hiding the BeginDragDropSource tooltip from the BeginDragDropTarget site.
MAKE_ENUM(ImGuiDragDropFlags_AcceptNoPreviewTooltip,AcceptNoPreviewTooltip)
//    ImGuiDragDropFlags_AcceptPeekOnly               = ImGuiDragDropFlags_AcceptBeforeDelivery | ImGuiDragDropFlags_AcceptNoDrawDefaultRect, // For peeking ahead and inspecting the payload before delivery.
MAKE_ENUM(ImGuiDragDropFlags_AcceptPeekOnly,AcceptPeekOnly)
END_ENUM(DragDropFlags)
//enum ImGuiDataType_

START_ENUM(DataType)
//    ImGuiDataType_S8,       // signed char / char (with sensible compilers)
MAKE_ENUM(ImGuiDataType_S8,S8)
//    ImGuiDataType_U8,       // unsigned char
MAKE_ENUM(ImGuiDataType_U8,U8)
//    ImGuiDataType_S16,      // short
MAKE_ENUM(ImGuiDataType_S16,S16)
//    ImGuiDataType_U16,      // unsigned short
MAKE_ENUM(ImGuiDataType_U16,U16)
//    ImGuiDataType_S32,      // int
MAKE_ENUM(ImGuiDataType_S32,S32)
//    ImGuiDataType_U32,      // unsigned int
MAKE_ENUM(ImGuiDataType_U32,U32)
//    ImGuiDataType_S64,      // long long / __int64
MAKE_ENUM(ImGuiDataType_S64,S64)
//    ImGuiDataType_U64,      // unsigned long long / unsigned __int64
MAKE_ENUM(ImGuiDataType_U64,U64)
//    ImGuiDataType_Float,    // float
MAKE_ENUM(ImGuiDataType_Float,Float)
//    ImGuiDataType_Double,   // double
MAKE_ENUM(ImGuiDataType_Double,Double)
//    ImGuiDataType_COUNT
MAKE_ENUM(ImGuiDataType_COUNT,COUNT)
END_ENUM(DataType)
//enum ImGuiDir_

START_ENUM(Dir)
//    ImGuiDir_None    = -1,
MAKE_ENUM(ImGuiDir_None,None)
//    ImGuiDir_Left    = 0,
MAKE_ENUM(ImGuiDir_Left,Left)
//    ImGuiDir_Right   = 1,
MAKE_ENUM(ImGuiDir_Right,Right)
//    ImGuiDir_Up      = 2,
MAKE_ENUM(ImGuiDir_Up,Up)
//    ImGuiDir_Down    = 3,
MAKE_ENUM(ImGuiDir_Down,Down)
//    ImGuiDir_COUNT
MAKE_ENUM(ImGuiDir_COUNT,COUNT)
END_ENUM(Dir)
//enum ImGuiSortDirection_

START_ENUM(SortDirection)
//    ImGuiSortDirection_None         = 0,
MAKE_ENUM(ImGuiSortDirection_None,None)
//    ImGuiSortDirection_Ascending    = 1,    // Ascending = 0->9, A->Z etc.
MAKE_ENUM(ImGuiSortDirection_Ascending,Ascending)
//    ImGuiSortDirection_Descending   = 2     // Descending = 9->0, Z->A etc.
MAKE_ENUM(ImGuiSortDirection_Descending,Descending)
END_ENUM(SortDirection)
//enum ImGuiKey : int

//enum ImGuiNavInput

//enum ImGuiConfigFlags_

START_ENUM(ConfigFlags)
//    ImGuiConfigFlags_None                   = 0,
MAKE_ENUM(ImGuiConfigFlags_None,None)
//    ImGuiConfigFlags_NavEnableKeyboard      = 1 << 0,   // Master keyboard navigation enable flag.
MAKE_ENUM(ImGuiConfigFlags_NavEnableKeyboard,NavEnableKeyboard)
//    ImGuiConfigFlags_NavEnableGamepad       = 1 << 1,   // Master gamepad navigation enable flag. Backend also needs to set ImGuiBackendFlags_HasGamepad.
MAKE_ENUM(ImGuiConfigFlags_NavEnableGamepad,NavEnableGamepad)
//    ImGuiConfigFlags_NavEnableSetMousePos   = 1 << 2,   // Instruct navigation to move the mouse cursor. May be useful on TV/console systems where moving a virtual mouse is awkward. Will update io.MousePos and set io.WantSetMousePos=true. If enabled you MUST honor io.WantSetMousePos requests in your backend, otherwise ImGui will react as if the mouse is jumping around back and forth.
MAKE_ENUM(ImGuiConfigFlags_NavEnableSetMousePos,NavEnableSetMousePos)
//    ImGuiConfigFlags_NavNoCaptureKeyboard   = 1 << 3,   // Instruct navigation to not set the io.WantCaptureKeyboard flag when io.NavActive is set.
MAKE_ENUM(ImGuiConfigFlags_NavNoCaptureKeyboard,NavNoCaptureKeyboard)
//    ImGuiConfigFlags_NoMouse                = 1 << 4,   // Instruct imgui to clear mouse position/buttons in NewFrame(). This allows ignoring the mouse information set by the backend.
MAKE_ENUM(ImGuiConfigFlags_NoMouse,NoMouse)
//    ImGuiConfigFlags_NoMouseCursorChange    = 1 << 5,   // Instruct backend to not alter mouse cursor shape and visibility. Use if the backend cursor changes are interfering with yours and you don't want to use SetMouseCursor() to change mouse cursor. You may want to honor requests from imgui by reading GetMouseCursor() yourself instead.
MAKE_ENUM(ImGuiConfigFlags_NoMouseCursorChange,NoMouseCursorChange)
//    ImGuiConfigFlags_DockingEnable          = 1 << 6,   // Docking enable flags.
MAKE_ENUM(ImGuiConfigFlags_DockingEnable,DockingEnable)
//    ImGuiConfigFlags_ViewportsEnable        = 1 << 10,  // Viewport enable flags (require both ImGuiBackendFlags_PlatformHasViewports + ImGuiBackendFlags_RendererHasViewports set by the respective backends)
MAKE_ENUM(ImGuiConfigFlags_ViewportsEnable,ViewportsEnable)
//    ImGuiConfigFlags_DpiEnableScaleViewports= 1 << 14,  // [BETA: Don't use] FIXME-DPI: Reposition and resize imgui windows when the DpiScale of a viewport changed (mostly useful for the main viewport hosting other window). Note that resizing the main window itself is up to your application.
MAKE_ENUM(ImGuiConfigFlags_DpiEnableScaleViewports,DpiEnableScaleViewports)
//    ImGuiConfigFlags_DpiEnableScaleFonts    = 1 << 15,  // [BETA: Don't use] FIXME-DPI: Request bitmap-scaled fonts to match DpiScale. This is a very low-quality workaround. The correct way to handle DPI is _currently_ to replace the atlas and/or fonts in the Platform_OnChangedViewport callback, but this is all early work in progress.
MAKE_ENUM(ImGuiConfigFlags_DpiEnableScaleFonts,DpiEnableScaleFonts)
//    ImGuiConfigFlags_IsSRGB                 = 1 << 20,  // Application is SRGB-aware.
MAKE_ENUM(ImGuiConfigFlags_IsSRGB,IsSRGB)
//    ImGuiConfigFlags_IsTouchScreen          = 1 << 21,  // Application is using a touch screen instead of a mouse.
MAKE_ENUM(ImGuiConfigFlags_IsTouchScreen,IsTouchScreen)
END_ENUM(ConfigFlags)
//enum ImGuiBackendFlags_

START_ENUM(BackendFlags)
//    ImGuiBackendFlags_None                  = 0,
MAKE_ENUM(ImGuiBackendFlags_None,None)
//    ImGuiBackendFlags_HasGamepad            = 1 << 0,   // Backend Platform supports gamepad and currently has one connected.
MAKE_ENUM(ImGuiBackendFlags_HasGamepad,HasGamepad)
//    ImGuiBackendFlags_HasMouseCursors       = 1 << 1,   // Backend Platform supports honoring GetMouseCursor() value to change the OS cursor shape.
MAKE_ENUM(ImGuiBackendFlags_HasMouseCursors,HasMouseCursors)
//    ImGuiBackendFlags_HasSetMousePos        = 1 << 2,   // Backend Platform supports io.WantSetMousePos requests to reposition the OS mouse position (only used if ImGuiConfigFlags_NavEnableSetMousePos is set).
MAKE_ENUM(ImGuiBackendFlags_HasSetMousePos,HasSetMousePos)
//    ImGuiBackendFlags_RendererHasVtxOffset  = 1 << 3,   // Backend Renderer supports ImDrawCmd::VtxOffset. This enables output of large meshes (64K+ vertices) while still using 16-bit indices.
MAKE_ENUM(ImGuiBackendFlags_RendererHasVtxOffset,RendererHasVtxOffset)
//    ImGuiBackendFlags_PlatformHasViewports  = 1 << 10,  // Backend Platform supports multiple viewports.
MAKE_ENUM(ImGuiBackendFlags_PlatformHasViewports,PlatformHasViewports)
//    ImGuiBackendFlags_HasMouseHoveredViewport=1 << 11,  // Backend Platform supports calling io.AddMouseViewportEvent() with the viewport under the mouse. IF POSSIBLE, ignore viewports with the ImGuiViewportFlags_NoInputs flag (Win32 backend, GLFW 3.30+ backend can do this, SDL backend cannot). If this cannot be done, Dear ImGui needs to use a flawed heuristic to find the viewport under.
MAKE_ENUM(ImGuiBackendFlags_HasMouseHoveredViewport,HasMouseHoveredViewport)
//    ImGuiBackendFlags_RendererHasViewports  = 1 << 12,  // Backend Renderer supports multiple viewports.
MAKE_ENUM(ImGuiBackendFlags_RendererHasViewports,RendererHasViewports)
END_ENUM(BackendFlags)
//enum ImGuiCol_

START_ENUM(Col)
//    ImGuiCol_Text,
MAKE_ENUM(ImGuiCol_Text,Text)
//    ImGuiCol_TextDisabled,
MAKE_ENUM(ImGuiCol_TextDisabled,TextDisabled)
//    ImGuiCol_WindowBg,              // Background of normal windows
MAKE_ENUM(ImGuiCol_WindowBg,WindowBg)
//    ImGuiCol_ChildBg,               // Background of child windows
MAKE_ENUM(ImGuiCol_ChildBg,ChildBg)
//    ImGuiCol_PopupBg,               // Background of popups, menus, tooltips windows
MAKE_ENUM(ImGuiCol_PopupBg,PopupBg)
//    ImGuiCol_Border,
MAKE_ENUM(ImGuiCol_Border,Border)
//    ImGuiCol_BorderShadow,
MAKE_ENUM(ImGuiCol_BorderShadow,BorderShadow)
//    ImGuiCol_FrameBg,               // Background of checkbox, radio button, plot, slider, text input
MAKE_ENUM(ImGuiCol_FrameBg,FrameBg)
//    ImGuiCol_FrameBgHovered,
MAKE_ENUM(ImGuiCol_FrameBgHovered,FrameBgHovered)
//    ImGuiCol_FrameBgActive,
MAKE_ENUM(ImGuiCol_FrameBgActive,FrameBgActive)
//    ImGuiCol_TitleBg,
MAKE_ENUM(ImGuiCol_TitleBg,TitleBg)
//    ImGuiCol_TitleBgActive,
MAKE_ENUM(ImGuiCol_TitleBgActive,TitleBgActive)
//    ImGuiCol_TitleBgCollapsed,
MAKE_ENUM(ImGuiCol_TitleBgCollapsed,TitleBgCollapsed)
//    ImGuiCol_MenuBarBg,
MAKE_ENUM(ImGuiCol_MenuBarBg,MenuBarBg)
//    ImGuiCol_ScrollbarBg,
MAKE_ENUM(ImGuiCol_ScrollbarBg,ScrollbarBg)
//    ImGuiCol_ScrollbarGrab,
MAKE_ENUM(ImGuiCol_ScrollbarGrab,ScrollbarGrab)
//    ImGuiCol_ScrollbarGrabHovered,
MAKE_ENUM(ImGuiCol_ScrollbarGrabHovered,ScrollbarGrabHovered)
//    ImGuiCol_ScrollbarGrabActive,
MAKE_ENUM(ImGuiCol_ScrollbarGrabActive,ScrollbarGrabActive)
//    ImGuiCol_CheckMark,
MAKE_ENUM(ImGuiCol_CheckMark,CheckMark)
//    ImGuiCol_SliderGrab,
MAKE_ENUM(ImGuiCol_SliderGrab,SliderGrab)
//    ImGuiCol_SliderGrabActive,
MAKE_ENUM(ImGuiCol_SliderGrabActive,SliderGrabActive)
//    ImGuiCol_Button,
MAKE_ENUM(ImGuiCol_Button,Button)
//    ImGuiCol_ButtonHovered,
MAKE_ENUM(ImGuiCol_ButtonHovered,ButtonHovered)
//    ImGuiCol_ButtonActive,
MAKE_ENUM(ImGuiCol_ButtonActive,ButtonActive)
//    ImGuiCol_Header,                // Header* colors are used for CollapsingHeader, TreeNode, Selectable, MenuItem
MAKE_ENUM(ImGuiCol_Header,Header)
//    ImGuiCol_HeaderHovered,
MAKE_ENUM(ImGuiCol_HeaderHovered,HeaderHovered)
//    ImGuiCol_HeaderActive,
MAKE_ENUM(ImGuiCol_HeaderActive,HeaderActive)
//    ImGuiCol_Separator,
MAKE_ENUM(ImGuiCol_Separator,Separator)
//    ImGuiCol_SeparatorHovered,
MAKE_ENUM(ImGuiCol_SeparatorHovered,SeparatorHovered)
//    ImGuiCol_SeparatorActive,
MAKE_ENUM(ImGuiCol_SeparatorActive,SeparatorActive)
//    ImGuiCol_ResizeGrip,            // Resize grip in lower-right and lower-left corners of windows.
MAKE_ENUM(ImGuiCol_ResizeGrip,ResizeGrip)
//    ImGuiCol_ResizeGripHovered,
MAKE_ENUM(ImGuiCol_ResizeGripHovered,ResizeGripHovered)
//    ImGuiCol_ResizeGripActive,
MAKE_ENUM(ImGuiCol_ResizeGripActive,ResizeGripActive)
//    ImGuiCol_Tab,                   // TabItem in a TabBar
MAKE_ENUM(ImGuiCol_Tab,Tab)
//    ImGuiCol_TabHovered,
MAKE_ENUM(ImGuiCol_TabHovered,TabHovered)
//    ImGuiCol_TabActive,
MAKE_ENUM(ImGuiCol_TabActive,TabActive)
//    ImGuiCol_TabUnfocused,
MAKE_ENUM(ImGuiCol_TabUnfocused,TabUnfocused)
//    ImGuiCol_TabUnfocusedActive,
MAKE_ENUM(ImGuiCol_TabUnfocusedActive,TabUnfocusedActive)
//    ImGuiCol_DockingPreview,        // Preview overlay color when about to docking something
MAKE_ENUM(ImGuiCol_DockingPreview,DockingPreview)
//    ImGuiCol_DockingEmptyBg,        // Background color for empty node (e.g. CentralNode with no window docked into it)
MAKE_ENUM(ImGuiCol_DockingEmptyBg,DockingEmptyBg)
//    ImGuiCol_PlotLines,
MAKE_ENUM(ImGuiCol_PlotLines,PlotLines)
//    ImGuiCol_PlotLinesHovered,
MAKE_ENUM(ImGuiCol_PlotLinesHovered,PlotLinesHovered)
//    ImGuiCol_PlotHistogram,
MAKE_ENUM(ImGuiCol_PlotHistogram,PlotHistogram)
//    ImGuiCol_PlotHistogramHovered,
MAKE_ENUM(ImGuiCol_PlotHistogramHovered,PlotHistogramHovered)
//    ImGuiCol_TableHeaderBg,         // Table header background
MAKE_ENUM(ImGuiCol_TableHeaderBg,TableHeaderBg)
//    ImGuiCol_TableBorderStrong,     // Table outer and header borders (prefer using Alpha=1.0 here)
MAKE_ENUM(ImGuiCol_TableBorderStrong,TableBorderStrong)
//    ImGuiCol_TableBorderLight,      // Table inner borders (prefer using Alpha=1.0 here)
MAKE_ENUM(ImGuiCol_TableBorderLight,TableBorderLight)
//    ImGuiCol_TableRowBg,            // Table row background (even rows)
MAKE_ENUM(ImGuiCol_TableRowBg,TableRowBg)
//    ImGuiCol_TableRowBgAlt,         // Table row background (odd rows)
MAKE_ENUM(ImGuiCol_TableRowBgAlt,TableRowBgAlt)
//    ImGuiCol_TextSelectedBg,
MAKE_ENUM(ImGuiCol_TextSelectedBg,TextSelectedBg)
//    ImGuiCol_DragDropTarget,        // Rectangle highlighting a drop target
MAKE_ENUM(ImGuiCol_DragDropTarget,DragDropTarget)
//    ImGuiCol_NavHighlight,          // Gamepad/keyboard: current highlighted item
MAKE_ENUM(ImGuiCol_NavHighlight,NavHighlight)
//    ImGuiCol_NavWindowingHighlight, // Highlight window when using CTRL+TAB
MAKE_ENUM(ImGuiCol_NavWindowingHighlight,NavWindowingHighlight)
//    ImGuiCol_NavWindowingDimBg,     // Darken/colorize entire screen behind the CTRL+TAB window list, when active
MAKE_ENUM(ImGuiCol_NavWindowingDimBg,NavWindowingDimBg)
//    ImGuiCol_ModalWindowDimBg,      // Darken/colorize entire screen behind a modal window, when one is active
MAKE_ENUM(ImGuiCol_ModalWindowDimBg,ModalWindowDimBg)
//    ImGuiCol_COUNT
MAKE_ENUM(ImGuiCol_COUNT,COUNT)
END_ENUM(Col)
//enum ImGuiStyleVar_

START_ENUM(StyleVar)
//    ImGuiStyleVar_Alpha,               // float     Alpha
MAKE_ENUM(ImGuiStyleVar_Alpha,Alpha)
//    ImGuiStyleVar_DisabledAlpha,       // float     DisabledAlpha
MAKE_ENUM(ImGuiStyleVar_DisabledAlpha,DisabledAlpha)
//    ImGuiStyleVar_WindowPadding,       // ImVec2    WindowPadding
MAKE_ENUM(ImGuiStyleVar_WindowPadding,WindowPadding)
//    ImGuiStyleVar_WindowRounding,      // float     WindowRounding
MAKE_ENUM(ImGuiStyleVar_WindowRounding,WindowRounding)
//    ImGuiStyleVar_WindowBorderSize,    // float     WindowBorderSize
MAKE_ENUM(ImGuiStyleVar_WindowBorderSize,WindowBorderSize)
//    ImGuiStyleVar_WindowMinSize,       // ImVec2    WindowMinSize
MAKE_ENUM(ImGuiStyleVar_WindowMinSize,WindowMinSize)
//    ImGuiStyleVar_WindowTitleAlign,    // ImVec2    WindowTitleAlign
MAKE_ENUM(ImGuiStyleVar_WindowTitleAlign,WindowTitleAlign)
//    ImGuiStyleVar_ChildRounding,       // float     ChildRounding
MAKE_ENUM(ImGuiStyleVar_ChildRounding,ChildRounding)
//    ImGuiStyleVar_ChildBorderSize,     // float     ChildBorderSize
MAKE_ENUM(ImGuiStyleVar_ChildBorderSize,ChildBorderSize)
//    ImGuiStyleVar_PopupRounding,       // float     PopupRounding
MAKE_ENUM(ImGuiStyleVar_PopupRounding,PopupRounding)
//    ImGuiStyleVar_PopupBorderSize,     // float     PopupBorderSize
MAKE_ENUM(ImGuiStyleVar_PopupBorderSize,PopupBorderSize)
//    ImGuiStyleVar_FramePadding,        // ImVec2    FramePadding
MAKE_ENUM(ImGuiStyleVar_FramePadding,FramePadding)
//    ImGuiStyleVar_FrameRounding,       // float     FrameRounding
MAKE_ENUM(ImGuiStyleVar_FrameRounding,FrameRounding)
//    ImGuiStyleVar_FrameBorderSize,     // float     FrameBorderSize
MAKE_ENUM(ImGuiStyleVar_FrameBorderSize,FrameBorderSize)
//    ImGuiStyleVar_ItemSpacing,         // ImVec2    ItemSpacing
MAKE_ENUM(ImGuiStyleVar_ItemSpacing,ItemSpacing)
//    ImGuiStyleVar_ItemInnerSpacing,    // ImVec2    ItemInnerSpacing
MAKE_ENUM(ImGuiStyleVar_ItemInnerSpacing,ItemInnerSpacing)
//    ImGuiStyleVar_IndentSpacing,       // float     IndentSpacing
MAKE_ENUM(ImGuiStyleVar_IndentSpacing,IndentSpacing)
//    ImGuiStyleVar_CellPadding,         // ImVec2    CellPadding
MAKE_ENUM(ImGuiStyleVar_CellPadding,CellPadding)
//    ImGuiStyleVar_ScrollbarSize,       // float     ScrollbarSize
MAKE_ENUM(ImGuiStyleVar_ScrollbarSize,ScrollbarSize)
//    ImGuiStyleVar_ScrollbarRounding,   // float     ScrollbarRounding
MAKE_ENUM(ImGuiStyleVar_ScrollbarRounding,ScrollbarRounding)
//    ImGuiStyleVar_GrabMinSize,         // float     GrabMinSize
MAKE_ENUM(ImGuiStyleVar_GrabMinSize,GrabMinSize)
//    ImGuiStyleVar_GrabRounding,        // float     GrabRounding
MAKE_ENUM(ImGuiStyleVar_GrabRounding,GrabRounding)
//    ImGuiStyleVar_TabRounding,         // float     TabRounding
MAKE_ENUM(ImGuiStyleVar_TabRounding,TabRounding)
//    ImGuiStyleVar_ButtonTextAlign,     // ImVec2    ButtonTextAlign
MAKE_ENUM(ImGuiStyleVar_ButtonTextAlign,ButtonTextAlign)
//    ImGuiStyleVar_SelectableTextAlign, // ImVec2    SelectableTextAlign
MAKE_ENUM(ImGuiStyleVar_SelectableTextAlign,SelectableTextAlign)
//    ImGuiStyleVar_COUNT
MAKE_ENUM(ImGuiStyleVar_COUNT,COUNT)
END_ENUM(StyleVar)
//enum ImGuiButtonFlags_

START_ENUM(ButtonFlags)
//    ImGuiButtonFlags_None                   = 0,
MAKE_ENUM(ImGuiButtonFlags_None,None)
//    ImGuiButtonFlags_MouseButtonLeft        = 1 << 0,   // React on left mouse button (default)
MAKE_ENUM(ImGuiButtonFlags_MouseButtonLeft,MouseButtonLeft)
//    ImGuiButtonFlags_MouseButtonRight       = 1 << 1,   // React on right mouse button
MAKE_ENUM(ImGuiButtonFlags_MouseButtonRight,MouseButtonRight)
//    ImGuiButtonFlags_MouseButtonMiddle      = 1 << 2,   // React on center mouse button
MAKE_ENUM(ImGuiButtonFlags_MouseButtonMiddle,MouseButtonMiddle)
END_ENUM(ButtonFlags)
//enum ImGuiColorEditFlags_

START_ENUM(ColorEditFlags)
//    ImGuiColorEditFlags_None            = 0,
MAKE_ENUM(ImGuiColorEditFlags_None,None)
//    ImGuiColorEditFlags_NoAlpha         = 1 << 1,   //              // ColorEdit, ColorPicker, ColorButton: ignore Alpha component (will only read 3 components from the input pointer).
MAKE_ENUM(ImGuiColorEditFlags_NoAlpha,NoAlpha)
//    ImGuiColorEditFlags_NoPicker        = 1 << 2,   //              // ColorEdit: disable picker when clicking on color square.
MAKE_ENUM(ImGuiColorEditFlags_NoPicker,NoPicker)
//    ImGuiColorEditFlags_NoOptions       = 1 << 3,   //              // ColorEdit: disable toggling options menu when right-clicking on inputs/small preview.
MAKE_ENUM(ImGuiColorEditFlags_NoOptions,NoOptions)
//    ImGuiColorEditFlags_NoSmallPreview  = 1 << 4,   //              // ColorEdit, ColorPicker: disable color square preview next to the inputs. (e.g. to show only the inputs)
MAKE_ENUM(ImGuiColorEditFlags_NoSmallPreview,NoSmallPreview)
//    ImGuiColorEditFlags_NoInputs        = 1 << 5,   //              // ColorEdit, ColorPicker: disable inputs sliders/text widgets (e.g. to show only the small preview color square).
MAKE_ENUM(ImGuiColorEditFlags_NoInputs,NoInputs)
//    ImGuiColorEditFlags_NoTooltip       = 1 << 6,   //              // ColorEdit, ColorPicker, ColorButton: disable tooltip when hovering the preview.
MAKE_ENUM(ImGuiColorEditFlags_NoTooltip,NoTooltip)
//    ImGuiColorEditFlags_NoLabel         = 1 << 7,   //              // ColorEdit, ColorPicker: disable display of inline text label (the label is still forwarded to the tooltip and picker).
MAKE_ENUM(ImGuiColorEditFlags_NoLabel,NoLabel)
//    ImGuiColorEditFlags_NoSidePreview   = 1 << 8,   //              // ColorPicker: disable bigger color preview on right side of the picker, use small color square preview instead.
MAKE_ENUM(ImGuiColorEditFlags_NoSidePreview,NoSidePreview)
//    ImGuiColorEditFlags_NoDragDrop      = 1 << 9,   //              // ColorEdit: disable drag and drop target. ColorButton: disable drag and drop source.
MAKE_ENUM(ImGuiColorEditFlags_NoDragDrop,NoDragDrop)
//    ImGuiColorEditFlags_NoBorder        = 1 << 10,  //              // ColorButton: disable border (which is enforced by default)
MAKE_ENUM(ImGuiColorEditFlags_NoBorder,NoBorder)
//    ImGuiColorEditFlags_AlphaBar        = 1 << 16,  //              // ColorEdit, ColorPicker: show vertical alpha bar/gradient in picker.
MAKE_ENUM(ImGuiColorEditFlags_AlphaBar,AlphaBar)
//    ImGuiColorEditFlags_AlphaPreview    = 1 << 17,  //              // ColorEdit, ColorPicker, ColorButton: display preview as a transparent color over a checkerboard, instead of opaque.
MAKE_ENUM(ImGuiColorEditFlags_AlphaPreview,AlphaPreview)
//    ImGuiColorEditFlags_AlphaPreviewHalf= 1 << 18,  //              // ColorEdit, ColorPicker, ColorButton: display half opaque / half checkerboard, instead of opaque.
MAKE_ENUM(ImGuiColorEditFlags_AlphaPreviewHalf,AlphaPreviewHalf)
//    ImGuiColorEditFlags_HDR             = 1 << 19,  //              // (WIP) ColorEdit: Currently only disable 0.0f..1.0f limits in RGBA edition (note: you probably want to use ImGuiColorEditFlags_Float flag as well).
MAKE_ENUM(ImGuiColorEditFlags_HDR,HDR)
//    ImGuiColorEditFlags_DisplayRGB      = 1 << 20,  // [Display]    // ColorEdit: override _display_ type among RGB/HSV/Hex. ColorPicker: select any combination using one or more of RGB/HSV/Hex.
MAKE_ENUM(ImGuiColorEditFlags_DisplayRGB,DisplayRGB)
//    ImGuiColorEditFlags_DisplayHSV      = 1 << 21,  // [Display]    // "
MAKE_ENUM(ImGuiColorEditFlags_DisplayHSV,DisplayHSV)
//    ImGuiColorEditFlags_DisplayHex      = 1 << 22,  // [Display]    // "
MAKE_ENUM(ImGuiColorEditFlags_DisplayHex,DisplayHex)
//    ImGuiColorEditFlags_Uint8           = 1 << 23,  // [DataType]   // ColorEdit, ColorPicker, ColorButton: _display_ values formatted as 0..255.
MAKE_ENUM(ImGuiColorEditFlags_Uint8,Uint8)
//    ImGuiColorEditFlags_Float           = 1 << 24,  // [DataType]   // ColorEdit, ColorPicker, ColorButton: _display_ values formatted as 0.0f..1.0f floats instead of 0..255 integers. No round-trip of value via integers.
MAKE_ENUM(ImGuiColorEditFlags_Float,Float)
//    ImGuiColorEditFlags_PickerHueBar    = 1 << 25,  // [Picker]     // ColorPicker: bar for Hue, rectangle for Sat/Value.
MAKE_ENUM(ImGuiColorEditFlags_PickerHueBar,PickerHueBar)
//    ImGuiColorEditFlags_PickerHueWheel  = 1 << 26,  // [Picker]     // ColorPicker: wheel for Hue, triangle for Sat/Value.
MAKE_ENUM(ImGuiColorEditFlags_PickerHueWheel,PickerHueWheel)
//    ImGuiColorEditFlags_InputRGB        = 1 << 27,  // [Input]      // ColorEdit, ColorPicker: input and output data in RGB format.
MAKE_ENUM(ImGuiColorEditFlags_InputRGB,InputRGB)
//    ImGuiColorEditFlags_InputHSV        = 1 << 28,  // [Input]      // ColorEdit, ColorPicker: input and output data in HSV format.
MAKE_ENUM(ImGuiColorEditFlags_InputHSV,InputHSV)
END_ENUM(ColorEditFlags)
//enum ImGuiSliderFlags_

START_ENUM(SliderFlags)
//    ImGuiSliderFlags_None                   = 0,
MAKE_ENUM(ImGuiSliderFlags_None,None)
//    ImGuiSliderFlags_AlwaysClamp            = 1 << 4,       // Clamp value to min/max bounds when input manually with CTRL+Click. By default CTRL+Click allows going out of bounds.
MAKE_ENUM(ImGuiSliderFlags_AlwaysClamp,AlwaysClamp)
//    ImGuiSliderFlags_Logarithmic            = 1 << 5,       // Make the widget logarithmic (linear otherwise). Consider using ImGuiSliderFlags_NoRoundToFormat with this if using a format-string with small amount of digits.
MAKE_ENUM(ImGuiSliderFlags_Logarithmic,Logarithmic)
//    ImGuiSliderFlags_NoRoundToFormat        = 1 << 6,       // Disable rounding underlying value to match precision of the display format string (e.g. %.3f values are rounded to those 3 digits)
MAKE_ENUM(ImGuiSliderFlags_NoRoundToFormat,NoRoundToFormat)
//    ImGuiSliderFlags_NoInput                = 1 << 7,       // Disable CTRL+Click or Enter key allowing to input text directly into the widget
MAKE_ENUM(ImGuiSliderFlags_NoInput,NoInput)
//    ImGuiSliderFlags_ClampOnInput = ImGuiSliderFlags_AlwaysClamp, // [renamed in 1.79]
MAKE_ENUM(ImGuiSliderFlags_ClampOnInput,ClampOnInput)
END_ENUM(SliderFlags)
//enum ImGuiMouseButton_

START_ENUM(MouseButton)
//    ImGuiMouseButton_Left = 0,
MAKE_ENUM(ImGuiMouseButton_Left,Left)
//    ImGuiMouseButton_Right = 1,
MAKE_ENUM(ImGuiMouseButton_Right,Right)
//    ImGuiMouseButton_Middle = 2,
MAKE_ENUM(ImGuiMouseButton_Middle,Middle)
//    ImGuiMouseButton_COUNT = 5
MAKE_ENUM(ImGuiMouseButton_COUNT,COUNT)
END_ENUM(MouseButton)
//enum ImGuiMouseCursor_

START_ENUM(MouseCursor)
//    ImGuiMouseCursor_None = -1,
MAKE_ENUM(ImGuiMouseCursor_None,None)
//    ImGuiMouseCursor_Arrow = 0,
MAKE_ENUM(ImGuiMouseCursor_Arrow,Arrow)
//    ImGuiMouseCursor_TextInput,         // When hovering over InputText, etc.
MAKE_ENUM(ImGuiMouseCursor_TextInput,TextInput)
//    ImGuiMouseCursor_ResizeAll,         // (Unused by Dear ImGui functions)
MAKE_ENUM(ImGuiMouseCursor_ResizeAll,ResizeAll)
//    ImGuiMouseCursor_ResizeNS,          // When hovering over a horizontal border
MAKE_ENUM(ImGuiMouseCursor_ResizeNS,ResizeNS)
//    ImGuiMouseCursor_ResizeEW,          // When hovering over a vertical border or a column
MAKE_ENUM(ImGuiMouseCursor_ResizeEW,ResizeEW)
//    ImGuiMouseCursor_ResizeNESW,        // When hovering over the bottom-left corner of a window
MAKE_ENUM(ImGuiMouseCursor_ResizeNESW,ResizeNESW)
//    ImGuiMouseCursor_ResizeNWSE,        // When hovering over the bottom-right corner of a window
MAKE_ENUM(ImGuiMouseCursor_ResizeNWSE,ResizeNWSE)
//    ImGuiMouseCursor_Hand,              // (Unused by Dear ImGui functions. Use for e.g. hyperlinks)
MAKE_ENUM(ImGuiMouseCursor_Hand,Hand)
//    ImGuiMouseCursor_NotAllowed,        // When hovering something with disallowed interaction. Usually a crossed circle.
MAKE_ENUM(ImGuiMouseCursor_NotAllowed,NotAllowed)
//    ImGuiMouseCursor_COUNT
MAKE_ENUM(ImGuiMouseCursor_COUNT,COUNT)
END_ENUM(MouseCursor)
//enum ImGuiCond_

START_ENUM(Cond)
//    ImGuiCond_None          = 0,        // No condition (always set the variable), same as _Always
MAKE_ENUM(ImGuiCond_None,None)
//    ImGuiCond_Always        = 1 << 0,   // No condition (always set the variable), same as _None
MAKE_ENUM(ImGuiCond_Always,Always)
//    ImGuiCond_Once          = 1 << 1,   // Set the variable once per runtime session (only the first call will succeed)
MAKE_ENUM(ImGuiCond_Once,Once)
//    ImGuiCond_FirstUseEver  = 1 << 2,   // Set the variable if the object/window has no persistently saved data (no entry in .ini file)
MAKE_ENUM(ImGuiCond_FirstUseEver,FirstUseEver)
//    ImGuiCond_Appearing     = 1 << 3,   // Set the variable if the object/window is appearing after being hidden/inactive (or the first time)
MAKE_ENUM(ImGuiCond_Appearing,Appearing)
END_ENUM(Cond)
//struct ImVector

//struct ImGuiStyle

//struct ImGuiKeyData

//struct ImGuiIO

//struct ImGuiInputTextCallbackData

//struct ImGuiSizeCallbackData

//struct ImGuiWindowClass

//struct ImGuiPayload

//struct ImGuiTableColumnSortSpecs

//struct ImGuiTableSortSpecs

//struct ImGuiOnceUponAFrame

//struct ImGuiTextFilter

//struct ImGuiTextBuffer

//struct ImGuiStorage

//struct ImGuiListClipper

//struct ImColor

//struct ImDrawCmd

//struct ImDrawVert

//struct ImDrawCmdHeader

//struct ImDrawChannel

//struct ImDrawListSplitter

//enum ImDrawFlags_

//enum ImDrawListFlags_

//struct ImDrawList

//    IMGUI_API void  PushClipRect(const ImVec2& clip_rect_min, const ImVec2& clip_rect_max, bool intersect_with_current_clip_rect = false);  // Render-level scissoring. This is passed down to your render function but not used for CPU-side coarse clipping. Prefer using higher-level ImGui::PushClipRect() to affect logic (hit-testing and widget culling)
IMGUI_FUNCTION_DRAW_LIST(PushClipRect)
IM_VEC_2_ARG(clip_rect_min)
IM_VEC_2_ARG(clip_rect_max)
OPTIONAL_BOOL_ARG(intersect_with_current_clip_rect, false)
DRAW_LIST_CALL_FUNCTION_NO_RET(PushClipRect, clip_rect_min, clip_rect_max, intersect_with_current_clip_rect)
END_IMGUI_FUNC
//    IMGUI_API void  PushClipRectFullScreen();
IMGUI_FUNCTION_DRAW_LIST(PushClipRectFullScreen)
DRAW_LIST_CALL_FUNCTION_NO_RET(PushClipRectFullScreen)
END_IMGUI_FUNC
//    IMGUI_API void  PopClipRect();
IMGUI_FUNCTION_DRAW_LIST(PopClipRect)
DRAW_LIST_CALL_FUNCTION_NO_RET(PopClipRect)
END_IMGUI_FUNC
//    IMGUI_API void  PushTextureID(ImTextureID texture_id);
IMGUI_FUNCTION_DRAW_LIST(PushTextureID)
IM_TEXTURE_ID_ARG(texture_id)
DRAW_LIST_CALL_FUNCTION_NO_RET(PushTextureID, texture_id)
END_IMGUI_FUNC
//    IMGUI_API void  PopTextureID();
IMGUI_FUNCTION_DRAW_LIST(PopTextureID)
DRAW_LIST_CALL_FUNCTION_NO_RET(PopTextureID)
END_IMGUI_FUNC
//    inline ImVec2   GetClipRectMin() const { const ImVec4& cr = _ClipRectStack.back(); return ImVec2 cr.x  cr.y; }
// Unsupported arg type ) const { const ImVec4& cr = _ClipRectStack.back(
//    inline ImVec2   GetClipRectMax() const { const ImVec4& cr = _ClipRectStack.back(); return ImVec2 cr.z  cr.w; }
// Unsupported arg type ) const { const ImVec4& cr = _ClipRectStack.back(
//    IMGUI_API void  AddLine(const ImVec2& p1, const ImVec2& p2, ImU32 col, float thickness = 1.0f);
IMGUI_FUNCTION_DRAW_LIST(AddLine)
IM_VEC_2_ARG(p1)
IM_VEC_2_ARG(p2)
UINT_ARG(col)
OPTIONAL_NUMBER_ARG(thickness, 1.0f)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddLine, p1, p2, col, thickness)
END_IMGUI_FUNC
//    IMGUI_API void  AddRect(const ImVec2& p_min, const ImVec2& p_max, ImU32 col, float rounding = 0.0f, ImDrawFlags flags = 0, float thickness = 1.0f);   // a: upper-left, b: lower-right (== upper-left + size)
IMGUI_FUNCTION_DRAW_LIST(AddRect)
IM_VEC_2_ARG(p_min)
IM_VEC_2_ARG(p_max)
UINT_ARG(col)
OPTIONAL_NUMBER_ARG(rounding, 0.0f)
OPTIONAL_INT_ARG(flags, 0)
OPTIONAL_NUMBER_ARG(thickness, 1.0f)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddRect, p_min, p_max, col, rounding, flags, thickness)
END_IMGUI_FUNC
//    IMGUI_API void  AddRectFilled(const ImVec2& p_min, const ImVec2& p_max, ImU32 col, float rounding = 0.0f, ImDrawFlags flags = 0);                     // a: upper-left, b: lower-right (== upper-left + size)
IMGUI_FUNCTION_DRAW_LIST(AddRectFilled)
IM_VEC_2_ARG(p_min)
IM_VEC_2_ARG(p_max)
UINT_ARG(col)
OPTIONAL_NUMBER_ARG(rounding, 0.0f)
OPTIONAL_INT_ARG(flags, 0)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddRectFilled, p_min, p_max, col, rounding, flags)
END_IMGUI_FUNC
//    IMGUI_API void  AddRectFilledMultiColor(const ImVec2& p_min, const ImVec2& p_max, ImU32 col_upr_left, ImU32 col_upr_right, ImU32 col_bot_right, ImU32 col_bot_left);
IMGUI_FUNCTION_DRAW_LIST(AddRectFilledMultiColor)
IM_VEC_2_ARG(p_min)
IM_VEC_2_ARG(p_max)
UINT_ARG(col_upr_left)
UINT_ARG(col_upr_right)
UINT_ARG(col_bot_right)
UINT_ARG(col_bot_left)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddRectFilledMultiColor, p_min, p_max, col_upr_left, col_upr_right, col_bot_right, col_bot_left)
END_IMGUI_FUNC
//    IMGUI_API void  AddQuad(const ImVec2& p1, const ImVec2& p2, const ImVec2& p3, const ImVec2& p4, ImU32 col, float thickness = 1.0f);
IMGUI_FUNCTION_DRAW_LIST(AddQuad)
IM_VEC_2_ARG(p1)
IM_VEC_2_ARG(p2)
IM_VEC_2_ARG(p3)
IM_VEC_2_ARG(p4)
UINT_ARG(col)
OPTIONAL_NUMBER_ARG(thickness, 1.0f)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddQuad, p1, p2, p3, p4, col, thickness)
END_IMGUI_FUNC
//    IMGUI_API void  AddQuadFilled(const ImVec2& p1, const ImVec2& p2, const ImVec2& p3, const ImVec2& p4, ImU32 col);
IMGUI_FUNCTION_DRAW_LIST(AddQuadFilled)
IM_VEC_2_ARG(p1)
IM_VEC_2_ARG(p2)
IM_VEC_2_ARG(p3)
IM_VEC_2_ARG(p4)
UINT_ARG(col)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddQuadFilled, p1, p2, p3, p4, col)
END_IMGUI_FUNC
//    IMGUI_API void  AddTriangle(const ImVec2& p1, const ImVec2& p2, const ImVec2& p3, ImU32 col, float thickness = 1.0f);
IMGUI_FUNCTION_DRAW_LIST(AddTriangle)
IM_VEC_2_ARG(p1)
IM_VEC_2_ARG(p2)
IM_VEC_2_ARG(p3)
UINT_ARG(col)
OPTIONAL_NUMBER_ARG(thickness, 1.0f)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddTriangle, p1, p2, p3, col, thickness)
END_IMGUI_FUNC
//    IMGUI_API void  AddTriangleFilled(const ImVec2& p1, const ImVec2& p2, const ImVec2& p3, ImU32 col);
IMGUI_FUNCTION_DRAW_LIST(AddTriangleFilled)
IM_VEC_2_ARG(p1)
IM_VEC_2_ARG(p2)
IM_VEC_2_ARG(p3)
UINT_ARG(col)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddTriangleFilled, p1, p2, p3, col)
END_IMGUI_FUNC
//    IMGUI_API void  AddCircle(const ImVec2& center, float radius, ImU32 col, int num_segments = 0, float thickness = 1.0f);
IMGUI_FUNCTION_DRAW_LIST(AddCircle)
IM_VEC_2_ARG(center)
NUMBER_ARG(radius)
UINT_ARG(col)
OPTIONAL_INT_ARG(num_segments, 0)
OPTIONAL_NUMBER_ARG(thickness, 1.0f)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddCircle, center, radius, col, num_segments, thickness)
END_IMGUI_FUNC
//    IMGUI_API void  AddCircleFilled(const ImVec2& center, float radius, ImU32 col, int num_segments = 0);
IMGUI_FUNCTION_DRAW_LIST(AddCircleFilled)
IM_VEC_2_ARG(center)
NUMBER_ARG(radius)
UINT_ARG(col)
OPTIONAL_INT_ARG(num_segments, 0)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddCircleFilled, center, radius, col, num_segments)
END_IMGUI_FUNC
//    IMGUI_API void  AddNgon(const ImVec2& center, float radius, ImU32 col, int num_segments, float thickness = 1.0f);
IMGUI_FUNCTION_DRAW_LIST(AddNgon)
IM_VEC_2_ARG(center)
NUMBER_ARG(radius)
UINT_ARG(col)
INT_ARG(num_segments)
OPTIONAL_NUMBER_ARG(thickness, 1.0f)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddNgon, center, radius, col, num_segments, thickness)
END_IMGUI_FUNC
//    IMGUI_API void  AddNgonFilled(const ImVec2& center, float radius, ImU32 col, int num_segments);
IMGUI_FUNCTION_DRAW_LIST(AddNgonFilled)
IM_VEC_2_ARG(center)
NUMBER_ARG(radius)
UINT_ARG(col)
INT_ARG(num_segments)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddNgonFilled, center, radius, col, num_segments)
END_IMGUI_FUNC
//    IMGUI_API void  AddText(const ImVec2& pos, ImU32 col, const char* text_begin, const char* text_end = NULL);
IMGUI_FUNCTION_DRAW_LIST(AddText)
IM_VEC_2_ARG(pos)
UINT_ARG(col)
LABEL_ARG(text_begin)
OPTIONAL_LABEL_ARG(text_end)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddText, pos, col, text_begin, text_end)
END_IMGUI_FUNC
//    IMGUI_API void  AddText(const ImFont* font, float font_size, const ImVec2& pos, ImU32 col, const char* text_begin, const char* text_end = NULL, float wrap_width = 0.0f, const ImVec4* cpu_fine_clip_rect = NULL);
// Unsupported arg type const ImFont* font
// Unsupported arg type  const ImVec4* cpu_fine_clip_rect = NULL
//    IMGUI_API void  AddPolyline(const ImVec2* points, int num_points, ImU32 col, ImDrawFlags flags, float thickness);
// Unsupported arg type const ImVec2* points
//    IMGUI_API void  AddConvexPolyFilled(const ImVec2* points, int num_points, ImU32 col);
// Unsupported arg type const ImVec2* points
//    IMGUI_API void  AddBezierCubic(const ImVec2& p1, const ImVec2& p2, const ImVec2& p3, const ImVec2& p4, ImU32 col, float thickness, int num_segments = 0); // Cubic Bezier (4 control points)
IMGUI_FUNCTION_DRAW_LIST(AddBezierCubic)
IM_VEC_2_ARG(p1)
IM_VEC_2_ARG(p2)
IM_VEC_2_ARG(p3)
IM_VEC_2_ARG(p4)
UINT_ARG(col)
NUMBER_ARG(thickness)
OPTIONAL_INT_ARG(num_segments, 0)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddBezierCubic, p1, p2, p3, p4, col, thickness, num_segments)
END_IMGUI_FUNC
//    IMGUI_API void  AddBezierQuadratic(const ImVec2& p1, const ImVec2& p2, const ImVec2& p3, ImU32 col, float thickness, int num_segments = 0);               // Quadratic Bezier (3 control points)
IMGUI_FUNCTION_DRAW_LIST(AddBezierQuadratic)
IM_VEC_2_ARG(p1)
IM_VEC_2_ARG(p2)
IM_VEC_2_ARG(p3)
UINT_ARG(col)
NUMBER_ARG(thickness)
OPTIONAL_INT_ARG(num_segments, 0)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddBezierQuadratic, p1, p2, p3, col, thickness, num_segments)
END_IMGUI_FUNC
//    IMGUI_API void  AddImage(ImTextureID user_texture_id, const ImVec2& p_min, const ImVec2& p_max, const ImVec2& uv_min = ImVec2 0  0, const ImVec2& uv_max = ImVec2 1  1, ImU32 col = IM_COL32_WHITE);
IMGUI_FUNCTION_DRAW_LIST(AddImage)
IM_TEXTURE_ID_ARG(user_texture_id)
IM_VEC_2_ARG(p_min)
IM_VEC_2_ARG(p_max)
OPTIONAL_IM_VEC_2_ARG(uv_min, 0, 0)
OPTIONAL_IM_VEC_2_ARG(uv_max, 1, 1)
OPTIONAL_UINT_ARG(col, IM_COL32_WHITE)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddImage, user_texture_id, p_min, p_max, uv_min, uv_max, col)
END_IMGUI_FUNC
//    IMGUI_API void  AddImageQuad(ImTextureID user_texture_id, const ImVec2& p1, const ImVec2& p2, const ImVec2& p3, const ImVec2& p4, const ImVec2& uv1 = ImVec2 0  0, const ImVec2& uv2 = ImVec2 1  0, const ImVec2& uv3 = ImVec2 1  1, const ImVec2& uv4 = ImVec2 0  1, ImU32 col = IM_COL32_WHITE);
IMGUI_FUNCTION_DRAW_LIST(AddImageQuad)
IM_TEXTURE_ID_ARG(user_texture_id)
IM_VEC_2_ARG(p1)
IM_VEC_2_ARG(p2)
IM_VEC_2_ARG(p3)
IM_VEC_2_ARG(p4)
OPTIONAL_IM_VEC_2_ARG(uv1, 0, 0)
OPTIONAL_IM_VEC_2_ARG(uv2, 1, 0)
OPTIONAL_IM_VEC_2_ARG(uv3, 1, 1)
OPTIONAL_IM_VEC_2_ARG(uv4, 0, 1)
OPTIONAL_UINT_ARG(col, IM_COL32_WHITE)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddImageQuad, user_texture_id, p1, p2, p3, p4, uv1, uv2, uv3, uv4, col)
END_IMGUI_FUNC
//    IMGUI_API void  AddImageRounded(ImTextureID user_texture_id, const ImVec2& p_min, const ImVec2& p_max, const ImVec2& uv_min, const ImVec2& uv_max, ImU32 col, float rounding, ImDrawFlags flags = 0);
IMGUI_FUNCTION_DRAW_LIST(AddImageRounded)
IM_TEXTURE_ID_ARG(user_texture_id)
IM_VEC_2_ARG(p_min)
IM_VEC_2_ARG(p_max)
IM_VEC_2_ARG(uv_min)
IM_VEC_2_ARG(uv_max)
UINT_ARG(col)
NUMBER_ARG(rounding)
OPTIONAL_INT_ARG(flags, 0)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddImageRounded, user_texture_id, p_min, p_max, uv_min, uv_max, col, rounding, flags)
END_IMGUI_FUNC
//    inline    void  PathLineTo(const ImVec2& pos)                               { _Path.push_back(pos); }
// Unsupported arg type const ImVec2& pos)                               { _Path.push_back(pos
//    inline    void  PathLineToMergeDuplicate(const ImVec2& pos)                 { if (_Path.Size == 0 || memcmp(&_Path.Data[_Path.Size - 1], &pos, 8) != 0) _Path.push_back(pos); }
// Unsupported arg type const ImVec2& pos)                 { if (_Path.Size == 0 || memcmp(&_Path.Data[_Path.Size - 1]
// Unsupported arg type  &pos
// Unsupported arg type  8) != 0) _Path.push_back(pos
//    inline    void  PathFillConvex(ImU32 col)                                   { AddConvexPolyFilled(_Path.Data, _Path.Size, col); _Path.Size = 0; }
// Unsupported arg type ImU32 col)                                   { AddConvexPolyFilled(_Path.Data
// Unsupported arg type  _Path.Size
// Unsupported arg type  col
//    inline    void  PathStroke(ImU32 col, ImDrawFlags flags = 0, float thickness = 1.0f) { AddPolyline(_Path.Data, _Path.Size, col, flags, thickness); _Path.Size = 0; }
// Unsupported arg type  float thickness = 1.0f) { AddPolyline(_Path.Data
// Unsupported arg type  _Path.Size
// Unsupported arg type  col
// Unsupported arg type  flags
// Unsupported arg type  thickness
//    IMGUI_API void  PathArcTo(const ImVec2& center, float radius, float a_min, float a_max, int num_segments = 0);
IMGUI_FUNCTION_DRAW_LIST(PathArcTo)
IM_VEC_2_ARG(center)
NUMBER_ARG(radius)
NUMBER_ARG(a_min)
NUMBER_ARG(a_max)
OPTIONAL_INT_ARG(num_segments, 0)
DRAW_LIST_CALL_FUNCTION_NO_RET(PathArcTo, center, radius, a_min, a_max, num_segments)
END_IMGUI_FUNC
//    IMGUI_API void  PathArcToFast(const ImVec2& center, float radius, int a_min_of_12, int a_max_of_12);                // Use precomputed angles for a 12 steps circle
IMGUI_FUNCTION_DRAW_LIST(PathArcToFast)
IM_VEC_2_ARG(center)
NUMBER_ARG(radius)
INT_ARG(a_min_of_12)
INT_ARG(a_max_of_12)
DRAW_LIST_CALL_FUNCTION_NO_RET(PathArcToFast, center, radius, a_min_of_12, a_max_of_12)
END_IMGUI_FUNC
//    IMGUI_API void  PathBezierCubicCurveTo(const ImVec2& p2, const ImVec2& p3, const ImVec2& p4, int num_segments = 0); // Cubic Bezier (4 control points)
IMGUI_FUNCTION_DRAW_LIST(PathBezierCubicCurveTo)
IM_VEC_2_ARG(p2)
IM_VEC_2_ARG(p3)
IM_VEC_2_ARG(p4)
OPTIONAL_INT_ARG(num_segments, 0)
DRAW_LIST_CALL_FUNCTION_NO_RET(PathBezierCubicCurveTo, p2, p3, p4, num_segments)
END_IMGUI_FUNC
//    IMGUI_API void  PathBezierQuadraticCurveTo(const ImVec2& p2, const ImVec2& p3, int num_segments = 0);               // Quadratic Bezier (3 control points)
IMGUI_FUNCTION_DRAW_LIST(PathBezierQuadraticCurveTo)
IM_VEC_2_ARG(p2)
IM_VEC_2_ARG(p3)
OPTIONAL_INT_ARG(num_segments, 0)
DRAW_LIST_CALL_FUNCTION_NO_RET(PathBezierQuadraticCurveTo, p2, p3, num_segments)
END_IMGUI_FUNC
//    IMGUI_API void  PathRect(const ImVec2& rect_min, const ImVec2& rect_max, float rounding = 0.0f, ImDrawFlags flags = 0);
IMGUI_FUNCTION_DRAW_LIST(PathRect)
IM_VEC_2_ARG(rect_min)
IM_VEC_2_ARG(rect_max)
OPTIONAL_NUMBER_ARG(rounding, 0.0f)
OPTIONAL_INT_ARG(flags, 0)
DRAW_LIST_CALL_FUNCTION_NO_RET(PathRect, rect_min, rect_max, rounding, flags)
END_IMGUI_FUNC
//    IMGUI_API void  AddCallback(ImDrawCallback callback, void* callback_data);  // Your rendering function must check for 'UserCallback' in ImDrawCmd and call the function instead of rendering triangles.
// Unsupported arg type ImDrawCallback callback
// Unsupported arg type  void* callback_data
//    IMGUI_API void  AddDrawCmd();                                               // This is useful if you need to forcefully create a new draw call (to allow for dependent rendering / blending). Otherwise primitives are merged into the same draw-call as much as possible
IMGUI_FUNCTION_DRAW_LIST(AddDrawCmd)
DRAW_LIST_CALL_FUNCTION_NO_RET(AddDrawCmd)
END_IMGUI_FUNC
//    inline void     ChannelsSplit(int count)    { _Splitter.Split(this, count); }
// Unsupported arg type int count)    { _Splitter.Split(this
// Unsupported arg type  count
//    inline void     ChannelsMerge()             { _Splitter.Merge(this); }
// Unsupported arg type )             { _Splitter.Merge(this
//    inline void     ChannelsSetCurrent(int n)   { _Splitter.SetCurrentChannel(this, n); }
// Unsupported arg type int n)   { _Splitter.SetCurrentChannel(this
// Unsupported arg type  n
//    IMGUI_API void  PrimReserve(int idx_count, int vtx_count);
IMGUI_FUNCTION_DRAW_LIST(PrimReserve)
INT_ARG(idx_count)
INT_ARG(vtx_count)
DRAW_LIST_CALL_FUNCTION_NO_RET(PrimReserve, idx_count, vtx_count)
END_IMGUI_FUNC
//    IMGUI_API void  PrimUnreserve(int idx_count, int vtx_count);
IMGUI_FUNCTION_DRAW_LIST(PrimUnreserve)
INT_ARG(idx_count)
INT_ARG(vtx_count)
DRAW_LIST_CALL_FUNCTION_NO_RET(PrimUnreserve, idx_count, vtx_count)
END_IMGUI_FUNC
//    IMGUI_API void  PrimRect(const ImVec2& a, const ImVec2& b, ImU32 col);      // Axis aligned rectangle (composed of two triangles)
IMGUI_FUNCTION_DRAW_LIST(PrimRect)
IM_VEC_2_ARG(a)
IM_VEC_2_ARG(b)
UINT_ARG(col)
DRAW_LIST_CALL_FUNCTION_NO_RET(PrimRect, a, b, col)
END_IMGUI_FUNC
//    IMGUI_API void  PrimRectUV(const ImVec2& a, const ImVec2& b, const ImVec2& uv_a, const ImVec2& uv_b, ImU32 col);
IMGUI_FUNCTION_DRAW_LIST(PrimRectUV)
IM_VEC_2_ARG(a)
IM_VEC_2_ARG(b)
IM_VEC_2_ARG(uv_a)
IM_VEC_2_ARG(uv_b)
UINT_ARG(col)
DRAW_LIST_CALL_FUNCTION_NO_RET(PrimRectUV, a, b, uv_a, uv_b, col)
END_IMGUI_FUNC
//    IMGUI_API void  PrimQuadUV(const ImVec2& a, const ImVec2& b, const ImVec2& c, const ImVec2& d, const ImVec2& uv_a, const ImVec2& uv_b, const ImVec2& uv_c, const ImVec2& uv_d, ImU32 col);
IMGUI_FUNCTION_DRAW_LIST(PrimQuadUV)
IM_VEC_2_ARG(a)
IM_VEC_2_ARG(b)
IM_VEC_2_ARG(c)
IM_VEC_2_ARG(d)
IM_VEC_2_ARG(uv_a)
IM_VEC_2_ARG(uv_b)
IM_VEC_2_ARG(uv_c)
IM_VEC_2_ARG(uv_d)
UINT_ARG(col)
DRAW_LIST_CALL_FUNCTION_NO_RET(PrimQuadUV, a, b, c, d, uv_a, uv_b, uv_c, uv_d, col)
END_IMGUI_FUNC
//    inline    void  PrimVtx(const ImVec2& pos, const ImVec2& uv, ImU32 col)         { PrimWriteIdx((ImDrawIdx)_VtxCurrentIdx); PrimWriteVtx(pos, uv, col); } // Write vertex with unique index
// Unsupported arg type  ImU32 col)         { PrimWriteIdx((ImDrawIdx)_VtxCurrentIdx
//    inline    void  AddBezierCurve(const ImVec2& p1, const ImVec2& p2, const ImVec2& p3, const ImVec2& p4, ImU32 col, float thickness, int num_segments = 0) { AddBezierCubic(p1, p2, p3, p4, col, thickness, num_segments); } // OBSOLETED in 1.80 (Jan 2021)
// Unsupported arg type  int num_segments = 0) { AddBezierCubic(p1
// Unsupported arg type  p2
// Unsupported arg type  p3
// Unsupported arg type  p4
// Unsupported arg type  col
// Unsupported arg type  thickness
// Unsupported arg type  num_segments
//    inline    void  PathBezierCurveTo(const ImVec2& p2, const ImVec2& p3, const ImVec2& p4, int num_segments = 0) { PathBezierCubicCurveTo(p2, p3, p4, num_segments); } // OBSOLETED in 1.80 (Jan 2021)
// Unsupported arg type  int num_segments = 0) { PathBezierCubicCurveTo(p2
// Unsupported arg type  p3
// Unsupported arg type  p4
// Unsupported arg type  num_segments
//    IMGUI_API void  _ResetForNewFrame();
IMGUI_FUNCTION_DRAW_LIST(_ResetForNewFrame)
DRAW_LIST_CALL_FUNCTION_NO_RET(_ResetForNewFrame)
END_IMGUI_FUNC
//    IMGUI_API void  _ClearFreeMemory();
IMGUI_FUNCTION_DRAW_LIST(_ClearFreeMemory)
DRAW_LIST_CALL_FUNCTION_NO_RET(_ClearFreeMemory)
END_IMGUI_FUNC
//    IMGUI_API void  _PopUnusedDrawCmd();
IMGUI_FUNCTION_DRAW_LIST(_PopUnusedDrawCmd)
DRAW_LIST_CALL_FUNCTION_NO_RET(_PopUnusedDrawCmd)
END_IMGUI_FUNC
//    IMGUI_API void  _TryMergeDrawCmds();
IMGUI_FUNCTION_DRAW_LIST(_TryMergeDrawCmds)
DRAW_LIST_CALL_FUNCTION_NO_RET(_TryMergeDrawCmds)
END_IMGUI_FUNC
//    IMGUI_API void  _OnChangedClipRect();
IMGUI_FUNCTION_DRAW_LIST(_OnChangedClipRect)
DRAW_LIST_CALL_FUNCTION_NO_RET(_OnChangedClipRect)
END_IMGUI_FUNC
//    IMGUI_API void  _OnChangedTextureID();
IMGUI_FUNCTION_DRAW_LIST(_OnChangedTextureID)
DRAW_LIST_CALL_FUNCTION_NO_RET(_OnChangedTextureID)
END_IMGUI_FUNC
//    IMGUI_API void  _OnChangedVtxOffset();
IMGUI_FUNCTION_DRAW_LIST(_OnChangedVtxOffset)
DRAW_LIST_CALL_FUNCTION_NO_RET(_OnChangedVtxOffset)
END_IMGUI_FUNC
//    IMGUI_API void  _PathArcToFastEx(const ImVec2& center, float radius, int a_min_sample, int a_max_sample, int a_step);
IMGUI_FUNCTION_DRAW_LIST(_PathArcToFastEx)
IM_VEC_2_ARG(center)
NUMBER_ARG(radius)
INT_ARG(a_min_sample)
INT_ARG(a_max_sample)
INT_ARG(a_step)
DRAW_LIST_CALL_FUNCTION_NO_RET(_PathArcToFastEx, center, radius, a_min_sample, a_max_sample, a_step)
END_IMGUI_FUNC
//    IMGUI_API void  _PathArcToN(const ImVec2& center, float radius, float a_min, float a_max, int num_segments);
IMGUI_FUNCTION_DRAW_LIST(_PathArcToN)
IM_VEC_2_ARG(center)
NUMBER_ARG(radius)
NUMBER_ARG(a_min)
NUMBER_ARG(a_max)
INT_ARG(num_segments)
DRAW_LIST_CALL_FUNCTION_NO_RET(_PathArcToN, center, radius, a_min, a_max, num_segments)
END_IMGUI_FUNC
//struct ImDrawData

//struct ImFontConfig

//struct ImFontGlyph

//struct ImFontGlyphRangesBuilder

//struct ImFontAtlasCustomRect

//enum ImFontAtlasFlags_

//struct ImFontAtlas

//struct ImFont

//enum ImGuiViewportFlags_

START_ENUM(ViewportFlags)
//    ImGuiViewportFlags_None                     = 0,
MAKE_ENUM(ImGuiViewportFlags_None,None)
//    ImGuiViewportFlags_IsPlatformWindow         = 1 << 0,   // Represent a Platform Window
MAKE_ENUM(ImGuiViewportFlags_IsPlatformWindow,IsPlatformWindow)
//    ImGuiViewportFlags_IsPlatformMonitor        = 1 << 1,   // Represent a Platform Monitor (unused yet)
MAKE_ENUM(ImGuiViewportFlags_IsPlatformMonitor,IsPlatformMonitor)
//    ImGuiViewportFlags_OwnedByApp               = 1 << 2,   // Platform Window: is created/managed by the application (rather than a dear imgui backend)
MAKE_ENUM(ImGuiViewportFlags_OwnedByApp,OwnedByApp)
//    ImGuiViewportFlags_NoDecoration             = 1 << 3,   // Platform Window: Disable platform decorations: title bar, borders, etc. (generally set all windows, but if ImGuiConfigFlags_ViewportsDecoration is set we only set this on popups/tooltips)
MAKE_ENUM(ImGuiViewportFlags_NoDecoration,NoDecoration)
//    ImGuiViewportFlags_NoTaskBarIcon            = 1 << 4,   // Platform Window: Disable platform task bar icon (generally set on popups/tooltips, or all windows if ImGuiConfigFlags_ViewportsNoTaskBarIcon is set)
MAKE_ENUM(ImGuiViewportFlags_NoTaskBarIcon,NoTaskBarIcon)
//    ImGuiViewportFlags_NoFocusOnAppearing       = 1 << 5,   // Platform Window: Don't take focus when created.
MAKE_ENUM(ImGuiViewportFlags_NoFocusOnAppearing,NoFocusOnAppearing)
//    ImGuiViewportFlags_NoFocusOnClick           = 1 << 6,   // Platform Window: Don't take focus when clicked on.
MAKE_ENUM(ImGuiViewportFlags_NoFocusOnClick,NoFocusOnClick)
//    ImGuiViewportFlags_NoInputs                 = 1 << 7,   // Platform Window: Make mouse pass through so we can drag this window while peaking behind it.
MAKE_ENUM(ImGuiViewportFlags_NoInputs,NoInputs)
//    ImGuiViewportFlags_NoRendererClear          = 1 << 8,   // Platform Window: Renderer doesn't need to clear the framebuffer ahead (because we will fill it entirely).
MAKE_ENUM(ImGuiViewportFlags_NoRendererClear,NoRendererClear)
//    ImGuiViewportFlags_TopMost                  = 1 << 9,   // Platform Window: Display on top (for tooltips only).
MAKE_ENUM(ImGuiViewportFlags_TopMost,TopMost)
//    ImGuiViewportFlags_Minimized                = 1 << 10,  // Platform Window: Window is minimized, can skip render. When minimized we tend to avoid using the viewport pos/size for clipping window or testing if they are contained in the viewport.
MAKE_ENUM(ImGuiViewportFlags_Minimized,Minimized)
//    ImGuiViewportFlags_NoAutoMerge              = 1 << 11,  // Platform Window: Avoid merging this window into another host window. This can only be set via ImGuiWindowClass viewport flags override (because we need to now ahead if we are going to create a viewport in the first place!).
MAKE_ENUM(ImGuiViewportFlags_NoAutoMerge,NoAutoMerge)
//    ImGuiViewportFlags_CanHostOtherWindows      = 1 << 12,  // Main viewport: can host multiple imgui windows (secondary viewports are associated to a single window).
MAKE_ENUM(ImGuiViewportFlags_CanHostOtherWindows,CanHostOtherWindows)
END_ENUM(ViewportFlags)
//struct ImGuiViewport

//struct ImGuiPlatformIO

//struct ImGuiPlatformMonitor

//struct ImGuiPlatformImeData

//namespace ImGui

//namespace ImGui

//enum ImDrawCornerFlags_

