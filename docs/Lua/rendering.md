# Rendering

PCSX-Redux is entirely running as an OpenGL3 application. All of its
aspects, including the UI elements, are rendered using OpenGL
primitives. This means there is very little boundaries between the
various rendered elements on the screen.

The rendering of the UI is done through [ImGui](https://github.com/ocornut/imgui), and a chunk of its API is
bound is to Lua using [bindings](https://github.com/grumpycoders/pcsx-redux/tree/main/third_party/imgui_lua_bindings).

A good portion of the OpenGL3 API is also bound to Lua, as well as the
[nanovg library](https://github.com/grumpycoders/nanovg/tree/master).

## Emulated GPU rendering pipeline

The content of the Output region is rendered in two steps. The first
step is called the "Offscreen rendering", and is done during the
emulated GPU vsyncs. Its job is to flush the contents of the VRAM
texture to an offscreen texture, which may be of a different
resolution. The resolution of the offscreen texture should be pixel
perfect with that of the Output region. By default, the associated
shader with this operation should only do a simple copy and
interpolation, but as the first stage of the rendering pipeline, this
can be used for some first pass output effect such as the first pass of
a crt shader.

The second step is called the "Output rendering", and is done every
time the UI wants to refresh its display, which may or may not be at
the same time as the emulated vsync. The resolution of the input will
match exactly the resolution of the input texture, and the default
shader should simply copy all the texels without any sort of
interpolation, but as the second stage of the rendering pipeline, this
can still be used for the second pass output effect.

The [crt-lottes](https://github.com/grumpycoders/pcsx-redux/blob/main/src/gui/shaders)
implementation leverages these two passes to do the full CRT-like
output.

## Shader editor

The shader editor is a simple text editor that allows to edit the
shader code. It is not a full IDE, and it is not meant to be. Its
point is to do quick iterations on the shader code, and to be able to
see the result of the changes in real time.

The shader editor is split in 3 regions:

  - The left tab is the vertex shader code. It is technically editable,
  but there shouldn't be much reason to edit it.

  - The middle tab is the fragment shader code. This is the main shader
  code. It is editable, and the changes will be reflected in real time.

  - The right tab is the Lua invoker code. This is the code that will
  be executed under multiple circumstances. It is editable, and the
  changes will be reflected in real time.

The Lua invoker code will be compiled and executed in a soft sandbox
environment. The code can still access already created globals and mutate them,
but any newly created global will be kept within the sandbox and won't be
accessible from other Lua code. All these globals will be saved and restored
with the normal emulator settings.

When the shaders are compiled, the Vertex and Fragment shader code will be
compiled together, and if the resulting program is valid, the Lua invoker code
will be compiled and executed. If the Lua code fails to compile or execute, the
shader will be considered invalid and the error will be displayed in the
shader editor.

This compilation order allows the Lua code to access the shader program
uniforms, and to set them up as needed. The global `shaderProgramID` will be
available to the Lua code, and will contain the ID of the shader program.

The code is expected to export a few functions:

  - `Draw`, which will be called periodically within the ImGui context,
  allowing to draw UI elements. The global `configureme` will be set to true
  when the user selects the "Configure Shaders" menu item. This allows to
  display a configuration UI to the user during this function call.

  - `Image(textureID, srcSizeX, srcSizeY, dstSizeX, dstSizeY)`, which will be
  called periodically within the ImGui context, when the emulator needs to draw the texture
  `textureID` at the given size. The texture ID is the OpenGL texture ID, and
  the size is in pixels. The code is at best expected to do a simple call
  to `imgui.Image(textureID, dstSizeX, dstSizeY, 0, 0, 1, 1)` to draw the
  texture. For the Emulated GPU Pipeline, this function will only be called on
  the Output shader, when being drawn to the Output region. As the function will be called
  during the ImGui context, it can capture certain ImGui state, such as the
  current ImGui cursor position, and use it to draw additional UI elements.
  Note that as with any normal ImGui function, this isn't the moment when the
  UI elements are actually drawn, but rather when the UI elements are queued
  to be drawn, meaning this isn't when the shader program will be executed,
  which is the point of the next function.

  - `BindAttributes(textureID, shaderProgramID, srcLocX, srcLocY, srcSizeX, srcSizeY, dstSizeX, dstSizeY)`
  will be called when the shader program is about to be executed, and needs
  to bind the attributes. The texture ID is the OpenGL texture ID, and the
  shader program ID is the OpenGL shader program ID. The location and sizes are in pixels, but are only
  used for the Emulated GPU Pipeline, when the Offscreen shader is being
  executed, as it needs to grab a portion of the VRAM texture to be rendered
  to the offscreen texture.

Additionally, it is possible to programmatically set the content of the editors using the following methods:

```lua
PCSX.GUI.OffscreenShader.setDefaults()
PCSX.GUI.OffscreenShader.setTextVS(text)
PCSX.GUI.OffscreenShader.setTextPS(text)
PCSX.GUI.OffscreenShader.setTextL(text)
PCSX.GUI.OutputShader.setDefaults()
PCSX.GUI.OutputShader.setTextVS(text)
PCSX.GUI.OutputShader.setTextPS(text)
PCSX.GUI.OutputShader.setTextL(text)
```

The `setDefaults` method will set the default shader code, and the `setText*` methods will set the
shader code to the given string. The `text` argument can be either an actual string, or a [`File` object](file-api.md).

## ImGui

The ImGui API is bound to Lua, and can be used to draw UI elements. The
ImGui API is documented on the [ImGui source code](https://github.com/ocornut/imgui/blob/docking/imgui.h).
There is also an [interactive manual available](https://pthom.github.io/imgui_manual_online/manual/imgui_manual.html).

Not all functions are necessarily bound to Lua, and one can check the
[bindings code](https://github.com/grumpycoders/pcsx-redux/blob/main/third_party/imgui_lua_bindings/imgui_iterator.inl)
to see which functions are bound, and why some functions are not bound.

The main reason for not binding a function is that its arguments or return
values are not trivial to bind. For example, the `ImGui::Text` C++ function is not
bound, as it takes a variadic number of arguments, which is not possible to
bind in Lua easily. Instead, the `ImGui::TextUnformatted` C++ function is bound, which
takes a single string argument.

The emulator will periodically try to call the global function `DrawImguiFrame` with no
arguments. If the function is not defined, nothing will happen. If the function
fails to execute, it will be removed from the global environment, and the
emulator will stop trying to call it until a new global is defined.

The `DrawImguiFrame` function is expected to call the `imgui.Begin` function
to create a new ImGui window, as there is no default window created by the
emulator for the Lua context. The `DrawImguiFrame` function is also expected
to call the `imgui.End` function as normal with the ImGui API.

Some extra functions are bound to Lua beyond the API listed above:

  - `imgui.extra.ImVec2.New(x, y)` will create a new FFI `ImVec2` object. The `ImVec2`
  object is a simple struct with two fields, `x` and `y`. The `New` function
  takes two optional arguments, the `x` and `y` values, and returns the new `ImVec2`
  object.

  - `imgui.extra.getCurrentViewportId()` will return the current viewport ID.
  Viewports in ImGui are a way to split the ImGui context into multiple
  independent contexts, and the viewport ID is a unique identifier for each
  viewport. Basically, each viewport is a physical window from the operating
  system, and it can contain one or more ImGui windows.

  - `imgui.extra.getViewportFlags(id)` will return the viewport flags for the
  specified viewport. The viewport flags are of the type `ImGuiViewportFlags_`
  in the ImGui C++ API, and is a bitmask of flags, which are exposed as
  individual values in the Lua generated bindings.

  - `imgui.extra.setViewportFlags(id, flags)` will set the viewport flags for
  the specified viewport. The proper usage of this function is to call
  `imgui.extra.getViewportFlags` to get the current flags, modify the flags
  as needed, and then call `imgui.extra.setViewportFlags` to set the new flags.

  - `imgui.extra.getViewportPos(id)` will return the position of the specified
  viewport. The position is returned as an `ImVec2` object.

  - `imgui.extra.getViewportSize(id)` will return the size of the specified
  viewport. The size is returned as an `ImVec2` object.

  - `imgui.extra.getViewportWorkPos(id)` will return the work position of the
  specified viewport. The work position is returned as an `ImVec2` object.

  - `imgui.extra.getViewportWorkSize(id)` will return the work size of the
  specified viewport. The work size is returned as an `ImVec2` object.

  - `imgui.extra.getViewportDpiScale(id)` will return the DPI scale of the
  specified viewport. The DPI scale is returned as a number. A value of 1.0
  means that the DPI scale for this viewport is 100%.

  - `imgui.extra.InputText(label, text[, flags])` will create an input text
  widget. The `label` is the label to display next to the input text, and the
  `text` is the current text to display in the input text. The `flags` are
  optional, and are the same flags as the ones used by the `imgui::InputText`
  C++ function. The function will return a boolean indicating if the text has
  changed or not, and the new text.

  - `imgui.extra.InputTextWithHint(label, hint, text[, flags])` will create an
  input text widget. The `label` is the label to display next to the input
  text, and the `hint` is the hint to display in the input text when the text
  is empty. The `text` is the current text to display in the input text. The
  `flags` are optional, and are the same flags as the ones used by the
  `imgui::InputTextWithHint` C++ function. The function will return a boolean
  indicating if the text has changed or not, and the new text.

## NanoVG

The NanoVG library is bound to Lua, and can be used to draw arbitrary vector graphics
on top of the emulator. The NanoVG API is documented on the [NanoVG source code](https://github.com/grumpycoders/nanovg/blob/master/src/nanovg.h). The API is very similar to the HTML5 Canvas API, meaning that
one can use the [MDN CanvasRenderingContext2D documentation](https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D) and [other](https://www.w3schools.com/html/html5_canvas.asp) [related documentation](https://developer.mozilla.org/en-US/docs/Web/API/Canvas_API/Tutorial/Drawing_shapes) to learn how to use it.

Using an HTML5 canvas toybox like [this one](https://codepen.io/nicolas_noble/pen/MWXqwQG) is a good way to learn how to use this API safely.

Note that the NanoVG rendering will happen after the ImGui rendering, meaning
that the NanoVG rendering will be on top of the ImGui rendering, regardless
of the order in which the NanoVG and ImGui functions are called.

Most of the NanoVG API is bound to Lua, with the exception of the following functions:

- `nvgBeginFrame`
- `nvgCancelFrame`
- `nvgEndFrame`
- `nvgCreateImage`
- `nvgCreateImageMem`

In addition, the enums and some constructors for the structures used in NanoVG are available
as extra values and functions. Please refer [to the Lua source code](https://github.com/grumpycoders/pcsx-redux/blob/main/src/gui/nvgffi.lua)
for more details.

The general idea is that the emulator will call `nvgBeginFrame` and `nvgEndFrame` before
and after the Lua code is executed, and the Lua code will be able to call
the other functions to draw the vector graphics.

The proper way to use the NanoVG API is to call `nvg:queueNvgRender(function() ... end)`,
when in an ImGui window in order to queue the NanoVG rendering for this specific window.

The `nvg:queueNvgRender` function takes a single argument, which is a function
that will be called when the NanoVG rendering is being executed. The function
will be called without argument.

All of the NanoVG functions are bound to the `nvg` object, which is a proxy
object to the proper NanoVG context, meaning it is only valid within the
function passed to `nvg:queueNvgRender`.

This allows the user to call the NanoVG functions without having to pass the
NanoVG context as the first argument, as it is done automatically by the
proxy object.

Note that the font used by the emulator is also loaded into the NanoVG context,
meaning that it is possible to use `nvg:Text` without having to load a font
first.

## Example of using everything together

As the NanoVG rendering is very low level, and requires a viewport to draw to,
it is required to use the ImGui API to draw some UI, grab the positions of the
vector graphics to add, and then queue some NanoVG calls within some ImGui
context to draw the wanted vector graphics.

The following example will draw a red rectangle in the middle of the Output
region. The rectangle will be 100x100 pixels in size, and will be drawn on top
of the emulator rendering. It should follow around the Output region when
resizing or moving the window.

In order to work, this example requires the code to be executed in the `Image` function
of the Output shader invoker, so we can get the position of the Output region
to draw to.

```lua
function Image(textureID, srcSizeX, srcSizeY, dstSizeX, dstSizeY)
    -- This helper is provided by the emulator, and will properly calculate
    -- arbitrary coordinates within an ImGui image that is dstSizeX x dstSizeY
    -- in size. The first two arguments are the coordinates to convert, and
    -- the middle two arguments are the boundaries of the source image.

    -- Here, we are using (1.0, 1.0) as the source image size, but it could
    -- be any other size, as long as the coordinates are within the boundaries
    -- of the source image. For example, if the source image is 320x240, then
    -- the coordinates should be within (0, 0) and (320, 240), and the helper
    -- will properly convert the coordinates to the destination image size.

    local cx, cy = PCSX.Helpers.UI.imageCoordinates(0.5, 0.5, 1.0, 1.0, dstSizeX, dstSizeY)

    -- As explained, we can't call NanoVG functions directly, so we need to
    -- queue the rendering of the vector graphics.
    nvg:queueNvgRender(function()
        nvg:beginPath()
        nvg:rect(cx - 50, cy - 50, 100, 100)
        nvg:fillColor(nvg.Color.New(1, 0, 0, 1))
        nvg:fill()
    end)
    imgui.Image(textureID, dstSizeX, dstSizeY, 0, 0, 1, 1)
end
```
