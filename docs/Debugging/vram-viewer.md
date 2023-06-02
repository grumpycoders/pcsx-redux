# VRAM viewer

## Navigating

Holding the middle button, or both the left and right buttons, allows you to pan the view around. Using the wheel allows you to zoom in and out, at the location of the mouse cursor.

## Lensing

Holding the CTRL key of your keyboard will bring up a lens, which will show you a locally zoomed version of the VRAM at the location of the mouse cursor. The lens can be resized by using the wheel while holding the CTRL key. Holding the CTRL and Shift buttons while using the wheel will change the size of the lens. The lens can be closed by releasing the CTRL key.

## The various viewers

There are different viewers available from the main menu, which can be used to visualize the VRAM in different ways. The main viewer will let you see the VRAM using various CLUTs. The CLUT viewer will let you select a CLUT to use for the main VRAM viewer. In order to do this, first select the 8-bits or 4-bits view in the main viewer. Then, in the CLUT viewer, select `View -> Select a CLUT`. At this point, hovering the CLUT viewer will automatically change the main viewer to use the hovered CLUT. Once the proper view is found, simply click on the first pixel of the CLUT viewer to select the CLUT more permanently.

The [GPU logger](gpu-logger.md) will also select CLUTs and change the main viewer's mode automatically, depending on the GPU commands being inspected.