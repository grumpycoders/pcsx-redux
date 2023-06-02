# GPU Logger

The GPU logger is a tool that allows you to see the GPU commands being executed by the emulator, and the resulting VRAM changes. It can be used to debug the GPU, and to understand how the executed software is rendering the scene. The logger will have a full frame worth of primitives, and will automatically clear the log when a new frame is started. Note that the notion of a frame may span over multiple vsyncs, if the PlayStation software isn't running at full FPS.

Note that it can be fairly resource intensive, and may significantly slow down the emulation, depending on the context.

The top of the GPU Logger window will have the following checkboxes:

- GPU Logging - Enable or disable the GPU logging.
- Breakpoint on vsync - Pause the emulation when a vsync occurs, allowing to inspect the current frame.
- Replay frame - Enables the replay of the current frame. See below for details.
- Show origins - Show the data path of the primitives. This will show the origin of the data, and the path it took to reach the GPU. For example, a sequence of primitives may be sent to the GPU via chained DMA.

## Understanding the logs

The top of the logger can be expanded to display rough frame statistics. These values aren't necessarily too accurate, and are only meant to give a rough idea of the frame complexity.

Each row of the logger displays one command sent to the GPU. The first button and checkbox will be used for the replay system. The next three buttons and checkboxes will be used for the highlighting system. The next column will display the command name, and opening the tree node will expand the command parameters.

The expanded node may have buttons which will affect the [main VRAM viewer](vram-viewer.md), either by selecting CLUTs, or zooming in on the corresponding region. The VRAM viewer will also be updated when the replay system is used.

## Highlighting Primitives

The GPU logger can highlight primitives in the VRAM viewer. One or more primitives may be selected, and the corresponding VRAM regions will be outlined. The highlighting will be cleared when a new frame is started. The default outlined colors will be red for written pixels, and green for read pixels. The colors can be changed in the main VRAM viewer settings.

Checking the `Highlight on hover` checkbox will temporarily outline a primitive when hovering it in the logger. This can be useful to quickly identify the corresponding primitive in the VRAM viewer by flicking the mouse over the logger.

Checking the second checkbox in a logger node will permanently highlight the corresponding primitive in the VRAM viewer. The `[B]` and `[E]` buttons will select the beginning and the end of a span of primitives, and highlight them in the VRAM viewer.

## Replay System

Once a frame has been logged properly, and the emulator is paused, the replay system can be used to replay the frame. The replay system will constantly replay the frame as long as it is activated, and it will update the VRAM viewer accordingly. By default, all nodes in the logger will be selected for replaying. Unselecting the first checkbox in a node will prevent it from being replayed, and the VRAM viewer will show what happens when this primitive isn't executed, and potentially see what is underneath it. Clicking the `[T]` button of a node will select all nodes for replaying until this node, allowing to easily see the frame being built up to this point.
