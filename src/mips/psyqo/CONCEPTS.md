The library has only three mandatory classes, and everything else is optional. The library tries to heavily follow the "pay only what you use" pattern. As a result, aside from the `GPU` class, things like font drawing, cdrom access, or input processing have to be explicitly instantiated and initialized.

# The `Application` class

The PSYQo library wants to take control of the whole execution flow. In order to do so, it needs to first be provided with a derived instance of the `Application` class. The method to do so can simply done the following way:

```c++
class MyApplication : public psyqo::Application {};

int main() {
    MyApplication app;
    return app.run();
}
```
The `run` method will never return. Now, the problem with the above example is that it won't do anything. We need to add some additional code to the `Application` class.

```c++
class MyApplication : public psyqo::Application {
    void prepare() override { /* Initialize the GPU */ }
    void createScene() override { /* Create the root scene */ }
};
```

These two methods are called during the execution of the application. The first one is called before the application starts, when the hardware hasn't been initialized yet, and the second one is called every time the scene stack is empty.

# The `Scene` class
The PSYQo library uses the concept of a `Scene` to represent the current state of the application. A minimum of one scene is needed to get the application to function properly.

The idea behind the scenes system is that state transitions is usually the hardest part of applications. By using the `Scene` class, we can easily create a scene stack, which will allow us to easily switch between different states of the application. Now, this doesn't mean the scene stack is mandatory, but it is a good idea to use it. An application with only a single root scene is an acceptable outcome.

Both the `Scene` class and the `Application` class have the methods `pushScene` and `popScene` to push and pop scenes. The `pushScene` method will push its scene argument to the scene stack. The `popScene` method will remove the top scene from the stack, returning its pointer.

As a result, our minimum working application becomes the following:

```c++
class MyScene : public psyqo::Scene { };
MyScene rootScene;

class MyApplication : public psyqo::Application {
    void createScene() override { pushScene(&rootScene); }
};

int main() {
    MyApplication app;
    return app.run();
}
```

Now, this still won't do much, but we're making progress. The next step is to add some code to the `Scene` class, which will have to interact with the `GPU` class.

# The `GPU` class
Our third and last unavoidable class is the `GPU` class. The `GPU` class is basically the heartbeat of the application. There is no need to instantiate it as the `Application` class will do it for us. This means it's possible to retrieve the `GPU` instance from the `Application` class using the method `gpu()`.

The class is responsible for drawing primitives on screen, and keeping the pace of the application. This means it also holds the timers for the application. It needs to be initialized from the `prepare` method of the `Application` class. This is done using a simple configuration system to create the rendering context.

When the application is running, the top scene on the stack will have its `frame` method called to draw the scene. This is the last piece of our puzzle in order to create a minimal working application. We can even easily create a simple animation using only what we have learned so far.

```c++
class MyApplication : public psyqo::Application {
    void prepare() override;
    void createScene() override;
};

class MyScene : public psyqo::Scene {
    void frame() override;
};

MyApplication app;
MyScene rootScene;

void MyApplication::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void MyApplication::createScene() {
    pushScene(&rootScene);
}

void MyScene::frame() {
    psyqo::Color c = {{.r = 0, .g = 0, .b = uint8_t(gpu().getFrameCount() % 255)}};
    gpu().clear(c);
}

int main() {
    return app.run();
}
```

# The scene stack

When creating an application with multiple scenes, only the top scene on the stack will be active and drawn. When pushing and popping scenes, they will get notified of the change. When a scene becomes active, its `start` method will be called. When a scene becomes inactive, its `teardown` method will be called. Both methods have a `reason` argument, which can be used to determine the reason for the change.

When a scene is started, it can be because it just got pushed to the stack (which is the `Create` reason), or because it became the top scene on the stack due to a call to `popScene` (which is the `Resume` reason).

When a scene is teardown, it can be because it just got popped from the stack (which is the `Destroy` reason), or because a new scene arrived on top of the stack due to a call to `pushScene` (which is the `Pause` reason).

By encapsulating scene states that way, we can simplify the general approach of state transitions within the whole application.

# Primitives

The PSYQo library provides a number of primitives to draw on screen. There are multiple ways to draw a primitive through the `GPU` class. First, we can just use the `sendPrimitive` method of the `GPU` class:

```c++
void MyScene::frame() {
    psyqo::Prim::Rectangle rect;
    rect.position = {{.x = 24, .y = 24}};
    rect.size = {{.w = 48, .h = 48}};
    rect.setColor({{.r = 255, .g = 0, .b = 0}});

    gpu().sendPrimitive(rect);
}
```

This isn't very efficient, but it is easy to use. This is a blocking function, and nothing can happen while the primitive is being sent.

# Fragments

The best method to send primitives however is to try and collect them into a batch, called `Fragment` within PSYQo. This is a collection of primitives that can be sent to the GPU in a single call. A fragment needs to have a `uint32_t head` member, reserved for the usage of the GPU, followed immediately by the primitives to send, and a `size_t getActualFragmentSize()` method that returns the size of the primitives to send in words.

We can then send the fragment to the GPU using the `sendFragment` method of the `GPU` class.

```c++
struct MyFragment {
    uint32_t head;
    psyqo::Prim::Rectangle rects[3];
    size_t getActualFragmentSize() const {
        return sizeof(rects) /  sizeof(uint32_t);
    }
};

void MyScene::frame() {
    MyFragment fragment;
    fragment.rects[0].position = {{.x = 24, .y = 24}};
    fragment.rects[0].size = {{.w = 48, .h = 48}};
    fragment.rects[0].setColor({{.r = gpu().getFrameCount() % 255, .g = 0, .b = 0}});
    fragment.rects[1].position = {{.x = 72, .y = 72}};
    fragment.rects[1].size = {{.w = 96, .h = 96}};
    fragment.rects[1].setColor({{.r = 0, .g = gpu().getFrameCount() % 255, .b = 0}});
    fragment.rects[2].position = {{.x = 144, .y = 144}};
    fragment.rects[2].size = {{.w = 192, .h = 192}};
    fragment.rects[2].setColor({{.r = 0, .g = 0, .b = gpu().getFrameCount() % 255}});
    gpu().sendFragment(fragment);
}
```

Using `sendFragment` will be more efficient than using `sendPrimitive` for each primitive. It is a blocking call, however background processing is not halted, and events can be fired while sending fragments.

# Fragment caching

Now, the whole idea behind fragments is that it's possible to cache them in memory, only changing the relevant portion of the primitives. This is useful for example when drawing a HUD, or a menu, that solely changes over time. The above example would be inefficient, as it would need to re-create the entire fragment every frame. It can be rewritten the following way:

```c++
MyFragment fragment;

MyScene::MyScene() {
    fragment.rects[0].position = {{.x = 24, .y = 24}};
    fragment.rects[0].size = {{.w = 48, .h = 48}};
    fragment.rects[1].position = {{.x = 72, .y = 72}};
    fragment.rects[1].size = {{.w = 96, .h = 96}};
    fragment.rects[2].position = {{.x = 144, .y = 144}};
    fragment.rects[2].size = {{.w = 192, .h = 192}};
}

void MyScene::frame() {
    fragment.rects[0].setColor({{.r = gpu().getFrameCount() % 255, .g = 0, .b = 0}});
    fragment.rects[1].setColor({{.r = 0, .g = gpu().getFrameCount() % 255, .b = 0}});
    fragment.rects[2].setColor({{.r = 0, .g = 0, .b = gpu().getFrameCount() % 255}});
    gpu().sendFragment(fragment);
}
```

This way, the fragment will be initialized and filled with the primitives only once, and then reused for every frame, with only the necessary changes being applied.

Note that the fragment is not copied when it is sent to the GPU, so it is not safe to mutate the fragment within event callbacks, as they can be dispatched during `sendFragment`. This could potentially create visual glitches as the fragment could be modified while it's being sent to the GPU.

# Memory management
Note that none of the current [examples](examples) are currently using any memory allocation, unless explicitly showcasing that memory allocation works. The core library itself may allocate memory, when it needs to overspill some heavy usage cases, but it should not be the general case.

Memory allocation in general with such a small amount of available memory is not necessarily a good idea, so it is generally recommended to avoid it. But all of the normal C++ memory allocation primitives should be working. Note that no libc is provided, so function calls like `malloc` and `free` are not available.

# Further reading
The [Tetris](examples/tetris) example has a thorough usage of the library so far, and is a great example of how to use it. The library itself is also thoroughly documented, and the [nugget website](https://pcsx-redux.github.io/nugget/) has a render of the doxygen documentation.

Since the library is still very new and in flux, please refer to this page often as it is being updated with new concepts.

To discuss PlayStation1's development, hacking, and reverse engineering in general, please join the PSX.Dev Discord server: [![Discord](https://img.shields.io/discord/642647820683444236)](https://discord.gg/QByKPpH)
