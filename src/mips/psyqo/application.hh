/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

#include <EASTL/fixed_vector.h>

#include "psyqo/gpu.hh"

namespace psyqo {

class Scene;

/**
 * @brief The application class.
 *
 * @details The application class is the main class of the application.
 * It's supposed to be a singleton object instantiated in your main program.
 * It's responsible for the main loop of the application, and creating the
 * initial scene. It will hold the `GPU` object that can be used to render
 * primitives throughout the lifetime of the application. The `main`
 * function should simply instantiate an application object and call
 * its `run` method.
 */

class Application {
  public:
    /**
     * @brief Runs the main loop.
     *
     * @details Call this from the `main` function. It will never return.
     */
    int run();

    /**
     * @brief Prepare the objects for the application
     *
     * @details This will be called once before the main loop, and
     * should be used to initialize any other objects necessary. Do
     * not try to access any hardware resources during this call,
     * as interrupts are disabled at this point.
     */
    virtual void prepare() {}

    /**
     * @brief Start the application.
     *
     * @details This will be called once before the main loop, and
     * after the `prepare` method. It should be used to initialize
     * any hardware resources necessary, as interrupts are enabled.
     */
    virtual void start() {}

    /**
     * @brief Create the root scene object.
     *
     * @details This will be called once before the main loop. It should
     * create the root scene object and push it onto the stack. This will
     * only be called if the `frame` method of the `Application` class
     * hasn't been overridden. If you override the `frame` method, you
     * are responsible for managing your own scene system.
     */
    virtual void createScene() {}

    /**
     * @brief Get the GPU object.
     *
     * @details Simple accessor for the `GPU` object.
     */
    psyqo::GPU& gpu() { return m_gpu; }

    /**
     * @brief Get the current scene object.
     *
     * @details Returns the top scene object on the stack.
     */
    Scene* getCurrentScene();

    /**
     * @brief Push a scene object onto the stack.
     *
     * @details Pushes a new scene object onto the stack.
     * There can be only one active scene at a time. Pushing a scene object
     * will cause the current scene, if any, to be teared down, and the
     * new scene to be started.
     */
    void pushScene(Scene* scene);

    /**
     * @brief Pop a scene object from the stack.
     *
     * @details Pops the top scene object from the stack.
     * There can be only one active scene at a time. Popping a scene object
     * will cause the current scene to be teared down and the new top scene,
     * if any, to be started. If the scene stack ends up being empty, the
     * `createScene` method will be called again.
     *
     * Calling this method when the stack is empty will return `nullptr`.
     *
     * @return the popped scene, potentially for deletion if needed.
     */
    Scene* popScene();

    /**
     * @brief The frame method.
     *
     * @details The default implementation of this method will call the
     * `createScene` method if the scene stack is empty, and then call
     * the `frame` method of the current scene. This method is called
     * once per frame, and should be used to update the application
     * state. If you override this method, you are responsible for
     * managing your own scene system.
     */
    virtual void frame();

    virtual ~Application() = default;

  private:
    psyqo::GPU m_gpu;
    eastl::fixed_vector<Scene*, 16> m_scenesStack;

    friend class Scene;
    friend void Kernel::takeOverKernel();
};

}  // namespace psyqo
