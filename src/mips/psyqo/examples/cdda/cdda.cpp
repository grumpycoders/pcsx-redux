/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/cdrom-device.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/scene.hh"

namespace {

// This is a very simple example of how to use the CD-Rom device
// to play CDDA audio. This example will loop playback of track 2
// forever, displaying the current track and playback location
// on the screen. This example is not a complete example of how
// to handle CDDA audio in a real application, but it should be
// a good starting point for understanding how to use the CD-Rom
// device to play CDDA audio. Enhancements to this example could
// include handling stop requests, track change requests, and
// retrying playback if it fails, displaying more information
// about the playback, using the pad to control playback, etc.
class CDDA final : public psyqo::Application {
    void prepare() override;
    void createScene() override;
    void loopPlaybackTrack(unsigned track);

  public:
    // The font to display our status text
    psyqo::Font<> m_font;
    // The CD-Rom device object
    psyqo::CDRomDevice m_cdrom;
    // Storage for the playback location data
    psyqo::CDRomDevice::PlaybackLocation m_playbackLocation;
    // Keeping internal states kosher
    bool m_cddaPlaying = false;
    bool m_getlocPending = false;
};

class CDDAScene final : public psyqo::Scene {
    void frame() override;
};

CDDA cdda;
CDDAScene cddaScene;

}  // namespace

void CDDA::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
    m_cdrom.prepare();
}

// This function will loop playback of a given track
// until the end of time. It's a simple example of
// how to use the CD-Rom device to play CDDA audio.
// This function will call itself when the track ends.
// In a real application, we'd want to handle a bit
// more state, such as retrying playback if it fails,
// or handling stop requests or track changes requests,
// which would require a more complex state machine.
void CDDA::loopPlaybackTrack(unsigned track) {
    // The callback will be called twice: once when the
    // track begins playing, and once when it ends, so
    // we need to keep track of the state to know when
    // to loop back to the beginning.
    m_cdrom.playCDDATrack(track, [this, track](bool success) {
        if (!success) {
            // If the playback failed, then the state
            // machine will just stop running. This is
            // a simple example, but in reality, we'd
            // want to handle this more gracefully,
            // perhaps by retrying the playback periodically.
            syscall_puts("CDDA playback failed\n");
            m_cddaPlaying = false;
            return;
        }
        m_cddaPlaying = !m_cddaPlaying;
        if (m_cddaPlaying) {
            ramsyscall_printf("CDDA playback started at track %d\n", track);
        } else {
            ramsyscall_printf("CDDA playback looping back to beginning of track %d\n", track);
            loopPlaybackTrack(track);
        }
    });
}

void CDDA::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&cddaScene);
    syscall_puts("CD-Rom device reset...\n");
    m_cdrom.resetBlocking(gpu());
    syscall_puts("CD-Rom device ready, getting TOC size...\n");
    auto tocSize = m_cdrom.getTOCSizeBlocking(gpu());
    ramsyscall_printf("CD-Rom track count: %d\n", tocSize);
    // Start playback of track 2, which is a good
    // track to loop because games with CDDA will
    // have a data track as track 1. We could also
    // use the track count from the TOC to retrieve
    // the table of contents and play a specific track.
    loopPlaybackTrack(2);
    using namespace psyqo::timer_literals;
    // This timer will check the playback location
    // every 20ms to update the display. The 20ms value
    // is way overkill for this purpose.
    gpu().armPeriodicTimer(20_ms, [this](uint32_t) {
        // We can't call getPlaybackLocation while
        // the CD-Rom device is busy with another
        // getPlaybackLocation call, so we need to
        // check if we're already waiting for a
        // location before we request another one.
        // Also, we can only call getPlaybackLocation
        // when the CD-Rom device is playing CDDA.
        if (!m_getlocPending && m_cddaPlaying) {
            m_getlocPending = true;
            m_cdrom.getPlaybackLocation(&m_playbackLocation, [this](auto location) { m_getlocPending = false; });
        }
    });
}

void CDDAScene::frame() {
    psyqo::Color bg{{.r = 0, .g = 64, .b = 91}};
    cdda.gpu().clear(bg);
    // The `m_playbackLocation` object will be updated
    // by the timer callback in the `CDDA` class, so we
    // can just use it here to display the current track
    // and playback location.
    auto& pos = cdda.m_playbackLocation.relative;
    cdda.m_font.printf(cdda.gpu(), {{.x = 4, .y = 20}}, {.r = 0xff, .g = 0xff, .b = 0xff}, "Track %i @%02i:%02i/%02i",
                       cdda.m_playbackLocation.track, pos.m, pos.s, pos.f);
}

int main() { return cdda.run(); }
