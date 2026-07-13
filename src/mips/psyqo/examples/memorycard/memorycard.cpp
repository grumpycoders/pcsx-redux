/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

// A self-contained, interactive exercise of the psyqo memory card API. It is
// intentionally free of any engine code: just the GPU, a pad, and the
// MemoryCard / MemoryCardFileSystem classes.
//
// Each press of Cross performs exactly one action and appends its result to
// the on-screen log, so the whole API can be stepped through by hand.
//
// WARNING: the very first action FORMATS the memory card in port 1, erasing
// it. The opening screen makes this clear before anything happens.

#include "psyqo/advancedpad.hh"
#include "psyqo/application.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/memory-card-filesystem.hh"
#include "psyqo/memory-card.hh"
#include "psyqo/primitives/rectangles.hh"
#include "psyqo/scene.hh"

namespace {

class MemoryCardExample final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    psyqo::AdvancedPad m_input;
    psyqo::MemoryCard m_card;
    psyqo::MemoryCardFileSystem m_fs{m_card};
};

// A single scene that walks through the test steps, one per Cross press.
class MemoryCardScene final : public psyqo::Scene {
    void frame() override;

    int m_index = 0;        // next step to run
    bool m_started = false;  // false -> showing the warning
    bool m_finished = false;
    bool m_prevCross = false;
};

MemoryCardExample app;
MemoryCardScene scene;

// ── Result log ──────────────────────────────────────────────────────────

struct LogLine {
    const char* text;
    bool isResult;  // true -> show a PASS/FAIL badge
    bool pass;
};

constexpr int kMaxLines = 24;
LogLine g_lines[kMaxLines];
int g_lineCount = 0;

void note(const char* text) {
    if (g_lineCount < kMaxLines) g_lines[g_lineCount++] = LogLine{text, false, false};
}

// Records a pass/fail, and on failure adds the reason as its own line.
void check(const char* name, bool pass, const char* detail = nullptr) {
    if (g_lineCount < kMaxLines) g_lines[g_lineCount++] = LogLine{name, true, pass};
    if (!pass && detail && g_lineCount < kMaxLines) g_lines[g_lineCount++] = LogLine{detail, false, false};
}

void checkOk(const char* name, psyqo::MemoryCard::Error error) {
    bool ok = error == psyqo::MemoryCard::Error::OK;
    check(name, ok, ok ? nullptr : psyqo::MemoryCard::errorMessage(error));
}

// ── Test fixtures ───────────────────────────────────────────────────────

// Up to 20 characters, the Sony filename limit.
const char* const kFileName = "PSYQO-MEMCARD-TEST";
// The save title. writeFile stores it as fullwidth Shift-JIS; readFileInfo
// hands those raw bytes back, which the modal decodes for display.
const char* const kTitle = "PSYQO MEMCARD TEST";

uint8_t g_payload[200];
constexpr uint32_t kPayloadLen = sizeof(g_payload);
uint8_t g_readback[200];

// State for the title modal shown after the readFileInfo step.
char g_modalTitle[40];
bool g_modalActive = false;
uint8_t g_modalIconFrames = 0;


// A simple 16x16 icon: a white border around a red fill.
void buildIcon(psyqo::MemoryCardFileSystem::Icon& icon) {
    __builtin_memset(&icon, 0, sizeof(icon));
    icon.frameCount = 1;
    icon.clut[0] = 0x0000;  // transparent
    icon.clut[1] = 0x7fff;  // white border
    icon.clut[2] = 0x001f;  // red fill
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x += 2) {
            uint8_t lo = (x == 0 || y == 0 || y == 15) ? 1 : 2;
            uint8_t hi = (x + 1 == 15 || y == 0 || y == 15) ? 1 : 2;
            icon.pixels[0][y * 8 + (x >> 1)] = lo | (hi << 4);
        }
    }
}

// The reverse of writeFile's ASCII->fullwidth-Shift-JIS title promotion, enough
// to show an ASCII save title read back by readFileInfo. Fullwidth space, digits
// and letters decode to ASCII; anything else shows as '?'. Stops at a 0x0000 pair
// or the end of the 64-byte field.
void decodeTitle(const uint8_t* title, char* out, uint32_t outMax) {
    uint32_t o = 0;
    for (uint32_t i = 0; i + 1 < 64 && o + 1 < outMax; i += 2) {
        uint16_t c = static_cast<uint16_t>((title[i] << 8) | title[i + 1]);
        if (c == 0x0000) break;
        char ch = '?';
        if (c == 0x8140) {
            ch = ' ';
        } else if (c >= 0x824f && c <= 0x8258) {
            ch = static_cast<char>('0' + (c - 0x824f));
        } else if (c >= 0x8260 && c <= 0x8279) {
            ch = static_cast<char>('A' + (c - 0x8260));
        } else if (c >= 0x8281 && c <= 0x829a) {
            ch = static_cast<char>('a' + (c - 0x8281));
        }
        out[o++] = ch;
    }
    out[o] = '\0';
}

bool streq(const char* a, const char* b) {
    for (uint32_t i = 0;; i++) {
        if (a[i] != b[i]) return false;
        if (a[i] == '\0') return true;
    }
}

constexpr int kStepCount = 14;

// Performs one test action. Returns false if the run should stop (e.g. no card).
bool runStep(int index) {
    using MC = psyqo::MemoryCard;
    auto port = MC::Port::Port0;
    auto& fs = app.m_fs;
    auto& card = app.m_card;
    uint32_t freeBlocks = 0;
    uint32_t outLen = 0;
    bool exists = false;
    MC::Error e;

    switch (index) {
        case 0:
            for (uint32_t i = 0; i < kPayloadLen; i++) g_payload[i] = static_cast<uint8_t>(i * 7 + 3);
            e = card.probeBlocking(port);
            checkOk("Card present", e);
            if (e != MC::Error::OK) {
                note("Insert a card in port 1, then reset.");
                return false;
            }
            return true;

        case 1:
            checkOk("Format card", fs.formatBlocking(app.gpu(), port));
            return true;

        case 2:
            checkOk("Card formatted", fs.getCardStateBlocking(app.gpu(), port));
            return true;

        case 3:
            e = fs.getFreeBlockCountBlocking(app.gpu(), port, &freeBlocks);
            check("Free blocks == 15", e == MC::Error::OK && freeBlocks == 15,
                  e != MC::Error::OK ? MC::errorMessage(e) : "unexpected free count");
            return true;

        case 4: {
            // The title is a plain UTF-8 string; the driver encodes it to the
            // Shift-JIS field the BIOS shows (printable ASCII becomes fullwidth).
            psyqo::MemoryCardFileSystem::Icon icon;
            buildIcon(icon);
            checkOk("Write file", fs.writeFileBlocking(app.gpu(), port, kFileName, kTitle, icon, g_payload, kPayloadLen));
            return true;
        }

        case 5: {
            // Read the title and icon back and confirm they round-trip. The
            // title is decoded from fullwidth Shift-JIS for display and compared
            // against what we wrote; the icon is compared byte-for-byte.
            psyqo::MemoryCardFileSystem::FileInfo info;
            __builtin_memset(&info, 0, sizeof(info));
            e = fs.readFileInfoBlocking(app.gpu(), port, kFileName, &info);
            psyqo::MemoryCardFileSystem::Icon expected;
            buildIcon(expected);
            decodeTitle(info.title, g_modalTitle, sizeof(g_modalTitle));
            bool titleOk = streq(g_modalTitle, kTitle);
            bool iconOk = __builtin_memcmp(&info.icon, &expected, sizeof(expected)) == 0;
            g_modalIconFrames = info.icon.frameCount;
            check("Read title + icon", e == MC::Error::OK && titleOk && iconOk,
                  e != MC::Error::OK ? MC::errorMessage(e) : (!titleOk ? "title mismatch" : "icon mismatch"));
            // Pop the modal so the decoded title is visible on-screen.
            if (e == MC::Error::OK) g_modalActive = true;
            return true;
        }

        case 6:
            e = fs.fileExistsBlocking(app.gpu(), port, kFileName, &exists);
            check("File exists", e == MC::Error::OK && exists,
                  e != MC::Error::OK ? MC::errorMessage(e) : "not found");
            return true;

        case 7:
            e = fs.readFileBlocking(app.gpu(), port, kFileName, g_readback, sizeof(g_readback), &outLen);
            check("Read + verify payload",
                  e == MC::Error::OK && outLen >= kPayloadLen &&
                      __builtin_memcmp(g_readback, g_payload, kPayloadLen) == 0,
                  e != MC::Error::OK ? MC::errorMessage(e) : "data mismatch");
            return true;

        case 8: {
            psyqo::MemoryCardFileSystem::FileEntry entries[15];
            uint32_t count = 0;
            e = fs.listFilesBlocking(app.gpu(), port, entries, 15, &count);
            bool listed = e == MC::Error::OK && count == 1;
            if (listed) {
                const char* n = entries[0].name;
                for (int i = 0; kFileName[i] || n[i]; i++) {
                    if (kFileName[i] != n[i]) {
                        listed = false;
                        break;
                    }
                }
            }
            check("List shows our file", listed, e != MC::Error::OK ? MC::errorMessage(e) : "wrong listing");
            return true;
        }

        case 9:
            e = fs.getFreeBlockCountBlocking(app.gpu(), port, &freeBlocks);
            check("Free blocks == 14", e == MC::Error::OK && freeBlocks == 14,
                  e != MC::Error::OK ? MC::errorMessage(e) : "unexpected free count");
            return true;

        case 10:
            checkOk("Delete file", fs.deleteFileBlocking(app.gpu(), port, kFileName));
            return true;

        case 11:
            e = fs.fileExistsBlocking(app.gpu(), port, kFileName, &exists);
            check("File removed", e == MC::Error::OK && !exists,
                  e != MC::Error::OK ? MC::errorMessage(e) : "still present");
            return true;

        case 12:
            e = fs.getFreeBlockCountBlocking(app.gpu(), port, &freeBlocks);
            check("Free blocks == 15", e == MC::Error::OK && freeBlocks == 15,
                  e != MC::Error::OK ? MC::errorMessage(e) : "unexpected free count");
            return true;

        case 13:
            e = fs.readFileBlocking(app.gpu(), port, kFileName, g_readback, sizeof(g_readback), &outLen);
            check("Missing file -> FileNotFound", e == MC::Error::FileNotFound, MC::errorMessage(e));
            note("Done.");
            return false;
    }
    return false;
}

}  // namespace

void MemoryCardExample::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
    m_card.prepare();
}

void MemoryCardExample::createScene() {
    m_font.uploadSystemFont(gpu());
    m_input.initialize();
    pushScene(&scene);
}

void MemoryCardScene::frame() {
    app.gpu().clear({{.r = 0, .g = 0, .b = 0}});

    static const auto white = psyqo::Color{{.r = 220, .g = 220, .b = 220}};
    static const auto gray = psyqo::Color{{.r = 150, .g = 150, .b = 150}};
    static const auto yellow = psyqo::Color{{.r = 255, .g = 230, .b = 0}};
    static const auto green = psyqo::Color{{.r = 0, .g = 230, .b = 0}};
    static const auto red = psyqo::Color{{.r = 255, .g = 40, .b = 40}};
    static const auto cyan = psyqo::Color{{.r = 0, .g = 200, .b = 230}};

    auto print = [](int16_t x, int16_t y, const psyqo::Color& c, const char* s) {
        app.m_font.print(app.gpu(), s, {{.x = x, .y = y}}, c);
    };

    if (!m_started) {
        print(16, 16, yellow, "psyqo memory card self-test");
        print(16, 48, white, "WARNING: pressing X will FORMAT the");
        print(16, 64, white, "memory card in PORT 1, erasing it.");
        print(16, 96, white, "Each X press runs the next action.");
        print(16, 208, cyan, "Press X to begin.");
    } else {
        for (int i = 0; i < g_lineCount; i++) {
            const LogLine& line = g_lines[i];
            int16_t y = int16_t(6 + i * 12);
            if (line.isResult) {
                print(8, y, white, line.text);
                print(240, y, line.pass ? green : red, line.pass ? "PASS" : "FAIL");
            } else {
                print(8, y, gray, line.text);
            }
        }
        if (m_finished) {
            print(8, 224, green, "All actions complete.");
        } else {
            print(8, 224, cyan, "Press X for the next action.");
        }
    }

    // The title modal: drawn over the log after the readFileInfo step, showing
    // the title decoded straight from what the card handed back.
    if (m_started && g_modalActive) {
        psyqo::Prim::Rectangle border;
        border.position.x = 38;
        border.position.y = 68;
        border.size.x = 244;
        border.size.y = 104;
        border.setColor({{.r = 200, .g = 200, .b = 200}});
        app.gpu().sendPrimitive(border);
        psyqo::Prim::Rectangle box;
        box.position.x = 42;
        box.position.y = 72;
        box.size.x = 236;
        box.size.y = 96;
        box.setColor({{.r = 10, .g = 20, .b = 60}});
        app.gpu().sendPrimitive(box);
        print(54, 82, yellow, "readFileInfo - title read back:");
        print(54, 104, white, g_modalTitle);
        char iconLine[20] = "icon frames: ";
        iconLine[13] = static_cast<char>('0' + (g_modalIconFrames % 10));
        iconLine[14] = '\0';
        print(54, 126, gray, iconLine);
        print(54, 150, cyan, "Press X to dismiss.");
    }

    // Rising-edge detect so a held button advances exactly one step.
    bool cross = app.m_input.isButtonPressed(psyqo::AdvancedPad::Pad::Pad1a, psyqo::AdvancedPad::Button::Cross);
    if (cross && !m_prevCross && !m_finished) {
        if (g_modalActive) {
            // Acknowledge the modal without advancing to the next step.
            g_modalActive = false;
        } else {
            if (!m_started) {
                m_started = true;
                note("Memory card self-test (port 1):");
            }
            bool more = runStep(m_index);
            m_index++;
            if (!more || m_index >= kStepCount) m_finished = true;
        }
    }
    m_prevCross = cross;
}

int main() { return app.run(); }
