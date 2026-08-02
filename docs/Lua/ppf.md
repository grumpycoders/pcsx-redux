# PPF patches

## Introduction & Rationale

PPF is the venerable patch format for disc images: a list of "at this absolute byte offset, replace these bytes" records, applied to a `.bin` image. PCSX-Redux both reads them and generates them, and the generation side is unusual enough to deserve an explanation, because there is no "make a patch" function anywhere. Patches are a side effect of writing to the disc.

The mental model is that the currently loaded disc image is writable in memory. Any write you perform is recorded as a difference against the original image, and at any point you can ask for the accumulated set of differences to be written out as a `.ppf` file. Nothing ever modifies the image on disk.

This makes the whole patch-authoring loop live: write to the disc from Lua, run the game right there to see the effect, adjust, and only save the PPF when the result is what you wanted.

## Loading patches

Nothing needs to be done to apply an existing patch. When a disc image is opened, PCSX-Redux looks for a file next to it with the same name and a `.ppf` extension, and loads it automatically if present. When this happens, `[+ppf]` is appended to the image's description in the log.

Once loaded, patches are applied transparently on every sector read, so the emulator, the ISO browser, and the Lua reader API all see the patched disc.

The reader accepts PPF1, PPF2 and PPF3. A few things are worth knowing about the extra metadata the later versions carry:

- The version is taken from the binary version byte at offset 5, not from the digit in the ASCII magic. Those disagree in the wild, and the binary byte is the authoritative one.
- The `FILE_ID.DIZ` block of PPF2 and PPF3 files is read and kept. Note the length field is 32-bit in PPF2 and 16-bit in PPF3, not the other way around.
- The image size check of PPF2, and the 1024-byte verification block of PPF2 and PPF3, are skipped rather than checked. PCSX-Redux will happily apply a patch to an image it was not built for, so a patch that produces garbage is not going to be caught for you.
- PPF3 undo data is skipped. It is not retained and cannot be applied in reverse.
- Of the PPF3 image types, only type 0 (2352-byte `.bin`) is accepted. GI/PrimoDVD images are rejected.

## Generating patches

Patches come from writing to the disc. Open a region of the current image as a `File` object, write to it, and every byte that ends up different from the original is recorded:

```lua
local iso = PCSX.getCurrentIso()
local f = iso:open(lba, size, mode)
f:writeAt('patched bytes', offset)
```

The details of `iso:open` and of what writing to a disc file does to sector headers and EDC/ECC are covered in the [File API](file-api.md) page. What matters here is what happens underneath: for each sector touched, the original 2352-byte sector and the modified one are compared byte by byte, and every contiguous run of differing bytes becomes a patch record holding the new bytes. Writes that happen to store the value that was already there produce nothing.

The far more convenient way to reach a specific region is through the reader, which resolves a path to an LBA for you:

```lua
local iso = PCSX.getCurrentIso()
local f = iso:createReader():open('SLUS_012.34;1')
f:writeAt(newCode, 0x1234)
iso:savePPF()
```

Patches accumulate across writes. Writing to the same bytes repeatedly is fine: the records are collapsed before saving, so the final `.ppf` describes the end state rather than the history of how you got there.

## Saving and clearing

```lua
:savePPF()  -- on an Iso object
:clearPPF() -- on an Iso object
```

`savePPF()` takes no filename. The destination is the disc image's own path with the extension replaced by `.ppf`, and an existing file at that path is truncated without asking. If you need the patch somewhere else, move it afterwards.

`clearPPF()` throws away every accumulated patch, returning the in-memory disc to the original image. Since the patches are the only record of your edits, this is not undoable.

Both are also reachable from the GUI, in the ISO browser, as the "Save PPF" and "Clear Patches" buttons, and over the [web server](../web_server.md) at `api/v1/cd/ppf?function=save` and `?function=clear`.

## What gets written

The generated file is always PPF1, regardless of what version was loaded. That is the version every PPF applier understands, and none of what the later versions add is data PCSX-Redux has: there is no undo information, no verification block, and no image size field.

The 50-byte description field and the `FILE_ID.DIZ` block are read from patches that carry them, but there is currently no way to set either one, from Lua or from anywhere else, so generated files carry an empty description.

One consequence of PPF1 having a single-byte length field is that a long run of changed bytes is emitted as several consecutive records of at most 255 bytes each. This is normal and every applier handles it.

## A worked example

Patching a binary on the disc, checking the result by running it, and only then saving:

```lua
local iso = PCSX.getCurrentIso()
local exe = iso:createReader():open('SLUS_012.34;1')

-- Replace an instruction with a nop.
exe:writeAt('\0\0\0\0', 0x8000)

-- The change is live on the disc now; reset and see what it does.
PCSX.resumeEmulator()

-- Happy with it:
iso:savePPF()
```

If it turns out not to be what you wanted, `iso:clearPPF()` puts the disc back and you can try again without ever having touched the image on disk.
