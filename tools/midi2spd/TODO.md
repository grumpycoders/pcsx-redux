# midi2spd - TODO

Roadmap for making midi2spd a fully-featured MIDI-to-SPUDUMP converter. Items are
grouped by domain and roughly ordered by impact within each group.

---

## Done

### MIDI event handling
- **Pitch bend on active voices** + **RPN pitch bend range** (CC#100/101/6/38)
- **Sustain pedal** (CC#64) with held-voice tracking and release on pedal-off
- **Modulation wheel** (CC#1) - sine vibrato LFO at ~6 Hz, per-tick updates
- **Bank Select** (CC#0 MSB, CC#32 LSB) with fallback to bank 0
- **All Notes Off** (CC#120), **All Sound Off** (CC#123), **Reset All Controllers** (CC#121)
- **Loop point detection** from CC#111 and "loopStart" marker meta events
- **MIDI metadata extraction** - track name -> SPD title, copyright -> SPD author

### SoundFont2 mapping
- **ADSR envelope extraction** from SF2 ampenv (calibrated against SPU timing formulas)
- **GM velocity curve** (quadratic) + **SF2 initial attenuation**
- **SF2 pan per region** combined with MIDI CC#10
- **Exclusive groups** - SF2 `group` field, hi-hat cut
- **Velocity layers / overlapping regions** - all matching SF2 regions trigger voices
- **Pitch keytrack** - non-100 `pitch_keytrack` handled correctly

### Voice allocator
- **Priority-based voice stealing** (sustain-held first, low velocity, oldest)
- **Exclusive group voice killing**
- **Max layers per note** (`-l` flag) to cap voice consumption from layered instruments

### Output quality
- **SPU hardware reverb** - 5 presets (off/room/studio/hall/space), CC#91 per-voice
  enable, reverb buffer deducted from SPU RAM. CLI: `-r <preset>`, default hall.
- **Pitch ceiling warnings** when samples would exceed SPU max pitch (0x3FFF)
- **SPU RAM overflow warnings** accounting for reverb buffer

### Architecture
- **Per-tick voice parameter update loop** for vibrato (portamento/LFOs slot in)
- **Channel state struct** with sustain, bank, modulation, reverb send, RPN, reset()
- **Makefile integration** - `midi2spd` in TOOLS list

---

## Remaining - audible impact

### Portamento (CC#5 rate, CC#65 on/off, CC#84 source note)
- **Status:** Not handled.
- **Work:** When portamento is on and a new note arrives before the old one is
  released, slide pitch from the old note to the new note over a duration
  controlled by CC#5. Requires per-tick pitch register updates.
- Per-tick update loop is already in place.

### Legato mode
- **Status:** Not handled.
- **Work:** When legato is active and a new note arrives on the same channel
  while another is sounding, don't retrigger (no key-off/key-on). Instead,
  update the pitch to the new note (optionally with portamento slide).
  Preserves the ADSR envelope across note transitions.

### SF2 vibrato LFO (per-region)
- **Status:** All LFO fields ignored: `delayVibLFO`, `freqVibLFO`,
  `vibLfoToPitch`.
- **Work:** Generate per-tick pitch modulation from the per-region vibrato
  parameters. Separate from CC#1 mod wheel - this is built into the
  instrument definition. Some instruments (strings, woodwinds) have default
  vibrato that's currently missing.
- Per-tick update loop is already in place.

### SF2 mod LFO to volume (tremolo)
- **Status:** `modLfoToVolume` field ignored.
- **Work:** Generate per-tick volume modulation. Same infrastructure as
  vibrato but modulating volume registers instead of pitch.

### SF2 modulation envelope (modenv)
- **Status:** `modenv_*` parameters are ignored.
- **Work:** Could modulate pitch at note start for attack transients (pitch
  scoops). Requires per-tick pitch updates during the envelope's active
  phase.

### Sample rate resampling
- **Status:** Warnings emitted when pitch ceiling would be exceeded. No
  automatic fix.
- **Work:** Pre-resample affected 22050 Hz samples to 44100 Hz before ADPCM
  encoding. The detection is already in place; the fix is the resampling.

### Note-off velocity
- **Status:** Parsed but ignored.
- **Work:** Could vary release rate per note-off event. Low priority.

---

## Remaining - polish

### Per-channel voice limits / priorities
- **Status:** Max-layers-per-note (`-l` flag) added as partial mitigation.
- **Work:** Optional per-channel voice reservation or priority levels.
  Drum channel gets N reserved voices, melody channels share the rest.

### Sample normalization
- **Status:** No amplitude adjustment.
- **Work:** Optional peak normalization or per-sample normalization. Limiter
  for hot SF2 samples.

### ADPCM encoder quality
- **Status:** Uses pcsx-redux's basic PSX ADPCM encoder.
- **Work:** Better encoders that minimize quantization error across block
  boundaries (Vagconv-style optimal filter selection).

### Configurable drum channel
- **Status:** Channel 10 (0-indexed: 9) hardcoded as drums.
- **Work:** CLI flag to specify drum channel(s). Auto-detect from GS SysEx.

### Polyphonic aftertouch (0xA0) / Channel pressure (0xD0)
- **Status:** Parsed and discarded.
- **Work:** Could modulate volume or pitch. Uncommon in most MIDI files.

### SF2 filter cutoff pre-filtering
- **Status:** `initialFilterFc` and `initialFilterQ` ignored.
- **Work:** Pre-filter samples offline before ADPCM encoding. SPU has no
  per-voice programmable filter.

### Noise synthesis
- **Status:** SPU noise registers never written.
- **Work:** Low priority. No standard MIDI mapping.

---

## Remaining - format/structure

### Multiple patterns and order table
- **Status:** Single pattern with loop-to-start.
- **Work:** Split MIDI into patterns (via markers, time signature, or fixed
  bar count). Each pattern needs a full SPU state snapshot for seeking.
- **Impact:** Enables seeking and reduces memory for streaming playback.

### Subsong table / Subsong names
- **Status:** Not used.
- **Work:** Multiple MIDI files -> single SPD with subsong table. Also handle
  MIDI format 2. Track names as subsong names.

### Mid-stream tick rate changes
- **Status:** Tempo changes handled internally. Single tick rate emitted.
- **Work:** Emit tick rate packets at tempo changes so the player knows BPM.
- **Impact:** Low. Current approach works for playback.

### Pattern state snapshots
- **Depends on:** Multiple patterns.

---

## Remaining - edge cases

### SysEx messages
- GM System On, GS Reset, XG System On, GS drum channel assignments.
- Low priority. Most MIDI files work fine without.

### MIDI Format 2
- Independent patterns per track. Extremely rare.

---

## Remaining - CLI

### Author flag (`-a`)
- Supplements auto-extraction from MIDI copyright events.

### Loop point flag
- Explicit loop point in MIDI ticks. Auto-detection is always on; flag
  would allow explicit override.

### Velocity curve flag (`-c`)
- Select linear, quadratic, or GM standard velocity curve.

### LFO enable/disable flag
- SF2 LFO generation increases file size. Opt in/out.

### Verbosity / diagnostics
- ~~Peak voices and total voice steals~~ DONE
- ~~Pitch ceiling warnings~~ DONE
- Per-sample SPU RAM usage breakdown.
- Voice steals per channel.
- Warnings for ignored SF2 features.

---

## Remaining - code quality

### SF2 region cache
- Pre-build per-preset, per-key, per-velocity region table at load time
  instead of linear search per note-on.
