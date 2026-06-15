#!/usr/bin/env python3
"""Upload a PS-EXE to a PS1 running Unirom via serial, then read output.

Protocol (from Unirom sio.c / kdebug.c and nops NOTPSXSERIAL.CS):

Handshake phase (ReadSIO echoes every byte):
  1. Send "SEXE" -> receive echo "SEXE" + "OKV2"
  2. Send "UPV2" -> receive echo "UPV2" + "OKAY"

Transfer phase (inside SEXE handler, no echo):
  3. Send 2048-byte PS-EXE header (discarded by Unirom)
  4. Send 16 bytes metadata: jumpAddr(4) + writeAddr(4) + size(4) + checksum(4)
  5. Send data in 2048-byte chunks
     For V2: after each chunk, Unirom sends "CHEK", we send chunk checksum (4 bytes),
     Unirom sends "MORE" (ok) or "ERR!" (retry)

After transfer: Unirom calls UnloadMe() and jumps to jumpAddr.

TTY output: Unirom's ttyredirect patches BIOS printf to send over SIO1.

PCDRV: on real hardware Unirom catches the PS1's `break 0, 0x101..0x107` and
bridges the file op over SIO1. We act as the "PC" side (the role nops plays),
serving file ops out of a base directory. The PS1->PC direction prefixes a file
op with the escape bytes 0x00 'p'; everything else is TTY. See HandlePCDrv in
unirom kdebug.c for the reference implementation. All 32-bit values are
little-endian; OKAY/NOPE/CHEK/MORE/ERR! are literal ASCII words.
"""
import argparse
import os
import struct
import sys
import time

import serial

CHUNK_SIZE = 2048

OKAY = b'OKAY'
NOPE = b'NOPE'
CHEK = b'CHEK'
MORE = b'MORE'
ERR = b'ERR!'

# PCDRV op codes (operand of `break 0, 0x10x`).
PC_INIT = 0x101
PC_CREATE = 0x102
PC_OPEN = 0x103
PC_CLOSE = 0x104
PC_READ = 0x105
PC_WRITE = 0x106
PC_SEEK = 0x107


def drain(ser, quiet_seconds=2.0):
    """Read and discard serial data until quiet for quiet_seconds."""
    drained = b''
    last_activity = time.time()
    while time.time() - last_activity < quiet_seconds:
        if ser.in_waiting:
            drained += ser.read(ser.in_waiting)
            last_activity = time.time()
        else:
            time.sleep(0.05)
    return drained


def read_until_token(ser, tokens, timeout=10):
    """Read serial data, scanning for any of the given byte tokens.
    Returns (matched_token, pre_data, post_data)."""
    buf = b''
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ser.in_waiting:
            buf += ser.read(ser.in_waiting)
            for tok in tokens:
                idx = buf.find(tok)
                if idx >= 0:
                    pre = buf[:idx]
                    post = buf[idx + len(tok):]
                    return tok, pre, post
        else:
            time.sleep(0.01)
    return None, buf, b''


def calculate_checksum(data):
    """Simple byte sum checksum (protocol V2)."""
    return sum(data) & 0xFFFFFFFF


def log(msg):
    """Print to stderr so program output on stdout stays clean."""
    print(msg, file=sys.stderr, flush=True)


def p32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)


def enable_debug_mode(ser):
    """Send "DEBG" so Unirom installs its kdebug handler. That handler catches
    every `break`: it bridges PCDRV's `break 0,0x10x` over SIO1, and it halts
    (HLTD) on the runtime's exit break so the host can detect end-of-binary.
    Unirom echoes the command byte-by-byte, then responds OKAY."""
    log("[*] Enabling Unirom debug mode (DEBG)...")
    ser.write(b'DEBG')
    ser.flush()
    tok, pre, _ = read_until_token(ser, [b'OKAY'], timeout=5)
    if tok != b'OKAY':
        log(f"[!] DEBG: no OKAY (got {pre!r}); kdebug not armed.")
        return False
    log("[*] Debug mode enabled.")
    return True


class SerialReader:
    """Buffered byte reader over a pyserial port. Lets the TTY loop and the
    PCDRV protocol handler share one stream without losing bytes."""

    def __init__(self, ser, prime=b''):
        self.ser = ser
        self.buf = bytearray(prime)

    def _fill(self, timeout):
        deadline = time.time() + timeout
        while not self.buf and time.time() < deadline:
            n = self.ser.in_waiting
            if n:
                self.buf += self.ser.read(n)
            else:
                time.sleep(0.005)

    def read1(self, timeout):
        """Return one byte (as bytes), or None on timeout."""
        if not self.buf:
            self._fill(timeout)
        if not self.buf:
            return None
        b = bytes(self.buf[:1])
        del self.buf[:1]
        return b

    def read_exact(self, n, timeout=10):
        out = bytearray()
        deadline = time.time() + timeout
        while len(out) < n:
            if not self.buf:
                self._fill(max(0.0, deadline - time.time()))
                if not self.buf:
                    raise TimeoutError(f'PCDRV: needed {n} bytes, got {len(out)}')
            take = min(n - len(out), len(self.buf))
            out += self.buf[:take]
            del self.buf[:take]
        return bytes(out)

    def read_u32(self, timeout=10):
        return struct.unpack('<I', self.read_exact(4, timeout))[0]

    def read_cstr(self, timeout=10):
        out = bytearray()
        while True:
            b = self.read_exact(1, timeout)
            if b == b'\x00':
                break
            out += b
        return bytes(out)


class PCDrv:
    """Host-side PCDRV file server, serving ops out of base_dir."""

    def __init__(self, base_dir):
        self.base = os.path.abspath(base_dir)
        self.files = {}  # fd -> python file object
        self.next_fd = 3  # 0/1/2 reserved by convention

    def _resolve(self, name):
        # PS1 names use libsn conventions; flatten to a safe path under base.
        name = name.decode('latin-1', 'replace').replace('\\', '/').lstrip('/')
        path = os.path.abspath(os.path.join(self.base, name))
        if not (path == self.base or path.startswith(self.base + os.sep)):
            raise ValueError(f'path escapes base: {name}')
        return path

    def _alloc(self, fobj):
        fd = self.next_fd
        self.next_fd += 1
        self.files[fd] = fobj
        return fd

    def create(self, name, mode):
        path = self._resolve(name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fobj = open(path, 'w+b')
        fd = self._alloc(fobj)
        log(f'[pcdrv] create {name!r} -> fd {fd}')
        return fd

    def open(self, name, flags):
        path = self._resolve(name)
        fobj = open(path, 'r+b' if (flags & 1) else 'rb')
        fd = self._alloc(fobj)
        log(f'[pcdrv] open {name!r} flags 0x{flags:x} -> fd {fd}')
        return fd

    def close(self, fd):
        fobj = self.files.pop(fd, None)
        if fobj:
            fobj.close()
        log(f'[pcdrv] close fd {fd}')
        return 0

    def read(self, fd, length):
        """Return (actual_bytes_read, padded_to_length_buffer)."""
        fobj = self.files[fd]
        data = fobj.read(length)
        n = len(data)
        if n < length:
            data = data + b'\x00' * (length - n)
        log(f'[pcdrv] read fd {fd} len {length} -> {n} bytes')
        return n, data

    def write(self, fd, data):
        fobj = self.files[fd]
        fobj.write(data)
        log(f'[pcdrv] write fd {fd} -> {len(data)} bytes')
        return len(data)

    def seek(self, fd, offset, wheel):
        fobj = self.files[fd]
        fobj.seek(offset, wheel)
        pos = fobj.tell()
        log(f'[pcdrv] seek fd {fd} off {offset} wheel {wheel} -> {pos}')
        return pos


def _pcdrv_recv_write_stream(ser, reader, length):
    """Receive a KDWriteStreamV2 payload: `length` raw bytes, with a 4-byte
    host->PS1 dummy at each 2048 boundary, then a trailing 4-byte checksum."""
    data = bytearray()
    received = 0
    while received < length:
        boundary = min(((received // CHUNK_SIZE) + 1) * CHUNK_SIZE, length)
        want = boundary - received
        data += reader.read_exact(want)
        received += want
        if received % CHUNK_SIZE == 0:
            ser.write(b'\x00\x00\x00\x00')  # dummy KDRead32 on the PS1 side
            ser.flush()
    reader.read_u32()  # trailing total checksum (PS1 trusts the host, ignore)
    return bytes(data)


def _pcdrv_send_read_stream(ser, reader, data):
    """Send a KDReadStreamV2 payload with per-chunk CHEK/MORE handshaking."""
    sent = 0
    total = len(data)
    while sent < total:
        boundary = min(((sent // CHUNK_SIZE) + 1) * CHUNK_SIZE, total)
        chunk = data[sent:boundary]
        while True:
            ser.write(chunk)
            ser.flush()
            tok = reader.read_exact(4)
            if tok != CHEK:
                raise IOError(f'PCDRV read stream: expected CHEK, got {tok!r}')
            ser.write(p32(calculate_checksum(chunk)))
            ser.flush()
            resp = reader.read_exact(4)
            if resp == MORE:
                break
            if resp == ERR:
                continue  # PS1 rewound; resend this chunk
            raise IOError(f'PCDRV read stream: expected MORE/ERR!, got {resp!r}')
        sent = boundary


def handle_pcdrv_op(ser, reader, pcdrv):
    """Service one PCDRV op. The escape (0x00 'p') has already been consumed."""
    operand = reader.read_u32()
    ser.write(OKAY)  # presence ack
    ser.flush()

    try:
        if operand in (PC_CREATE, PC_OPEN):
            name = reader.read_cstr()
            mode = reader.read_u32()
            fd = pcdrv.create(name, mode) if operand == PC_CREATE else pcdrv.open(name, mode)
            ser.write(OKAY + p32(fd))
            ser.flush()
            return

        a1 = reader.read_u32()  # handle
        a2 = reader.read_u32()  # length / offset
        a3 = reader.read_u32()  # memaddr / wheel

        if operand == PC_WRITE:
            ser.write(OKAY)  # allow the write
            ser.flush()
            data = _pcdrv_recv_write_stream(ser, reader, a2)
            n = pcdrv.write(a1, data)
            ser.write(OKAY + p32(n))
            ser.flush()
        elif operand == PC_READ:
            n, data = pcdrv.read(a1, a2)
            ser.write(OKAY + p32(n))
            ser.write(p32(calculate_checksum(data)))
            ser.flush()
            _pcdrv_send_read_stream(ser, reader, data)
        elif operand == PC_CLOSE:
            r = pcdrv.close(a1)
            ser.write(OKAY + p32(r))
            ser.flush()
        elif operand == PC_SEEK:
            pos = pcdrv.seek(a1, a2, a3)
            ser.write(OKAY + p32(pos))
            ser.flush()
        else:
            log(f'[pcdrv] unsupported operand 0x{operand:x}')
            ser.write(NOPE)
            ser.flush()
    except (OSError, ValueError, KeyError) as e:
        log(f'[pcdrv] op 0x{operand:x} failed: {e}')
        ser.write(NOPE)
        ser.flush()


def serve_output(ser, reader, pcdrv=None, idle_timeout=30):
    """Stream TTY output to stdout, servicing PCDRV ops inline. Ends on Unirom's
    HLTD halt token (the program trapping into the debugger, e.g. the exit break)
    or after idle_timeout seconds of silence."""
    output = bytearray()
    pending_zero = False
    last = time.time()
    while time.time() - last < idle_timeout:
        b = reader.read1(timeout=0.2)
        if b is None:
            continue
        last = time.time()

        if pending_zero:
            pending_zero = False
            if b == b'p' and pcdrv is not None:
                handle_pcdrv_op(ser, reader, pcdrv)
                continue
            if b == b'\x00':
                pending_zero = True
                continue
            # stray escape: drop the 0x00, emit this byte

        elif b == b'\x00':
            pending_zero = True
            continue

        output += b
        sys.stdout.buffer.write(b)
        sys.stdout.buffer.flush()
        # HLTD is Unirom's halt token, emitted whenever a program traps into the
        # debugger via break - including the deliberate exit break the test
        # runtime fires on shutdown. It's a protocol-level signal independent of
        # program output, so it's the only end-of-binary marker we rely on; tests
        # route their exit through the break rather than printing a sentinel.
        if b'HLTD' in output[-16:]:
            time.sleep(0.5)
            tail = ser.read(ser.in_waiting or 0)
            if tail:
                sys.stdout.buffer.write(tail.replace(b'\x00', b''))
                sys.stdout.buffer.flush()
            break


def upload_exe(port, filepath, baud=115200, pcdrv_base=None):
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    # Pad to 2048-byte boundary
    mod = len(data) % CHUNK_SIZE
    if mod != 0:
        data += bytearray(CHUNK_SIZE - mod)

    if len(data) < 0x800:
        log("[!] File too small to be a PS-EXE (need at least 0x800 byte header)")
        return False

    ser = serial.Serial(port, baud, timeout=2)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    # Drain any pending boot output
    drain(ser, quiet_seconds=2.0)

    # Always arm Unirom's kdebug handler before upload. It bridges PCDRV ops
    # over serial when those are in use, and regardless of PCDRV it's what
    # catches the runtime's exit break and halts (HLTD) - the deterministic
    # end-of-binary signal serve_output waits on. Harmless to arm when unused.
    enable_debug_mode(ser)
    drain(ser, quiet_seconds=0.5)

    # === Handshake phase ===
    log("[*] Sending SEXE...")
    ser.write(b'SEXE')

    tok, pre, post = read_until_token(ser, [b'OKV2', b'OKV3', b'OKAY'], timeout=5)
    if tok is None:
        log(f"[!] No response from Unirom. Raw: {pre}")
        ser.close()
        return False

    protocol = 1
    if tok == b'OKV2':
        ser.write(b'UPV2')
        protocol = 2
        tok2, _, post = read_until_token(ser, [b'OKAY'], timeout=3)
        log("[*] Protocol V2")
    elif tok == b'OKV3':
        ser.write(b'UPV3')
        protocol = 3
        tok2, _, post = read_until_token(ser, [b'OKAY'], timeout=3)
        log("[*] Protocol V3")
    else:
        log("[*] Protocol V1")

    # Drain post-handshake echo/boot data
    time.sleep(0.5)
    drain(ser, quiet_seconds=1.0)

    # === Transfer phase ===
    jump_addr = struct.unpack_from('<I', data, 0x10)[0]
    base_addr = struct.unpack_from('<I', data, 0x18)[0]
    data_size = len(data) - 0x800
    checksum = calculate_checksum(data[0x800:])

    log(f"[*] Upload: {data_size} bytes -> 0x{base_addr:08X}, jump 0x{jump_addr:08X}")

    # Send header
    ser.write(bytes(data[:2048]))
    ser.flush()
    time.sleep(0.05)

    # Send metadata
    ser.write(struct.pack('<I', jump_addr))
    ser.write(struct.pack('<I', base_addr))
    ser.write(struct.pack('<I', data_size))
    ser.write(struct.pack('<I', checksum))
    ser.flush()
    time.sleep(0.05)

    # Send data chunks
    total = len(data)
    num_data_chunks = (total - CHUNK_SIZE) // CHUNK_SIZE
    chunk_num = 0
    errors = 0

    # Bytes that landed alongside protocol tokens during chunk acks. The
    # binary may start running and printing before the host has finished
    # processing the last chunk's MORE; if those output bytes arrive in the
    # same buffer as the token, read_until_token would otherwise drop them.
    early_output = b''

    def stash_program_bytes(*chunks):
        nonlocal early_output
        for c in chunks:
            if c:
                early_output += c

    for i in range(CHUNK_SIZE, total, CHUNK_SIZE):
        chunk_end = min(i + CHUNK_SIZE, total)
        chunk = data[i:chunk_end]
        chunk_num += 1

        ser.write(bytes(chunk))
        ser.flush()

        if protocol >= 2:
            tok, pre, post = read_until_token(ser, [b'CHEK'], timeout=10)
            if tok != b'CHEK':
                log(f"[!] Chunk {chunk_num}/{num_data_chunks}: CHEK timeout")
                errors += 1
                continue
            stash_program_bytes(pre, post)

            chunk_sum = calculate_checksum(chunk)
            ser.write(struct.pack('<I', chunk_sum))

            tok2, pre2, post2 = read_until_token(ser, [b'MORE', b'ERR!'], timeout=10)
            if tok2 == b'ERR!':
                log(f"[!] Chunk {chunk_num}/{num_data_chunks}: checksum error")
                errors += 1
            stash_program_bytes(pre2, post2)

    log(f"[*] Uploaded {chunk_num} chunks, {errors} errors. Executing.")

    # === Read program output (serving PCDRV if enabled) ===
    pcdrv = None
    if pcdrv_base is not None:
        pcdrv = PCDrv(pcdrv_base)
        log(f"[*] PCDRV enabled, base dir: {pcdrv.base}")
    reader = SerialReader(ser, prime=early_output)
    serve_output(ser, reader, pcdrv=pcdrv)

    ser.close()
    return True


def main():
    ap = argparse.ArgumentParser(description="Upload a PS-EXE to a PS1 via Unirom serial.")
    ap.add_argument('file', help='PS-EXE file to upload')
    ap.add_argument('port', nargs='?', default='/dev/ttyUSB0', help='serial port (default /dev/ttyUSB0)')
    ap.add_argument('--baud', type=int, default=115200, help='baud rate (default 115200)')
    ap.add_argument('--pcdrv-base', metavar='DIR',
                    help='serve PCDRV file ops out of DIR (enables PCDRV)')
    args = ap.parse_args()
    ok = upload_exe(args.port, args.file, baud=args.baud, pcdrv_base=args.pcdrv_base)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
