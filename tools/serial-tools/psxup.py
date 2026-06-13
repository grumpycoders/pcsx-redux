#!/usr/bin/env python3
"""Upload a PS-EXE to a PS1 running Unirom via serial, then read output.

Protocol (from Unirom sio.c and nops NOTPSXSERIAL.CS):

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
PCDRV framing: PS1-to-PC direction uses \\x00 to distinguish file ops from TTY output.
"""
import serial
import struct
import sys
import time

CHUNK_SIZE = 2048


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


def upload_exe(port, filepath, baud=115200):
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

    # === Read program output ===
    # All program output goes to stdout, all status to stderr.
    deadline = time.time() + 30
    output = b''
    if early_output:
        # Surface any binary output bytes that arrived during the upload
        # phase before the read loop took over.
        display = early_output.replace(b'\x00', b'')
        output += display
        if display:
            sys.stdout.buffer.write(display)
            sys.stdout.buffer.flush()
    while time.time() < deadline:
        if ser.in_waiting:
            chunk = ser.read(ser.in_waiting)
            display = chunk.replace(b'\x00', b'')
            output += display
            if display:
                sys.stdout.buffer.write(display)
                sys.stdout.buffer.flush()
            if b'=== Done ===' in output or b'Synthesis:' in output:
                time.sleep(0.5)
                if ser.in_waiting:
                    final = ser.read(ser.in_waiting).replace(b'\x00', b'')
                    sys.stdout.buffer.write(final)
                    sys.stdout.buffer.flush()
                break
        else:
            time.sleep(0.05)

    ser.close()
    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        log(f"Usage: {sys.argv[0]} <file.ps-exe> [port]")
        sys.exit(1)
    port = sys.argv[2] if len(sys.argv) > 2 else '/dev/ttyUSB0'
    upload_exe(port, sys.argv[1])
