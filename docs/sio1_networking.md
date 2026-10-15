# SIO1 networking

SIO1 is the PlayStation's second serial interface, connected to the serial port. PCSX-Redux can relay that port over TCP, either by listening for a connection (the SIO1 server) or by connecting to another machine (the SIO1 client). This can be used to link two instances of PCSX-Redux, or to let a program running in the emulator talk to a tool on the host.

## Settings

All the settings are in `Configuration > Emulation`, in the `Emulation Configuration` window:

| Setting | Default | Function |
| :- | :- | :- |
| Enable SIO1 Server | off | Listens for an incoming TCP connection, and relays it to SIO1. |
| SIO1 Server Port | 6699 | Port the server listens on. |
| Enable SIO1 Client | off | Connects to a remote SIO1 server, and relays the connection to SIO1. |
| SIO1 Client Host | | Address of the server to connect to. |
| SIO1 Client Port | 6699 | Port of the server to connect to. |
| SIO1Mode | Protobuf | How the bytes are carried over TCP, see below. |

The server listens on all network interfaces, so it is reachable from other machines on the network, and not only from `localhost`. The client host has to be an IPv4 address, such as `127.0.0.1`; host names are not resolved.

The mode is read when the server or the client starts. Changing it while one of them is running has no effect until it is disabled and enabled again.

The `Reset SIO` button resets the SIO1 registers. The `Reconnect` button is only available while the client is enabled and its connection has dropped. If the client fails to connect in the first place, disable and enable it again instead.

The state of the SIO1 registers can be inspected with `Debug > Misc hardware > Show SIO1 debug`.

## Modes

### Protobuf

This is the default mode, meant for linking two instances of PCSX-Redux together, one running the server and the other one running the client. Both sides need to be set to this mode.

Each message is sent as a single byte holding the length of the message, followed by the message itself, encoded as a protobuf `SIOPayload` message:

```proto
message DataTransfer {
    bytes data = 1;
}

message FlowControl {
    bool dxr = 1;
    bool xts = 2;
}

message SIOPayload {
    DataTransfer data_transfer = 1;
    FlowControl flow_control = 2;
}
```

Every byte the program transmits is sent in its own `data_transfer` message. Whenever the program changes the DTR or RTS bits of the SIO1 control register, a `flow_control` message is sent, with `dxr` holding DTR and `xts` holding RTS. On the receiving side, `dxr` sets the DSR bit of the status register, and `xts` sets the CTS bit.

Received data bytes are only stored in the receive FIFO while the receiving program has RTS set in its control register; otherwise they are dropped. If a message cannot be decoded, the connection is closed, and the server or client needs to be restarted.

### Raw

In this mode, the TCP connection carries the serial bytes as they are, with no framing and no flow control: every byte the program writes to the data register is sent as is, and every byte received is placed in the receive FIFO. The CTS and DSR bits are not driven by the remote side. This is the mode to use to talk to a tool on the host, such as a terminal or a script.

Raw mode is only supported by the server. The client does not support it, so select Protobuf before enabling the client.

## Example

The following program configures SIO1 for 8 data bits, no parity, 1 stop bit, then sends back every byte it receives. It polls the status register, with SIO1 interrupts left disabled.

```c
#include <stdint.h>

#define SIO1_DATA (*(volatile uint8_t *)0x1f801050)
#define SIO1_STAT (*(volatile uint16_t *)0x1f801054)
#define SIO1_MODE (*(volatile uint16_t *)0x1f801058)
#define SIO1_CTRL (*(volatile uint16_t *)0x1f80105a)
#define SIO1_BAUD (*(volatile uint16_t *)0x1f80105e)

int main(void) {
    SIO1_CTRL = 0x0040;  // reset
    SIO1_MODE = 0x004e;  // reload factor x16, 8 data bits, no parity, 1 stop bit
    SIO1_BAUD = 18;      // 33868800 / (18 * 16) = 117600 bps, close to 115200
    SIO1_CTRL = 0x0027;  // TX enable, DTR, RX enable, RTS

    for (;;) {
        while (!(SIO1_STAT & 0x0002));  // wait until a byte is received
        uint8_t c = SIO1_DATA;
        while (!(SIO1_STAT & 0x0001));  // wait until the transmitter is ready
        SIO1_DATA = c;
    }
}
```

The data register is accessed with 8-bit reads and writes, and the mode, control and baud rate registers with 16-bit writes. See the [serial interfaces](https://psx-spx.consoledev.net/dev/ps1/sio/serialinterfacessio/) page of psx-spx for the meaning of each bit.

To try it, set `SIO1Mode` to `Raw`, then enable the SIO1 server, and run the program. Then connect to the server from the host, for instance with netcat:

```bash
$ nc localhost 6699
```

Anything typed in netcat is sent back by the program.

The emulator relays the bytes regardless of the configured baud rate, which only affects the timing of the SIO1 interrupts.
