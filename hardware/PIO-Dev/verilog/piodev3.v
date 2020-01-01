module piodev3(
  // The address lines we have connected.
  input A0,
  input A1,
  input A2,
  input A3,
  input A4,
  input A16,
  input A17,
  input A18,
  input A19,
  input A20,
  input A21,
  input A22,

  // The internal data bus, that connects to all of our parts on the board.
  inout [0:7] D,

  // The PIO's !WR and !RD pins.
  input nWR,
  input nRD,

  // The CS pin of the SRAM.
  output nCS_SRAM,

  // The !OE pin of the switch's latch.
  output nCS_SWITCH,

  // Our 12Mhz clock.
  input CLK,

  // A20 and CS pins for the onboard flash, and zif socket.
  output A20_FLASH,
  output nCS_FLASH,
  output A20_SOCKET,
  output nCS_SOCKET,

  // Two hardware jumpers, pulled up. Grounded on version 3.0 of the board.
  // Version 3.1 has the actual jumpers traces.
  input JP1,
  input JP2,

  // The CH375's CS pin.
  output nCS_CH,

  // The CH375's interrupt line.
  input nIN_CH,

  // The LE pin of the LED's latch.
  output CS_LEDS,

  // Our momentary soft button, pulled up.
  input SOFT,

  // The FT2232H's !CS, A0, and !RESET lines. The !RESET line is
  // pulled down by default, and goes up when a usb cable is
  // connected to the computer, providing 5v.
  output nCS_PORTB,
  output A0_PORTA,
  output nCS_PORTA,
  inout nRESET_FT,

  // The 10 optional GPIO pins on top of the CPLD.
  inout [1:10] GPIO,

  // The additional pins from the PIO.
  inout DACK,
  input nWR2,
  inout DREQ,

  // The two small dip switches near the CPLD.
  input SW1,
  input SW2,

  // The A20 pin of the SRAM.
  output A20_SRAM,

  // The interrupt line of the PIO port.
  output nIN10,

  // The Switch Board enable pin, to redirect the CS2 line.
  // If the line 5 of the PIO port hasn't been cut, this will
  // make the CPLD burn 3.3v through ground. There is a 200ohm
  // resistor to prevent damage.
  output SBEN,

  // !CS0 and !CS2 from the PIO. The !CS2 line will only work if
  // the Switch Board has been installed, SBEN is high, and the
  // line 39 of the PIO port has been cut and redirected to the
  // Switch Board properly.
  //
  // By default, !CS0 will be active when reading from the
  // 0x1f000000 memory range, and !CS2 will be active when reading
  // from the 0xbfc00000 memory range.
  input nCS0,
  input nCS2,

  // The PIO's data line. It isn't connected on any other device on
  // the PCB, leaving it up to the CPLD to latch it.
  inout [0:7] PD,

  // The PSX's !RESET line. Will go high after ~300ms after power up,
  // as long as the reset controller chips are still there on the PSU.
  // Can be used to cause the PSX to reset, by asserting this line low.
  inout nRESET
);

// --------------------------------

// Some helpers. Should be easily optimized away by the compiler.

wire [23:0] A = {
  1'b0,  A22,  A21,  A20,
   A19,  A18,  A17,  A16,
  1'b0, 1'b0, 1'b0, 1'b0,
  1'b0, 1'b0, 1'b0, 1'b0,
  1'b0, 1'b0, 1'b0, 1'b0,
  1'b0, 1'b0, 1'b0,   A4,
    A3,   A2,   A1,   A0
};

wire WR = ~nWR;
wire RD = ~nRD;
wire IN_CH = ~nIN_CH;
wire CS0 = ~nCS0;
wire CS2 = ~nCS2;

// Defaults for all of the outputs.
//assign nCS_SRAM = 1'b1;
//assign nCS_SWITCH = 1'b1;
//assign CS_LEDS = 1'b0;
//assign A20_FLASH = 1'b0;
//assign nCS_FLASH = 1'b1;
//assign A20_SOCKET = 1'b0;
//assign nCS_SOCKET = 1'b1;

//assign nCS_CH = 1'b1;

//assign nCS_PORTB = 1'b1;
//assign A0_PORTA = 1'b0;
//assign nCS_PORTA = 1'b1;

assign nRESET_FT = 1'bz;

assign GPIO = 10'bzzzzzzzzzz;

assign DACK = 1'bz;
assign DREQ = 1'bz;

//assign A20_SRAM = 1'b0;
assign nIN_10 = 1'b1;

//assign SBEN = 1'b0;

//assign PD = 8'bzzzzzzzz;
//assign D = 8'bzzzzzzzz;
assign nRESET = 1'bz;

// --------------------------------

// Quick diagnostics code. Will make LEDs blink,
// according to the clock by default, and according to
// the dip switches when the soft button is pressed.
//
// Tests if the dip switches, the LEDs, the latches and the clock
// are properly wired and working correctly.

/*
assign CS_LEDS = 1'b1;
assign nCS_SWITCH = SOFT;

reg [31:0] cnt = 0;
always @(posedge CLK) cnt <= cnt + 1;

assign D = SOFT ? ~cnt[27:20] : 8'bzzzzzzzz;
*/

// --------------------------------

// Passthrough from CS0 to the FT2232H's port A (recovery)

/*
assign nCS_PORTA = nCS0;
assign A0_PORTA = 1'b0;
assign PD = RD && CS0 ? D : 8'bzzzzzzzz;
*/

// --------------------------------

// Passthrough from CS0 to the socket flash (caetla)

/*
assign nCS_SOCKET = nCS0;
assign A20_SOCKET = 1'b0;
assign PD = RD && CS0 ? D : 8'bzzzzzzzz;
*/

// --------------------------------

// Passthrough from CS2 to the socket flash (bios)

/*
assign nCS_SOCKET = nCS2;
assign A20_SOCKET = 1'b0;
assign PD = RD && CS2 ? D : 8'bzzzzzzzz;
assign SBEN = 1'b1;
*/

// --------------------------------

// Main behavior description of the PIO board

reg [7:0] bufferOut = 8'b00000000;
reg [7:0] bufferIn = 8'b00000000;
reg activateOutput = 0;
reg [7:0] bits = 8'b00000000;

// Helper for making sure CS isn't strobing.
wire strobe = WR || RD;

// Our mappings.

// Flash1 runs from 0x000000 to 0x1fffff, so check address bits A21 and A22,
// and ignore everything else.
assign nCS_FLASH = !(strobe && CS0 && !A22 && !A21);
// Flash2 runs from 0x200000 to 0x3fffff, so check address bits A21 and A22,
// and ignore everything else. It's also used to mirror the BIOS, so toggle
// it for any CS2 read.
assign nCS_SOCKET = !(strobe && CS2 || CS0 && !A22 && A21);
// SRAM runs from 0x400000 to 0x5fffff, so check address bits A21 and A22,
// and ignore everything else.
assign nCS_SRAM = !(strobe && CS0 && A22 && !A21);
// While all of the above are full-length mappings, the next ones are one
// or two bytes larges, therefore we need to check more address bits.
// We technically have more address bits than that tied to the CPLD, but
// for now, that's all we need to distinguish. If we need to add more
// addresses to watch for, then we'll have to add more address bits to
// these checks.
// FT2232H's port A runs from 0x600000 to 0x600001.
assign nCS_PORTA = !(strobe && CS0 && A22 && A21 && !A2 && !A1);
// FT2232H's port B runs from 0x600002 to 0x600003.
assign nCS_PORTB = !(strobe && CS0 && A22 && A21 && !A2 && A1);
// CH375B's runs from 0x600004 to 0x600005.
assign nCS_CH = !(strobe && CS0 && A22 && A21 && A2 && !A1);
// Switches and leds are at 0x600006. Writing to this address means
// assigning some value to the LEDs. Reading this address means
// reading the dip switch values.
assign nCS_SWITCH = !(strobe && CS0 && A22 && A21 && A2 && A1 && !A0 && RD);
assign CS_LEDS = (strobe && CS0 && A22 && A21 && A2 && A1 && !A0 && WR);
// Configuration bits are at 0x600007.
wire internalData = strobe && A22 && A21 && A2 && A1 && A0;


// We need to pay attention for CS0 and CS2.
// Note that CS2 is on a grounded line of the PIO by default.
// If not cut, this will always be active.
wire CS = CS0 || CS2;

// When the CPU is writing, the PIO's data port needs to be an input.
assign PD = WR ? 8'bzzzzzzzz :
// Otherwise, if we're currently being read, pass through the data bus
// to the PIO data bus.
(CS && RD ? (internalData ? bits : D) :
// RD goes up before CS usually. When that's the case, try to sustain
// the sampled value of the data bus.
(CS && activateOutput ? bufferOut :
// By default, in any other case, present a high-Z bus to the PIO.
8'bzzzzzzzz));

// When the CPU is writing, just be a pass through from the CPU to
// our data bus.
assign D = WR ? PD :
// Othewise, when the CPU is reading from us, we need to be an input
// for the devices on our data bus.
(CS && RD ? 8'bzzzzzzzz : 
// In all other cases, mirror on the data bus the last sampled value
// from the CPU. This last case covers the moment when WR goes up before
// CS, giving time to the devices on our data bus to sample it properly.
bufferIn);

// For now, no special paging.
assign A20_FLASH = A20;
assign A20_SOCKET = A20;
assign A20_SRAM = A20;

// Disable real BIOS chip.
assign SBEN = 1'b1;

// For now, no special meaning for port A's A0.
// Might be useful for recovery mode later on.
assign A0_PORTA = A0;

// When RD goes up, sample the devices on our data bus.
always @(posedge nRD) begin
  bufferOut <= internalData ? bits : D;
end

// When WR goes up, sample the PIO's data bus.
always @(posedge nWR) begin
  bufferIn <= PD;
end

// Our internal configuration bits' special needs.
always @(posedge nWR or posedge nRESET) begin
  if (nRESET) begin
    bits <= 8'b00000000;
  end else if (internalData) begin
    bits <= PD;
  end
end

// Sample our boolean telling us if we need to emit data on the
// PIO port when RD goes low.
always @(negedge nRD) begin
  activateOutput <= CS;
end

assign GPIO[1] = nCS_PORTB;
assign GPIO[2] = nCS_CH;
assign GPIO[3] = nCS_SRAM;
assign GPIO[4] = nCS_FLASH;
assign GPIO[5] = nCS_PORTA;

endmodule
