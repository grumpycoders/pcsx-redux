#include "ps1sdk.h"

static int _use_flow_control = 0;

static inline void sio_set_ctrl(uint16_t mask, uint16_t v)
{	
	*R_PS1_SIO1_CTRL = ((*R_PS1_SIO1_CTRL & mask) | v);
}

static inline void sio_set_mode(uint16_t v)
{
	// bits 0 and 1 should always be 0 and 1, respectively
	// this apparently corresponds to "baud rate multiplier 16"
	*R_PS1_SIO1_MODE = ((v & (~3)) | 2;
}

static inline void sio_set_baud(uint16_t v)
{
	// I don't understand this... PsyQ says "bps must be in the range 9600 - 2073600 and evenly divisible into 2073600"
	*R_PS1_SIO1_BAUD = 2116800/v;
}

static inline uint16_t sio_get_status(void)
{
	return 	*R_PS1_SIO1_STATUS;
}

static inline uint8_t sio_get_data(void)
{
	return *R_PS1_SIO1_DATA;
}

static inline void sio_put_data(uint8_t d)
{
	*R_PS1_SIO1_DATA = d;
}

uint8_t read_sio(void)
{
	uint8_t d;
	
	// assert RTR(Ready To Receive akia "CTS")
	sio_set_ctrl(~(SIO_CTRL_CTS_EN), SIO_CTRL_CTS_EN);
	
	// wait for data in the RX FIFO
	while(!(sio_get_status() & SIO_STAT_RX_RDY));
	
	// pop a byte from the RX FIFO
	d = sio_get_data();

	// deassert RTR
	sio_set_ctrl(~(SIO_CTRL_CTS_EN), 0);

	return d;
}

void write_sio(uint8_t d)
{
	// wait for TX FIFO to be ready and empty
	while((sio_get_status() & (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY)) != (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY));

	// push a byte into the TX FIFO
	sio_set_data(d);
}

void init_sio(uint32_t baud)
{
	sio_set_mode(SIO_MODE_CHLEN_8 | SIO_MODE_P_NONE | SIO_MODE_SB_1); /* 8bit, no-parity, 1 stop-bit */
	sio_set_baud(baud);
	sio_set_ctrl(0, SIO_CTRL_RX_EN | SIO_CTRL_TX_EN);
}

uint32_t sio_read32(void)
{
	uint32_t d;
	
	d = read_sio() | \
		(read_sio() << 8) | \
		(read_sio() << 16) | \
		(read_sio() << 24);
    return d; 
}

// sizeof() == 0x3C(60)
typedef struct st_ExecInfo
{
    uint32_t entry;      // 0x00 : Address of program entry-point.
    uint32_t init_gp;    // 0x04 : SCE only.  Initial value the "gp" register is set to.  0 for PS-X EXE.
    uint32_t text_addr;  // 0x08 : Memory address to which the .text section is loaded.
    uint32_t text_size;  // 0x0C : Size of the .text section in the file and memory.
    uint32_t data_addr;  // 0x10 : SCE only.  Memory address to which the .data section is loaded.  0 for PS-X EXE.
    uint32_t data_size;  // 0x14 : SCE only.  Size of the .data section in the file and memory.  0 for PS-X EXE.
    uint32_t bss_addr;   // 0x18 : Memory address of the .bss section.  .bss is initialized by Exec().
    uint32_t bss_size;   // 0x1C : Size of the .bss section in memory.
    uint32_t stack_addr; // 0x20 : Memory address pointing to the bottom(lowest address) of the stack. BIOS replaces with "STACK" parameter of "SYSTEM.CNF" file.
    uint32_t stack_size; // 0x24 : Size of the stack.  Can be 0.
    uint32_t saved_sp;   // 0x28 : Used by BIOS Exec() function to preserve the "sp" register.
    uint32_t saved_fp;   // 0x2C : Used by BIOS Exec() function to preserve the "fp" register.
    uint32_t saved_gp;   // 0x30 : Used by BIOS Exec() function to preserve the "gp" register.
    uint32_t saved_ra;   // 0x34 : Used by BIOS Exec() function to preserve the "ra" register.
    uint32_t saved_s0;   // 0x38 : Used by BIOS Exec() function to preserve the "s0" register.
} ExecInfo;

// sizeof() == 0x88(136)
typedef struct st_EXE_Header
{
    uint8_t magic[8];    // 0x00-0x07 : "PS-X EXE"(retail) or "SCE EXE"(???)
    uint32_t text_off;   // 0x08 : SCE only.  Offset of the start of the .text section in the file. 0 for PS-X EXE.
    uint32_t data_off;   // 0x0C : SCE only.  Offset of the start of the .text section in the file. 0 for PS-X EXE.
    struct st_ExecInfo exec; // 0x10-0x4B
    char license[60]; // 0x4C-0x87
} EXE_Header;

void sioload()
{
	int i;
	uint8_t sync;
	uint8_t *p;
	uint8_t header_buf[2048];
	EXE_Header *header = (EXE_Header *) header_buf;
	uint32_t x_addr, // ignored
			write_addr,
			n_load;

	sio_write

	do { sync = read_sio() } while (sync != 99);

	for(i = 0; i < sizeof(header_buf); i++)
	{
		header_buf[i] = read_sio();
	}
	
    x_addr = sio_read32();
    write_addr = sio_read32();
    n_load = sio_read32();

	for(i = 0; i < n_load; i++)
	{
		((uint8_t *) write_addr)[i] = read_sio();
	}
	
	header->exec.stack_addr = STACKP;
	header->exec.stack_size = 0;
	EnterCriticalSection();
	Exec(&(header->exec), 1, 0);
}

//extern long _sio_control(unsigned long cmd, unsigned long arg, unsigned long param);

//~ int Sio1Callback (void (*func)())
//~ {
	//~ return InterruptCallback(8, func);
//~ }

int DelSIO(void)
{
	close(stdin);
	close(stdout);
	DelDrv("tty");
	sio_set_ctrl(SIO_CTRL_RESET_INT | SIO_CTRL_RESET_ERR);
	AddCONSOLEDevice();
	if(open("tty00:", O_RDONLY) != stdin) return 1;
	if(open("tty00:", O_WRONLY) != stdout) return 1;
	return 0;
}

int main(void)
{      
	DelSIO(); // removes the "tty" device

	// 2073600(2Mbaud) is max
	// 1036800(1Mbaud)
	init_sio(1036800);
	sioload();
	return 0;
}
