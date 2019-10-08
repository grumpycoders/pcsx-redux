/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# Main header for the PlayStation 1 SDK
#
*/

#ifndef _LIBPS1_H
#define _LIBPS1_H

#include <stddef.h>
#include <pstypes.h>
#include <exec.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EV_DESC_MASK 0xFF000000

enum {
    EV_DESC_HW = 0xF0000000,
    EV_DESC_EV = 0xF1000000,
    EV_DESC_RC = 0xF2000000,
    EV_DESC_USR = 0xF3000000,
    EV_DESC_SW = 0xF4000000,
    EV_DESC_TH = 0xFF000000
};

/* Hardware Events */
enum {
    EVD_HW_VBLANK = 0xF0000001,
    EVD_HW_GPU = 0xF0000002,
    EVD_HW_CDROM = 0xF0000003,
    EVD_HW_DMAC = 0xF0000004,
    EVD_HW_RTC0 = 0xF0000005,
    EVD_HW_RTC1 = 0xF0000006,
    EVD_HW_RTC2 = 0xF0000007,
    EVD_HW_PAD = 0xF0000008,
    EVD_HW_SPU = 0xF0000009,
    EVD_HW_PIO = 0xF000000A,
    EVD_HW_SIO = 0xF000000B,
    EVD_HW_CPU = 0xF0000010,
    EVD_HW_CARD = 0xF0000011,
    EVD_HW_CARD_0 = 0xF0000012,
    EVD_HW_CARD_1 = 0xF0000013
};

/* Software Events */
enum {
    EVD_SW_CARD = 0xF4000001,  // memcard
    EVD_SW_MATH = 0xF4000002,  // math
};

// Root Counter Events
enum {
    EVD_RC_CNT0 = 0xF2000000,  // display pixel
    EVD_RC_CNT1 = 0xF2000001,  // horizontal sync
    EVD_RC_CNT2 = 0xF2000002,  // 1/8 system clock
    EVD_RC_CNT3 = 0xF2000003   // VBlank
};

enum {
    EVSP_COUNT_Z = 0x0001,   /* counter becomes zero */
    EVSP_INTR = 0x0002,      /* interrupted */
    EVSP_IO_ERR = 0x0004,    /* end of i/o */
    EVSP_FCLOSE = 0x0008,    /* file was closed */
    EVSP_CMD_ACK = 0x0010,   /* command acknowledged */
    EVSP_CMD_COMP = 0x0020,  /* command completed */
    EVSP_DATA_RDY = 0x0040,  /* data ready */
    EVSP_DATA_END = 0x0080,  /* data end */
    EVSP_TIMEOUT = 0x0100,   /* time out */
    EVSP_UNKNOWN = 0x0200,   /* unknown command */
    EVSP_DOM_ERR = 0x0301,   /* domain error in libmath */
    EVSP_RANGE_ERR = 0x0302, /* range error in libmath */
    EVSP_IO_END_R = 0x0400,  /* end of read buffer */
    EVSP_IO_END_W = 0x0800,  /* end of write buffer */
    EVSP_TRAP = 0x1000,      /* general interrupt */
    EVSP_NEW_DEV = 0x2000,   /* new device */
    EVSP_SYSCALL = 0x4000,   /* system call instruction */
    EVSP_ERROR = 0x8000,     /* error happened */
    EVSP_PREV_ERR = 0x8001,  /* previous write error happened */
};

// Event Modes
enum {
    EVENT_MODE_INTR = 0x1000,   // interrupt
    EVENT_MODE_NOINTR = 0x2000  // no interrupt
};

// Event Status
enum {
    EVST_UNUSED = 0x0000,  // unused event
    EVST_WAIT = 0x1000,    // waiting
    EVST_ACTIVE = 0x2000,  // active
    EVST_ALREADY = 0x4000  // already occurred
};

// Task Modes
enum {
    TASK_MODE_RT = 0x1000,  // real-time
    TASK_MODE_PRI = 0x2000  // priority
};

// Task Status
enum {
    TASK_STAT_UNUSED = 0x1000,  // unused
    TASK_STAT_ACTIVE = 0x4000,  // active
};

typedef struct st_TableInfo {
    void* buf;
    int size;
} TableInfo;

struct TCBH {
    struct TCB* entry; /* NULL */
    uint32_t flag;
};

typedef struct st_Queue {
    void* head;
    void* tail;
} Queue;

/* Interrupt Control Block(IntrCB) */
/* sizeof() == 0x10(16) */
typedef struct st_IntrCB {
    struct st_IntrCB* next;  // 0x00
    void* func1;             // 0x04 - called if "func0" returns non-zero.  Can be NULL.
    void* func0;             // 0x08 - called first.  Should return 0 if "func1" should be called.
    uint32_t __pad;          // 0x0C
} IntrCB;

// sizeof() == 0x30(48)
typedef struct st_EntryInt {
    uint32_t ret;   // 0x00
    uint32_t r_sp;  // 0x04
    uint32_t r_fp;  // 0x08
    uint32_t r_s0;  // 0x0C
    uint32_t r_s1;  // 0x10
    uint32_t r_s2;  // 0x14
    uint32_t r_s3;  // 0x18
    uint32_t r_s4;  // 0x1C
    uint32_t r_s5;  // 0x20
    uint32_t r_s6;  // 0x24
    uint32_t r_s7;  // 0x28
    uint32_t r_gp;  // 0x2C
} EntryInt;

/* Task Control Block(TaskCB) */
/* sizeof() == 0xC0(192) */
typedef struct st_TaskCB {
    uint32_t status;  // 0x00
    uint32_t mode;    // 0x04
    uint32_t r_zero;  // 0x08
    uint32_t r_at;    // 0x0C
    uint32_t r_v0;    // 0x10
    uint32_t r_v1;    // 0x14

    uint32_t r_a0;  // 0x18
    uint32_t r_a1;  // 0x1C
    uint32_t r_a2;  // 0x20
    uint32_t r_a3;  // 0x24

    uint32_t r_t0;  // 0x28
    uint32_t r_t1;  // 0x2C
    uint32_t r_t2;  // 0x30
    uint32_t r_t3;  // 0x34
    uint32_t r_t4;  // 0x38
    uint32_t r_t5;  // 0x3C
    uint32_t r_t6;  // 0x40
    uint32_t r_t7;  // 0x44

    uint32_t r_s0;  // 0x48
    uint32_t r_s1;  // 0x4C
    uint32_t r_s2;  // 0x50
    uint32_t r_s3;  // 0x54
    uint32_t r_s4;  // 0x58
    uint32_t r_s5;  // 0x5C
    uint32_t r_s6;  // 0x60
    uint32_t r_s7;  // 0x64

    uint32_t r_t8;  // 0x68
    uint32_t r_t9;  // 0x6C

    uint32_t r_k0;  // 0x70
    uint32_t r_k1;  // 0x74

    uint32_t r_gp;  // 0x78
    uint32_t r_sp;  // 0x7C
    uint32_t r_fp;  // 0x80

    uint32_t r_ra;  // 0x84

    uint32_t r_pc;  // 0x88

    uint32_t r_hi;  // 0x8C
    uint32_t r_lo;  // 0x90

    uint32_t r_status;  // 0x94
    uint32_t r_cause;   // 0x98

    uint32_t r_unk9C;  // 0x9C
    uint32_t r_unkA0;  // 0xA0
    uint32_t r_unkA4;  // 0xA4

    uint32_t system[6];  // 0xA8-0xBF
} TaskCB;

/* Event Control Block(EventCB) */
/* sizeof() == 0x1C(28) */
typedef struct st_EventCB {
    uint32_t desc;          // 0x00-0x03
    uint32_t status;        // 0x04-0x07
    uint32_t spec;          // 0x08-0x0B
    uint32_t mode;          // 0x0C-0x0F
    uint32_t (*handler)();  // 0x10-0x13
    uint32_t system[2];     // 0x14-0x1B
} EventCB;

// sizeof() == 0x0C(12)
typedef struct st_SystemConf {
    int tcb;         // 0x00
    int event;       // 0x04
    uint32_t stack;  // 0x08
} SystemConf;

typedef struct st_FixedPool {
    int entry_size;
    int max_entries;  // number of entries in the pool
    uint32_t* masks;
    void* entries;
} FixedPool;

void* malloc(uint32_t size);
void* calloc(uint32_t size);
void free(void* p);

uint32_t fpool_create(int entry_size, int max_entries);
void fpool_destroy(uint32_t pool_id);
void* fpool_alloc(uint32_t pool_id);
void fpool_free(uint32_t pool_id, void* p);

/* Kernel API calls */

extern void* SysMalloc(size_t size);

extern void SystemError(uint8_t type, uint32_t code);

// Install and init the ISO9660 device driver.
// Return: ???
extern int __96_init(void);

// remove the ISO9660 device driver.
// Return: ???
extern int __96_remove(void);

// test if a file is a valid PS-X EXE.
// The ExecInfo structure from the file header
// is loaded into "exec".
// Return: 1 on success, 0 on failure.
extern int LoadTest(const char* filename, ExecInfo* exec);

// Execute the application described in "exec".
// Return: 1
extern int Exec(ExecInfo* exec, uint32_t stack_addr, uint32_t stack_size);

// Load the executable file "filename" into memory.
// The ExecInfo structure from the file header
// is loaded into "exec".
// Return: 1 on success, 0 on failure.
extern int Load(const char* filename, ExecInfo* exec);

// Load the executable file "filename" into memory and execute it.
// Return: 1 on success, 0 on failure.
int LoadExec(const char* filename, uint32_t stack_addr, uint32_t stack_size);

// Get the current system configuration information.
void GetConf(int* event_p, int* tcb_p, uint32_t* stack_p);

// Set the system configuration information.
void SetConf(int event, int tcb, uint32_t stack);

void KernelRedirect(int tty_mode);
// AddCONSOLEDevice
void AddDummyConsoleDevice();

int _cdevscan(void);

void _exit_A0_58(int status);

/* Kernel System calls */
extern void Exception(void);
extern void EnterCriticalSection(void);
extern void ExitCriticalSection(void);

uint32_t* GetB0Table(void);
uint32_t* GetC0Table(void);

/* Non-native functions */

// initialize the system.  Only needed when the BIOS system init
//  has been bypassed, for example by hooking the PIO device "startup"
//  entry point.
int SystemInit(void);

// Boot the CD-ROM currently inserted in the drive.
// Skips PS1 logo display and additional disc checks.
// Call with "1" if __96_init() has previously been called.
int FastBootDisc(int rem96);

// pad/controller
int PAD_init(uint32_t type, void* buf);
int PAD_dr(void);
int InitPAD(void* buf1, int len1, void* buf2, int len2);

void FlushCache(void);

void delay_ms(uint32_t n);

// macros

#define M_TO_SYS_ID(__addr) (((uint32_t)__addr) >> 2)
#define M_FROM_SYS_ID(__id) (((uint32_t)__id) << 2)

// suspend/resume interrupts
#define M_SUSPEND_INTR(__state_ptr)                \
    {                                              \
        *(__state_ptr) = GetCOP0_STATUS();         \
        SetCOP0_STATUS(*(__state_ptr)&0xFFFFFFFE); \
        *(__state_ptr) &= 1;                       \
    }
#define M_RESUME_INTR(__state_ptr) \
    { SetCOP0_STATUS((*(__state_ptr)&1) | (GetCOP0_STATUS() & 0xFFFFFFFE)); }

#ifdef __cplusplus
}
#endif

#endif /* _LIBPS1_H */
