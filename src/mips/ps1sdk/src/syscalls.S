.set push
.set noreorder
.set noat

#include <mipsregs.h>

.text

.macro M_SYSCALL, label, tablenum, callnum
.global \label
.type \label, @function
.ent \label
\label:
                li      t1, \tablenum
                jr      t1
                li      t0, \callnum
.end \label
.endm

/* this will only be accurate if interrupts are disabled */
.global delay_ms
.type delay_ms, @function
.ent delay_ms
delay_ms:
                li      t0, 1665
_delay_ms_l2:
                bnez    t0, _delay_ms_l2
                addiu   t0, -1
                bnez    a0, delay_ms
                addiu   a0, -1
                jr      ra
                nop
.end delay_ms

M_SYSCALL open, 0xA0, 0x0000
M_SYSCALL lseek, 0xA0, 0x0001
M_SYSCALL read, 0xA0, 0x0002
M_SYSCALL write, 0xA0, 0x0003
M_SYSCALL close, 0xA0, 0x0004
M_SYSCALL ioctl, 0xA0, 0x0005
M_SYSCALL exit, 0xA0, 0x0006
M_SYSCALL sys_b0_39, 0xA0, 0x0007
M_SYSCALL getc, 0xA0, 0x0008
M_SYSCALL putc, 0xA0, 0x0009
M_SYSCALL todigit, 0xA0, 0x000a
M_SYSCALL atof, 0xA0, 0x000b
M_SYSCALL strtoul, 0xA0, 0x000c
M_SYSCALL strtol, 0xA0, 0x000d
M_SYSCALL abs, 0xA0, 0x000e
M_SYSCALL fabs, 0xA0, 0x000f
M_SYSCALL atoi, 0xA0, 0x0010
M_SYSCALL atol, 0xA0, 0x0011
M_SYSCALL atob, 0xA0, 0x0012
M_SYSCALL setjmp, 0xA0, 0x0013
M_SYSCALL longjmp, 0xA0, 0x0014
M_SYSCALL strcat, 0xA0, 0x0015
M_SYSCALL strncat, 0xA0, 0x0016
M_SYSCALL strcmp, 0xA0, 0x0017
M_SYSCALL strncmp, 0xA0, 0x0018
M_SYSCALL strcpy, 0xA0, 0x0019
M_SYSCALL strncpy, 0xA0, 0x001a
M_SYSCALL strlen, 0xA0, 0x001b
M_SYSCALL index, 0xA0, 0x001c
M_SYSCALL rindex, 0xA0, 0x001d
M_SYSCALL strchr, 0xA0, 0x001e
M_SYSCALL strrchr, 0xA0, 0x001f
M_SYSCALL strpbrk, 0xA0, 0x0020
M_SYSCALL strspn, 0xA0, 0x0021
M_SYSCALL strcspn, 0xA0, 0x0022
M_SYSCALL strtok, 0xA0, 0x0023
M_SYSCALL strstr, 0xA0, 0x0024
M_SYSCALL toupper, 0xA0, 0x0025
M_SYSCALL tolower, 0xA0, 0x0026
M_SYSCALL bcopy, 0xA0, 0x0027
M_SYSCALL bzero, 0xA0, 0x0028
M_SYSCALL bcmp, 0xA0, 0x0029
M_SYSCALL memcpy, 0xA0, 0x002a
M_SYSCALL memset, 0xA0, 0x002b
M_SYSCALL memmove, 0xA0, 0x002c
M_SYSCALL memcmp, 0xA0, 0x002d
M_SYSCALL memchr, 0xA0, 0x002e
M_SYSCALL rand, 0xA0, 0x002f
M_SYSCALL srand, 0xA0, 0x0030
M_SYSCALL qsort, 0xA0, 0x0031
M_SYSCALL strtod, 0xA0, 0x0032
M_SYSCALL malloc, 0xA0, 0x0033
M_SYSCALL free, 0xA0, 0x0034
M_SYSCALL lsearch, 0xA0, 0x0035
M_SYSCALL bsearch, 0xA0, 0x0036
M_SYSCALL calloc, 0xA0, 0x0037
M_SYSCALL realloc, 0xA0, 0x0038
M_SYSCALL InitHeap, 0xA0, 0x0039
M_SYSCALL _exit_A0_58, 0xA0, 0x003a
M_SYSCALL getchar, 0xA0, 0x003b
M_SYSCALL putchar, 0xA0, 0x003c
M_SYSCALL gets, 0xA0, 0x003d
M_SYSCALL puts, 0xA0, 0x003e
M_SYSCALL printf, 0xA0, 0x003f
M_SYSCALL LoadTest, 0xA0, 0x0041
M_SYSCALL Load, 0xA0, 0x0042
M_SYSCALL Exec, 0xA0, 0x0043
M_SYSCALL FlushCache, 0xA0, 0x0044
M_SYSCALL InstallInterruptDispatch, 0xA0, 0x0045
M_SYSCALL GPU_dw, 0xA0, 0x0046
M_SYSCALL GPU_mem2vram, 0xA0, 0x47
M_SYSCALL SetGPUStatus, 0xA0, 0x0048
M_SYSCALL GPU_cw, 0xA0, 0x0049
M_SYSCALL GPU_cwb, 0xA0, 0x004a
M_SYSCALL GPU_SendPackets, 0xA0, 0x4B
M_SYSCALL GPU_abort, 0xA0, 0x4C
M_SYSCALL GetGPUStatus, 0xA0, 0x004d
M_SYSCALL GPU_sync, 0xA0, 0x004e
M_SYSCALL LoadExec, 0xA0, 0x0051
M_SYSCALL GetSysSp, 0xA0, 0x0052
M_SYSCALL _96_init, 0xA0, 0x0054
M_SYSCALL _bu_init, 0xA0, 0x0055
M_SYSCALL _96_remove, 0xA0, 0x0056
M_SYSCALL dev_tty_init, 0xA0, 0x005b
M_SYSCALL dev_tty_open, 0xA0, 0x005c
M_SYSCALL dev_tty_strategy, 0xA0, 0x5D
M_SYSCALL dev_tty_ioctl, 0xA0, 0x005e
M_SYSCALL dev_cd_open, 0xA0, 0x005f
M_SYSCALL dev_cd_read, 0xA0, 0x0060
M_SYSCALL dev_cd_close, 0xA0, 0x0061
M_SYSCALL dev_cd_firstfile, 0xA0, 0x0062
M_SYSCALL dev_cd_nextfile, 0xA0, 0x0063
M_SYSCALL dev_cd_chdir, 0xA0, 0x0064
M_SYSCALL dev_card_open, 0xA0, 0x0065
M_SYSCALL dev_card_read, 0xA0, 0x0066
M_SYSCALL dev_card_write, 0xA0, 0x0067
M_SYSCALL dev_card_close, 0xA0, 0x0068
M_SYSCALL dev_card_firstfile, 0xA0, 0x0069
M_SYSCALL dev_card_nextfile, 0xA0, 0x006a
M_SYSCALL dev_card_erase, 0xA0, 0x006b
M_SYSCALL dev_card_undelete, 0xA0, 0x006c
M_SYSCALL dev_card_format, 0xA0, 0x006d
M_SYSCALL dev_card_rename, 0xA0, 0x006e
M_SYSCALL dev_card_call111, 0xA0, 0x6F
/* M_SYSCALL _bu_init, 0xA0, 0x0070
 M_SYSCALL _96_init, 0xA0, 0x0071
 M_SYSCALL _96_remove, 0xA0, 0x0072
*/
M_SYSCALL _96_CdSeekL, 0xA0, 0x0078
M_SYSCALL _96_CdGetStatus, 0xA0, 0x007c
M_SYSCALL _96_CdRead, 0xA0, 0x007e
M_SYSCALL _96_SetMode, 0xA0, 0x81
M_SYSCALL _96_CdStop, 0xA0, 0x0085
M_SYSCALL _kcallA0_144, 0xA0, 0x90
M_SYSCALL _kcallA0_145, 0xA0, 0x91
M_SYSCALL _kcallA0_146, 0xA0, 0x92
M_SYSCALL _kcallA0_147, 0xA0, 0x93
M_SYSCALL _kcallA0_148, 0xA0, 0x94
M_SYSCALL _kcallA0_149, 0xA0, 0x95
M_SYSCALL AddCDROMDevice, 0xA0, 0x0096
M_SYSCALL AddMemCardDevice, 0xA0, 0x0097
M_SYSCALL AddDEBUGCONDevice, 0xA0, 0x0098
// aka add_nullcon_driver and AddConsoleDevice
M_SYSCALL AddDummyConsoleDevice, 0xA0, 0x0099
M_SYSCALL SetConf, 0xA0, 0x009c
M_SYSCALL GetConf, 0xA0, 0x009d
M_SYSCALL _kcallA0_158, 0xA0, 0x9E
M_SYSCALL SetMem, 0xA0, 0x009f
M_SYSCALL _boot, 0xA0, 0x00A0
M_SYSCALL SystemError, 0xA0, 0x00a1
M_SYSCALL EnqCdIntr, 0xA0, 0x00a2
M_SYSCALL DeqCdIntr, 0xA0, 0x00a3
M_SYSCALL _96_call_A0_164, 0xA0, 0xA4
M_SYSCALL ReadSector, 0xA0, 0x00a5
M_SYSCALL IsCdOpen, 0xA0, 0x00a6
M_SYSCALL bufs_cb_0, 0xA0, 0x00a7
M_SYSCALL bufs_cb_1, 0xA0, 0x00a8
M_SYSCALL bufs_cb_2, 0xA0, 0x00a9
M_SYSCALL bufs_cb_3, 0xA0, 0x00aa
M_SYSCALL _card_info, 0xA0, 0x00ab
M_SYSCALL _card_load, 0xA0, 0x00ac
M_SYSCALL _card_auto, 0xA0, 0x00ad
M_SYSCALL bufs_cb_4, 0xA0, 0x00ae
M_SYSCALL _card_call175, 0xA0, 0xAF
M_SYSCALL do_longjmp, 0xA0, 0x00b2
M_SYSCALL GetKernelInfo, 0xA0, 0x00b4
M_SYSCALL _SysMalloc, 0xB0, 0x0000
M_SYSCALL SysFree, 0xB0, 1
M_SYSCALL SetRCnt, 0xB0, 2
M_SYSCALL GetRCnt, 0xB0, 3
M_SYSCALL StartRCnt, 0xB0, 4
M_SYSCALL StopRCnt, 0xB0, 5
M_SYSCALL ResetRCnt, 0xB0, 6
M_SYSCALL DeliverEvent, 0xB0, 0x0007
M_SYSCALL OpenEvent, 0xB0, 0x0008
M_SYSCALL CloseEvent, 0xB0, 0x0009
M_SYSCALL WaitEvent, 0xB0, 0x000a
M_SYSCALL TestEvent, 0xB0, 0x000b
M_SYSCALL EnableEvent, 0xB0, 0x000c
M_SYSCALL DisableEvent, 0xB0, 0x000d
M_SYSCALL OpenTh, 0xB0, 0x000e
M_SYSCALL CloseTh, 0xB0, 0x000f
M_SYSCALL ChangeTh, 0xB0, 0x0010
M_SYSCALL InitPAD, 0xB0, 0x0012
M_SYSCALL StartPAD, 0xB0, 0x0013
M_SYSCALL StopPAD, 0xB0, 0x0014
M_SYSCALL PAD_init, 0xB0, 0x0015
M_SYSCALL PAD_dr, 0xB0, 0x0016
M_SYSCALL ReturnFromException, 0xB0, 0x0017
M_SYSCALL ResetEntryInt, 0xB0, 0x0018
M_SYSCALL HookEntryInt, 0xB0, 0x0019
M_SYSCALL UnDeliverEvent, 0xB0, 0x0020
M_SYSCALL _open, 0xB0, 0x32
M_SYSCALL _lseek, 0xB0, 0x33
M_SYSCALL _read, 0xB0, 0x34
M_SYSCALL _write, 0xB0, 0x35
M_SYSCALL _close, 0xB0, 0x36
M_SYSCALL _ioctl, 0xB0, 0x37
M_SYSCALL _exit, 0xB0, 0x38
M_SYSCALL _is_a_tty, 0xB0, 0x39
M_SYSCALL _getc, 0xB0, 0x3A
M_SYSCALL _putc, 0xB0, 0x3B
M_SYSCALL _getchar, 0xB0, 0x3C
M_SYSCALL _putchar, 0xB0, 0x3D
M_SYSCALL _gets, 0xB0, 0x3E
M_SYSCALL _puts, 0xB0, 0x3F
M_SYSCALL _chdir, 0xB0, 0x40
M_SYSCALL _format, 0xB0, 0x41
M_SYSCALL firstfile, 0xB0, 0x42
M_SYSCALL nextfile, 0xB0, 0x43
M_SYSCALL rename, 0xB0, 0x44
M_SYSCALL delete, 0xB0, 0x45
M_SYSCALL undelete, 0xB0, 0x0046
/* Alias AddDrv */
M_SYSCALL AddDevice, 0xB0, 0x0047
/* Alias DelDrv */
M_SYSCALL DelDevice, 0xB0, 0x0048
M_SYSCALL PrintInstalledDevices, 0xB0, 0x0049
M_SYSCALL InitCARD, 0xB0, 0x004a
M_SYSCALL StartCARD, 0xB0, 0x004b
M_SYSCALL StopCARD, 0xB0, 0x004c
M_SYSCALL _card_callB0_77, 0xB0, 0x4D
M_SYSCALL _card_write, 0xB0, 0x004e
M_SYSCALL _card_read, 0xB0, 0x004f
M_SYSCALL _new_card, 0xB0, 0x0050
M_SYSCALL Krom2RawAdd, 0xB0, 0x0051
M_SYSCALL _kcallB0_83, 0xB0, 0x53
M_SYSCALL _get_errno, 0xB0, 0x0054
M_SYSCALL _get_error, 0xB0, 0x0055
M_SYSCALL GetC0Table, 0xB0, 0x0056
M_SYSCALL GetB0Table, 0xB0, 0x0057
M_SYSCALL _card_chan, 0xB0, 0x0058
M_SYSCALL iocall_B0_89, 0xB0, 0x59
M_SYSCALL ChangeClearPad, 0xB0, 0x005b
M_SYSCALL _card_status, 0xB0, 0x005c
M_SYSCALL _card_wait, 0xB0, 0x005d
M_SYSCALL InitRCnt, 0xC0, 0x0000
M_SYSCALL InitException, 0xC0, 0x0001
M_SYSCALL SysEnqIntRP, 0xC0, 0x0002
M_SYSCALL SysDeqIntRP, 0xC0, 0x0003
M_SYSCALL get_free_event_slot, 0xC0, 0x0004
M_SYSCALL get_free_TCB_slot, 0xC0, 0x0005
M_SYSCALL ExceptionHandler, 0xC0, 0x0006
M_SYSCALL InstallExceptionHandlers, 0xC0, 0x0007
M_SYSCALL SysInitMemory, 0xC0, 0x0008
M_SYSCALL SysInitKMem, 0xC0, 0x0009
M_SYSCALL ChangeClearRCnt, 0xC0, 0x000a
/*M_SYSCALL SystemError, 0xC0, 0x000b*/
M_SYSCALL InitDefInt, 0xC0, 0x000c
M_SYSCALL SetIrqClearEn, 0xC0, 0xD
M_SYSCALL InstallDevices, 0xC0, 0x0012
M_SYSCALL FlushStdInOut, 0xC0, 0x0013
M_SYSCALL GetWord8644, 0xC0, 0x14
M_SYSCALL _cdevinput, 0xC0, 0x0015
M_SYSCALL _cdevscan, 0xC0, 0x0016
M_SYSCALL _circgetc, 0xC0, 0x0017
M_SYSCALL _circputc, 0xC0, 0x0018
M_SYSCALL ioabort, 0xC0, 0x0019
M_SYSCALL SetWord8644, 0xC0, 0x1A
M_SYSCALL KernelRedirect, 0xC0, 0x1B
M_SYSCALL PatchAOTable, 0xC0, 0x1C

.global Exception
.type delay_ms, @function
.ent Exception
Exception:
                li      a0, 0
                syscall 0
                jr      ra
                nop
.end Exception

.global EnterCriticalSection
.type EnterCriticalSection, @function
.ent EnterCriticalSection
EnterCriticalSection:
                li      a0, 1
                syscall 0
                jr      ra
                nop
.end EnterCriticalSection

.global ExitCriticalSection
.type ExitCriticalSection, @function
.ent ExitCriticalSection
ExitCriticalSection:
                li      a0, 2
                syscall 0
                jr      ra
                nop
.end ExitCriticalSection

.global GetCOP0_STATUS
.type GetCOP0_STATUS, @function
.ent GetCOP0_STATUS
GetCOP0_STATUS:
                mfc0    v0, C0_STATUS
                nop
                jr      ra
                nop
.end GetCOP0_STATUS

.global SetCOP0_STATUS
.type SetCOP0_STATUS, @function
.ent SetCOP0_STATUS
SetCOP0_STATUS:
                mtc0    a0, C0_STATUS
                nop
                jr      ra
                nop
.end SetCOP0_STATUS

.set pop
