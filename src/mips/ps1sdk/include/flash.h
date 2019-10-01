/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# "FLASH.h" for PS1.
#
*/

#ifndef _FLASH_H
#define _FLASH_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_FlashMemoryDeviceBlock {
    uint32_t n_sects;
    uint32_t sz_sects;
} FlashMemoryDeviceBlock;

typedef int (*FlashMapperFunc)(void* dev, uint32_t offset, uint32_t* p_voff);
typedef int (*FlashChipUnprotectFunc)(uint32_t base_addr, int wait);
typedef int (*FlashChipProtectFunc)(uint32_t base_addr, int wait);
typedef int (*FlashChipEraseFunc)(uint32_t base_addr, int wait);
typedef int (*FlashSectEraseFunc)(uint32_t base_addr, uint32_t sect_addr, int wait);
typedef int (*FlashSectProgFunc)(uint32_t base_addr, uint32_t sect_addr, void* data, int len, int wait);

typedef struct st_FlashMemoryDevice {
    const char* name; // pointer to ASCII-Z string containing the name of the device.
    uint16_t man_id; // manufacturer ID.
    uint16_t prod_id; // product ID.
    uint32_t attr; // attributes.
    uint32_t n_total_bytes; // total number of bytes in the device.

    FlashMapperFunc mapper; // pointer to function which handles "mapping" for this chip.

    FlashChipUnprotectFunc chip_unprotect; // pointer to function which "unprotects" this chip for programming.
    int chip_unprot_wait; // number of milliseconds to wait after doing a "chip_unlock".
    FlashChipProtectFunc chip_protect; // pointer to function which "protects" this chip to disable programming.
    int chip_prot_wait; // number of milliseconds to wait after doing a "chip_lock".

    FlashChipEraseFunc chip_erase; // pointer to function which erases this entire chip.
    int chip_erase_wait; // number of milliseconds to wait after doing a "chip_erase".
    FlashSectEraseFunc sect_erase; // pointer to function which erases a single sector of this chip.
    int sect_erase_wait; // number of milliseconds to wait after doing a "sect_erase".
    FlashSectProgFunc sect_prog; // pointer to function which programs a single sector of this chip.
    int sect_prog_wait; // number of milliseconds to wait after doing a "sect_prog".

    int n_blocks; // number of blocks in the following array.
    struct {
        uint32_t n_sects; // number of sectors in this block.
        uint32_t sect_sz; // size, in bytes, of each sector in this block.
    } blocks[];
} FlashMemoryDevice;

#define FLASH_MANUF_AMD (0x0001)
#define FLASH_MANUF_ATMEL (0x001F)
#define FLASH_MANUF_SST (0x00BF)
#define FLASH_MANUF_MX (0x00C2)
#define FLASH_MANUF_WINBOND (0x00DA)

// attributes for flash memory devices

// supports sector erase
#define FLASH_ATTR_SECT_ERASE (1 << 0)

// supports chip erase
#define FLASH_ATTR_CHIP_ERASE (1 << 1)

#define FLASH_ATTR_EEPROM (1 << 2)

// uniform sector sizes.
#define FLASH_ATTR_UNIFORM (1 << 3)
// "bottom" boot block.
#define FLASH_ATTR_BOTTOM_BOOT (1 << 4)
// "top" boot block.
#define FLASH_ATTR_TOP_BOOT (1 << 5)

int flash_read_ids(uint32_t base_addr, uint16_t* pman_id, uint16_t* pprod_id);
uint8_t flash_detect_mappers(uint32_t base_addr, uint16_t* p_man_id, uint16_t* p_prod_id);
FlashMemoryDevice* flash_detect_device(uint32_t base_addr);
FlashMemoryDevice* find_device_by_ids(uint16_t man_id, uint16_t prod_id);
int flash_dump_chip(FlashMemoryDevice* dev, uint32_t base_addr, uint32_t off, void* data, int max_bytes);

void flash_chip_unprotect(FlashMemoryDevice* dev, uint32_t base_addr);
void flash_chip_protect(FlashMemoryDevice* dev, uint32_t base_addr);

int flash_chip_erase(FlashMemoryDevice* dev, uint32_t base_addr);
int flash_sect_erase(FlashMemoryDevice* dev, uint32_t base_addr, uint32_t sect_addr);
int flash_lookup_sect(
    FlashMemoryDevice* dev, uint32_t off, uint32_t* p_sect_addr, uint32_t* p_sect_off, int* p_sect_size);
int flash_sect_prog(FlashMemoryDevice* dev, uint32_t base_addr, uint32_t sect_addr, void* data, int n_bytes);
int flash_blank_check(void* start, int n);
void flash_wait_toggle(uint32_t addr);
void delay_ns(int n);

static inline void flash_unlock_cycle(uint32_t base_addr, uint8_t cmd)
{
    //    base_addr &= 0xFFFE0000;

    ((vuint8_t*)base_addr)[0x5555] = 0xAA;
    ((vuint8_t*)base_addr)[0x2AAA] = 0x55;
    ((vuint8_t*)base_addr)[0x5555] = cmd;
}

#ifdef __cplusplus
}
#endif

#endif /* _FLASH_H */
