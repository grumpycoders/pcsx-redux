////////////////////////////////////////////////////////////////////////////////
//
#define TITLE "ecm - Encoder/decoder for Error Code Modeler format"
#define COPYR "Copyright (C) 2002-2011 Neill Corlett"
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
////////////////////////////////////////////////////////////////////////////////

//#include "common.h"
//#include "banner.h"

////////////////////////////////////////////////////////////////////////////////
//
// Sector types
//
// Mode 1
// -----------------------------------------------------
//        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
// 0000h 00 FF FF FF FF FF FF FF FF FF FF 00 [-ADDR-] 01
// 0010h [---DATA...
// ...
// 0800h                                     ...DATA---]
// 0810h [---EDC---] 00 00 00 00 00 00 00 00 [---ECC...
// ...
// 0920h                                      ...ECC---]
// -----------------------------------------------------
//
// Mode 2 (XA), form 1
// -----------------------------------------------------
//        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
// 0000h 00 FF FF FF FF FF FF FF FF FF FF 00 [-ADDR-] 02
// 0010h [--FLAGS--] [--FLAGS--] [---DATA...
// ...
// 0810h             ...DATA---] [---EDC---] [---ECC...
// ...
// 0920h                                      ...ECC---]
// -----------------------------------------------------
//
// Mode 2 (XA), form 2
// -----------------------------------------------------
//        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
// 0000h 00 FF FF FF FF FF FF FF FF FF FF 00 [-ADDR-] 02
// 0010h [--FLAGS--] [--FLAGS--] [---DATA...
// ...
// 0920h                         ...DATA---] [---EDC---]
// -----------------------------------------------------
//
// ADDR:  Sector address, encoded as minutes:seconds:frames in BCD
// FLAGS: Used in Mode 2 (XA) sectors describing the type of sector; repeated
//        twice for redundancy
// DATA:  Area of the sector which contains the actual data itself
// EDC:   Error Detection Code
// ECC:   Error Correction Code
//

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define ECM_HEADER_SIZE 4

uint32_t len_decoded_ecm_buffer = 0;  // same as decoded ECM file length or 2x size
uint32_t len_ecm_savetable = 0;       // same as sector count of decoded ECM file or 2x count

#ifdef ENABLE_ECM_FULL  // setting this makes whole ECM to be decoded in-memory meaning buffer could eat up to 700 MB of
                        // memory
uint32_t decoded_ecm_sectors = 1;  // initially sector 1 is always decoded
#else
uint32_t decoded_ecm_sectors = 0;  // disabled
#endif

bool ecm_file_detected = false;
uint32_t prevsector;

FILE* decoded_ecm = NULL;
void* decoded_ecm_buffer;

// Function that is used to read CD normally
int (*cdimg_read_func_o)(FILE* f, unsigned int base, void* dest, int sector) = NULL;

typedef struct ECMFILELUT {
    int32_t sector;
    int32_t filepos;
} ECMFILELUT;

ECMFILELUT* ecm_savetable = NULL;

static const size_t ECM_SECTOR_SIZE[4] = {1, 2352, 2336, 2336};

////////////////////////////////////////////////////////////////////////////////

static uint32_t get32lsb(const uint8_t* src) {
    return (((uint32_t)(src[0])) << 0) | (((uint32_t)(src[1])) << 8) | (((uint32_t)(src[2])) << 16) |
           (((uint32_t)(src[3])) << 24);
}

static void put32lsb(uint8_t* dest, uint32_t value) {
    dest[0] = (uint8_t)(value);
    dest[1] = (uint8_t)(value >> 8);
    dest[2] = (uint8_t)(value >> 16);
    dest[3] = (uint8_t)(value >> 24);
}

////////////////////////////////////////////////////////////////////////////////
//
// LUTs used for computing ECC/EDC
//
static uint8_t ecc_f_lut[256];
static uint8_t ecc_b_lut[256];
static uint32_t edc_lut[256];

static void eccedc_init(void) {
    size_t i;
    for (i = 0; i < 256; i++) {
        uint32_t edc = i;
        size_t j = (i << 1) ^ (i & 0x80 ? 0x11D : 0);
        ecc_f_lut[i] = j;
        ecc_b_lut[i ^ j] = i;
        for (j = 0; j < 8; j++) {
            edc = (edc >> 1) ^ (edc & 1 ? 0xD8018001 : 0);
        }
        edc_lut[i] = edc;
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// Compute EDC for a block
//
static uint32_t edc_compute(uint32_t edc, const uint8_t* src, size_t size) {
    for (; size; size--) {
        edc = (edc >> 8) ^ edc_lut[(edc ^ (*src++)) & 0xFF];
    }
    return edc;
}

//
// Write ECC block (either P or Q)
//
static void ecc_writepq(const uint8_t* address, const uint8_t* data, size_t major_count, size_t minor_count,
                        size_t major_mult, size_t minor_inc, uint8_t* ecc) {
    size_t size = major_count * minor_count;
    size_t major;
    for (major = 0; major < major_count; major++) {
        size_t index = (major >> 1) * major_mult + (major & 1);
        uint8_t ecc_a = 0;
        uint8_t ecc_b = 0;
        size_t minor;
        for (minor = 0; minor < minor_count; minor++) {
            uint8_t temp;
            if (index < 4) {
                temp = address[index];
            } else {
                temp = data[index - 4];
            }
            index += minor_inc;
            if (index >= size) {
                index -= size;
            }
            ecc_a ^= temp;
            ecc_b ^= temp;
            ecc_a = ecc_f_lut[ecc_a];
        }
        ecc_a = ecc_b_lut[ecc_f_lut[ecc_a] ^ ecc_b];
        ecc[major] = (ecc_a);
        ecc[major + major_count] = (ecc_a ^ ecc_b);
    }
}

//
// Write ECC P and Q codes for a sector
//
static void ecc_writesector(const uint8_t* address, const uint8_t* data, uint8_t* ecc) {
    ecc_writepq(address, data, 86, 24, 2, 86, ecc);          // P
    ecc_writepq(address, data, 52, 43, 86, 88, ecc + 0xAC);  // Q
}

////////////////////////////////////////////////////////////////////////////////

static const uint8_t zeroaddress[4] = {0, 0, 0, 0};

////////////////////////////////////////////////////////////////////////////////
//
// Reconstruct a sector based on type
//
static void reconstruct_sector(uint8_t* sector,  // must point to a full 2352-byte sector
                               int8_t type) {
    //
    // Sync
    //
    sector[0x000] = 0x00;
    sector[0x001] = 0xFF;
    sector[0x002] = 0xFF;
    sector[0x003] = 0xFF;
    sector[0x004] = 0xFF;
    sector[0x005] = 0xFF;
    sector[0x006] = 0xFF;
    sector[0x007] = 0xFF;
    sector[0x008] = 0xFF;
    sector[0x009] = 0xFF;
    sector[0x00A] = 0xFF;
    sector[0x00B] = 0x00;

    switch (type) {
        case 1:
            //
            // Mode
            //
            sector[0x00F] = 0x01;
            //
            // Reserved
            //
            sector[0x814] = 0x00;
            sector[0x815] = 0x00;
            sector[0x816] = 0x00;
            sector[0x817] = 0x00;
            sector[0x818] = 0x00;
            sector[0x819] = 0x00;
            sector[0x81A] = 0x00;
            sector[0x81B] = 0x00;
            break;
        case 2:
        case 3:
            //
            // Mode
            //
            sector[0x00F] = 0x02;
            //
            // Flags
            //
            sector[0x010] = sector[0x014];
            sector[0x011] = sector[0x015];
            sector[0x012] = sector[0x016];
            sector[0x013] = sector[0x017];
            break;
    }

    //
    // Compute EDC
    //
    switch (type) {
        case 1:
            put32lsb(sector + 0x810, edc_compute(0, sector, 0x810));
            break;
        case 2:
            put32lsb(sector + 0x818, edc_compute(0, sector + 0x10, 0x808));
            break;
        case 3:
            put32lsb(sector + 0x92C, edc_compute(0, sector + 0x10, 0x91C));
            break;
    }

    //
    // Compute ECC
    //
    switch (type) {
        case 1:
            ecc_writesector(sector + 0xC, sector + 0x10, sector + 0x81C);
            break;
        case 2:
            ecc_writesector(zeroaddress, sector + 0x10, sector + 0x81C);
            break;
    }

    //
    // Done
    //
}
