/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# PS1 CD-ROM definitions.
#
*/

#ifndef _PS1_CDROM_H_
#define _PS1_CDROM_H_

// PS1 CD-ROM Commands
enum {
    PS1_CdSync = 0x00,
    PS1_CdNop = 0x01,
    PS1_CdSetloc = 0x02,
    PS1_CdPlay = 0x03,
    PS1_CdForward = 0x04,
    PS1_CdBackward = 0x05,
    PS1_CdReadN = 0x06,
    PS1_CdStandby = 0x07,
    PS1_CdStop = 0x08,
    PS1_CdPause = 0x09,
    PS1_CdInit = 0x0A,
    PS1_CdMute = 0x0B,
    PS1_CdDemute = 0x0C,
    PS1_CdSetFilter = 0x0D,
    PS1_CdSetMode = 0x0E,
    PS1_CdGetParam = 0x0F,
    PS1_CdGetLocL = 0x10,
    PS1_CdGetLocP = 0x11,
    PS1_CdCmd12 = 0x12,
    PS1_CdGetTN = 0x13,
    PS1_CdGetTD = 0x14,
    PS1_CdSeekL = 0x15,
    PS1_CdSeekP = 0x16,
    PS1_CdCmd17 = 0x17,
    PS1_CdCmd18 = 0x18,
    PS1_CdTest = 0x19,
    PS1_CdReadDiscID = 0x1A,
    PS1_CdReadS = 0x1B,
    PS1_CdReset = 0x1C,
    PS1_CdCmd1D = 0x1D,
    PS1_CdReadTOC = 0x1E,
    PS1_CdCmd1F = 0x1F,
};

// macros for reading CD-ROM registers.
#define M_CD_RD_IFSTAT(__res)                                                                                          \
    {                                                                                                                  \
        __res = *R_PS1_CDROM0;                                                                                         \
    }
#define M_CD_RD_RESULT(__res)                                                                                          \
    {                                                                                                                  \
        __res = *R_PS1_CDROM1;                                                                                         \
    }
#define M_CD_RD_DATA(__res)                                                                                            \
    {                                                                                                                  \
        __res = *R_PS1_CDROM2;                                                                                         \
    }
#define M_CD_RD_INTMASK(__res)                                                                                         \
    {                                                                                                                  \
        *R_PS1_CDROM0 = 0;                                                                                             \
        __res = *R_PS1_CDROM3 & 0x1F;                                                                                  \
    }
#define M_CD_RD_INTSTAT(__res)                                                                                         \
    {                                                                                                                  \
        *R_PS1_CDROM0 = 1;                                                                                             \
        __res = *R_PS1_CDROM3 & 0x1F;                                                                                  \
    }

// macros for writing CD-ROM registers.
#define M_CD_WR_CMD(__val)                                                                                             \
    {                                                                                                                  \
        *R_PS1_CDROM0 = 0;                                                                                             \
        *R_PS1_CDROM1 = (__val);                                                                                       \
    }
#define M_CD_WR_PARAM(__val)                                                                                           \
    {                                                                                                                  \
        *R_PS1_CDROM0 = 0;                                                                                             \
        *R_PS1_CDROM2 = (__val);                                                                                       \
    }
#define M_CD_WR_CHPCTRL(__val)                                                                                         \
    {                                                                                                                  \
        *R_PS1_CDROM0 = 0;                                                                                             \
        *R_PS1_CDROM3 = (__val);                                                                                       \
    }
#define M_CD_WR_INTMASK(__val)                                                                                         \
    {                                                                                                                  \
        *R_PS1_CDROM0 = 1;                                                                                             \
        *R_PS1_CDROM2 = (__val)&0x1F;                                                                                  \
    }
#define M_CD_WR_CLRCTRL(__val)                                                                                         \
    {                                                                                                                  \
        *R_PS1_CDROM0 = 1;                                                                                             \
        *R_PS1_CDROM3 = (__val);                                                                                       \
    }

enum {
    CdIntrNone = 0,
    CdIntrDataRdy = 1,
    CdIntrComplete = 2,
    CdIntrAcknowledge = 3,
    CdIntrDataEnd = 4,
    CdIntrDiskError = 5
};

// bits for "status" byte returned by commands.
enum {
    CdStatusCmdErr = (1 << 0), // command error
    CdStatusStandby = (1 << 1), // spindle motor rotating
    CdStatusUnk2 = (1 << 2), // unknown
    CdStatusSeekErr = (1 << 3), // seek error
    CdStatusOpen = (1 << 4), // drive lid has been opened
    CdStatusRead = (1 << 5), // reading data
    CdStatusSeek = (1 << 6), // seeking
    CdStatusPlay = (1 << 7) // playing CD-DA
};

enum {
    CD_IFSTAT_RA0 = (1 << 0),
    CD_IFSTAT_RA1 = (1 << 1),
    CD_IFSTAT_ADPCM_BUSY = (1 << 2),
    CD_IFSTAT_PARAM_EMPTY = (1 << 3),
    CD_IFSTAT_PARAM_WR_RDY = (1 << 4),
    CD_IFSTAT_RESULT_RDY = (1 << 5),
    CD_IFSTAT_DATA_REQ = (1 << 6),
    CD_IFSTAT_CMD_BUSY = (1 << 7),
};

#endif // _PS1_CDROM_H_
