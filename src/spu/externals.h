/***************************************************************************
                         externals.h  -  description
                             -------------------
    begin                : Wed May 15 2002
    copyright            : (C) 2002 by Pete Bernert
    email                : BlackDove@addcom.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version. See also the license.txt file for *
 *   additional informations.                                              *
 *                                                                         *
 ***************************************************************************/

//*************************************************************************//
// History of changes:
//
// 2002/04/04 - Pete
// - increased channel struct for interpolation
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#pragma once

#include "core/decode_xa.h"

/////////////////////////////////////////////////////////
// generic defines
/////////////////////////////////////////////////////////

#define PSE_LT_SPU 4
#define PSE_SPU_ERR_SUCCESS 0
#define PSE_SPU_ERR -60
#define PSE_SPU_ERR_NOTCONFIGURED PSE_SPU_ERR - 1
#define PSE_SPU_ERR_INIT PSE_SPU_ERR - 2

////////////////////////////////////////////////////////////////////////
// spu defines
////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////
// struct defines
///////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////

// Tmp Flags

// used for debug channel muting
#define FLAG_MUTE 1

// used for simple interpolation
#define FLAG_IPOL0 2
#define FLAG_IPOL1 4
