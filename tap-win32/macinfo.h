/*
 *  TAP-Win32 -- A kernel driver to provide virtual tap device functionality
 *               on Windows.  Derived from the CIPE-Win32 project at
 *               http://cipe-win32.sourceforge.net/
 *
 *  Copyright (C) 2003 Damion K. Wilson
 *
 *  Modifications by James Yonan in accordance with the GPL.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef MacInfoDefined
#define MacInfoDefined

#ifdef __cplusplus
extern "C" {
#endif

//=====================================================================================
//                                  NDIS + Win32 Settings
//=====================================================================================
#ifdef NDIS_MINIPORT_DRIVER
#   include <ndis.h>
#endif

//===================================================================================
//                                      Macros
//===================================================================================
#define IsMacDelimiter(a) (a == ':' || a == '-' || a == '.')

#ifdef ASSERT
#   undef ASSERT
#endif

#define ASSERT(a) if (! (a)) return

//===================================================================================
//                          MAC Address Manipulation Routines
//===================================================================================
unsigned char HexStringToDecimalInt (unsigned char p_Character);
void ConvertMacInfo (unsigned char *p_Destination, unsigned char *p_Source, unsigned long p_Length);

#ifdef __cplusplus
}
#endif

#endif
