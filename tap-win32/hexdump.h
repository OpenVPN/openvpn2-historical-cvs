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

#ifndef HEXDUMP_DEFINED
#define HEXDUMP_DEFINED

#ifdef __cplusplus
extern "C" {
#endif

//=====================================================================================
//                                   Debug Routines
//=====================================================================================

#ifndef NDIS_MINIPORT_DRIVER
#   include <stdio.h>
#   include <ctype.h>
#   include <windows.h>
#   include <winnt.h>
#   include <memory.h>

#   ifndef DbgPrint
#      define DbgPrint DbgMessage
#   endif

    extern void (*DbgMessage)(char *p_Format, ...);

    void DisplayDebugString (char *p_Format, ...);
#endif

//===================================================================================
//                              Reporting / Debugging
//===================================================================================
#define IfPrint(c) (c >= 32 && c < 127 ? c : '.')

void HexDump (unsigned char *p_Buffer, unsigned long p_Size);

#ifdef __cplusplus
}
#endif

#endif
