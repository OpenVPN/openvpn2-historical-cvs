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

#ifdef __cplusplus
extern "C" {
#endif

#include "hexdump.h"

#ifndef NDIS_MINIPORT_DRIVER

void (*DbgMessage)(char *p_Format, ...) = DisplayDebugString;

void DisplayDebugString (char *p_Format, ...)
   {
    static char l_Buffer [4096];

    va_list l_ArgumentList; 
    va_start (l_ArgumentList, p_Format); 
    vsprintf (l_Buffer, p_Format, l_ArgumentList); 
    va_end (l_ArgumentList); 

    OutputDebugStringA (l_Buffer);
   }

#endif

void HexDump (unsigned char *p_Buffer, unsigned long p_Size)
   {
    unsigned long l_Index, l_Idx;
    unsigned char l_Row [17];

    for (l_Index = l_Row [16] = 0; l_Index < p_Size || l_Index % 16; ++l_Index)
       {
        if (l_Index % 16 == 0) DbgPrint ("%05x   ", l_Index);
        DbgPrint ("%02x ", l_Row [l_Index % 16] = (l_Index < p_Size ? p_Buffer [l_Index] : 0));
        l_Row [l_Index % 16] = IfPrint (l_Row [l_Index % 16]);
        if ((l_Index + 1) % 16 == 0) DbgPrint ("   %s\n", l_Row);
       }

    DbgPrint ("\n");
   }

#ifdef __cplusplus
}
#endif
