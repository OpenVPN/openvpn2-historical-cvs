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

#include "macinfo.h"

unsigned char HexStringToDecimalInt (unsigned char p_Character)
   {
    unsigned char l_Value = 0;

    if (p_Character >= 'A' && p_Character <= 'F')
       l_Value = (p_Character - 'A') + 10;
    else if (p_Character >= 'a' && p_Character <= 'f')
       l_Value = (p_Character - 'a') + 10;
    else if (p_Character >= '0' && p_Character <= '9')
       l_Value = p_Character - '0';

    return l_Value;
   }

void ConvertMacInfo (unsigned char *p_Destination, unsigned char *p_Source, unsigned long p_Length)
   {
    unsigned long l_Index, l_HexIdx, l_Ind = 0, l_Init = 1;

    ASSERT (p_Destination);
    ASSERT (p_Source);
    ASSERT (p_Length);

    for (l_Index = l_HexIdx = l_Ind = 0; l_Index < p_Length && l_HexIdx < 6 && p_Source [l_Index]; ++l_Index)
       {
        if (IsMacDelimiter (p_Source [l_Index]))
           l_Ind = 0, ++l_HexIdx, l_Init = 1;
        else if (++l_Ind == 3)
           (++l_HexIdx < 6 ? (p_Destination [l_HexIdx] = HexStringToDecimalInt (p_Source [l_Index]), l_Ind = 0) : 0);
        else
           p_Destination [l_HexIdx] = (l_Init ? 0 : p_Destination [l_HexIdx] * 16) + HexStringToDecimalInt (p_Source [l_Index]), l_Init = 0;
       }
   }

/*
 * Generate a random MAC, using the adapter name string, current system
 * time, and an incrementing local sequence number as entropy.
 */

int random_mac_sequence_number = 0;
unsigned char random_mac_previous[6] = { 0, 0, 0, 0, 0, 0};

void GenerateRandomMac (unsigned char *mac, char *adapter_name)
{
  md5_state_t md5;
  md5_byte_t d[16];
  LARGE_INTEGER current_time;

  ++random_mac_sequence_number;
  KeQuerySystemTime (&current_time);

  /* compute MD5 digest of entropy */
  md5_init (&md5);
  md5_append (&md5, (md5_byte_t *) &random_mac_previous, sizeof (random_mac_previous));
  md5_append (&md5, (md5_byte_t *) &random_mac_sequence_number, sizeof (random_mac_sequence_number));
  md5_append (&md5, (md5_byte_t *) &current_time, sizeof (current_time));
  md5_append (&md5, (md5_byte_t *) &adapter_name, strlen (adapter_name));
  md5_process (&md5, d);

  /* build mac from digest */
  mac[0] = 0x00;  /* 0:FF prefix taken from linux TAP driver */
  mac[1] = 0xFF;
  mac[2] = d[0] ^ d[4] ^ d[8] ^ d[12];
  mac[3] = d[1] ^ d[5] ^ d[9] ^ d[13];
  mac[4] = d[2] ^ d[6] ^ d[10] ^ d[14];
  mac[5] = d[3] ^ d[7] ^ d[11] ^ d[15];

  /* save to use as entropy for next call */
  memcpy (random_mac_previous, mac, 6);
}

#ifdef __cplusplus
}
#endif
