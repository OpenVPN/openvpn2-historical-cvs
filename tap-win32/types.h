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

#ifndef TAP_TYPES_DEFINED
#define TAP_TYPES_DEFINED

//===========================================================================================
//
//===========================================================================================
typedef PVOID LITEM;

typedef enum 
   {
    LMODE_STACK,
    LMODE_QUEUE
   }
LMODE;

typedef struct LNODESTRUCT
   {
    struct LNODESTRUCT *m_Next, *m_Previous;
    LITEM m_Payload;
   }
*LNODE;

typedef struct LROOTSTRUCT
   {
    ULONG m_Count, m_Limit;
    LNODE m_First, m_Last;
   }
*LROOT;

//===========================================================================================
//
//===========================================================================================
typedef struct _TapAdapter;
typedef struct _TapPacket;

typedef union _TapAdapterQuery
   {
    NDIS_HARDWARE_STATUS m_HardwareStatus;
    NDIS_MEDIUM m_Medium;
    UCHAR m_MacAddress [6];
    UCHAR m_Buffer [256];
    ULONG m_Long;
    USHORT m_Short;
    UCHAR m_Byte;
   }
TapAdapterQuery, *TapAdapterQueryPointer;

typedef struct _TapExtension
   {
    struct LROOTSTRUCT m_PacketQueue, m_IrpQueue;
    struct _TapAdapter *m_Adapter;
   }
TapExtension, *TapExtensionPointer;

typedef struct _TapPacket
   {
    ULONG m_Size;
    UCHAR m_Data [1]; // Do NOT rearrange the order here, m_Buffer MUST be last !!
   }
TapPacket, *TapPacketPointer;

typedef struct _TapAdapter
   {
    unsigned char m_MAC [6], *m_Name, *m_TapName;
    BOOLEAN m_TapIsRunning, m_InterfaceIsRunning;
    NDIS_HANDLE m_MiniportAdapterHandle;
    ULONG m_Rx, m_Tx, m_RxErr, m_TxErr;
    UNICODE_STRING m_UnicodeLinkName;
    PDEVICE_OBJECT m_TapDevice;
    NDIS_SPIN_LOCK m_Lock;
    NDIS_MEDIUM m_Medium;
    ULONG m_Lookahead;
    ULONG m_TapOpens;
    ULONG m_MTU;
   }
TapAdapter, *TapAdapterPointer;

#endif

