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

#ifndef TAP_PROTOTYPES_DEFINED
#define TAP_PROTOTYPES_DEFINED

//===========================================================================================
//
//===========================================================================================
LROOT ListAlloc         (ULONG p_Limit);
VOID  ListFree          (LROOT p_Root);
LROOT ListActivate      (LROOT p_Root, ULONG p_Limit);
VOID  ListDeactivate    (LROOT p_Root);
LITEM ListAdd           (LROOT p_Root, LITEM p_Payload);
LITEM ListExtract       (LROOT p_Root, LITEM p_Payload);
LITEM ListRemove        (LROOT p_Root, LMODE p_Mode);
LITEM ListPeek          (LROOT p_Root, LMODE p_Mode);
ULONG ListCount         (LROOT p_Root);

#define QueueNew        ListAlloc
#define QueueDelete     ListFree
#define QueuePush(a,b)  ListAdd (a,b)
#define QueuePop(a)     ListRemove (a, LMODE_QUEUE)
#define QueuePeek(a)    ListPeek (a, LMODE_QUEUE)
#define QueueCount(a)   ListCount (a)
#define QueueExtract    ListExtract

#define StackNew        ListAlloc
#define StackDelete     ListFree
#define StackPush(a,b)  ListAdd (a, b)
#define StackPop(a)     ListRemove (a, LMODE_STACK)
#define StackPeek(a)    ListPeek (a, LMODE_STACK)
#define StackCount(a)   ListCount (a)
#define StackExtract    ListExtract

#define Push(a,b)       QueuePush(a,b)
#define Pull(a)         QueuePop(a)
#define Pop(a)          StackPop(a)
#define Peek(a)         QueuePeek(a)
#define Count(a)        QueueCount(a)
#define Extract         ListExtract

//===========================================================================================
//
//===========================================================================================
NTSTATUS DriverEntry
   (
    IN PDRIVER_OBJECT p_DriverObject,
    IN PUNICODE_STRING p_RegistryPath
   );

NDIS_STATUS AdapterCreate
   (
    OUT PNDIS_STATUS p_ErrorStatus,
    OUT PUINT p_MediaIndex,
    IN PNDIS_MEDIUM p_Media,
    IN UINT p_MediaCount,
    IN NDIS_HANDLE p_AdapterHandle,
    IN NDIS_HANDLE p_ConfigurationHandle
   );

VOID AdapterDestroy
   (
    IN NDIS_HANDLE p_AdapterContext
   );

NDIS_STATUS AdapterReset
   (
    OUT PBOOLEAN p_AddressingReset,
    IN NDIS_HANDLE p_AdapterContext
   );

VOID AdapterStop
   (
    IN NDIS_HANDLE p_AdapterContext
   );

NDIS_STATUS AdapterQuery
   (
    IN NDIS_HANDLE p_AdapterContext,
    IN NDIS_OID p_OID,
    IN PVOID p_Buffer,
    IN ULONG p_BufferLength,
    OUT PULONG p_BytesWritten,
    OUT PULONG p_BytesNeeded
   );

NDIS_STATUS AdapterModify
   (
    IN NDIS_HANDLE p_AdapterContext,
    IN NDIS_OID p_OID,
    IN PVOID p_Buffer,
    IN ULONG p_BufferLength,
    OUT PULONG p_BytesRead,
    OUT PULONG p_BytesNeeded
   );

NDIS_STATUS AdapterTransmit
   (
    IN NDIS_HANDLE p_AdapterContext,
    IN PNDIS_PACKET p_Packet,
    IN UINT p_Flags
   );

NDIS_STATUS AdapterReceive
   (
    OUT PNDIS_PACKET p_Packet,
    OUT PUINT p_Transferred,
    IN NDIS_HANDLE p_AdapterContext,
    IN NDIS_HANDLE p_ReceiveContext,
    IN UINT p_Offset,
    IN UINT p_ToTransfer
   );

NTSTATUS TapDeviceHook (IN PDEVICE_OBJECT p_DeviceObject, IN PIRP p_IRP);
NDIS_STATUS CreateTapDevice (TapAdapterPointer p_Adapter);
VOID DestroyTapDevice (TapAdapterPointer p_Adapter);
VOID HookDispatchFunctions();

NTSTATUS CompleteIRP (TapAdapterPointer p_Adapter, IN PIRP p_IRP,
		      IN TapExtensionPointer p_Extension, IN CCHAR PriorityBoost);

VOID CancelIRP (IN PDEVICE_OBJECT p_DeviceObject, IN PIRP p_IRP);

VOID  MemFree  (PVOID p_Addr, ULONG p_Size);
PVOID MemAlloc (ULONG p_Size);

#endif
