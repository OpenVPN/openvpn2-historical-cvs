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

#define NDIS_MINIPORT_DRIVER
#define BINARY_COMPATIBLE 0
#define NDIS40_MINIPORT 1
#define NDIS_WDM 0
#define NDIS40 1
#define OVERWRITE_OLD_PACKETS FALSE

#include "ndis.h"
#include "constants.h"
#include "types.h"
#include "prototypes.h"

#ifdef ENABLE_RANDOM_MAC
#include "md5.h"
#include "md5.c"
#endif

#include "macinfo.c"

//===========================================================================================
//                                         Globals
//===========================================================================================
PDRIVER_DISPATCH g_DispatchHook [IRP_MJ_MAXIMUM_FUNCTION + 1];
NDIS_MINIPORT_CHARACTERISTICS g_Properties;
PDRIVER_OBJECT g_TapDriverObject = NULL;
struct LROOTSTRUCT g_TapAdapterList;
char g_DispatchFunctionsHooked = 0;
NDIS_HANDLE g_NdisWrapperHandle;
unsigned char g_MAC [6] = {0, 0, 0, 0, 0, 0};

UINT g_SupportedOIDList[] =
   {
    OID_GEN_HARDWARE_STATUS,       OID_GEN_MEDIA_SUPPORTED,        OID_GEN_MEDIA_IN_USE,
    OID_GEN_MAXIMUM_LOOKAHEAD,     OID_GEN_MAC_OPTIONS,            OID_GEN_LINK_SPEED,
    OID_GEN_TRANSMIT_BLOCK_SIZE,   OID_GEN_RECEIVE_BLOCK_SIZE,     OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_DRIVER_VERSION,        OID_GEN_XMIT_OK,                OID_GEN_RCV_OK,
    OID_GEN_XMIT_ERROR,            OID_GEN_RCV_ERROR,              OID_802_3_PERMANENT_ADDRESS,
    OID_802_3_CURRENT_ADDRESS,     OID_GEN_RCV_NO_BUFFER,          OID_802_3_RCV_ERROR_ALIGNMENT,
    OID_802_3_XMIT_ONE_COLLISION,  OID_802_3_XMIT_MORE_COLLISIONS, OID_802_3_MULTICAST_LIST,
    OID_802_3_MAXIMUM_LIST_SIZE,   OID_GEN_VENDOR_ID,              OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_CURRENT_PACKET_FILTER, OID_GEN_PROTOCOL_OPTIONS,       OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_TRANSMIT_BUFFER_SPACE, OID_GEN_RECEIVE_BUFFER_SPACE,   OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_VENDOR_DRIVER_VERSION, OID_GEN_MAXIMUM_SEND_PACKETS,   OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_SUPPORTED_LIST
   };

//===========================================================================================
//                                       Driver Entry
//===========================================================================================
#pragma NDIS_INIT_FUNCTION (DriverEntry)

NTSTATUS DriverEntry (IN PDRIVER_OBJECT p_DriverObject, IN PUNICODE_STRING p_RegistryPath)
   {
    NDIS_STATUS l_Status = NDIS_STATUS_FAILURE;

    ListActivate (&g_TapAdapterList, 0);

    NdisMInitializeWrapper (&g_NdisWrapperHandle, g_TapDriverObject = p_DriverObject, p_RegistryPath, NULL);

    NdisZeroMemory (&g_Properties, sizeof (g_Properties));

    g_Properties.MajorNdisVersion        = TAP_NDIS_MAJOR_VERSION;
    g_Properties.MinorNdisVersion        = TAP_NDIS_MINOR_VERSION;
    g_Properties.InitializeHandler       = AdapterCreate;
    g_Properties.HaltHandler             = AdapterDestroy; 
    g_Properties.ResetHandler            = AdapterReset; 
    g_Properties.TransferDataHandler     = AdapterReceive;
    g_Properties.SendHandler             = AdapterTransmit;
    g_Properties.QueryInformationHandler = AdapterQuery;
    g_Properties.SetInformationHandler   = AdapterModify;
    g_Properties.DisableInterruptHandler = NULL;
    g_Properties.EnableInterruptHandler  = NULL;
    g_Properties.HandleInterruptHandler  = NULL;
    g_Properties.ISRHandler              = NULL;
    g_Properties.ReconfigureHandler      = NULL;
    g_Properties.CheckForHangHandler     = NULL;
    g_Properties.ReturnPacketHandler     = NULL;
    g_Properties.SendPacketsHandler      = NULL;
    g_Properties.AllocateCompleteHandler = NULL;

#ifndef ENABLE_RANDOM_MAC
    ConvertMacInfo (g_MAC, TAP_MAC_ROOT_ADDRESS, strlen (TAP_MAC_ROOT_ADDRESS));
#endif

    switch (l_Status = NdisMRegisterMiniport (g_NdisWrapperHandle, &g_Properties, sizeof (g_Properties)))
       {
        case NDIS_STATUS_SUCCESS:
           {
            DbgPrint ("[TAP] version [%d.%d] registered miniport successfully\n", TAP_DRIVER_MAJOR_VERSION, TAP_DRIVER_MINOR_VERSION);
            break;
           }

        case NDIS_STATUS_BAD_CHARACTERISTICS:
           {
            DbgPrint ("[TAP] Miniport characteristics were badly defined\n");
            NdisTerminateWrapper (g_NdisWrapperHandle, NULL);
            break;
           }

        case NDIS_STATUS_BAD_VERSION:
           {
            DbgPrint ("[TAP] NDIS Version is wrong for the given characteristics\n");
            NdisTerminateWrapper (g_NdisWrapperHandle, NULL);
            break;
           }

        case NDIS_STATUS_RESOURCES:
           {
            DbgPrint ("[TAP] Insufficient resources\n");
            NdisTerminateWrapper (g_NdisWrapperHandle, NULL);
            break;
           }

        case NDIS_STATUS_FAILURE:
           {
            DbgPrint ("[TAP] Unknown fatal registration error\n");
            NdisTerminateWrapper (g_NdisWrapperHandle, NULL);
            break;
           }
       }

    return l_Status;
   }

//===================================================================================
//                            Adapter Initialization
//===================================================================================
NDIS_STATUS AdapterCreate
   (
    OUT PNDIS_STATUS p_ErrorStatus,
    OUT PUINT p_MediaIndex,
    IN PNDIS_MEDIUM p_Media,
    IN UINT p_MediaCount,
    IN NDIS_HANDLE p_AdapterHandle,
    IN NDIS_HANDLE p_ConfigurationHandle
   )
   {
    static NDIS_PHYSICAL_ADDRESS l_HighestAcceptableMax = NDIS_PHYSICAL_ADDRESS_CONST (-1,-1);
    NDIS_MEDIUM l_PreferredMedium = NdisMedium802_3;
    TapAdapterPointer l_Adapter;
    ANSI_STRING l_AdapterString;
#ifndef ENABLE_RANDOM_MAC
    unsigned char l_MAC [6];
#endif
    UINT l_Index;

    for (l_Index = 0; l_Index < p_MediaCount && p_Media [l_Index] != NdisMedium802_3; ++l_Index);

    if (l_Index == p_MediaCount)
       {
        DbgPrint ("[TAP] Unsupported adapter type [%d]\n", NdisMedium802_3);
        return NDIS_STATUS_UNSUPPORTED_MEDIA;
       }

    *p_MediaIndex = l_Index;

    NdisAllocateMemory ((PVOID *) &l_Adapter, sizeof (TapAdapter), 0, l_HighestAcceptableMax);

    if (l_Adapter == NULL)
       {
        DbgPrint ("[TAP] Couldn't allocate adapter memory\n");
        return NDIS_STATUS_RESOURCES;
       }

    NdisMSetAttributesEx
       (
        p_AdapterHandle,
        (NDIS_HANDLE) l_Adapter,
        16,
        NDIS_ATTRIBUTE_DESERIALIZE,
        NdisInterfaceInternal
       );

    NdisZeroMemory (l_Adapter, sizeof (TapAdapter));
    NdisMRegisterAdapterShutdownHandler (p_AdapterHandle, l_Adapter, AdapterStop);
    NdisAllocateSpinLock (&l_Adapter->m_Lock);

    l_Adapter->m_TapIsRunning = l_Adapter->m_InterfaceIsRunning = FALSE;
    l_Adapter->m_MiniportAdapterHandle = p_AdapterHandle;
    l_Adapter->m_Lookahead = DEFAULT_PACKET_LOOKAHEAD;
    l_Adapter->m_TapName = l_Adapter->m_Name = "";
    l_Adapter->m_Medium = l_PreferredMedium;
    l_Adapter->m_TapOpens = 0;

    //====================================
    // Allocate and construct adapter name
    //====================================

    l_AdapterString.MaximumLength = ((PNDIS_MINIPORT_BLOCK) p_AdapterHandle)->MiniportName.Length + 5;

    if ((l_Adapter->m_Name = l_AdapterString.Buffer = ExAllocatePool (NonPagedPool, l_AdapterString.MaximumLength)) == NULL)
       {
        NdisMDeregisterAdapterShutdownHandler (p_AdapterHandle);
        NdisFreeMemory ((PVOID) l_Adapter, sizeof (TapAdapter), NDIS_MEMORY_NONCACHED | NDIS_MEMORY_CONTIGUOUS);
        return NDIS_STATUS_RESOURCES;
       }

    RtlUnicodeStringToAnsiString (&l_AdapterString, &((PNDIS_MINIPORT_BLOCK) p_AdapterHandle)->MiniportName, FALSE);
    l_AdapterString.Buffer [l_AdapterString.Length] = 0;

    //==================================
    // Store and update MAC address info
    //==================================

#ifdef ENABLE_RANDOM_MAC
    GenerateRandomMac (g_MAC, l_Adapter->m_Name);
    memcpy (l_Adapter->m_MAC, g_MAC, 6);
#else
    memcpy (l_Adapter->m_MAC, g_MAC, 6);

    l_MAC [0] = g_MAC [5];
    l_MAC [1] = g_MAC [4];

    ++(*((unsigned short *) l_MAC));

    g_MAC [5] = l_MAC [0];
    g_MAC [4] = l_MAC [1];
#endif

    DbgPrint ("[%s] Using MAC %x:%x:%x:%x:%x:%x\n",
	      l_Adapter->m_Name,
	      l_Adapter->m_MAC[0], l_Adapter->m_MAC[1], l_Adapter->m_MAC[2],
	      l_Adapter->m_MAC[3], l_Adapter->m_MAC[4], l_Adapter->m_MAC[5]);

    ListAdd (&g_TapAdapterList, l_Adapter);
    HookDispatchFunctions();
    CreateTapDevice (l_Adapter);
    l_Adapter->m_InterfaceIsRunning = TRUE;

    return NDIS_STATUS_SUCCESS;
   }

VOID AdapterDestroy (IN NDIS_HANDLE p_AdapterContext)
   {
    TapAdapterPointer l_Adapter = (TapAdapterPointer) p_AdapterContext;
    DbgPrint ("[%s] is being removed from the system\n", l_Adapter->m_Name);
    AdapterStop (p_AdapterContext);
    ListExtract (&g_TapAdapterList, l_Adapter);

    if (l_Adapter->m_TapDevice)
       {
        DestroyTapDevice (l_Adapter);
       }

    DbgPrint ("[%s] is being deregistered\n", l_Adapter->m_Name);

    if (l_Adapter->m_Name)
       {
        ExFreePool (l_Adapter->m_Name);
        l_Adapter->m_Name = 0;
       }

    NdisMDeregisterAdapterShutdownHandler (l_Adapter->m_MiniportAdapterHandle);
    NdisFreeMemory ((PVOID) l_Adapter, sizeof (TapAdapter), 0);
   }

//===========================================================================================
//                             Tap Device Initialization
//===========================================================================================
NDIS_STATUS CreateTapDevice (TapAdapterPointer p_Adapter)
   {
    unsigned short l_AdapterLength = (unsigned short) strlen (p_Adapter->m_Name);
    ANSI_STRING l_TapString, l_LinkString;
    TapTapExtensionPointer l_Extension;
    UNICODE_STRING l_TapUnicode;
    NTSTATUS l_Status;

    l_TapString.MaximumLength = l_LinkString.MaximumLength = l_AdapterLength + strlen (TAPSUFFIX);

    DbgPrint ("[%s] Creating tap device\n", p_Adapter->m_Name);

    if ((p_Adapter->m_TapName = l_TapString.Buffer = ExAllocatePool (NonPagedPool, l_TapString.MaximumLength)) == NULL)
       {
        DbgPrint ("[%s] couldn't alloc TAP name buffer\n", p_Adapter->m_Name);
        return NDIS_STATUS_RESOURCES;
       }
    else if ((l_LinkString.Buffer = ExAllocatePool (NonPagedPool, l_LinkString.MaximumLength)) == NULL)
       {
        DbgPrint ("[%s] couldn't alloc TAP symbolic link name buffer\n", p_Adapter->m_Name);
        ExFreePool (p_Adapter->m_TapName);
        return NDIS_STATUS_RESOURCES;
       }

    //=======================================================
    // Modify for tap device name ("\Device\TAPn.tap")
    //=======================================================
    NdisMoveMemory (l_TapString.Buffer, p_Adapter->m_Name, l_AdapterLength);
    NdisMoveMemory (l_TapString.Buffer + l_AdapterLength, TAPSUFFIX, strlen (TAPSUFFIX) + 1);
    NdisMoveMemory (l_TapString.Buffer, "\\Device", 7); // For Win2K problem
    l_TapString.Length = l_AdapterLength + strlen (TAPSUFFIX);

    //=======================================================
    // And modify for tap link name ("\??\TAPn.tap")
    //=======================================================
    NdisMoveMemory (l_LinkString.Buffer, l_TapString.Buffer, l_TapString.Length);
    NdisMoveMemory (l_LinkString.Buffer, USERDEVICEDIR, strlen (USERDEVICEDIR));

    NdisMoveMemory
       (
        l_LinkString.Buffer + strlen (USERDEVICEDIR),
        l_LinkString.Buffer + strlen (SYSDEVICEDIR),
        l_TapString.Length - strlen (SYSDEVICEDIR) 
       );

    l_LinkString.Buffer [l_LinkString.Length = l_TapString.Length - (strlen (SYSDEVICEDIR) - strlen (USERDEVICEDIR))] = 0;

    //==================================================
    // Create new tap device and associate with adapter
    //==================================================
    if (RtlAnsiStringToUnicodeString (&l_TapUnicode, &l_TapString, TRUE) != STATUS_SUCCESS)
       {
        DbgPrint ("[%s] couldn't alloc TAP unicode name buffer\n", p_Adapter->m_Name);
        ExFreePool (l_LinkString.Buffer);
        ExFreePool (p_Adapter->m_TapName);
        return NDIS_STATUS_RESOURCES;
       }

    l_Status = IoCreateDevice
       (
        g_TapDriverObject,
        sizeof (TapTapExtension),
        &l_TapUnicode,
        FILE_DEVICE_PHYSICAL_NETCARD | 0x8000,
        0,
        FALSE,
        &(p_Adapter->m_TapDevice)
       );

    if (l_Status != STATUS_SUCCESS)
       {
        DbgPrint ("[%s] couldn't be created\n", p_Adapter->m_TapName);
        RtlFreeUnicodeString (&l_TapUnicode);
        ExFreePool (l_LinkString.Buffer);
        ExFreePool (p_Adapter->m_TapName);
        return NDIS_STATUS_RESOURCES;
       }

    if (RtlAnsiStringToUnicodeString (&p_Adapter->m_UnicodeLinkName, &l_LinkString, TRUE) != STATUS_SUCCESS)
       {
        DbgPrint ("[%s] Couldn't allocate unicode string for symbolic link name\n", p_Adapter->m_Name);
        IoDeleteDevice (p_Adapter->m_TapDevice); 
        RtlFreeUnicodeString (&l_TapUnicode);
        ExFreePool (l_LinkString.Buffer);
        ExFreePool (p_Adapter->m_TapName);
        return NDIS_STATUS_RESOURCES;
       }

    //==================================================
    // Associate symbolic link with new device
    //==================================================
    if (! NT_SUCCESS (IoCreateSymbolicLink (&p_Adapter->m_UnicodeLinkName, &l_TapUnicode)))
       {
        DbgPrint ("[%s] symbolic link couldn't be created\n", l_LinkString.Buffer);
        IoDeleteDevice (p_Adapter->m_TapDevice); 
        RtlFreeUnicodeString (&p_Adapter->m_UnicodeLinkName);
        RtlFreeUnicodeString (&l_TapUnicode);
        ExFreePool (l_LinkString.Buffer);
        ExFreePool (p_Adapter->m_TapName);
        return NDIS_STATUS_RESOURCES;
       }

    l_Extension = ((TapTapExtensionPointer) p_Adapter->m_TapDevice->DeviceExtension);

    NdisZeroMemory (l_Extension, sizeof (TapTapExtension));

    ListActivate (&l_Extension->m_PacketQueue, PACKET_QUEUE_SIZE);
    ListActivate (&l_Extension->m_IrpQueue, IRP_QUEUE_SIZE);

    l_Extension->m_Adapter = p_Adapter;

    p_Adapter->m_TapDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    p_Adapter->m_TapDevice->Flags |= DO_DIRECT_IO;        /* instead of DO_BUFFERED_IO */

    RtlFreeUnicodeString (&l_TapUnicode);
    ExFreePool (l_LinkString.Buffer);

    DbgPrint ("[%s] successfully created TAP device [%s]\n", p_Adapter->m_Name, p_Adapter->m_TapName);

    p_Adapter->m_TapIsRunning = TRUE;

    return NDIS_STATUS_SUCCESS;
   }

VOID DestroyTapDevice (TapAdapterPointer p_Adapter)
   {
    TapTapExtensionPointer l_Extension = (TapTapExtensionPointer) p_Adapter->m_TapDevice->DeviceExtension;
    TapPacketPointer l_PacketBuffer;
    PIRP l_IRP;

    DbgPrint ("[%s] Destroying tap device\n", p_Adapter->m_TapName);

    p_Adapter->m_TapIsRunning = FALSE;
    p_Adapter->m_TapOpens = 0;

    while (QueueCount (&l_Extension->m_IrpQueue)) if (l_IRP = QueuePop (&l_Extension->m_IrpQueue))
       {
        CancelIRP (p_Adapter->m_TapDevice, l_IRP);
       }

    while (QueueCount (&l_Extension->m_PacketQueue)) if (l_PacketBuffer = QueuePop (&l_Extension->m_PacketQueue))
       {
        MemFree (l_PacketBuffer, sizeof (TapPacket) + l_PacketBuffer->m_Size);
       }

    ListDeactivate (&l_Extension->m_PacketQueue);
    ListDeactivate (&l_Extension->m_IrpQueue);
    IoDeleteSymbolicLink (&p_Adapter->m_UnicodeLinkName);
    RtlFreeUnicodeString (&p_Adapter->m_UnicodeLinkName);
    IoDeleteDevice (p_Adapter->m_TapDevice);
    ExFreePool (p_Adapter->m_TapName);
    p_Adapter->m_TapDevice = 0;
    p_Adapter->m_TapName = 0;
   }

//===========================================================================================
//                                    Adapter Control
//===========================================================================================
NDIS_STATUS AdapterReset (OUT PBOOLEAN p_AddressingReset, IN NDIS_HANDLE p_AdapterContext)
   {
    TapAdapterPointer l_Adapter = (TapAdapterPointer) p_AdapterContext;
    DbgPrint ("[%s] is resetting\n", l_Adapter->m_Name);
    return NDIS_STATUS_SUCCESS;
   }

VOID AdapterStop (IN NDIS_HANDLE p_AdapterContext)
   {
    TapAdapterPointer l_Adapter = (TapAdapterPointer) p_AdapterContext;
    DbgPrint ("[%s] is stopping\n", l_Adapter->m_Name);
    l_Adapter->m_InterfaceIsRunning = FALSE;
   }

NDIS_STATUS AdapterReceive
   (
    OUT PNDIS_PACKET p_Packet,
    OUT PUINT p_Transferred,
    IN NDIS_HANDLE p_AdapterContext,
    IN NDIS_HANDLE p_ReceiveContext,
    IN UINT p_Offset,
    IN UINT p_ToTransfer
   )
   {
    return NDIS_STATUS_SUCCESS;
   }

//===========================================================================================
//                            Adapter Option Query/Modification
//===========================================================================================
NDIS_STATUS AdapterQuery
   (
    IN NDIS_HANDLE p_AdapterContext,
    IN NDIS_OID p_OID,
    IN PVOID p_Buffer,
    IN ULONG p_BufferLength,
    OUT PULONG p_BytesWritten,
    OUT PULONG p_BytesNeeded
   )
   {
    TapAdapterPointer l_Adapter = (TapAdapterPointer) p_AdapterContext;
    TapAdapterQuery l_Query, *l_QueryPtr = &l_Query;
    NDIS_STATUS l_Status = NDIS_STATUS_SUCCESS;
    UINT l_QueryLength = 4;

    NdisZeroMemory (&l_Query, sizeof (l_Query));
    NdisAcquireSpinLock (&l_Adapter->m_Lock);

    switch (p_OID)
       {
        //===========================================================================
        //                       Vendor & Driver version Info
        //===========================================================================
        case OID_GEN_VENDOR_DESCRIPTION:
           l_QueryPtr = (TapAdapterQueryPointer) PRODUCT_STRING;
           l_QueryLength = strlen (PRODUCT_STRING) + 1;
           break;

        case OID_GEN_VENDOR_ID:
           l_Query.m_Long = 0xffffff;
           break;

        case OID_GEN_DRIVER_VERSION:
           l_Query.m_Short = (((USHORT) TAP_NDIS_MAJOR_VERSION) << 8 | (USHORT) TAP_NDIS_MINOR_VERSION);
           l_QueryLength = sizeof (unsigned short);
           break;

        case OID_GEN_VENDOR_DRIVER_VERSION:
           l_Query.m_Long = (((USHORT) TAP_DRIVER_MAJOR_VERSION) << 8 | (USHORT) TAP_DRIVER_MINOR_VERSION);
           break;

        //===========================================================================
        //                             Statistics
        //===========================================================================
        case OID_GEN_RCV_NO_BUFFER:
           l_Query.m_Long = 0;
           break;

        case OID_802_3_RCV_ERROR_ALIGNMENT:
           l_Query.m_Long = 0;
           break;

        case OID_802_3_XMIT_ONE_COLLISION:
           l_Query.m_Long = 0;
           break;

        case OID_802_3_XMIT_MORE_COLLISIONS:
           l_Query.m_Long = 0;
           break;

        case OID_GEN_XMIT_OK:
           l_Query.m_Long = l_Adapter->m_Tx;
           break;

        case OID_GEN_RCV_OK:
           l_Query.m_Long = l_Adapter->m_Rx;
           break;

        case OID_GEN_XMIT_ERROR:
           l_Query.m_Long = l_Adapter->m_TxErr;
           break;

        case OID_GEN_RCV_ERROR:
           l_Query.m_Long = l_Adapter->m_RxErr;
           break;

        //===========================================================================
        //                       Device & Protocol Options
        //===========================================================================
        case OID_GEN_SUPPORTED_LIST:
           l_QueryPtr = (TapAdapterQueryPointer) g_SupportedOIDList;
           l_QueryLength = sizeof (g_SupportedOIDList);
           break;

        case OID_GEN_MAC_OPTIONS:
           l_Query.m_Long =
              (
               NDIS_MAC_OPTION_RECEIVE_SERIALIZED  |
               NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | // This MUST be here !!!
               NDIS_MAC_OPTION_NO_LOOPBACK |
               NDIS_MAC_OPTION_TRANSFERS_NOT_PEND
              );

           break;

        case OID_GEN_CURRENT_PACKET_FILTER:
           l_Query.m_Long =
              (
               NDIS_PACKET_TYPE_ALL_LOCAL |
               NDIS_PACKET_TYPE_BROADCAST |
               NDIS_PACKET_TYPE_DIRECTED |
               NDIS_PACKET_TYPE_ALL_FUNCTIONAL
              );

           break;

        case OID_GEN_PROTOCOL_OPTIONS:
           l_Query.m_Long = 0;
           break;

        //===========================================================================
        //                            Device Info
        //===========================================================================
        case OID_GEN_MEDIA_CONNECT_STATUS:
           l_Query.m_Long = NdisMediaStateConnected;
           break;

        case OID_GEN_HARDWARE_STATUS:
           l_Query.m_HardwareStatus = NdisHardwareStatusReady;
           l_QueryLength = sizeof (NDIS_HARDWARE_STATUS);
           break;

        case OID_GEN_MEDIA_SUPPORTED:
        case OID_GEN_MEDIA_IN_USE:
           l_Query.m_Medium = l_Adapter->m_Medium;
           l_QueryLength = sizeof (NDIS_MEDIUM);
           break;

        case OID_GEN_LINK_SPEED:
           l_Query.m_Long = 100000;
           break;

        case OID_802_3_MULTICAST_LIST:
           l_Query.m_Long = 0;
           break;

        case OID_802_3_PERMANENT_ADDRESS:
        case OID_802_3_CURRENT_ADDRESS:
           memcpy (l_Query.m_MacAddress, l_Adapter->m_MAC, 6);
           l_QueryLength = 6;
           break;

        //===========================================================================
        //                             Limits
        //===========================================================================
        case OID_GEN_MAXIMUM_SEND_PACKETS:
           l_Query.m_Long = 1;
           break;

        case OID_802_3_MAXIMUM_LIST_SIZE:
           l_Query.m_Long = 0;
           break;

        case OID_GEN_MAXIMUM_TOTAL_SIZE:
           l_Query.m_Long = DEFAULT_PACKET_LOOKAHEAD;
           break;

        case OID_GEN_TRANSMIT_BUFFER_SPACE:
        case OID_GEN_RECEIVE_BUFFER_SPACE:
        case OID_GEN_CURRENT_LOOKAHEAD:
        case OID_GEN_RECEIVE_BLOCK_SIZE:
           l_Query.m_Long = l_Adapter->m_Lookahead;
           break;

        case OID_GEN_TRANSMIT_BLOCK_SIZE:
        case OID_GEN_MAXIMUM_FRAME_SIZE:
        case OID_GEN_MAXIMUM_LOOKAHEAD:
           l_Query.m_Long = DEFAULT_PACKET_LOOKAHEAD - 14;
           break;

        //===========================================================================
        //                          Not Handled
        //===========================================================================
        default:
           DbgPrint ("[%s] Unhandled OID %lx\n", l_Adapter->m_Name, p_OID);
           l_Status = NDIS_STATUS_INVALID_OID;
           break;
       }

    if (l_Status != NDIS_STATUS_SUCCESS)
       ;
    else if (l_QueryLength > p_BufferLength)
       l_Status = NDIS_STATUS_INVALID_LENGTH, *p_BytesNeeded = l_QueryLength;
    else
       NdisMoveMemory (p_Buffer, (PVOID) l_QueryPtr, (*p_BytesWritten = l_QueryLength));

    NdisReleaseSpinLock (&l_Adapter->m_Lock);

    return l_Status;
   }

NDIS_STATUS AdapterModify
   (
    IN NDIS_HANDLE p_AdapterContext,
    IN NDIS_OID p_OID,
    IN PVOID p_Buffer,
    IN ULONG p_BufferLength,
    OUT PULONG p_BytesRead,
    OUT PULONG p_BytesNeeded
   )
   {
    TapAdapterQueryPointer l_Query = (TapAdapterQueryPointer) p_Buffer;
    TapAdapterPointer l_Adapter = (TapAdapterPointer) p_AdapterContext;
    NDIS_STATUS l_Status = NDIS_STATUS_INVALID_OID;
    ULONG l_Long;

    NdisAcquireSpinLock (&l_Adapter->m_Lock);

    switch (p_OID)
       {
        //===========================================================================
        //                            Device Info
        //===========================================================================
        case OID_802_3_MULTICAST_LIST:
           DbgPrint ("[%s] Setting [OID_802_3_MAXIMUM_LIST_SIZE]\n", l_Adapter->m_Name);
           l_Status = NDIS_STATUS_SUCCESS;
           break;

        case OID_GEN_CURRENT_PACKET_FILTER:
           l_Status = NDIS_STATUS_INVALID_LENGTH, *p_BytesNeeded = 4;

           if (p_BufferLength >= sizeof (ULONG))
              {
               DbgPrint ("[%s] Setting [OID_GEN_CURRENT_PACKET_FILTER] to [0x%02lx]\n", l_Adapter->m_Name, l_Query->m_Long);
               l_Status = NDIS_STATUS_SUCCESS;
               *p_BytesRead = sizeof (ULONG);
              }

           break;

        case OID_GEN_CURRENT_LOOKAHEAD:
           if (p_BufferLength < sizeof (ULONG))
              l_Status = NDIS_STATUS_INVALID_LENGTH, *p_BytesNeeded = 4;
           else if (l_Query->m_Long > DEFAULT_PACKET_LOOKAHEAD || l_Query->m_Long <= 0)
              l_Status = NDIS_STATUS_INVALID_DATA;
           else
              {
               DbgPrint ("[%s] Setting [OID_GEN_CURRENT_LOOKAHEAD] to [%d]\n", l_Adapter->m_Name, l_Query->m_Long);
               l_Adapter->m_Lookahead = l_Query->m_Long;
               l_Status = NDIS_STATUS_SUCCESS;
               *p_BytesRead = sizeof (ULONG);
              }

           break;

        case OID_GEN_NETWORK_LAYER_ADDRESSES:
           l_Status = NDIS_STATUS_SUCCESS;
           *p_BytesRead = *p_BytesNeeded = 0;
           break;

        case OID_GEN_TRANSPORT_HEADER_OFFSET:
           l_Status = NDIS_STATUS_SUCCESS;
           *p_BytesRead = *p_BytesNeeded = 0;
           break;

        case OID_PNP_REMOVE_WAKE_UP_PATTERN:
        case OID_PNP_ADD_WAKE_UP_PATTERN:
           l_Status = NDIS_STATUS_SUCCESS;
           *p_BytesRead = *p_BytesNeeded = 0;
           break;

        default:
           DbgPrint ("[%s] Can't set value for OID %lx\n", l_Adapter->m_Name, p_OID);
           l_Status = NDIS_STATUS_INVALID_OID;
           *p_BytesRead = *p_BytesNeeded = 0;
           break;
       }

    NdisReleaseSpinLock (&l_Adapter->m_Lock);

    return l_Status;
   }

//===========================================================================================
//                               Adapter Transmission
//===========================================================================================
NDIS_STATUS AdapterTransmit (IN NDIS_HANDLE p_AdapterContext, IN PNDIS_PACKET p_Packet, IN UINT p_Flags)
   {
    static NDIS_PHYSICAL_ADDRESS l_HighestAcceptableMax = NDIS_PHYSICAL_ADDRESS_CONST (-1,-1);
    TapAdapterPointer l_Adapter = (TapAdapterPointer) p_AdapterContext;
    ULONG l_Index = 0, l_BufferLength = 0, l_PacketLength = 0;
    TapPacketPointer l_PacketBuffer, l_Throwaway;
    TapTapExtensionPointer l_Extension;
    PNDIS_BUFFER l_NDIS_Buffer;
    PUCHAR l_Buffer;

    NdisQueryPacket (p_Packet, NULL, NULL, &l_NDIS_Buffer, &l_PacketLength);

    //====================================================
    // Here we abandon the transmission attempt if any of
    // the parameters is wrong or memory allocation fails
    // but we do not indicate failure. The packet is
    // silently dropped.
    //====================================================

    if (l_Adapter->m_TapDevice == NULL)
       return NDIS_STATUS_FAILURE;
    else if ((l_Extension = (TapTapExtensionPointer) l_Adapter->m_TapDevice->DeviceExtension) == NULL)
       return NDIS_STATUS_FAILURE;
    else if (l_PacketLength < ETHERNET_HEADER_SIZE)
       return NDIS_STATUS_FAILURE;
    else if (l_PacketLength > 65535) // Cap packet size to TCP/IP maximum
       return NDIS_STATUS_FAILURE;
    else if (! l_Adapter->m_TapOpens) // Nothing is bound to the TAP device
       return NDIS_STATUS_SUCCESS;

    NdisAllocateMemory (&l_PacketBuffer, sizeof (TapPacket) + l_PacketLength, 0, l_HighestAcceptableMax);

    if (l_PacketBuffer == NULL)
       return NDIS_STATUS_RESOURCES;
    else
       NdisZeroMemory (l_PacketBuffer, l_PacketLength);

    l_PacketBuffer->m_Size = l_PacketLength;

    //===========================
    // Reassemble packet contents
    //===========================
    __try
       {
        for (l_Index = 0; l_NDIS_Buffer && l_Index < l_PacketLength; l_Index += l_BufferLength)
           {
            NdisQueryBuffer (l_NDIS_Buffer, (PVOID *) &l_Buffer, &l_BufferLength);
            NdisMoveMemory (l_PacketBuffer->m_Data + l_Index, l_Buffer, l_BufferLength);
            NdisGetNextBuffer (l_NDIS_Buffer, &l_NDIS_Buffer);
           }

        if (QueuePush (&l_Extension->m_PacketQueue, l_PacketBuffer) != l_PacketBuffer) switch (OVERWRITE_OLD_PACKETS)
           {
            //******************** ALERT ************************
            // If the oldest packet is discarded when a new queue
            // insertion is attempted, the usermode thread may
            // get a packet whose contents are partially invalid
            // I.E. the packet gets deleted while the usermode
            // thread is trying to fetch it
            //******************** ALERT ************************
            case TRUE: // Try to throw away oldest packet
               {
                if (l_Throwaway = QueuePop (&l_Extension->m_PacketQueue))
                   {
                    NdisFreeMemory (l_Throwaway, sizeof (TapPacket) + l_Throwaway->m_Size, 0);
                   }

                if (QueuePush (&l_Extension->m_PacketQueue, l_PacketBuffer) != l_PacketBuffer)
                   {
                    NdisFreeMemory (l_PacketBuffer, sizeof (TapPacket) + l_PacketBuffer->m_Size, 0);
                   }

                break;
               }

            case FALSE:
               {
                NdisFreeMemory (l_PacketBuffer, sizeof (TapPacket) + l_PacketBuffer->m_Size, 0);
                break;
               }
           }
       }
    __except (EXCEPTION_EXECUTE_HANDLER)
       {
       }

    while (QueueCount (&l_Extension->m_PacketQueue) && QueueCount (&l_Extension->m_IrpQueue))
       {
        CompleteIRP (QueuePop (&l_Extension->m_IrpQueue), l_Extension);
       }

    return NDIS_STATUS_SUCCESS;
   }

//===========================================================================================
// Hook for catching tap device IRP's. Network adapter requests are forwarded on to NDIS
//===========================================================================================
NTSTATUS TapTapDeviceHook (IN PDEVICE_OBJECT p_DeviceObject, IN PIRP p_IRP)
   {
    PIO_STACK_LOCATION l_IrpSp = IoGetCurrentIrpStackLocation (p_IRP);
    TapTapExtensionPointer l_Extension;
    NTSTATUS l_Status = STATUS_SUCCESS; 
    TapPacketPointer l_PacketBuffer;
    TapAdapterPointer l_Adapter;

    //=======================================================================
    //  If it's not the private data device type, call the original handler
    //=======================================================================
    if (p_DeviceObject->DeviceType != (FILE_DEVICE_PHYSICAL_NETCARD | 0x8000))
       {
        return (*g_DispatchHook [l_IrpSp->MajorFunction]) (p_DeviceObject, p_IRP);
       }

    //=======================================================================
    //     Only TAP device I/O requests get handled below here
    //=======================================================================
    l_Extension = (TapTapExtensionPointer) p_DeviceObject->DeviceExtension;
    l_Adapter = l_Extension->m_Adapter;

    p_IRP->IoStatus.Status = STATUS_SUCCESS;
    p_IRP->IoStatus.Information = 0; 

    switch (l_IrpSp->MajorFunction)
       {
        //-----------------------------------------------------------
        //                 Ioctl call handlers
        //-----------------------------------------------------------
        case IRP_MJ_DEVICE_CONTROL:
           {
            switch (l_IrpSp->Parameters.DeviceIoControl.IoControlCode)
               {
                case TAP_IOCTL_GET_LASTMAC:
                   {
                    if (l_IrpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof (g_MAC))
                       {
                        NdisMoveMemory (p_IRP->AssociatedIrp.SystemBuffer, g_MAC, sizeof (g_MAC));
                        p_IRP->IoStatus.Information = sizeof (g_MAC);
                       }

                    break;
                   }

                case TAP_IOCTL_GET_MAC:
                   {
                    if (l_IrpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof (g_MAC))
                       {
                        NdisMoveMemory (p_IRP->AssociatedIrp.SystemBuffer, l_Adapter->m_MAC, sizeof (g_MAC));
                        p_IRP->IoStatus.Information = sizeof (g_MAC);
                       }

                    break;
                   }

                case TAP_IOCTL_SET_STATISTICS:
                   {
                    if (l_IrpSp->Parameters.DeviceIoControl.InputBufferLength >= (sizeof (ULONG) * 4))
                       {
                        l_Adapter->m_Tx    = ((PULONG) (p_IRP->AssociatedIrp.SystemBuffer)) [0];
                        l_Adapter->m_Rx    = ((PULONG) (p_IRP->AssociatedIrp.SystemBuffer)) [1];
                        l_Adapter->m_TxErr = ((PULONG) (p_IRP->AssociatedIrp.SystemBuffer)) [2];
                        l_Adapter->m_RxErr = ((PULONG) (p_IRP->AssociatedIrp.SystemBuffer)) [3];
                        p_IRP->IoStatus.Information = 1; // Simple boolean value
                       }

                    break;
                   }

                default:
                   {
                    p_IRP->IoStatus.Status = l_Status = STATUS_INVALID_PARAMETER;
                    break;
                   }
               }

            IoCompleteRequest (p_IRP, IO_NO_INCREMENT);
            break;
           }

        //-----------------------------------------------------------
        // User mode thread issued a read request on the tap device
        // If there are packets waiting to be read, then the request
        // will be satisfied here. If not, then the request will be
        // queued and satisfied by any packet that is not used to
        // satisfy requests ahead of it.
        //-----------------------------------------------------------
        case IRP_MJ_READ:
           {
            p_IRP->IoStatus.Information = l_IrpSp->Parameters.Read.Length; // Save IRP accessible copy of buffer length
            p_IRP->AssociatedIrp.SystemBuffer = MmGetSystemAddressForMdl (p_IRP->MdlAddress); /* DO_DIRECT_IO only !!! */

            if (! l_Adapter->m_InterfaceIsRunning)
               {
                DbgPrint ("[%s] is unavailable for reading via TAP %s\n", l_Adapter->m_Name, l_Adapter->m_TapName);
                p_IRP->IoStatus.Status = l_Status = STATUS_UNSUCCESSFUL;
                p_IRP->IoStatus.Information = 0;
                IoCompleteRequest (p_IRP, IO_NO_INCREMENT);
               }
            else if (QueueCount (&l_Extension->m_PacketQueue) && QueueCount (&l_Extension->m_IrpQueue) == 0) // Immediate service
               {
                l_Status = CompleteIRP (p_IRP, l_Extension);
               }
            else if (QueuePush (&l_Extension->m_IrpQueue, p_IRP) == p_IRP) // Attempt to pend read request
               {
                IoSetCancelRoutine (p_IRP, CancelIRP);
                l_Status = STATUS_PENDING;
                IoMarkIrpPending (p_IRP);
               }
            else // Can't queue anymore IRP's
               {
                DbgPrint ("[%s] TAP [%s] read IRP overrun\n", l_Adapter->m_Name, l_Adapter->m_TapName);
                p_IRP->IoStatus.Status = l_Status = STATUS_UNSUCCESSFUL;
                p_IRP->IoStatus.Information = 0;
                IoCompleteRequest (p_IRP, IO_NO_INCREMENT);
               }

            break;
           }

        //-----------------------------------------------------------
        // User mode thread issued a write request on the tap device
        // The request will always get satisfied here. The call may
        // fail if there are too many pending packets (queue full)
        //-----------------------------------------------------------
        case IRP_MJ_WRITE:
           {
            p_IRP->AssociatedIrp.SystemBuffer = MmGetSystemAddressForMdl (p_IRP->MdlAddress); /* DO_DIRECT_IO only !!! */

            if (! l_Adapter->m_InterfaceIsRunning)
               {
                DbgPrint ("[%s] is unavailable for writing via TAP %s\n", l_Adapter->m_Name, l_Adapter->m_TapName);
                p_IRP->IoStatus.Status = l_Status = STATUS_UNSUCCESSFUL;
                p_IRP->IoStatus.Information = 0;
                l_Status = STATUS_UNSUCCESSFUL;
               }
            else if (p_IRP->AssociatedIrp.SystemBuffer && (p_IRP->IoStatus.Information = l_IrpSp->Parameters.Write.Length) >= ETHERNET_HEADER_SIZE)
               {
                __try
                   {
                    NdisMEthIndicateReceive
                       (
                        l_Adapter->m_MiniportAdapterHandle,
                        (NDIS_HANDLE) l_Adapter,
                        (unsigned char *) p_IRP->AssociatedIrp.SystemBuffer,
                        ETHERNET_HEADER_SIZE,
                        (unsigned char *) p_IRP->AssociatedIrp.SystemBuffer + ETHERNET_HEADER_SIZE,
                        l_IrpSp->Parameters.Write.Length - ETHERNET_HEADER_SIZE,
                        l_IrpSp->Parameters.Write.Length - ETHERNET_HEADER_SIZE
                       );

                    NdisMEthIndicateReceiveComplete (l_Adapter->m_MiniportAdapterHandle);
                   }
                __except (EXCEPTION_EXECUTE_HANDLER)
                   {
                    p_IRP->IoStatus.Status = l_Status = STATUS_UNSUCCESSFUL;
                    p_IRP->IoStatus.Information = 0;
                   }
               }
            else
               {
                p_IRP->IoStatus.Information = 0; // ETHERNET_HEADER_SIZE;
                p_IRP->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
                l_Status = STATUS_UNSUCCESSFUL;
               }

            IoCompleteRequest (p_IRP, IO_NO_INCREMENT);
            break;
           }

        //-----------------------------------------------------------
        //   User mode thread has called open() on the tap device
        //-----------------------------------------------------------
        case IRP_MJ_CREATE:
           {
	     if (l_Adapter->m_TapIsRunning
#ifdef DISABLE_DEVICE_SHARING
		 && l_Adapter->m_TapOpens < 1
#endif
		 )
               {
                DbgPrint ("[%s] [TAP] release [%d.%d] open request (m_TapOpens=%d)\n", l_Adapter->m_Name, TAP_DRIVER_MAJOR_VERSION, TAP_DRIVER_MINOR_VERSION, l_Adapter->m_TapOpens);
                ++l_Adapter->m_TapOpens;
               }
            else
               {
                DbgPrint ("[%s] TAP is presently unavailable (m_TapOpens=%d)\n", l_Adapter->m_Name, l_Adapter->m_TapOpens);
                p_IRP->IoStatus.Status = l_Status = STATUS_UNSUCCESSFUL;
                p_IRP->IoStatus.Information = 0;
               }

            IoCompleteRequest (p_IRP, IO_NO_INCREMENT);
            break;
           }

        //-----------------------------------------------------------
        //        User mode thread close() on the tap device
        //-----------------------------------------------------------
        case IRP_MJ_CLOSE:
           {
            DbgPrint ("[%s] [TAP] release [%d.%d] close request\n", l_Adapter->m_Name, TAP_DRIVER_MAJOR_VERSION, TAP_DRIVER_MINOR_VERSION);
            while (QueueCount (&l_Extension->m_PacketQueue)) QueuePop (&l_Extension->m_PacketQueue); // Exhaust packet queue
            // If we were going to CancelIrp() all the IRPs in queue, we would do it here :-)
            if (l_Adapter->m_TapOpens) --l_Adapter->m_TapOpens;
            IoCompleteRequest (p_IRP, IO_NO_INCREMENT); 
            break;
           }

        //-----------------------------------------------------------
        // Something screwed up if it gets here ! It won't die, though
        //-----------------------------------------------------------
        default:
           {
            IoCompleteRequest (p_IRP, IO_NO_INCREMENT); 
            break;
           }
       }
 
    return l_Status;
   }

//===========================================================================================
//                               IRP Management Routines
//===========================================================================================
NTSTATUS CompleteIRP (IN PIRP p_IRP, IN TapTapExtensionPointer p_Extension)
   {
    NTSTATUS l_Status = STATUS_UNSUCCESSFUL;
    TapPacketPointer l_PacketBuffer;

    if ((l_PacketBuffer = QueuePeek (&p_Extension->m_PacketQueue)) == 0) // The topmost packet buffer is invalid !
       {
        QueuePop (&p_Extension->m_PacketQueue);
       }
    else if (p_IRP)
       {
        IoSetCancelRoutine (p_IRP, NULL); // Disable cancel routine

        if (p_IRP->IoStatus.Information < l_PacketBuffer->m_Size)
           {
            p_IRP->IoStatus.Information = 0; // l_PacketBuffer->m_Size;
            p_IRP->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
           }
        else
           {
            p_IRP->IoStatus.Information = l_PacketBuffer->m_Size;
            p_IRP->IoStatus.Status = l_Status = STATUS_SUCCESS;
            QueuePop (&p_Extension->m_PacketQueue);

            __try
               {
                NdisMoveMemory (p_IRP->AssociatedIrp.SystemBuffer, l_PacketBuffer->m_Data, l_PacketBuffer->m_Size);
               }
            __except (EXCEPTION_EXECUTE_HANDLER)
               {
                p_IRP->IoStatus.Status = STATUS_UNSUCCESSFUL;
                p_IRP->IoStatus.Information = 0;
               }

            __try
               {
                NdisFreeMemory (l_PacketBuffer, sizeof (TapPacket) + l_PacketBuffer->m_Size, 0);
               }
            __except (EXCEPTION_EXECUTE_HANDLER)
               {
               }
           }

        IoCompleteRequest (p_IRP, IO_NO_INCREMENT);
       }

    return l_Status;
   }

VOID CancelIRP (IN PDEVICE_OBJECT p_DeviceObject, IN PIRP p_IRP)
   {
    TapTapExtensionPointer l_Extension = (TapTapExtensionPointer) p_DeviceObject->DeviceExtension;

    if (p_IRP) if (QueueExtract (&l_Extension->m_IrpQueue, p_IRP) == p_IRP)
       {
        IoSetCancelRoutine (p_IRP, NULL); 
        IoReleaseCancelSpinLock (p_IRP->CancelIrql); 
        p_IRP->IoStatus.Status = STATUS_CANCELLED;
        p_IRP->IoStatus.Information = 0;
        IoCompleteRequest (p_IRP, IO_NO_INCREMENT);
       }
   }

//===========================================================================================
//                             Dispatch Table Managemement
//===========================================================================================
VOID HookDispatchFunctions()
   {
    unsigned long l_Index;

    //==============================================================
    // Save original NDIS dispatch functions and override with ours
    //==============================================================
    if (! g_DispatchFunctionsHooked) for (l_Index = 0, g_DispatchFunctionsHooked = 1; l_Index <= IRP_MJ_MAXIMUM_FUNCTION; ++l_Index)
       {
        g_DispatchHook [l_Index] = g_TapDriverObject->MajorFunction [l_Index];
        g_TapDriverObject->MajorFunction [l_Index] = TapTapDeviceHook;
       }
   }

//===========================================================================================
//                         Linked List Management Routines
//===========================================================================================
LROOT ListAlloc (ULONG p_Limit)
   {
    return ListActivate ((LROOT) MemAlloc (sizeof (struct LROOTSTRUCT)), p_Limit);
   }

VOID ListFree (LROOT p_Root)
   {
    if (p_Root)
       {
        ListDeactivate (p_Root);
        MemFree ((PVOID) p_Root, sizeof (struct LROOTSTRUCT));
       }
   }

LROOT ListActivate (LROOT p_Root, ULONG p_Limit)
   {
    if (p_Root)
       {
        p_Root->m_First = p_Root->m_Last = 0;
        p_Root->m_Limit = p_Limit;
        p_Root->m_Count = 0;
       }

    return p_Root;
   }

VOID ListDeactivate (LROOT p_Root)
   {
    if (p_Root) while (p_Root->m_Count) ListRemove (p_Root, LMODE_QUEUE);
   }

LITEM ListAdd (LROOT p_Root, LITEM p_Payload)
   {
    LITEM l_Return = 0;
    LNODE l_Node;

    if (p_Root)
       {
        if (p_Root->m_Count >= p_Root->m_Limit && p_Root->m_Limit)
           ;
        else if ((l_Node = (LNODE) MemAlloc (sizeof (struct LNODESTRUCT))) == 0)
           ;
        else if (p_Root->m_First)
           {
            (l_Node->m_Previous = p_Root->m_Last)->m_Next = l_Node;
            l_Return = l_Node->m_Payload = p_Payload;
            p_Root->m_Last = l_Node;
            ++p_Root->m_Count;
           }
        else
           {
            l_Return = l_Node->m_Payload = p_Payload;
            p_Root->m_First = p_Root->m_Last = l_Node;
            l_Node->m_Next = l_Node->m_Previous = 0;
            p_Root->m_Count = 1;
           }
       }

    return l_Return;
   }

LITEM ListRemove (LROOT p_Root, LMODE p_Mode)
   {
    LITEM l_Return = 0;
    LNODE l_Node;

    if (p_Root)
       {
        if (p_Root->m_Count == 0)
           ;
        else if ((l_Node = (p_Mode == LMODE_QUEUE ? p_Root->m_First : p_Root->m_Last)) == 0)
           p_Root->m_Count = 0;
        else
           {
            if (l_Node->m_Next && p_Mode == LMODE_QUEUE)
               (p_Root->m_First = l_Node->m_Next)->m_Previous = 0;
            else if (l_Node->m_Previous && p_Mode == LMODE_STACK)
               (p_Root->m_Last = l_Node->m_Previous)->m_Next = 0;
            else
               p_Root->m_First = p_Root->m_Last = 0;

            l_Return = l_Node->m_Payload;
            MemFree ((PVOID) l_Node, sizeof (struct LNODESTRUCT)); // DEBUG DEBUG DEBUG
            --p_Root->m_Count;
           }
       }

    return l_Return;
   }

LITEM ListExtract (LROOT p_Root, LITEM p_Payload)
   {
    LITEM l_Return = 0;
    LNODE l_Node = 0;

    if (p_Root)
       {
        if (p_Root->m_Count)
           {
            for (l_Node = p_Root->m_First; l_Node && l_Node->m_Payload != p_Payload; l_Node = l_Node->m_Next);
           }

        if (l_Node)
           {
            if (l_Node->m_Previous) l_Node->m_Previous->m_Next = l_Node->m_Next;
            if (l_Node->m_Next) l_Node->m_Next->m_Previous = l_Node->m_Previous;
            if (p_Root->m_Last == l_Node) p_Root->m_Last = l_Node->m_Previous;
            if (p_Root->m_First == l_Node) p_Root->m_First = l_Node->m_Next;
            l_Return = l_Node->m_Payload;
            MemFree ((PVOID) l_Node, sizeof (struct LNODESTRUCT));
            --p_Root->m_Count;
           }
       }

    return l_Return;
   }

LITEM ListPeek (LROOT p_Root, LMODE p_Mode)
   {
    LITEM l_Return = 0;

    if (p_Root)
       {
        if (p_Root->m_Count == 0)
           ;
        else if (p_Root->m_First && p_Mode == LMODE_QUEUE)
           l_Return = p_Root->m_First->m_Payload;
        else if (p_Root->m_Last && p_Mode == LMODE_STACK)
           l_Return = p_Root->m_Last->m_Payload;
        else
           l_Return = (LITEM) (p_Root->m_Count = 0);
       }

    return l_Return;
   }

ULONG ListCount (LROOT p_Root)
   {
    return (p_Root ? p_Root->m_Count : 0);
   }

//===========================================================================================
//                               Memory Management
//===========================================================================================
PVOID MemAlloc (ULONG p_Size)
   {
    PVOID l_Return = 0;

    if (p_Size)
       {
        __try
           {
            static NDIS_PHYSICAL_ADDRESS l_HighestAcceptableMax = NDIS_PHYSICAL_ADDRESS_CONST (-1,-1);
            NdisAllocateMemory (&l_Return, p_Size, 0, l_HighestAcceptableMax);
            NdisZeroMemory (l_Return, p_Size);
           }
        __except (EXCEPTION_EXECUTE_HANDLER)
           {
            l_Return = 0;
           }
       }

    return l_Return;
   }

VOID MemFree (PVOID p_Addr, ULONG p_Size)
   {
    if (p_Addr && p_Size)
       {
        __try
           {
            NdisFreeMemory (p_Addr, p_Size, 0);
           }
        __except (EXCEPTION_EXECUTE_HANDLER)
           {
           }
       }
   }

//===========================================================================================
//                                    End of Source
//===========================================================================================
