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

#ifndef TAP_CONSTANTS_DEFINED
#define TAP_CONSTANTS_DEFINED

//========================================================================================
//                        Product and Version public settings
//========================================================================================
#define PRODUCT_STRING "TAP VPN Adapter."
#define TAP_SERVICE_NAME "TAP_Daemon"
#define TAP_DRIVER_NAME "TAP"

#define TAP_NDIS_MAJOR_VERSION 5
#define TAP_NDIS_MINOR_VERSION 0

#ifndef TAP_DRIVER_MAJOR_VERSION
#   define TAP_DRIVER_MAJOR_VERSION 2
#endif

#ifndef TAP_DRIVER_MINOR_VERSION
#   define TAP_DRIVER_MINOR_VERSION 1
#endif

#ifndef ENABLE_RANDOM_MAC
# ifndef TAP_MAC_ROOT_ADDRESS
#   define TAP_MAC_ROOT_ADDRESS "8:0:58:0:0:1"
# endif
#endif

#ifdef CIPE_SERVICE_DEFINES

#ifndef PING_TIMEOUT
#   define PING_TIMEOUT 15000         // milliseconds before ping timeout
#endif

#ifndef KEY_EXCHANGE_PACKETS
#   define KEY_EXCHANGE_PACKETS 10000 // Number of packets before key exchange
#endif

#ifndef KEY_EXCHANGE_TIMEOUT
#   define KEY_EXCHANGE_TIMEOUT 600   // Ten minutes in seconds
#endif

#ifndef STATISTICS_UPDATE_FREQUENCY
#   define STATISTICS_UPDATE_FREQUENCY 100   // Once every 100 packets
#endif

#ifndef KEY_EXCHANGE_EARLY
#   define KEY_EXCHANGE_EARLY 1       // Make 0 if a "lazy" key exchange is desired
#endif

#ifndef KEY_REMEMBER_DYNAMIC
#   define KEY_REMEMBER_DYNAMIC 0     // Make 1 if we want to save dynamic keys
#endif

#ifndef DAEMON_SELECT_TIMEOUT
#   define DAEMON_SELECT_TIMEOUT 10000 // Ten second Select() timeout
#endif

#endif

//========================================================================================
//
//========================================================================================
#define TAP_CONTROL_CODE(request,method) CTL_CODE (FILE_DEVICE_PHYSICAL_NETCARD | 8000, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_GET_LASTMAC    TAP_CONTROL_CODE (0, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MAC        TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_SET_STATISTICS TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MTU        TAP_CONTROL_CODE (3, METHOD_BUFFERED)

//========================================================================================
//                                   Windows 2000 OID's
//========================================================================================
#ifndef OID_GEN_TRANSPORT_HEADER_OFFSET

#define	OID_GEN_SUPPORTED_GUIDS					0x00010117
#define	OID_GEN_NETWORK_LAYER_ADDRESSES			0x00010118	// Set only
#define OID_GEN_TRANSPORT_HEADER_OFFSET			0x00010119  // Set only

//
//	TCP/IP OIDs
//
#define	OID_TCP_TASK_OFFLOAD					0xFC010201
#define	OID_TCP_TASK_IPSEC_ADD_SA				0xFC010202
#define	OID_TCP_TASK_IPSEC_DELETE_SA			0xFC010203
#define OID_TCP_SAN_SUPPORT						0xFC010204

//
//	Defines for FFP
//
#define OID_FFP_SUPPORT							0xFC010210
#define	OID_FFP_FLUSH							0xFC010211
#define	OID_FFP_CONTROL							0xFC010212
#define	OID_FFP_PARAMS							0xFC010213
#define	OID_FFP_DATA							0xFC010214

#define	OID_FFP_DRIVER_STATS					0xFC020210
#define	OID_FFP_ADAPTER_STATS					0xFC020211

//
//	PnP and PM OIDs
//
#define	OID_PNP_CAPABILITIES					0xFD010100
#define	OID_PNP_SET_POWER						0xFD010101
#define	OID_PNP_QUERY_POWER						0xFD010102
#define OID_PNP_ADD_WAKE_UP_PATTERN				0xFD010103
#define OID_PNP_REMOVE_WAKE_UP_PATTERN			0xFD010104
#define	OID_PNP_WAKE_UP_PATTERN_LIST			0xFD010105
#define	OID_PNP_ENABLE_WAKE_UP					0xFD010106

#endif
//========================================================================================
//
//========================================================================================
#define DEFAULT_PACKET_LOOKAHEAD (ETHERNET_PACKET_SIZE - ETHERNET_HEADER_SIZE)
#define ETHERNET_PACKET_SIZE 1514
#define ETHERNET_HEADER_SIZE 14
#define MINIMUM_MTU 576 // USE TCP Minimum MTU

#define USERMODEDEVICEDIR "\\\\.\\"
#define SYSDEVICEDIR  "\\Device\\"
#define USERDEVICEDIR "\\??\\"
#define TAPSUFFIX     ".tap"

#define KEY_EXCHANGE_BUFFER_SIZE 64

#define UDP_DATAGRAM_BUFFER_SIZE 65536
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define BLOWFISH_DATA_SIZE 8      // Eight bytes (64 bit) datum
#define BLOWFISH_KEY_LENGTH 16    // Keys are 16 bytes long

#define NETCARD_REG_KEY_2000 "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETCARD_REG_KEY      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"
#define REG_SERVICE_KEY      "SYSTEM\\CurrentControlSet\\Services"

#define PACKET_QUEUE_SIZE   64
#define IRP_QUEUE_SIZE      64

//========================================================================================
//
//========================================================================================
typedef unsigned char UDPBUFFER [UDP_DATAGRAM_BUFFER_SIZE];
typedef unsigned char MACADDR [6];
typedef unsigned long IPADDR;

typedef enum
   {
    NK_KEY_EXCHANGE = 2,
    NK_DATA = 0,
    NK_REQ = 1,
    NK_IND = 2,
    NK_ACK = 3,
    CT_DUMMY = 0x70,
    CT_DEBUG = 0x71,
    CT_PING = 0x72,
    CT_PONG = 0x73,
    CT_KILL = 0x74
   }
NK_Type;

//========================================================================================
//
//========================================================================================
typedef struct
   {
    MACADDR        m_MAC_Destination;        // Reverse these two
    MACADDR        m_MAC_Source;             // to answer ARP requests
    unsigned short m_MAC_FrameType;          // 0x0806
    unsigned short m_MAC_AddressType;        // 0x0001
    unsigned short m_PROTO_AddressType;      // 0x0800
    unsigned char  m_MAC_AddressSize;        // 0x06
    unsigned char  m_PROTO_AddressSize;      // 0x04
    unsigned short m_MAC_Operation;          // 0x0001 for ARP request, 0x0002 for ARP reply
    MACADDR        m_ARP_MAC_Source;
    unsigned char  m_ARP_IP_Source [4];
    MACADDR        m_ARP_MAC_Destination;
    unsigned char  m_ARP_IP_Destination [4];
   }
ARP_PACKET, *PARP_PACKET;

//========================================================================================
//
//========================================================================================
#define MatchingMAC(a,b)  (memcmp (a, b, sizeof (MACADDR)) == 0)
#define MIN(a,b) (a > b ? b : a)
#define MAX(a,b) (a < b ? b : a)

#endif
