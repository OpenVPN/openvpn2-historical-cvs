/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2004 James Yonan <jim@yonan.net>
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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#if P2MP

#include "mroute.h"
#include "proto.h"
#include "error.h"
#include "socket.h"

#include "memdbg.h"

static const uint8_t ethernet_bcast_addr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

bool
mroute_learnable_address (const struct mroute_addr *addr)
{
  int i;
  bool not_all_zeros = false;
  bool not_all_ones = false;

  for (i = 0; i < addr->len; ++i)
    {
      int b = addr->addr[i];
      if (b != 0x00)
	not_all_zeros = true;
      if (b != 0xFF)
	not_all_ones = true;
    }
  return not_all_zeros && not_all_ones;
}

unsigned int
mroute_extract_addr_from_packet (struct mroute_addr *src,
				 struct mroute_addr *dest,
				 const struct buffer *buf,
				 int tunnel_type)
{
  unsigned int ret = 0;
  if (tunnel_type == DEV_TYPE_TUN)
    {
      if (BLEN (buf) >= 1)
	{
	  switch (OPENVPN_IPH_GET_VER (*BPTR(buf)))
	    {
	    case 4:
	      if (BLEN (buf) >= (int) sizeof (struct openvpn_iphdr))
		{
		  const struct openvpn_iphdr *ip = (const struct openvpn_iphdr *) BPTR (buf);
		  if (src)
		    {
		      src->type = MR_ADDR_IPV4;
		      src->len = 4;
		      memcpy (src->addr, &ip->saddr, 4);
		    }
		  if (dest)
		    {
		      in_addr_t dest_addr;
		      dest->type = MR_ADDR_IPV4;
		      dest->len = 4;
		      memcpy (dest->addr, &ip->daddr, 4);
		      memcpy (&dest_addr, &ip->daddr, 4);

		      /* mcast address? */
		      if ((ntohl (dest_addr) & IP_MCAST_SUBNET_MASK) == (unsigned long) IP_MCAST_NETWORK)
			ret |= MROUTE_EXTRACT_MCAST;

		      /* IGMP message? */
		      if (ip->protocol == OPENVPN_IPPROTO_IGMP)
			ret |= MROUTE_EXTRACT_IGMP;
		    }
		  ret |= MROUTE_EXTRACT_SUCCEEDED;
		}
	      break;
	    case 6:
	      {
		msg (M_WARN, "Need IPv6 code in mroute_extract_addr_from_packet"); 
		break;
	      }
	    }
	}
    }
  else if (tunnel_type == DEV_TYPE_TAP)
    {
      if (BLEN (buf) >= (int) sizeof (struct openvpn_ethhdr))
	{
	  const struct openvpn_ethhdr *eth = (const struct openvpn_ethhdr *) BPTR (buf);
	  if (src)
	    {
	      src->type = MR_ADDR_ETHER;
	      src->len = 6;
	      memcpy (src->addr, eth->source, 6);
	    }
	  if (dest)
	    {
	      dest->type = MR_ADDR_ETHER;
	      dest->len = 6;
	      memcpy (dest->addr, eth->dest, 6);

	      /* broadcast packet? */
	      if (memcmp (eth->dest, ethernet_bcast_addr, 6) == 0)
		ret |= MROUTE_EXTRACT_BCAST;
	    }
	  
	  ret |= MROUTE_EXTRACT_SUCCEEDED;
	}
    }
  return ret;
}

bool
mroute_extract_sockaddr_in (struct mroute_addr *addr, const struct sockaddr_in *saddr, bool use_port)
{
  if (saddr->sin_family == AF_INET)
    {
      if (use_port)
	{
	  addr->type = MR_ADDR_IPV4 | MR_WITH_PORT;
	  addr->len = 6;
	  memcpy (addr->addr, &saddr->sin_addr.s_addr, 4);
	  memcpy (addr->addr + 4, &saddr->sin_port, 2);
	}
      else
	{
	  addr->type = MR_ADDR_IPV4;
	  addr->len = 4;
	  memcpy (addr->addr, &saddr->sin_addr.s_addr, 4);
	}
      return true;
    }
  return false;
}

uint32_t
mroute_addr_hash_function (const void *key, uint32_t iv)
{
  return hash_func (mroute_addr_hash_ptr ((const struct mroute_addr *) key),
		    mroute_addr_hash_len ((const struct mroute_addr *) key),
		    iv);
}

bool
mroute_addr_compare_function (const void *key1, const void *key2)
{
  return mroute_addr_equal ((const struct mroute_addr *) key1,
			    (const struct mroute_addr *) key2);
}

const char *
mroute_addr_print (const struct mroute_addr *ma, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (64, gc);
  bool with_port = false;
  struct mroute_addr maddr = *ma;

  // JYFIXME -- print addresses for all types
  switch (maddr.type)
    {
    case MR_ADDR_ETHER:
      buf_printf (&out, "%s", format_hex_ex (ma->addr, 6, 0, 1, ":", gc)); 
      break;
    case MR_ADDR_IPV4|MR_WITH_PORT:
      with_port = true;
    case MR_ADDR_IPV4:
      {
	struct buffer buf;
	in_addr_t addr;
	int port;
	bool status;
	buf_set_read (&buf, maddr.addr, maddr.len);
	addr = buf_read_u32 (&buf, &status);
	if (status)
	  buf_printf (&out, "%s", print_in_addr_t (addr, true, gc));
	if (with_port)
	  {
	    port = buf_read_u16 (&buf);
	    if (port >= 0)
	      buf_printf (&out, ":%d", port);
	  }
      }
      break;
    case MR_ADDR_IPV6:
      buf_printf (&out, "IPV6"); 
      break;
    case MR_ADDR_IPV6|MR_WITH_PORT:
      buf_printf (&out, "IPV6/PORT"); 
      break;
    default:
      buf_printf (&out, "UNKNOWN"); 
      break;
    }
  return BSTR (&out);
}

#else
static void dummy(void) {}
#endif /* P2MP */
