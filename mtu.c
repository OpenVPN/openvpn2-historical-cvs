/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2003 James Yonan <jim@yonan.net>
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

#include "config.h"

#include "syshead.h"

#include "buffer.h"
#include "mtu.h"
#include "error.h"

#include "memdbg.h"

#define MTUDISC_NOT_SUPPORTED_MSG "--mtu-disc is not supported on this OS"

void
set_mtu_discover_type (int sd, int mtu_type)
{
  if (mtu_type >= 0)
    {
#if defined(HAVE_SETSOCKOPT) && defined(SOL_IP) && defined(IP_MTU_DISCOVER)
      if (setsockopt
	  (sd, SOL_IP, IP_MTU_DISCOVER, &mtu_type, sizeof (mtu_type)))
	msg (M_ERR, "Error setting IP_MTU_DISCOVER type=%d on UDP socket",
	     mtu_type);
#else
      msg (M_FATAL, MTUDISC_NOT_SUPPORTED_MSG);
#endif
    }
}

int
translate_mtu_discover_type_name (const char *name)
{
#if defined(IP_PMTUDISC_DONT) && defined(IP_PMTUDISC_WANT) && defined(IP_PMTUDISC_DO)
  if (!strcmp (name, "yes"))
    return IP_PMTUDISC_DO;
  if (!strcmp (name, "maybe"))
    return IP_PMTUDISC_WANT;
  if (!strcmp (name, "no"))
    return IP_PMTUDISC_DONT;
  msg (M_FATAL,
       "invalid --mtu-disc type: '%s' -- valid types are 'yes', 'maybe', or 'no'",
       name);
#else
  msg (M_FATAL, MTUDISC_NOT_SUPPORTED_MSG);
#endif
  return -1;			/* NOTREACHED */
}

/*
 *
 * The following code is adapted from tracepath
 * by Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>.
 */

#include <linux/types.h>
#include <linux/errqueue.h>

struct probehdr
{
	__u32 ttl;
	struct timeval tv;
};

void
set_sock_extended_error_passing (int sd)
{
  int on = 1;
  if (setsockopt (sd, SOL_IP, IP_RECVERR, &on, sizeof (on)))
    msg (M_WARN | M_ERRNO,
	 "Note: enable extended error passing on UDP socket failed (IP_RECVERR)");
  if (setsockopt (sd, SOL_IP, IP_TTL, &on, sizeof (on)))
    msg (M_WARN | M_ERRNO,
	 "Note: enable extended error passing on UDP socket failed (IP_TTL)");
}

void
print_extended_socket_error(int sd)
{
  struct buffer out = alloc_buf_gc (512);
  format_extended_socket_error (sd, 1, &out);
  msg (M_WARN, "Extended socket error: %s", out.data);
}

int
format_extended_socket_error (int fd, int ttl, struct buffer *out)
{
  int res;
  struct probehdr rcvbuf;
  char cbuf[512];
  struct iovec iov;
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct sock_extended_err *e;
  struct sockaddr_in addr;
  struct timeval tv;
  struct timeval *rettv;
  int slot= 0;
  int rethops = 0;
  int sndhops = 0;
  int progress = -1;
  int broken_router;
  int mtu = 65535;
  int hops_to = -1;
  int hops_from = -1;
  int no_resolve = 0;

restart:
  memset (&rcvbuf, -1, sizeof (rcvbuf));
  iov.iov_base = &rcvbuf;
  iov.iov_len = sizeof (rcvbuf);
  msg.msg_name = (__u8 *) & addr;
  msg.msg_namelen = sizeof (addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof (cbuf);

  gettimeofday (&tv, NULL);
  res = recvmsg (fd, &msg, MSG_ERRQUEUE);
  if (res < 0)
    {
      if (errno == EAGAIN)
	return progress;
      goto restart;
    }

  progress = mtu;

  rethops = -1;
  sndhops = -1;
  e = NULL;
  rettv = NULL;
#if 0
  slot = ntohs (addr.sin_port) - base_port;
  if (slot >= 0 && slot < 63 && his[slot].hops)
    {
      sndhops = his[slot].hops;
      rettv = &his[slot].sendtime;
      his[slot].hops = 0;
    }
#endif
  broken_router = 0;
  if (res == sizeof (rcvbuf))
    {
      if (rcvbuf.ttl == 0 || rcvbuf.tv.tv_sec == 0)
	{
	  broken_router = 1;
	}
      else
	{
	  sndhops = rcvbuf.ttl;
	  rettv = &rcvbuf.tv;
	}
    }

  for (cmsg = CMSG_FIRSTHDR (&msg); cmsg; cmsg = CMSG_NXTHDR (&msg, cmsg))
    {
      if (cmsg->cmsg_level == SOL_IP)
	{
	  if (cmsg->cmsg_type == IP_RECVERR)
	    {
	      e = (struct sock_extended_err *) CMSG_DATA (cmsg);
	    }
	  else if (cmsg->cmsg_type == IP_TTL)
	    {
	      rethops = *(int *) CMSG_DATA (cmsg);
	    }
	  else
	    {
	      buf_printf (out ,"cmsg:%d\n ", cmsg->cmsg_type);
	    }
	}
    }
  if (e == NULL)
    {
      buf_printf (out, "no info\n");
      return 0;
    }
  if (e->ee_origin == SO_EE_ORIGIN_LOCAL)
    {
      buf_printf (out, "%2d?: %-15s ", ttl, "[LOCALHOST]");
    }
  else if (e->ee_origin == SO_EE_ORIGIN_ICMP)
    {
      char abuf[128];
      struct sockaddr_in *sin = (struct sockaddr_in *) (e + 1);

      inet_ntop (AF_INET, &sin->sin_addr, abuf, sizeof (abuf));

      if (sndhops > 0)
	buf_printf (out, "%2d:  ", sndhops);
      else
	buf_printf (out, "%2d?: ", ttl);

      if (!no_resolve)
	{
	  char fabuf[256];
	  struct hostent *h;
	  fflush (stdout);
	  h =
	    gethostbyaddr ((char *) &sin->sin_addr, sizeof (sin->sin_addr),
			   AF_INET);
	  snprintf (fabuf, sizeof (fabuf), "%s (%s)", h ? h->h_name : abuf,
		    abuf);
	  buf_printf (out, "%-52s ", fabuf);
	}
      else
	{
	  buf_printf (out, "%-15s ", abuf);
	}
    }

  if (rethops >= 0)
    {
      if (rethops <= 64)
	rethops = 65 - rethops;
      else if (rethops <= 128)
	rethops = 129 - rethops;
      else
	rethops = 256 - rethops;
      if (sndhops >= 0 && rethops != sndhops)
	buf_printf (out, "asymm %2d ", rethops);
      else if (sndhops < 0 && rethops != ttl)
	buf_printf (out, "asymm %2d ", rethops);
    }

  if (rettv)
    {
      int diff =
	(tv.tv_sec - rettv->tv_sec) * 1000000 + (tv.tv_usec - rettv->tv_usec);
      buf_printf (out, "%3d.%03dms ", diff / 1000, diff % 1000);
      if (broken_router)
	buf_printf (out, "(This broken router returned corrupted payload) ");
    }

  switch (e->ee_errno)
    {
    case ETIMEDOUT:
      buf_printf (out, "\n");
      break;
    case EMSGSIZE:
      buf_printf (out, "pmtu %d\n", e->ee_info);
      mtu = e->ee_info;
      progress = mtu;
      break;
    case ECONNREFUSED:
      buf_printf (out, "reached\n");
      hops_to = sndhops < 0 ? ttl : sndhops;
      hops_from = rethops;
      return 0;
    case EPROTO:
      buf_printf (out, "!P\n");
      return 0;
    case EHOSTUNREACH:
      if (e->ee_origin == SO_EE_ORIGIN_ICMP &&
	  e->ee_type == 11 && e->ee_code == 0)
	{
	  buf_printf (out, "\n");
	  break;
	}
      buf_printf (out, "!H\n");
      return 0;
    case ENETUNREACH:
      buf_printf (out, "!N\n");
      return 0;
    case EACCES:
      buf_printf (out, "!A\n");
      return 0;
    default:
      buf_printf (out, "NET ERROR\n");
      errno = e->ee_errno;
      return 0;
    }
  goto restart;
}
