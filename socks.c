/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

/*
 * 2004-01-30: Added Socks5 proxy support
 *   (Christof Meerwald, http://cmeerw.org)
 *
 * see RFC 1928, only supports "no authentication"
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "common.h"
#include "buffer.h"
#include "misc.h"
#include "io.h"
#include "socket.h"
#include "fdmisc.h"
#include "proxy.h"

#include "memdbg.h"


void socks_adjust_frame_parameters (struct frame *frame, int proto)
{
  if (proto == PROTO_UDPv4)
    frame_add_to_extra_buffer (frame, 10);
}

void
init_socks_proxy (struct socks_proxy_info *p,
		  const char *server,
		  int port,
		  bool retry)
{
  CLEAR (*p);
  ASSERT (server);
  ASSERT (legal_ipv4_port (port));

  strncpynt (p->server, server, sizeof (p->server));
  p->port = port;
  p->retry = retry;
  p->defined = true;
}

static bool
socks_handshake (socket_descriptor_t sd, volatile int *signal_received)
{
  char buf[2];
  int len = 0;
  const int timeout_sec = 5;

  /* VER = 5, NMETHODS = 1, METHODS = [0] */
  const ssize_t size = send (sd, "\x05\x01\x00", 3, MSG_NOSIGNAL);
  if (size != 3)
    {
      msg (D_LINK_ERRORS | M_ERRNO_SOCK, "TCP port write failed on send()");
      return false;
    }

  while (len < 2)
    {
      int status;
      ssize_t size;
      fd_set reads;
      struct timeval tv;
      char c;

      FD_ZERO (&reads);
      FD_SET (sd, &reads);
      tv.tv_sec = timeout_sec;
      tv.tv_usec = 0;

      status = select (sd + 1, &reads, NULL, NULL, &tv);

      GET_SIGNAL (*signal_received);
      if (*signal_received)
	return false;

      /* timeout? */
      if (status == 0)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "TCP port read timeout expired");
	  return false;
	}

      /* error */
      if (status < 0)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "TCP port read failed on select()");
	  return false;
	}

      /* read single char */
      size = recv(sd, &c, 1, MSG_NOSIGNAL);

      /* error? */
      if (size != 1)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "TCP port read failed on recv()");
	  return false;
	}

      /* store char in buffer */
      buf[len++] = c;
    }

  /* VER == 5 && METHOD == 0 */
  if (buf[0] != '\x05' || buf[1] != '\x00')
    {
      msg (D_LINK_ERRORS, "Socks proxy returned bad status");
      return false;
    }

  return true;
}

static bool
recv_socks_reply (socket_descriptor_t sd, struct sockaddr_in *addr,
		  volatile int *signal_received)
{
  char atyp = '\0';
  int alen = 0;
  int len = 0;
  char buf[22];
  const int timeout_sec = 5;

  if (addr != NULL)
    {
      addr->sin_family = AF_INET;
      addr->sin_addr.s_addr = htonl (INADDR_ANY);
      addr->sin_port = htons (0);
    }

  while (len < 4 + alen + 2)
    {
      int status;
      ssize_t size;
      fd_set reads;
      struct timeval tv;
      char c;

      FD_ZERO (&reads);
      FD_SET (sd, &reads);
      tv.tv_sec = timeout_sec;
      tv.tv_usec = 0;

      status = select (sd + 1, &reads, NULL, NULL, &tv);

      GET_SIGNAL (*signal_received);
      if (*signal_received)
	return false;

      /* timeout? */
      if (status == 0)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "TCP port read timeout expired");
	  return false;
	}

      /* error */
      if (status < 0)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "TCP port read failed on select()");
	  return false;
	}

      /* read single char */
      size = recv(sd, &c, 1, MSG_NOSIGNAL);

      /* error? */
      if (size != 1)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "TCP port read failed on recv()");
	  return false;
	}

      if (len == 3)
	atyp = c;

      if (len == 4)
	{
	  switch (atyp)
	    {
	    case '\x01':	/* IP V4 */
	      alen = 4;
	      break;

	    case '\x03':	/* DOMAINNAME */
	      alen = (unsigned char) c;
	      break;

	    case '\x04':	/* IP V6 */
	      alen = 16;
	      break;

	    default:
	      msg (D_LINK_ERRORS, "Socks proxy returned bad address type");
	      return false;
	    }
	}

      /* store char in buffer */
      if (len < (int)sizeof(buf))
	buf[len] = c;
      ++len;
    }

  /* VER == 5 && REP == 0 (succeeded) */
  if (buf[0] != '\x05' || buf[1] != '\x00')
    {
      msg (D_LINK_ERRORS, "Socks proxy returned bad reply");
      return false;
    }

  /* ATYP == 1 (IP V4 address) */
  if (atyp == '\x01' && addr != NULL)
    {
      memcpy (&addr->sin_addr, buf + 4, sizeof (addr->sin_addr));
      memcpy (&addr->sin_port, buf + 8, sizeof (addr->sin_port));
    }


  return true;
}

void
establish_socks_proxy_passthru (struct socks_proxy_info *p,
			        socket_descriptor_t sd, /* already open to proxy */
			        const char *host,       /* openvpn server remote */
			        const int port,         /* openvpn server port */
			        volatile int *signal_received)
{
  char buf[128];
  size_t len;

  if (!socks_handshake (sd, signal_received))
    goto error;

  /* format Socks CONNECT message */
  buf[0] = '\x05';		/* VER = 5 */
  buf[1] = '\x01';		/* CMD = 1 (CONNECT) */
  buf[2] = '\x00';		/* RSV */
  buf[3] = '\x03';		/* ATYP = 3 (DOMAINNAME) */

  len = strlen(host);
  len = (5 + len + 2 > sizeof(buf)) ? (sizeof(buf) - 5 - 2) : len;

  buf[4] = (char) len;
  memcpy(buf + 5, host, len);

  buf[5 + len] = (char) (port >> 8);
  buf[5 + len + 1] = (char) (port & 0xff);

  {
    const ssize_t size = send (sd, buf, 5 + len + 2, MSG_NOSIGNAL);
    if ((int)size != 5 + (int)len + 2)
      {
	msg (D_LINK_ERRORS | M_ERRNO_SOCK, "TCP port write failed on send()");
	goto error;
      }
  }

  /* receive reply from Socks proxy and discard */
  if (!recv_socks_reply (sd, NULL, signal_received))
    goto error;

  return;

 error:
  /* on error, should we exit or restart? */
  if (!*signal_received)
    *signal_received = (p->retry ? SIGUSR1 : SIGTERM);
  return;
}

void
establish_socks_proxy_udpassoc (struct socks_proxy_info *p,
			        socket_descriptor_t ctrl_sd, /* already open to proxy */
				socket_descriptor_t udp_sd,
				struct sockaddr_in *relay_addr,
			        volatile int *signal_received)
{
  if (!socks_handshake (ctrl_sd, signal_received))
    goto error;

  {
    /* send Socks UDP ASSOCIATE message */
    /* VER = 5, CMD = 3 (UDP ASSOCIATE), RSV = 0, ATYP = 1 (IP V4),
       BND.ADDR = 0, BND.PORT = 0 */
    const ssize_t size = send (ctrl_sd,
			       "\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00",
			       10, MSG_NOSIGNAL);
    if (size != 10)
      {
	msg (D_LINK_ERRORS | M_ERRNO_SOCK, "TCP port write failed on send()");
	goto error;
      }
  }

  /* receive reply from Socks proxy */
  CLEAR (*relay_addr);
  if (!recv_socks_reply (ctrl_sd, relay_addr, signal_received))
    goto error;

  return;

 error:
  /* on error, should we exit or restart? */
  if (!*signal_received)
    *signal_received = (p->retry ? SIGUSR1 : SIGTERM);
  return;
}
