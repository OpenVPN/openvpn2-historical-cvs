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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "socket.h"
#include "fdmisc.h"
#include "thread.h"
#include "misc.h"
#include "io.h"

#include "memdbg.h"

/*
 * Functions used to check return status
 * of I/O operations.
 */

unsigned int x_cs_info_level;
unsigned int x_cs_verbose_level;

void
reset_check_status ()
{
  x_cs_info_level = 0;
  x_cs_verbose_level = 0;
}

void
set_check_status (unsigned int info_level, unsigned int verbose_level)
{
  x_cs_info_level = info_level;
  x_cs_verbose_level = verbose_level;
}

/*
 * Called after most socket operations, via the inline function check_status().
 * Decide if we should print an error message, and see if we can extract any useful
 * info from the error, such as a Path MTU hint from the OS.
 */
void
x_check_status (int status, const char *description, struct link_socket *sock)
{
  const int my_errno = openvpn_errno_socket ();
  const char *extended_msg = NULL;

  msg (x_cs_verbose_level, "%s returned %d", description, status);

  if (status < 0)
    {
#if EXTENDED_SOCKET_ERROR_CAPABILITY
      /* get extended socket error message and possible PMTU hint from OS */
      if (sock)
	{
	  int mtu;
	  extended_msg = format_extended_socket_error (sock->sd, &mtu);
	  if (mtu > 0 && sock->mtu != mtu)
	    {
	      sock->mtu = mtu;
	      sock->mtu_changed = true;
	    }
	}
#endif
      if (my_errno != EAGAIN)
	{
	  if (extended_msg)
	    msg (x_cs_info_level, "%s %s [%s]: %s",
		 description,
		 sock ? proto2ascii (sock->proto, true) : "",
		 extended_msg,
		 strerror_ts (my_errno));
	  else
	    msg (x_cs_info_level, "%s %s: %s",
		 description,
		 sock ? proto2ascii (sock->proto, true) : "",
		 strerror_ts (my_errno));
	}
    }
}

/*
 * Functions releated to the translation of DNS names to IP addresses.
 */

static const char*
h_errno_msg(int h_errno_err)
{
  switch (h_errno_err)
    {
    case HOST_NOT_FOUND:
      return "[HOST_NOT_FOUND] The specified host is unknown.";
    case NO_DATA:
      return "[NO_DATA] The requested name is valid but does not have an IP address.";
    case NO_RECOVERY:
      return "[NO_RECOVERY] A non-recoverable name server error occurred.";
    case TRY_AGAIN:
      return "[TRY_AGAIN] A temporary error occurred on an authoritative name server.";
    }
  return "[unknown h_errno value]";
}

/*
 * Translate IP addr or hostname to in_addr_t.
 * If resolve error, try again for
 * resolve_retry_seconds seconds.
 */
static in_addr_t
getaddr (const char *hostname, int resolve_retry_seconds)
{
  struct in_addr ia;
  const int status = inet_aton (hostname, &ia);

  if (!status)
    {
      const int fail_wait_interval = 5; /* seconds */
      int resolve_retries = resolve_retry_seconds / fail_wait_interval;

      /*
       * Resolve hostname
       */
      struct hostent *h;
      while ( !(h = gethostbyname (hostname)) )
	{
	  msg ((resolve_retries > 0  ? D_RESOLVE_ERRORS : M_FATAL),
	       "Cannot resolve host address: %s: %s",
	       hostname, h_errno_msg (h_errno));
	  sleep (fail_wait_interval);
	  --resolve_retries;
	}

      /* potentially more than one address returned, but we take first */
      ia.s_addr = *(in_addr_t *) (h->h_addr_list[0]);

      if (ia.s_addr)
	{
	  if (h->h_addr_list[1])
	    msg (M_WARN, "Warning: %s has multiple addresses", hostname);
	}
    }
  return ia.s_addr;
}

/*
 * Functions used for establishing a TCP stream connection.
 */

static int
socket_listen_accept (int sd,
		      struct sockaddr_in *remote,
		      const struct sockaddr_in *local)
{
  socklen_t remote_len = sizeof (*remote);
  const struct sockaddr_in remote_orig = *remote;
  int new_sd;

  msg (M_INFO, "Listening for incoming TCP connection on %s", 
       print_sockaddr (local));
  if (listen (sd, 1))
    msg (M_SOCKERR, "listen() failed");

  while (true)
    {
      new_sd = accept (sd, (struct sockaddr *) remote, &remote_len);
      if (new_sd == -1)
	msg (M_SOCKERR, "accept() failed");
      if (addr_defined (&remote_orig) && !addr_match (&remote_orig, remote))
	{
	  msg (M_WARN, "Rejected connection attempt from %s due to --remote setting",
	       print_sockaddr (remote));
	  if (openvpn_close_socket (new_sd))
	    msg (M_SOCKERR, "close socket failed (new_sd)");
	  sleep (1);
	}
      else
	break;
    }

  if (openvpn_close_socket (sd))
    msg (M_SOCKERR, "close socket failed (sd)");
  msg (M_INFO, "TCP connection established with %s", 
       print_sockaddr (remote));
  return new_sd;
}

static void
socket_connect (int sd,
		struct sockaddr_in *remote)
{
  const int try_again_seconds = 5;

  msg (M_INFO, "Attempting to establish TCP connection with %s", 
       print_sockaddr (remote));
  while (true)
    {
      if (connect (sd, (struct sockaddr *) remote, sizeof (*remote)))
	msg (D_LINK_ERRORS | M_ERRNO_SOCK, "connect() failed, will try again in %d seconds, error",
	     try_again_seconds);
      else
	break;
      sleep (try_again_seconds);
    }
  msg (M_INFO, "TCP connection established with %s", 
       print_sockaddr (remote));
}

/*
 * SOCKET INITALIZATION CODE.
 * Create a TCP/UDP socket
 */
void
link_socket_init (struct link_socket *sock,
		  const char *local_host,
		  const char *remote_host,
		  int proto,
		  int local_port,
		  int remote_port,
		  bool bind_local,
		  bool remote_float,
		  bool inetd,
		  struct link_socket_addr *lsa,
		  const char *ipchange_command,
		  int resolve_retry_seconds,
		  int mtu_discover_type)
{
  CLEAR (*sock);

  sock->remote_float = remote_float;
  sock->addr = lsa;
  sock->ipchange_command = ipchange_command;
  sock->proto = proto;

  /* bind behavior for TCP server vs. client */
  if (sock->proto == PROTO_TCPv4_SERVER)
    bind_local = true;
  else if (sock->proto == PROTO_TCPv4_CLIENT)
    bind_local = false;

  /* were we started by inetd or xinetd? */
  if (inetd)
    {
      ASSERT (inetd_socket_descriptor >= 0);
      sock->sd = inetd_socket_descriptor;
    }
  else
    {
      /* create socket */
      if (sock->proto == PROTO_UDPv4)
	{
	  if ((sock->sd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	    msg (M_SOCKERR, "Cannot create UDP socket");
	}
      else if (sock->proto == PROTO_TCPv4_SERVER
	       || sock->proto == PROTO_TCPv4_CLIENT)
	{
	  int on = 1;
	  if ((sock->sd = socket (PF_INET, SOCK_STREAM, 0)) < 0)
	    msg (M_SOCKERR, "Cannot create TCP socket");
	  if (setsockopt (sock->sd, SOL_SOCKET, SO_REUSEADDR,
			  (void *) &on, sizeof (on)) < 0)
	    msg (M_SOCKERR, "Cannot setsockopt on TCP socket");
	}
      else
	{
	  ASSERT (0);
	}
      
      /* resolve local address if undefined */
      if (!addr_defined (&lsa->local))
	{
	  lsa->local.sin_family = AF_INET;
	  lsa->local.sin_addr.s_addr =
	    (local_host ? getaddr (local_host, resolve_retry_seconds)
	     : htonl (INADDR_ANY));
	  lsa->local.sin_port = htons (local_port);
	}

      /* bind to local address/port */
      if (bind_local)
	{
	  if (bind (sock->sd, (struct sockaddr *) &lsa->local, sizeof (lsa->local)))
	    {
	      const int errnum = openvpn_errno_socket ();
	      msg (M_FATAL, "Socket bind failed on local address %s: %s",
		   print_sockaddr (&lsa->local),
		   strerror_ts (errnum));
	    }
	}

      /* resolve remote address if undefined */
      if (!addr_defined (&lsa->remote))
	{
	  lsa->remote.sin_family = AF_INET;
	  lsa->remote.sin_addr.s_addr =
	    (remote_host ? getaddr (remote_host, resolve_retry_seconds) : 0);
	  lsa->remote.sin_port = htons (remote_port);
	}

      /* should we re-use previous active remote address? */
      if (addr_defined (&lsa->actual))
	msg (M_INFO, "Preserving recently used remote address: %s",
	     print_sockaddr (&lsa->actual));
      else
	lsa->actual = lsa->remote;

      /* TCP client/server */
      if (sock->proto == PROTO_TCPv4_SERVER)
	sock->sd = socket_listen_accept (sock->sd, &lsa->actual, &lsa->local);
      else if (sock->proto == PROTO_TCPv4_CLIENT)
	socket_connect (sock->sd, &lsa->actual);
    }

  /* set socket to non-blocking mode */
  set_nonblock (sock->sd);

  /* set socket file descriptor to not pass across execs, so that
     scripts don't have access to it */
  set_cloexec (sock->sd);

  /* set Path MTU discovery options on the socket */
  set_mtu_discover_type (sock->sd, mtu_discover_type);

#if EXTENDED_SOCKET_ERROR_CAPABILITY
  /* if the OS supports it, enable extended error passing on the socket */
  set_sock_extended_error_passing (sock->sd);
#endif

  /* print local address */
  if (sock->sd == INETD_SOCKET_DESCRIPTOR)
    msg (M_INFO, "%s link local: [inetd]", proto2ascii (sock->proto, true));
  else
    msg (M_INFO, "%s link local%s: %s",
	 proto2ascii (sock->proto, true),
	 (bind_local ? " (bound)" : ""),
	 print_sockaddr_ex (&lsa->local, bind_local, ":"));

  /* print active remote address */
  msg (M_INFO, "%s link remote: %s",
       proto2ascii (sock->proto, true),
       print_sockaddr_ex (&lsa->actual, addr_defined (&lsa->actual), ":"));
}

/* for stream protocols, allow for packet length prefix */
void
socket_adjust_frame_parameters (struct frame *frame, struct link_socket *sock)
{
  if (link_socket_connection_oriented (sock))
    frame_add_to_extra_frame (frame, sizeof (packet_size_type));
}

/* For stream protocols, allocate a buffer to build up packet.
   Called after frame has been finalized. */

void
socket_frame_init (struct frame *frame, struct link_socket *sock)
{
#ifdef WIN32
  overlapped_io_init (&sock->reads, frame, FALSE, false);
  overlapped_io_init (&sock->writes, frame, TRUE, false);
#endif

  if (link_socket_connection_oriented (sock))
    {
#ifdef WIN32
      stream_buf_init (&sock->stream_buf, &sock->reads.buf_init);
#else
      alloc_buf_sock_tun (&sock->stream_buf_data, frame, false);
      stream_buf_init (&sock->stream_buf, &sock->stream_buf_data);
#endif
    }
}

void
link_socket_set_outgoing_addr (const struct buffer *buf,
			      struct link_socket *sock,
			      const struct sockaddr_in *addr)
{
  mutex_lock (L_SOCK);
  if (!buf || buf->len > 0)
    {
      struct link_socket_addr *lsa = sock->addr;
      ASSERT (addr_defined (addr));
      if ((sock->remote_float
	   || !addr_defined (&lsa->remote)
	   || addr_port_match (addr, &lsa->remote))
	  && (!addr_port_match (addr, &lsa->actual)
	      || !sock->set_outgoing_initial))
	{
	  lsa->actual = *addr;
	  sock->set_outgoing_initial = true;
	  mutex_unlock (L_SOCK);
	  msg (M_INFO, "Peer Connection Initiated with %s", print_sockaddr (&lsa->actual));
	  if (sock->ipchange_command)
	    {
	      char command[512];
	      struct buffer out;
	      buf_set_write (&out, (uint8_t *)command, sizeof (command));
	      buf_printf (&out, "%s %s",
			  sock->ipchange_command,
			  print_sockaddr_ex (&lsa->actual, true, " "));
	      msg (D_TLS_DEBUG, "executing ip-change command: %s", command);
	      system_check (command, "ip-change command failed", false);
	    }
	  mutex_lock (L_SOCK);
	}
    }
  mutex_unlock (L_SOCK);
}

void
link_socket_incoming_addr (struct buffer *buf,
			   const struct link_socket *sock,
			   const struct sockaddr_in *from_addr)
{
  mutex_lock (L_SOCK);
  if (buf->len > 0)
    {
      if (from_addr->sin_family != AF_INET)
	goto bad;
      if (!addr_defined (from_addr))
	goto bad;
      if (sock->remote_float || !addr_defined (&sock->addr->remote))
	goto good;

      if (link_socket_connection_oriented (sock))
	{
	  if (addr_match (from_addr, &sock->addr->remote))
	    goto good;
	}
      else
	{
	  if (addr_port_match (from_addr, &sock->addr->remote))
	    goto good;
	}
    }

bad:
  msg (D_LINK_ERRORS,
       "Incoming packet rejected from %s[%d], expected peer address: %s (allow this incoming source address/port by removing --remote or adding --float)",
       print_sockaddr (from_addr),
       (int)from_addr->sin_family,
       print_sockaddr (&sock->addr->remote));
  buf->len = 0;
  mutex_unlock (L_SOCK);
  return;

good:
  msg (D_READ_WRITE, "IP Address OK from %s",
       print_sockaddr (from_addr));
  mutex_unlock (L_SOCK);
  return;
}

void
link_socket_get_outgoing_addr (struct buffer *buf,
			      const struct link_socket *sock,
			      struct sockaddr_in *addr)
{
  mutex_lock (L_SOCK);
  if (buf->len > 0)
    {
      struct link_socket_addr *lsa = sock->addr;
      if (addr_defined (&lsa->actual))
	{
	  *addr = lsa->actual;
	}
      else
	{
	  msg (D_READ_WRITE, "No outgoing address to send packet");
	  buf->len = 0;
	}
    }
  mutex_unlock (L_SOCK);
}

void
link_socket_close (struct link_socket *sock)
{
  if (sock->sd >= 0 && sock->sd != INETD_SOCKET_DESCRIPTOR)
    {
#ifdef WIN32
      overlapped_io_close (&sock->reads);
      overlapped_io_close (&sock->writes);
#endif
      if (openvpn_close_socket (sock->sd))
	msg (M_WARN | M_ERRNO_SOCK, "Warning: Close Socket failed");
      sock->sd = -1;
    }
  stream_buf_close (&sock->stream_buf);
  free_buf (&sock->stream_buf_data);
}

/*
 * Stream buffer functions, used to packetize a TCP
 * stream connection.
 */

void
stream_buf_init (struct stream_buf *sb,
		 struct buffer *buf)
{
  sb->buf_init = *buf;
  sb->maxlen = sb->buf_init.len;
  sb->buf_init.len = 0;
  sb->residual = alloc_buf (sb->maxlen);
  stream_buf_reset (sb);

  msg (D_CO_DEBUG, "CO: INIT maxlen=%d", sb->maxlen);
}

void
stream_buf_close (struct stream_buf* sb)
{
  free_buf (&sb->residual);
}

bool
stream_buf_added (struct stream_buf *sb,
		  int length_added)
{
  msg (D_CO_DEBUG, "CO: ADD length_added=%d", length_added);
  if (length_added > 1)
    sb->buf.len += length_added;

  /* if length unknown, see if we can get the length prefix from
     the head of the buffer */
  if (sb->len < 0 && sb->buf.len >= (int) sizeof (packet_size_type))
    {
      packet_size_type net_size;
      ASSERT (buf_read (&sb->buf, &net_size, sizeof (net_size)));
      sb->len = ntohps (net_size);
      if (sb->len < 1 || sb->len > sb->maxlen)
	msg (M_FATAL, "Bad encapsulated packet length from peer (%d), which must be > 0 and <= %d -- please ensure that --link-mtu is equal on both peers -- this condition could also indicate a possible active attack on the TCP link", sb->len, sb->maxlen); /* it might be better behaviour to restart than crash at this point */
    }

  /* is our incoming packet fully read? */
  if (sb->len > 0 && sb->buf.len >= sb->len)
    {
      /* save any residual data that's part of the next packet */
      ASSERT (buf_init (&sb->residual, 0));
      if (sb->buf.len > sb->len)
	  ASSERT (buf_copy_excess (&sb->residual, &sb->buf, sb->len));
      msg (D_CO_DEBUG, "CO: ADD returned TRUE, buf_len=%d, residual_len=%d",
	   BLEN (&sb->buf),
	   BLEN (&sb->residual));
      return true;
    }
  else
    {
      stream_buf_set_next (sb);
      msg (D_CO_DEBUG, "CO: ADD returned FALSE");
      return false;
    }
}

/*
 * Format IP addresses in ascii
 */

const char *
print_sockaddr (const struct sockaddr_in *addr)
{
  return print_sockaddr_ex(addr, true, ":");
}

const char *
print_sockaddr_ex (const struct sockaddr_in *addr, bool do_port, const char* separator)
{
  struct buffer out = alloc_buf_gc (64);
  const int port = ntohs (addr->sin_port);

  mutex_lock (L_INET_NTOA);
  buf_printf (&out, "%s", (addr_defined (addr) ? inet_ntoa (addr->sin_addr) : "[local]"));
  mutex_unlock (L_INET_NTOA);

  if (do_port && port)
    {
      if (separator)
	buf_printf (&out, "%s", separator);

      buf_printf (&out, "%d", port);
    }
  return BSTR (&out);
}

/*
 * Convert protocol names between index and ascii form.
 */

struct proto_names {
  const char *short_form;
  const char *display_form;
};

/* Indexed by PROTO_x */
static const struct proto_names proto_names[] = {
  {"udp",        "UDPv4"},
  {"tcp-server", "TCPv4_SERVER"},
  {"tcp-client", "TCPv4_CLIENT"}
};

int
ascii2proto (const char* proto_name)
{
  int i;
  for (i = 0; i < PROTO_N; ++i)
    if (!strcmp (proto_name, proto_names[i].short_form))
      return i;
  return -1;
}

const char *
proto2ascii (int proto, bool display_form)
{
  if (proto < 0 || proto > PROTO_N)
    return "[unknown protocol]";
  else if (display_form)
    return proto_names[proto].display_form;
  else
    return proto_names[proto].short_form;
}

const char *
proto2ascii_all ()
{
  struct buffer out = alloc_buf_gc (256);
  int i;

  for (i = 0; i < PROTO_N; ++i)
    {
      if (i)
	buf_printf(&out, " ");
      buf_printf(&out, "[%s]", proto2ascii(i, false));
    }
  return BSTR (&out);
}

/*
 * Win32 overlapped socket I/O functions.
 */

#ifdef WIN32

int
socket_recv_queue (struct link_socket *sock, int maxsize)
{
  if (sock->reads.iostate == IOSTATE_INITIAL)
    {
      WSABUF wsabuf[1];
      int status;

      /* reset buf to its initial state */
      if (sock->proto == PROTO_UDPv4)
	{
	  sock->reads.buf = sock->reads.buf_init;
	}
      else if (sock->proto == PROTO_TCPv4_CLIENT || sock->proto == PROTO_TCPv4_SERVER)
	{
	  stream_buf_get_next (&sock->stream_buf, &sock->reads.buf);
	}
      else
	{
	  ASSERT (0);
	}

      /* Win32 docs say it's okay to allocate the wsabuf on the stack */
      wsabuf[0].buf = BPTR (&sock->reads.buf);
      wsabuf[0].len = maxsize ? maxsize : BLEN (&sock->reads.buf);
      ASSERT (wsabuf[0].len <= BLEN (&sock->reads.buf));

      /* the overlapped read will signal this event on I/O completion */
      ASSERT (ResetEvent (sock->reads.overlapped.hEvent));
      sock->reads.flags = 0;

      if (sock->proto == PROTO_UDPv4)
	{
	  sock->reads.addr_defined = true;
	  sock->reads.addrlen = sizeof (sock->reads.addr);
	  status = WSARecvFrom(
			       sock->sd,
			       wsabuf,
			       1,
			       &sock->reads.size,
			       &sock->reads.flags,
			       (struct sockaddr *) &sock->reads.addr,
			       &sock->reads.addrlen,
			       &sock->reads.overlapped,
			       NULL);
	}
      else if (sock->proto == PROTO_TCPv4_CLIENT || sock->proto == PROTO_TCPv4_SERVER)
	{
	  sock->reads.addr_defined = false;
	  status = WSARecv(
			   sock->sd,
			   wsabuf,
			   1,
			   &sock->reads.size,
			   &sock->reads.flags,
			   &sock->reads.overlapped,
			   NULL);
	}
      else
	{
	  status = 0;
	  ASSERT (0);
	}

      if (!status) /* operation completed immediately? */
	{
	  ASSERT (!sock->reads.addr_defined || sock->reads.addrlen == sizeof (sock->reads.addr));
	  sock->reads.iostate = IOSTATE_IMMEDIATE_RETURN;

	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (sock->reads.overlapped.hEvent));
	  sock->reads.status = 0;
	}
      else
	{
	  status = WSAGetLastError (); 
	  if (status == WSA_IO_PENDING) /* operation queued? */
	    {
	      sock->reads.iostate = IOSTATE_QUEUED;
	      sock->reads.status = status;
	    }
	  else /* error occurred */
	    {
	      ASSERT (SetEvent (sock->reads.overlapped.hEvent));
	      sock->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
	      sock->reads.status = status;
	    }
	}
    }
  return sock->reads.iostate;
}

int
socket_send_queue (struct link_socket *sock, struct buffer *buf, const struct sockaddr_in *to)
{
  if (sock->writes.iostate == IOSTATE_INITIAL)
    {
      WSABUF wsabuf[1];
      int status;
 
      /* make a private copy of buf */
      sock->writes.buf = sock->writes.buf_init;
      sock->writes.buf.len = 0;
      ASSERT (buf_copy (&sock->writes.buf, buf));

      /* Win32 docs say it's okay to allocate the wsabuf on the stack */
      wsabuf[0].buf = BPTR (&sock->writes.buf);
      wsabuf[0].len = BLEN (&sock->writes.buf);

      /* the overlapped write will signal this event on I/O completion */
      ASSERT (ResetEvent (sock->writes.overlapped.hEvent));
      sock->writes.flags = 0;

      if (sock->proto == PROTO_UDPv4)
	{
	  /* set destination address for UDP writes */
	  sock->writes.addr_defined = true;
	  sock->writes.addr = *to;
	  sock->writes.addrlen = sizeof (sock->writes.addr);

	  status = WSASendTo(
			       sock->sd,
			       wsabuf,
			       1,
			       &sock->writes.size,
			       sock->writes.flags,
			       (struct sockaddr *) &sock->writes.addr,
			       sock->writes.addrlen,
			       &sock->writes.overlapped,
			       NULL);
	}
      else if (sock->proto == PROTO_TCPv4_CLIENT || sock->proto == PROTO_TCPv4_SERVER)
	{
	  /* destination address for TCP writes was established on connection initiation */
	  sock->writes.addr_defined = false;

	  status = WSASend(
			   sock->sd,
			   wsabuf,
			   1,
			   &sock->writes.size,
			   sock->writes.flags,
			   &sock->writes.overlapped,
			   NULL);
	}
      else 
	{
	  status = 0;
	  ASSERT (0);
	}

      if (!status) /* operation completed immediately? */
	{
	  sock->writes.iostate = IOSTATE_IMMEDIATE_RETURN;

	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (sock->writes.overlapped.hEvent));

	  sock->writes.status = 0;
	}
      else
	{
	  status = WSAGetLastError (); 
	  if (status == WSA_IO_PENDING) /* operation queued? */
	    {
	      sock->writes.iostate = IOSTATE_QUEUED;
	      sock->writes.status = status;
	    }
	  else /* error occurred */
	    {
	      ASSERT (SetEvent (sock->writes.overlapped.hEvent));
	      sock->writes.iostate = IOSTATE_IMMEDIATE_RETURN;
	      sock->writes.status = status;
	    }
	}
    }
  return sock->writes.iostate;
}

int
socket_finalize (
		 SOCKET s,
		 struct overlapped_io *io,
		 struct buffer *buf,
		 struct sockaddr_in *from)
{
  int ret = -1;
  BOOL status;

  switch (io->iostate)
    {
    case IOSTATE_QUEUED:
      status = WSAGetOverlappedResult(
				      s,
				      &io->overlapped,
				      &io->size,
				      FALSE,
				      &io->flags
				      );
      if (status)
	{
	  /* successful return for a queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  io->iostate = IOSTATE_INITIAL;
	  ASSERT (ResetEvent (io->overlapped.hEvent));
	}
      else
	{
	  /* error during a queued operation */
	  ret = -1;
	  if (WSAGetLastError() != WSA_IO_INCOMPLETE)
	    {
	      /* if no error (i.e. just not finished yet), then DON'T execute this code */
	      io->iostate = IOSTATE_INITIAL;
	      ASSERT (ResetEvent (io->overlapped.hEvent));
	    }
	}
      break;

    case IOSTATE_IMMEDIATE_RETURN:
      ASSERT (ResetEvent (io->overlapped.hEvent));
      if (io->status)
	{
	  /* error return for a non-queued operation */
	  WSASetLastError (io->status);
	  ret = -1;
	}
      else
	{
	  /* successful return for a non-queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  io->iostate = IOSTATE_INITIAL;
	}
      break;

    case IOSTATE_INITIAL: /* were we called without proper queueing? */
      WSASetLastError (WSAEINVAL);
      ret = -1;
      break;

    default:
      ASSERT (0);
    }
  
  /* return from address if requested */
  if (from)
    {
      if (ret >= 0 && io->addr_defined)
	{
	  ASSERT (io->addrlen == sizeof (io->addr));
	  *from = io->addr;
	}
      else
	CLEAR (*from);
    }
  
  if (buf)
    buf->len = ret;
  return ret;
}

#endif /* WIN32 */
