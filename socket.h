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

#ifndef SOCKET_H
#define SOCKET_H

#include "buffer.h"
#include "common.h"
#include "error.h"
#include "mtu.h"

/* packet_size_type is used communicate packet size
   over the wire when stream oriented protocols are
   being used */
typedef uint16_t packet_size_type;

/* convert a packet_size_type from host to network order */
#define htonps(x) htons(x)

/* convert a packet_size_type from network to host order */
#define ntohps(x) ntohs(x)

/* persistant across SIGUSR1s */
struct link_socket_addr
{
  struct sockaddr_in local;
  struct sockaddr_in remote; /* initial remote */
  struct sockaddr_in actual; /* remote may change due to --float */
};

struct link_socket
{
  int sd;			/* file descriptor for socket */
  int proto;                    /* Protocol (PROTO_x defined below) */
  struct link_socket_addr *addr;

  bool remote_float;
  int mtu;                      /* OS discovered MTU, or 0 if unknown */
  int mtu_changed;              /* Set to true when mtu value is changed */
  bool set_outgoing_initial;
  const char *ipchange_command;

  /* for stream sockets */
  packet_size_type stream_len;
  int stream_len_size;
  int stream_len_max;
  struct buffer stream_buf_init;
  struct buffer stream_buf;
};

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
		  int mtu_discover_type);

void
socket_adjust_frame_parameters (struct frame *frame, struct link_socket *sock);

void
socket_frame_init (struct frame *frame, struct link_socket *sock);

bool
link_socket_read (struct link_socket *sock,
		  struct buffer *buf,
		  int maxsize,
		  struct sockaddr_in *from);

int
link_socket_write (struct link_socket *sock,
		   struct buffer *buf,
		   struct sockaddr_in *to);

void
link_socket_set_outgoing_addr (const struct buffer *buf,
			      struct link_socket *sock,
			      const struct sockaddr_in *addr);

void
link_socket_incoming_addr (struct buffer *buf,
			  const struct link_socket *sock,
			  const struct sockaddr_in *from_addr);


void
link_socket_get_outgoing_addr (struct buffer *buf,
			      const struct link_socket *sock,
			      struct sockaddr_in *addr);

void link_socket_close (struct link_socket *sock);

const char *
print_sockaddr_ex (const struct sockaddr_in *addr, bool do_port, const char* separator);

const char *
print_sockaddr (const struct sockaddr_in *addr);

/* protocol types */

#define PROTO_UDPv4        0
#define PROTO_TCPv4_SERVER 1
#define PROTO_TCPv4_CLIENT 2
#define PROTO_N            3

int
ascii2proto (const char* proto_name);

const char *
proto2ascii (int proto, bool display_form);

const char *
proto2ascii_all ();

/* adjustments based on protocol overhead */

/*
 * Delta between UDP datagram size and total IP packet size.
 */
#define IPv4_UDP_HEADER_SIZE              28
#define IPv4_TCP_HEADER_SIZE              40
#define IPv6_UDP_HEADER_SIZE              40

static const int proto_overhead[] = { /* indexed by PROTO_x */
  IPv4_UDP_HEADER_SIZE,
  IPv4_TCP_HEADER_SIZE,
  IPv4_TCP_HEADER_SIZE
};

static inline int
datagram_overhead (int proto)
{
  ASSERT (proto >= 0 && proto < PROTO_N);
  return proto_overhead [proto];
}

/*
 * Adjust frame structure based on a Path MTU value given
 * to us by the OS.
 */
static inline void
frame_adjust_path_mtu (struct frame *frame, int pmtu, int proto)
{
  frame_set_mtu_dynamic (frame, pmtu - datagram_overhead (proto));
  frame_dynamic_finalize (frame);
}

/*
 * Inline functions
 */

static inline bool
addr_defined (const struct sockaddr_in *addr)
{
  return addr->sin_addr.s_addr != 0;
}

static inline bool
addr_match (const struct sockaddr_in *a1, const struct sockaddr_in *a2)
{
  return a1->sin_addr.s_addr == a2->sin_addr.s_addr;
}

static inline bool
addr_port_match (const struct sockaddr_in *a1, const struct sockaddr_in *a2)
{
  return a1->sin_addr.s_addr == a2->sin_addr.s_addr && a1->sin_port == a2->sin_port;
}

static inline bool
socket_connection_reset()
{
  const int err = openvpn_errno_socket ();
  return err == ECONNRESET;
}

static inline bool
link_socket_connection_oriented (const struct link_socket *sock)
{
  return sock->proto == PROTO_TCPv4_SERVER || sock->proto == PROTO_TCPv4_CLIENT;
}

/*
 * Check status, usually after a socket read or write
 */

extern unsigned int x_cs_info_level;
extern unsigned int x_cs_verbose_level;

void reset_check_status (void);
void set_check_status (unsigned int info_level, unsigned int verbose_level);
void x_check_status (int status, const char *description, struct link_socket *sock);

static inline void
check_status (int status, const char *description, struct link_socket *sock)
{
  if (status < 0 || check_debug_level (x_cs_verbose_level))
    x_check_status (status, description, sock);
}

#endif /* SOCKET_H */
