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
 * I/O functionality used by both the sockets and TUN/TAP I/O layers.
 *
 * We also try to abstract away the differences between Posix and Win32
 * for the benefit of openvpn.c.
 */

#ifndef OPENVPN_IO_H
#define OPENVPN_IO_H

#include "common.h"
#include "error.h"
#include "basic.h"
#include "mtu.h"
#include "buffer.h"

/* allocate a buffer for socket or tun layer */
void alloc_buf_sock_tun (struct buffer *buf, const struct frame *frame, bool tuntap_buffer);

#ifdef WIN32

/* 
 * We try to do all Win32 I/O using overlapped
 * (i.e. asynchronous) I/O for a performance win.
 */
struct overlapped_io {
# define IOSTATE_INITIAL          0
# define IOSTATE_QUEUED           1 /* overlapped I/O has been queued */
# define IOSTATE_IMMEDIATE_RETURN 2 /* I/O function returned immediately without queueing */
  int iostate;
  OVERLAPPED overlapped;
  DWORD size;
  DWORD flags;
  int status;
  bool addr_defined;
  struct sockaddr_in addr;
  int addrlen;
  struct buffer buf_init;
  struct buffer buf;
};

void overlapped_io_init (struct overlapped_io *o,
			 const struct frame *frame,
			 BOOL event_state,
			 bool tuntap_buffer);

void overlapped_io_close (struct overlapped_io *o);

static inline bool
overlapped_io_active (struct overlapped_io *o)
{
  return o->iostate == IOSTATE_QUEUED || o->iostate == IOSTATE_IMMEDIATE_RETURN;
}

const char *
overlapped_io_state_ascii (const struct overlapped_io *o, const char* prefix);

/*
 * On Win32, use WSAWaitForMultipleEvents instead of select as our main event
 * loop I/O wait mechanism.  This is done for efficiency and also for the simple
 * reason that Win32 select() can only wait on sockets, not on the TAP-Win32 file
 * handle.
 */

#define MAX_EVENTS 4

struct event_wait {
  HANDLE events[4];
  DWORD n_events;
  HANDLE trigger;  /* handle that satisfied the most recent wait */
};

#define SELECT() my_select (&event_wait, tv)

static inline int
my_select (struct event_wait *ew, const struct timeval *tv)
{
#if 0
  {
    int i;
    msg (D_SELECT, "WSAWaitForMultipleEvents n=%d", (int) ew->n_events);
    for (i = 0; i < ew->n_events; ++i)
      msg (D_SELECT, "WSAWaitForMultipleEvents [%d] 0x%08x state=%d",
	   i, (unsigned int) ew->events[i], (int) WaitForSingleObject (ew->events[i], 0));
  }
#endif

  const DWORD status = WSAWaitForMultipleEvents(
    ew->n_events,
    ew->events,
    FALSE,
    tv ? (DWORD) (tv->tv_sec * 1000 + tv->tv_usec / 1000) : WSA_INFINITE,
    FALSE);

  if (status >= WSA_WAIT_EVENT_0 && status < WSA_WAIT_EVENT_0 + ew->n_events)
    {
      const int n = status - WSA_WAIT_EVENT_0;
      ew->trigger = ew->events [n];
      return n + 1;
    }
  else if (status == WSA_WAIT_TIMEOUT)
    return 0;
  else
    return -1;
}

static inline void
wait_init (struct event_wait *ew)
{
  CLEAR (*ew);
}

static inline void
wait_reset (struct event_wait *ew)
{
  ew->n_events = 0;
  ew->trigger = NULL;
}

static inline void
wait_add (struct event_wait *ew, HANDLE h)
{
  ASSERT (ew->n_events < MAX_EVENTS);
  ew->events[ew->n_events++] = h;
}

static inline bool
wait_trigger (const struct event_wait *ew, HANDLE h)
{
  return ew->trigger == h;
}

#else /* Posix stuff here */

struct event_wait {
  int max_fd_plus_one;
  fd_set reads, writes;
};

#define SELECT() select (event_wait.max_fd_plus_one, &event_wait.reads, &event_wait.writes, NULL, tv)

static inline void
wait_init (struct event_wait *ew)
{
  ew->max_fd_plus_one = -1;
}

static inline void
wait_reset (struct event_wait *ew)
{
  FD_ZERO (&ew->reads);
  FD_ZERO (&ew->writes);
}

static inline void
wait_update_maxfd (struct event_wait *ew, int fd)
{
  ew->max_fd_plus_one = max_int (ew->max_fd_plus_one, fd + 1);
}

#endif /* WIN32 */

#endif
