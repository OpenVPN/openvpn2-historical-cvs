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

/*
 * I/O functionality used by both the sockets and TUN/TAP I/O layers.
 *
 * We also try to abstract away the differences between Posix and Win32.
 */

#ifndef OPENVPN_IO_H
#define OPENVPN_IO_H

#include "common.h"
#include "integer.h"
#include "error.h"
#include "basic.h"
#include "mtu.h"
#include "buffer.h"
#include "event.h"

/* allocate a buffer for socket or tun layer */
void alloc_buf_sock_tun (struct buffer *buf, const struct frame *frame, bool tuntap_buffer);

#ifdef WIN32

/*
 * Use keyboard input or events
 * to simulate incoming signals
 */

#define SIGUSR1   1
#define SIGUSR2   2
#define SIGHUP    3
#define SIGTERM   4
#define SIGINT    5

/*
 * If we are being run as a win32 service,
 * use this event as our exit trigger.
 */
#define EXIT_EVENT_NAME PACKAGE "_exit"

struct win32_signal {
  /*
   * service is true if we are being run as a win32 service.
   * if service == true, in is an event handle which will be
   *   signaled when we should exit.
   * if service == false, in is a keyboard handle which we will
   *   use as a source of asynchronous signals.
   */
  bool service;
  struct rw_handle in;
};

extern struct win32_signal win32_signal; /* static/global */

void win32_signal_init (void); 
void win32_signal_close (void);
int win32_signal_get (struct win32_signal *ws);
void win32_pause (void);

static inline void
wait_signal (struct event_set *es, void *arg)
{
  if (win32_signal.in.read != INVALID_HANDLE_VALUE)
    event_ctl (es, &win32_signal.in, EVENT_READ, arg);
}

static inline void
get_signal (volatile int *sig)
{
  *sig = win32_signal_get (&win32_signal);
}

/*
 * Set the text on the window title bar
 */
void generate_window_title (const char *title);
void save_window_title ();
void restore_window_title ();

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

char *overlapped_io_state_ascii (const struct overlapped_io *o);

/*
 * Use to control access to resources that only one
 * OpenVPN process on a given machine can access at
 * a given time.
 */

struct semaphore
{
  const char *name;
  bool locked;
  HANDLE hand;
};

void semaphore_clear (struct semaphore *s);
void semaphore_open (struct semaphore *s, const char *name);
bool semaphore_lock (struct semaphore *s, int timeout_milliseconds);
void semaphore_release (struct semaphore *s);
void semaphore_close (struct semaphore *s);

/*
 * Special global semaphore used to protect network
 * shell commands from simultaneous instantiation.
 *
 * Not kidding -- you can't run more than one instance
 * of netsh on the same machine at the same time.
 */

extern struct semaphore netcmd_semaphore;
void netcmd_semaphore_init (void);
void netcmd_semaphore_close (void);
void netcmd_semaphore_lock (void);
void netcmd_semaphore_release (void);

char *getpass (const char *prompt);

#else /* posix */

static inline void
wait_signal (struct event_set *es, void *arg)
{
}

static inline void
get_signal (volatile int *sig)
{
}

#endif
#endif
