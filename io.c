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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "io.h"

#include "memdbg.h"

/* allocate a buffer for socket or tun layer */
void
alloc_buf_sock_tun (struct buffer *buf, const struct frame *frame, bool tuntap_buffer)
{
  /* allocate buffer for overlapped I/O */
  *buf = alloc_buf (BUF_SIZE (frame));
  ASSERT (buf_init (buf, EXTRA_FRAME (frame)));
  buf->len = tuntap_buffer ? MAX_RW_SIZE_TUN (frame) : MAX_RW_SIZE_LINK (frame);
  ASSERT (buf_safe (buf, 0));
}

#ifdef WIN32

void
overlapped_io_init (struct overlapped_io *o,
		    const struct frame *frame,
		    BOOL event_state,
		    bool tuntap_buffer) /* if true: tuntap buffer, if false: socket buffer */
{
  CLEAR (*o);

  /* manual reset event, initially set according to event_state */
  o->overlapped.hEvent = CreateEvent (NULL, TRUE, event_state, NULL);
  if (o->overlapped.hEvent == NULL)
    msg (M_ERR, "CreateEvent failed");

  /* allocate buffer for overlapped I/O */
  alloc_buf_sock_tun (&o->buf_init, frame, tuntap_buffer);
}

void
overlapped_io_close (struct overlapped_io *o)
{
  if (!CloseHandle (o->overlapped.hEvent))
    msg (M_WARN | M_ERRNO, "Warning: CloseHandle failed on overlapped I/O event object");
  free_buf (&o->buf_init);
}

const char *
overlapped_io_state_ascii (const struct overlapped_io *o, const char* prefix)
{
  struct buffer out = alloc_buf_gc (16);
  buf_printf (&out, "%s", prefix);
  switch (o->iostate)
    {
    case IOSTATE_INITIAL:
      buf_printf (&out, "0");
      break;
    case IOSTATE_QUEUED:
      buf_printf (&out, "Q");
      break;
    case IOSTATE_IMMEDIATE_RETURN:
      buf_printf (&out, "R");
      break;
    }
  return BSTR (&out);
}

#endif
