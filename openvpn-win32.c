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

/*
 * Win32-specific OpenVPN code, targetted at the mingw
 * development environment.
 */

#ifdef WIN32

#include "config-win32.h"

#include "syshead.h"
#include "openvpn-win32.h"
#include "error.h"

#include "memdbg.h"

static struct WSAData wsa_state;

void
init_win32 (void)
{
  if (WSAStartup(0x0101, &wsa_state))
    {
      msg (M_ERR, "WSAStartup failed");
    }
}

void
uninit_win32 (void)
{
  WSACleanup ();
}

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
  o->buf_init = alloc_buf (BUF_SIZE (frame));
  ASSERT (buf_init (&o->buf_init, EXTRA_FRAME (frame)));
  o->buf_init.len = tuntap_buffer ? MAX_RW_SIZE_TUN (frame) : MAX_RW_SIZE_LINK (frame);
  ASSERT (buf_safe (&o->buf_init, 0));
}

void
overlapped_io_close (struct overlapped_io *o)
{
  CloseHandle (o->overlapped.hEvent);
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
