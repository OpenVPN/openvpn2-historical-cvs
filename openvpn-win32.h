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

#ifdef WIN32
#ifndef OPENVPN_WIN32_H
#define OPENVPN_WIN32_H

#include "basic.h"
#include "mtu.h"
#include "buffer.h"

/*
 * Win32-specific OpenVPN code, targetted at the mingw
 * development environment.
 */

void init_win32 (void);
void uninit_win32 (void);

struct overlapped_io {
# define IOSTATE_INITIAL          0
# define IOSTATE_QUEUED           1
# define IOSTATE_IMMEDIATE_RETURN 2
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
			 BOOL event_state);

void overlapped_io_close (struct overlapped_io *o);

static inline bool
overlapped_io_active (struct overlapped_io *o)
{
  return o->iostate == IOSTATE_QUEUED || o->iostate == IOSTATE_IMMEDIATE_RETURN;
}

const char *
overlapped_io_state_ascii (const struct overlapped_io *o, const char* prefix);

#endif
#endif
