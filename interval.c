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

#include "interval.h"
#include "misc.h"

#include "memdbg.h"

/* 
 * Return a numerical string describing a struct timeval.
 */
const char *
tv_string (const struct timeval *tv, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (64, gc);
  buf_printf (&out, "[%d/%d]",
	      (int) tv->tv_sec,
	      (int )tv->tv_usec);
  return BSTR (&out);
}

/* 
 * Return an ascii string describing an absolute
 * date/time in a struct timeval.
 * 
 */
const char *
tv_string_abs (const struct timeval *tv, struct gc_arena *gc)
{
  return time_string ((time_t) tv->tv_sec,
		      (int) tv->tv_usec,
		      true,
		      gc);
}
