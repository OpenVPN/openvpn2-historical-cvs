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

#if P2MP

#include "buffer.h"
#include "mcast.h"

#include "memdbg.h"

struct mcast_set *
mcast_init (void)
{
  struct mcast_set *ret;
  ALLOC_OBJ (ret, struct mcast_set);
  ret->buf = NULL;
  return ret;
}

void
mcast_free (struct mcast_set *ms)
{
  if (ms->buf)
    mcast_free_buf (ms->buf);
  free (ms);
}

struct mcast_buffer *
mcast_alloc_buf (const struct buffer *buf)
{
  struct mcast_buffer *ret;
  ALLOC_OBJ (ret, struct mcast_buffer);
  ret->buf = clone_buf (buf);
  ret->refcount = 1;
  return ret;
}

void
mcast_free_buf (struct mcast_buffer *mb)
{
  if (--mb->refcount <= 0)
    {
      free_buf (&mb->buf);
      free (mb);
    }
}

bool
mcast_add_buf (struct mcast_set *ms, struct mcast_buffer* mb)
{
  if (ms->buf)
    {
      return false;
    }
  else
    {
      ms->buf = mb;
      ++mb->refcount;
      return true;
    }
}

struct mcast_buffer *
mcast_extract_buf (struct mcast_set *ms)
{
  struct mcast_buffer *ret = NULL;
  if (ms->buf)
    {
      ret = ms->buf;
      ms->buf = NULL;
    }
  return ret;
}

#else
static void dummy(void) {}
#endif /* P2MP */
