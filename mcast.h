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

#ifndef MCAST_H
#define MCAST_H

/*
 * Handle both multicast and broadcast functions.
 */

#if P2MP

/* define this to enable special test mode */
/*#define MCAST_TEST*/

#include "basic.h"
#include "buffer.h"

struct mcast_buffer
{
  struct buffer buf;
  int refcount;
};

struct mcast_set
{
  struct mcast_buffer *buf;
};

struct mcast_set *mcast_init (void);
void mcast_free (struct mcast_set *ms);

struct mcast_buffer *mcast_alloc_buf (const struct buffer *buf);
void mcast_free_buf (struct mcast_buffer *mb);

bool mcast_add_buf (struct mcast_set *ms, struct mcast_buffer* mb);
struct mcast_buffer *mcast_extract_buf (struct mcast_set *ms);

static inline bool
mcast_defined (const struct mcast_set *ms)
{
  return ms && ms->buf;
}

#endif
#endif
