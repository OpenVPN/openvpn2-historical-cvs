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

#ifndef MBUF_H
#define MBUF_H

/*
 * Handle both multicast and broadcast functions.
 */

#if P2MP

/* define this to enable special test mode */
/*#define MBUF_TEST*/

#include "basic.h"
#include "buffer.h"
#include "multi.h"

#define MBUF_INDEX(head, offset, size) (((head) + (offset)) & ((size)-1))

struct mbuf_buffer
{
  struct buffer buf;
  int refcount;
};

struct mbuf_item
{
  struct mbuf_buffer *buffer;
  struct multi_instance *instance;
};

struct mbuf_set
{
  unsigned int head;
  unsigned int len;
  unsigned int capacity;
  struct mbuf_item *array;
};

struct mbuf_set *mbuf_init (unsigned int size);
void mbuf_free (struct mbuf_set *ms);

struct mbuf_buffer *mbuf_alloc_buf (const struct buffer *buf);
void mbuf_free_buf (struct mbuf_buffer *mb);

void mbuf_add_item (struct mbuf_set *ms, const struct mbuf_item *item);

static inline bool
mbuf_defined (const struct mbuf_set *ms)
{
  return ms && ms->len;
}

static inline bool
mbuf_extract_item (struct mbuf_set *ms, struct mbuf_item *item)
{
  if (ms->len)
    {
      *item = ms->array[ms->head];
      ms->head = MBUF_INDEX(ms->head, 1, ms->capacity);
      --ms->len;
      return true;
    }
  else
    return false;
}

#endif
#endif
