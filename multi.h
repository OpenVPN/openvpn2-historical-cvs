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

#ifndef MULTI_H
#define MULTI_H

#if P2MP

#include "openvpn.h"
#include "mroute.h"
#include "mbuf.h"
#include "list.h"
#include "schedule.h"
#include "pool.h"

/*
 * One multi_instance object per client instance.
 */
struct multi_instance {
  struct schedule_entry se;    /* this must be the first element of the structure */
  MUTEX_DEFINE (mutex);
  bool defined;
  bool halt;
  time_t created;
  struct timeval wakeup;       /* absolute time */
  struct mroute_addr real;
  ifconfig_pool_handle vaddr_handle;
  const char *msg_prefix;
  struct gc_arena gc;

  bool did_open_context;
  bool did_real_hash;
  bool did_iter;
  bool connection_established_flag;

  struct context context;
};

/*
 * One multi_context object per server daemon.
 */
struct multi_context {
  struct hash *hash;   /* indexed by real address */
  struct hash *vhash;  /* indexed by virtual address */
  struct hash *iter;   /* like real address hash but optimized for iteration */
  struct schedule *schedule;
  struct mbuf_set *mbuf;
  struct ifconfig_pool *ifconfig_pool;
  struct frequency_limit *new_connection_limiter;

  bool enable_c2c;
};

/*
 * One multi_thread object per thread.
 */
struct multi_thread {
  struct multi_context *multi; /* shared between all threads */
  struct multi_instance *link_out;
  struct multi_instance *link_out_bcast;
  struct multi_instance *tun_out;
  struct multi_instance *earliest_wakeup;  
  struct context_buffers *context_buffers;
  struct context top;
};

void tunnel_server_single_threaded (struct context *top);

#ifdef USE_PTHREAD
void tunnel_server_multi_threaded (struct context *top);
#endif

const char *multi_instance_string (struct multi_instance *mi, bool null, struct gc_arena *gc);

void multi_bcast (struct multi_context *m,
		  const struct buffer *buf,
		  struct multi_instance *omit);

/*
 * Add a mbuf buffer to a particular
 * instance.
 */
static inline void
multi_add_mbuf (struct multi_context *m,
		struct multi_instance *mi,
		struct mbuf_buffer *mb)
{
  struct mbuf_item item;
  item.buffer = mb;
  item.instance = mi;
  mbuf_add_item (m->mbuf, &item);
}

#endif /* P2MP */
#endif /* MULTI_H */
