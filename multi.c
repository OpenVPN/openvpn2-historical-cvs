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

#include "multi.h"
#include "init.h"
#include "forward.h"
#include "push.h"

#include "memdbg.h"

#define MULTI_DEBUG // JYFIXME

static bool multi_process_post (struct multi_context *m, struct multi_instance *mi);

void
multi_init (struct multi_context *m, struct context *t)
{
  msg (D_MULTI_DEBUG, "MULTI: multi_init called, r=%d v=%d",
       t->options.real_hash_size,
       t->options.virtual_hash_size);

  CLEAR (*m);
  t->mode = CM_TOP;

  m->hash = hash_init (t->options.real_hash_size,
		       false,
		       mroute_addr_hash_function,
		       mroute_addr_compare_function);

  m->vhash = hash_init (t->options.virtual_hash_size,
			false,
			mroute_addr_hash_function,
			mroute_addr_compare_function);

  m->schedule = schedule_init ();

  ASSERT (t->options.ifconfig_pool_defined);

  m->ifconfig_pool = ifconfig_pool_init (t->options.ifconfig_pool_start,
					 t->options.ifconfig_pool_end);
}

static inline struct multi_instance *
multi_get_instance_by_real_addr (struct multi_context *m, const struct sockaddr_in *addr)
{
  struct mroute_addr ma;
  struct multi_instance *ret = NULL;
  if (mroute_extract_sockaddr_in (&ma, addr, true))
    {
      ret = (struct multi_instance *) hash_lookup (m->hash, &ma);
#ifdef MULTI_DEBUG
      {
	struct gc_arena gc = gc_new ();
	msg (D_MULTI_DEBUG, "GET INST BY REAL: %s %s",
	     mroute_addr_print (&ma, &gc),
	     ret ? "[succeeded]" : "[failed]");
	gc_free (&gc);
#endif
      }
    }
  return ret;
}

static inline struct multi_instance *
multi_get_instance_by_virtual_addr (struct multi_context *m, const struct mroute_addr *addr)
{
  struct multi_instance *ret = (struct multi_instance *) hash_lookup (m->vhash, addr);
#ifdef MULTI_DEBUG
  {
    struct gc_arena gc = gc_new ();
    msg (D_MULTI_DEBUG, "GET INST BY VIRT: %s %s",
	 mroute_addr_print (addr, &gc),
	 ret ? "[succeeded]" : "[failed]");
    gc_free (&gc);
  }
#endif
  return ret;
}

static inline void
multi_close_context (struct context *c)
{
  c->sig->signal_received = SIGTERM;
  close_instance (c);
  context_gc_free (c);
  free (c->sig);
}

static inline void
multi_close_instance (struct multi_context *m, struct multi_instance *mi)
{
  msg (D_MULTI_DEBUG, "MULTI: multi_close_instance called");

  if (mi->did_open_context)
    {
      multi_close_context (&mi->context);
    }
  if (mi->did_real_hash)
    {
      ASSERT (hash_remove (m->hash, &mi->real.addr));
    }
  if (mi->did_virtual_hash)
    {
      ASSERT (hash_remove (m->vhash, &mi->virtual.addr));
    }
  if (mi->did_ifconfig)
    {
      ifconfig_pool_release (m->ifconfig_pool, mi->vaddr_handle);
    }
  if (mi->did_routes)
    {
      mroute_list_free (&mi->real);
      mroute_list_free (&mi->virtual);
    }
  free (mi);
}

void
multi_uninit (struct multi_context *m)
{
  if (m->hash)
    {
      struct hash_iterator hi;
      struct multi_instance *mi;

      hash_iterator_init (m->hash, &hi);

      while ((mi = (struct multi_instance *) hash_iterator_next (&hi)) != NULL)
	multi_close_instance (m, mi);

      hash_free (m->hash);
      hash_free (m->vhash);
      m->hash = NULL;

      schedule_free (m->schedule);

      ifconfig_pool_free (m->ifconfig_pool);
    }
}

static void
multi_inherit_context (struct context *dest, const struct context *src)
{
  /* assume that dest has been zeroed */

  dest->mode = CM_CHILD;
  dest->first_time = false;

  /* signals */
  ALLOC_OBJ_CLEAR (dest->sig, struct signal_info);

  /* c1 init */
  clear_tuntap (&dest->c1.tuntap);
  packet_id_persist_init (&dest->c1.pid_persist);

  /* inherit SSL context */
  dest->c1.ks.ssl_ctx = src->c1.ks.ssl_ctx;
  dest->c1.ks.key_type = src->c1.ks.key_type;

  /* options */
  dest->options = src->options;
  context_gc_detach (dest, true);

  /* context init */
  init_instance (dest, false);
  if (IS_SIG (dest))
    return;

  /* all instances use top-level parent buffers */
  dest->c2.buffers = src->c2.buffers;

  /* inherit parent link_socket and tuntap */
  link_socket_inherit_passive (&dest->c2.link_socket, &src->c2.link_socket, &dest->c1.link_socket_addr);
  tuntap_inherit_passive (&dest->c1.tuntap, &src->c1.tuntap);
}

static struct multi_instance *
multi_open_instance (struct multi_context *m, struct context *t)
{
  struct gc_arena gc = gc_new ();
  struct multi_instance *mi;

  ALLOC_OBJ_CLEAR (mi, struct multi_instance);

  msg (D_MULTI_DEBUG, "MULTI: multi_open_instance called");

  mroute_list_init (&mi->real);
  mroute_list_init (&mi->virtual);
  mi->did_routes = true;

  /* remember source address for subsequent references to this instance */
  if (!mroute_extract_sockaddr_in (&mi->real.addr, &t->c2.from, true))
    {
      msg (D_MULTI_DEBUG, "MULTI: unable to parse source address from incoming packet");
      goto err;
    }
  msg (D_MULTI_DEBUG, "MULTI: real address: %s", mroute_addr_print (&mi->real.addr, &gc));

  if (!hash_add (m->hash, &mi->real.addr, mi))
    {
      msg (D_MULTI_DEBUG, "MULTI: unable to add real address [%s] to global hash table",
	   mroute_addr_print (&mi->real.addr, &gc));
      goto err;
    }
  mi->did_real_hash = true;

  /* get a free /30 subnet from pool */
  {
    in_addr_t local, remote;
    struct sockaddr_in remote_si;

    if (ifconfig_pool_acquire_30_net (m->ifconfig_pool, &local, &remote) < 0)
      {
	msg (D_MULTI_ERROR, "MULTI: client connection rejected because no free --ifconfig-pool addresses are available");
	goto err;
      }

    mi->did_ifconfig = true;

    mi->context.c2.push_ifconfig_local = remote;
    mi->context.c2.push_ifconfig_remote = local;

    CLEAR (remote_si);
    remote_si.sin_family = AF_INET;
    remote_si.sin_addr.s_addr = htonl (remote);

    ASSERT (mroute_extract_sockaddr_in (&mi->virtual.addr, &remote_si, false));
    msg (D_MULTI_DEBUG, "MULTI: virtual address: %s", mroute_addr_print (&mi->virtual.addr, &gc));

    if (!hash_add (m->vhash, &mi->virtual.addr, mi))
      {
	msg (D_MULTI_ERROR, "MULTI: unable to add virtual address [%s] to global hash table",
	     mroute_addr_print (&mi->virtual.addr, &gc));
	goto err;
      }
    mi->did_virtual_hash = true;
  }
  
  multi_inherit_context (&mi->context, t);
  mi->did_open_context = true;

  if (!multi_process_post (m, mi))
    {
      msg (D_MULTI_ERROR, "MULTI: signal occurred during client instance initialization");
      goto err;
    }

  gc_free (&gc);
  return mi;

 err:
  multi_close_instance (m, mi);
  gc_free (&gc);
  return NULL;
}

/*
 * Compute earliest timeout expiry from the set of
 * all instances.  Output:
 *
 * m->earliest_wakeup : instance needing the earliest service.
 * dest               : earliest timeout as a delta in relation
 *                      to current time.
 */
static inline void
multi_get_timeout (struct multi_context *m, struct timeval *dest)
{
  struct timeval tv, current;

  m->earliest_wakeup = (struct multi_instance *) schedule_get_earliest_wakeup (m->schedule, &tv);
  if (m->earliest_wakeup)
    {
      ASSERT (!gettimeofday (&current, NULL));
      tv_delta (dest, &current, &tv);
    }
  else
    {
      dest->tv_sec = BIG_TIMEOUT;
      dest->tv_usec = 0;
    }
}

void
multi_select (struct multi_context *m, struct context *t)
{
  // LOCK -- global read lock

  /*
   * Set up for select call.
   *
   * Decide what kind of events we want to wait for.
   */
  wait_reset (&t->c2.event_wait);

  /*
   * On win32 we use the keyboard or an event object as a source
   * of asynchronous signals.
   */
  WAIT_SIGNAL (&t->c2.event_wait);

  /*
   * If outgoing data (for TCP/UDP port) pending, wait for ready-to-send
   * status from TCP/UDP port. Otherwise, wait for incoming data on
   * TUN/TAP device.
   */
  if (m->link_out)
    {
      SOCKET_SET_WRITE (&t->c2.event_wait, &t->c2.link_socket);
    }
  else
    {
      TUNTAP_SET_READ (&t->c2.event_wait, &t->c1.tuntap);
    }

  /*
   * If outgoing data (for TUN/TAP device) pending, wait for ready-to-send status
   * from device.  Otherwise, wait for incoming data on TCP/UDP port.
   */
  if (m->tun_out)
    {
      TUNTAP_SET_WRITE (&t->c2.event_wait, &t->c1.tuntap);
    }
  else
    {
      SOCKET_SET_READ (&t->c2.event_wait, &t->c2.link_socket);
    }

  /*
   * Wait for something to happen.
   */
  t->c2.select_status = 1;	/* this will be our return "status" if select doesn't get called */
  if (!t->sig->signal_received)
    {
      multi_get_timeout (m, &t->c2.timeval);
      if (check_debug_level (D_SELECT))
	show_select_status (t);
      t->c2.select_status = SELECT (&t->c2.event_wait, &t->c2.timeval);
      check_status (t->c2.select_status, "multi-select", NULL, NULL);
    }

  /* current should always be a reasonably up-to-date timestamp */
  t->c2.current = time (NULL);

  /* set signal_received if a signal was received */
  SELECT_SIGNAL_RECEIVED (&t->c2.event_wait, t->sig->signal_received);
}

void
multi_print_status (struct multi_context *m, struct context *t)
{
  // JYFIXME -- code me
}

/*
 * Given a time delta, indicating that we wish to be
 * awoken by the scheduler a time current + delta, figure
 * a sigma parameter (in microseconds) that represents
 * a sort of fuzz factor around delta, so that we're
 * really telling the scheduler to wake us up any time
 * between current + delta - sigma and current + delta + sigma.
 *
 * The sigma parameter helps the scheduler to run more efficiently.
 * Sigma should be no larger than TV_WITHIN_SIGMA_MAX_USEC
 */
static inline unsigned int
compute_wakeup_sigma (const struct timeval *delta)
{
  if (delta->tv_sec < 1)
    {
      /* if < 1 sec, fuzz = # of microseconds / 8 */
      return delta->tv_usec >> 3;
    }
  else
    {
      /* if < 10 minutes, fuzz = 13.1% of timeout */
      if (delta->tv_sec < 600)
	return delta->tv_sec << 17;
      else
	return 120000000; /* if >= 10 minutes, fuzz = 2 minutes */
    }
}

/*
 * Figure instance-specific timers, convert
 * earliest to absolute time in mi->wakeup,
 * call scheduler with our future wakeup time.
 *
 * Also close context on signal.
 */
static bool
multi_process_post (struct multi_context *m, struct multi_instance *mi)
{
  if (!IS_SIG (&mi->context))
    {
      /* figure timeouts and fetch possible outgoing
	 to_link packets (such as ping or TLS control) */
      pre_select (&mi->context);

      if (!IS_SIG (&mi->context))
	{
	  /* calculate an absolute wakeup time */
	  ASSERT (!gettimeofday (&mi->wakeup, NULL));
	  tv_add (&mi->wakeup, &mi->context.c2.timeval);

	  /* tell scheduler to wake us up at some point in the future */
	  schedule_add_entry (m->schedule,
			      (struct schedule_entry *) mi,
			      &mi->wakeup,
			      compute_wakeup_sigma (&mi->context.c2.timeval));
	}
    }
  if (IS_SIG (&mi->context))
    {
      /* make sure that link_out or tun_out is nullified if
	 it points to our soon-to-be-deleted instance */
      if (m->link_out == mi)
	m->link_out = NULL;
      if (m->tun_out == mi)
	m->link_out = NULL;
      multi_close_instance (m, mi);
      return false;
    }
  else
    {
      /* did pre_select produce any to_link or to_tun output packets? */
      if (m->link_out)
	{
	  if (!BLEN (&mi->context.c2.to_link))
	    m->link_out = NULL;
	}
      else
	{
	  if (BLEN (&mi->context.c2.to_link))
	    m->link_out = mi;
	}
      if (m->tun_out)
	{
	  if (!BLEN (&mi->context.c2.to_tun))
	    m->tun_out = NULL;
	}
      else
	{
	  if (BLEN (&mi->context.c2.to_tun))
	    m->tun_out = mi;
	}
      return true;
    }
}

static void
multi_process_incoming_link (struct multi_context *m, struct context *t)
{
  if (BLEN (&t->c2.buf))
    {
      struct context *c;
      ASSERT (!m->tun_out);

      /* existing client? */
      m->tun_out = multi_get_instance_by_real_addr (m, &t->c2.from);

      /* no, assume new client */
      if (!m->tun_out)
	{
	  m->tun_out = multi_open_instance (m, t);
	  if (!m->tun_out)
	    return;
	}

      /* get instance context */
      c = &m->tun_out->context;

      // LOCK -- instance lock

      /* transfer packet pointer from top-level context buffer to instance */
      c->c2.buf = t->c2.buf;

      /* transfer from-addr from top-level context buffer to instance */
      c->c2.from = t->c2.from;

      /* decrypt in instance context */
      process_incoming_link (c);

      /* postprocess and set wakeup */
      multi_process_post (m, m->tun_out);
    }
}

static void
multi_process_incoming_tun (struct multi_context *m, struct context *t)
{
  if (BLEN (&t->c2.buf))
    {
      struct context *c;
      struct mroute_addr addr;

      ASSERT (!m->link_out);

      /* 
       * Route an incoming tun/tap packet to
       * the appropriate multi_instance object.
       */

      if (!mroute_extract_addr_from_packet (&addr, &t->c2.buf, TUNNEL_TYPE (&t->c1.tuntap), true))
	return;

      m->link_out = multi_get_instance_by_virtual_addr (m, &addr);
      if (!m->link_out)
	return;

      /* get instance context */
      c = &m->link_out->context;

      // LOCK -- instance lock

      /* transfer packet pointer from top-level context buffer to instance */
      c->c2.buf = t->c2.buf;
     
      /* encrypt in instance context */
      process_incoming_tun (c);

      /* postprocess and set wakeup */
      multi_process_post (m, m->link_out);
    }
}

static inline void
multi_process_outgoing_link (struct multi_context *m, struct context *t)
{
  struct multi_instance *mi = m->link_out;
  ASSERT (mi);
  m->link_out = NULL;
  process_outgoing_link (&mi->context, &t->c2.link_socket);
  multi_process_post (m, mi);
}

static inline void
multi_process_outgoing_tun (struct multi_context *m, struct context *t)
{
  struct multi_instance *mi = m->tun_out;
  ASSERT (mi);
  m->tun_out = NULL;
  process_outgoing_tun (&mi->context, &t->c1.tuntap);
  multi_process_post (m, mi);
}

void
multi_process_io (struct multi_context *m, struct context *t)
{
  if (t->c2.select_status > 0)
    {
      /* TCP/UDP port ready to accept write */
      if (SOCKET_ISSET (&t->c2.event_wait, &t->c2.link_socket, writes))
	{
	  multi_process_outgoing_link (m, t);
	}
      /* TUN device ready to accept write */
      else if (TUNTAP_ISSET (&t->c2.event_wait, &t->c1.tuntap, writes))
	{
	  multi_process_outgoing_tun (m, t);
	}
      /* Incoming data on TCP/UDP port */
      else if (SOCKET_ISSET (&t->c2.event_wait, &t->c2.link_socket, reads))
	{
	  read_incoming_link (t);
	  // LOCK -- global read unlock
	  if (!IS_SIG (t))
	    multi_process_incoming_link (m, t);
	}
      /* Incoming data on TUN device */
      else if (TUNTAP_ISSET (&t->c2.event_wait, &t->c1.tuntap, reads))
	{
	  read_incoming_tun (t);
	  // LOCK -- global read unlock
	  if (!IS_SIG (t))
	    multi_process_incoming_tun (m, t);
	}
    }
}

void
multi_process_timeout (struct multi_context *m, struct context *t)
{
  // LOCK -- global read unlock

  /* instance marked for wakeup in multi_get_timeout? */
  if (m->earliest_wakeup)
    {
      multi_process_post (m, m->earliest_wakeup);
      m->earliest_wakeup = NULL;
    }
}

#else
static void dummy(void) {}
#endif /* P2MP */
