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

#include "memdbg.h"

void
multi_init (struct multi_context *m, struct context *t)
{
  int i;

  CLEAR (*m);
  t->mode = CM_TOP;
  m->array = (struct multi_instance *) malloc (sizeof (struct multi_instance) * MULTI_N_INSTANCE);
  ASSERT (m->array);

  for (i = 0; i < MULTI_N_INSTANCE; ++i)
    {
      CLEAR (m->array[i]);
    }
}

/*
 * Compute earliest timeout expiry from the set of
 * all instances.  Output:
 *
 * m->earliest_wakeup : instance needing the earliest service.
 * dest               : earliest timeout
 */
static void
multi_get_timeout (struct multi_context *m, struct timeval *dest)
{
  struct gc_arena gc = gc_new (); // JYFIXME
  struct timeval tv, current;
  int i;

  // JYFIXME -- inefficient linear search

  tv.tv_sec = BIG_TIMEOUT;
  tv.tv_usec = 0;
  m->earliest_wakeup = NULL;

  for (i = 0; i < MULTI_N_INSTANCE; ++i)
    {
      struct multi_instance *mi = &m->array[i];
#if 1 // JYFIXME
      if (mi->defined)
	{
	  msg (M_INFO, "[%d] WAKEUP %s", i, tv_string (&mi->wakeup, &gc));
	}
#endif
      if (mi->defined && (!m->earliest_wakeup || tv_lt (&mi->wakeup, &tv)))
	{
	  m->earliest_wakeup = mi;
	  tv = mi->wakeup;
	}
    }

  if (m->earliest_wakeup)
    {
      ASSERT (!gettimeofday (&current, NULL));
#if 1 // JYFIXME
      msg (M_INFO, "CURRENT %s", tv_string (&current, &gc));
      msg (M_INFO, "EARLIEST %s", tv_string (&tv, &gc));
#endif
      tv_delta (dest, &current, &tv);
    }
  else
    {
      dest->tv_sec = BIG_TIMEOUT;
      dest->tv_usec = 0;
    }

  gc_free (&gc);
}

void
multi_select (struct multi_context *m, struct context *t)
{
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
}

static struct multi_instance *
multi_get_instance_by_real_addr (struct multi_context *m, const struct sockaddr_in *addr)
{
  struct mroute_addr ma;
  if (mroute_extract_sockaddr_in (&ma, addr, true))
    {
      int i;
      for (i = 0; i < MULTI_N_INSTANCE; ++i)
	{
	  struct multi_instance *mi = &m->array[i];
	  if (mi->defined)
	    {
	      if (mroute_addr_equal (&ma, &mi->real.addr))
		return mi;
	    }
	}
    }
  return NULL;
}

static struct multi_instance *
multi_get_instance_by_virtual_addr (struct multi_context *m, const struct mroute_addr *addr)
{
  int i;
  for (i = 0; i < MULTI_N_INSTANCE; ++i)
    {
      struct multi_instance *mi = &m->array[i];
      if (mi->defined)
	{
	  if (mroute_addr_equal (addr, &mi->virtual.addr))
	    return mi;
	}
    }
  return NULL;
}

static inline void
multi_close_context (struct context *c)
{
  c->sig->signal_received = SIGTERM;
  close_instance (c);
  free (c->sig);
}

static inline void
multi_close_instance (struct multi_instance *mi)
{
  if (mi->defined)
    {
      mroute_list_free (&mi->real);
      mroute_list_free (&mi->virtual);
      multi_close_context (&mi->context);
      mi->defined = false;
    }
}

/*
 * Figure instance-specific timers, convert
 * earliest to absolute time in mi->wakeup.
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

      /* calculate an absolute wakeup time */
      ASSERT (!gettimeofday (&mi->wakeup, NULL));
      tv_add (&mi->wakeup, &mi->context.c2.timeval);
    }
  if (IS_SIG (&mi->context))
    {
      /* make sure that link_out or tun_out is nullified if
	 it points to our soon-to-be-deleted instance */
      if (m->link_out == mi)
	m->link_out = NULL;
      if (m->tun_out == mi)
	m->link_out = NULL;
      multi_close_instance (mi);
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
multi_inherit_context (struct context *dest, const struct context *src)
{
  /* assume that dest has been zeroed */

  dest->mode = CM_CHILD;
  dest->first_time = false;

  /* signals */
  ALLOC_STRUCT (dest->sig, struct signal_info, true);

  /* c1 init */
  clear_tuntap (&dest->c1.tuntap);
  packet_id_persist_init (&dest->c1.pid_persist);

  /* inherit SSL context */
  dest->c1.ks.ssl_ctx = src->c1.ks.ssl_ctx;
  dest->c1.ks.key_type = src->c1.ks.key_type;

  /* options */
  dest->options = src->options;
  context_gc_detach (dest, true);

#ifdef USE_PTHREAD
  dest->options.tls_thread = false; // JYFIXME -- point-to-multipoint doesn't support a threaded control channel yet
#endif
  
  /* context init */
  init_instance (dest);
  if (IS_SIG (dest))
    return;

  /* all instances use top-level parent buffers */
  inherit_buffers (dest, src);

  /* inherit parent link_socket and tuntap */
  link_socket_inherit_passive (&dest->c2.link_socket, &src->c2.link_socket, &dest->c1.link_socket_addr);
  tuntap_inherit_passive (&dest->c1.tuntap, &src->c1.tuntap);
}

static struct multi_instance *
multi_instance_get_free (struct multi_context *m)
{
  int i;
  for (i = 0; i < MULTI_N_INSTANCE; ++i)
    {
      struct multi_instance *mi = &m->array[i];
      if (!mi->defined)
	return mi;
    }
  return NULL;
}

static struct multi_instance *
multi_open_instance (struct multi_context *m, struct context *t)
{
  struct multi_instance *mi = multi_instance_get_free (m);
  ASSERT (mi); /* this will fail if we run out of free instances */

  msg (M_INFO, "DEBUG: multi_open_instance called");

  CLEAR (*mi);
  mi->defined = true;
  mroute_list_init (&mi->real);
  mroute_list_init (&mi->virtual);

  /* remember source address for subsequent references to this instance */
  mroute_extract_sockaddr_in (&mi->real.addr, &t->c2.from, true);

  multi_inherit_context (&mi->context, t);

  if (multi_process_post (m, mi))
    return mi;
  else
    return NULL;
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
	  if (!IS_SIG (t))
	    multi_process_incoming_link (m, t);
	}
      /* Incoming data on TUN device */
      else if (TUNTAP_ISSET (&t->c2.event_wait, &t->c1.tuntap, reads))
	{
	  read_incoming_tun (t);
	  if (!IS_SIG (t))
	    multi_process_incoming_tun (m, t);
	}
    }
}

void
multi_process_timeout (struct multi_context *m, struct context *t)
{
  /* instance marked for wakeup in multi_get_timeout? */
  if (m->earliest_wakeup)
    {
      multi_process_post (m, m->earliest_wakeup);
      m->earliest_wakeup = NULL;
    }
}

void
multi_uninit (struct multi_context *m)
{
  if (m->array)
    {
      int i;
      for (i = 0; i < MULTI_N_INSTANCE; ++i)
	multi_close_instance (&m->array[i]);
      free (m->array);
      m->array = NULL;
    }
}

#else
static void dummy(void) {}
#endif /* P2MP */
