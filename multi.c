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
#include "misc.h"
#include "otime.h"

#include "memdbg.h"

#define MULTI_DEBUG // JYFIXME

static bool multi_process_post (struct multi_context *m, struct multi_instance *mi);

/*
 * Check for signals -- to be used
 * in the context of the
 * tunnel_multiclient_udp_server function. 
 */
#define TNUS_SIG() \
  if (IS_SIG (top)) \
  { \
    if (top->sig->signal_received == SIGUSR2) \
      { \
        multi_print_status (&multi, top); \
        top->sig->signal_received = 0; \
        continue; \
      } \
    break; \
  }

void
tunnel_server (struct context *top)
{
  struct multi_context multi;

  ASSERT (top->options.proto == PROTO_UDPv4);
  ASSERT (top->options.mode == MODE_SERVER);

#ifdef USE_PTHREAD
  if (top->options.n_threads > 1) // JYFIXME
    openvpn_thread_init ();
#endif

  multi_init (&multi, top);
  context_clear_2 (top);

  /* initialize tunnel instance */
  init_instance (top, true);
  if (IS_SIG (top))
    return;

  /* per-packet event loop */
  while (true)
    {
      /* set up and do the select() */
      multi_select (&multi, top);
      TNUS_SIG ();

      /* timeout? */
      if (!top->c2.select_status)
	{
	  multi_process_timeout (&multi, top);
	}
      else
	{
	  /* process the I/O which triggered select */
	  multi_process_io (&multi, top);
	  TNUS_SIG ();
	}
    }

  /* tear down tunnel instance (unless --persist-tun) */
  close_instance (top);
  multi_uninit (&multi);
  top->first_time = false;

#ifdef USE_PTHREAD
  if (top->options.n_threads > 1) // JYFIXME
    openvpn_thread_cleanup ();
#endif
}

void
multi_init (struct multi_context *m, struct context *t)
{
  int dev = DEV_TYPE_UNDEF;

  msg (D_MULTI_DEBUG, "MULTI: multi_init called, r=%d v=%d",
       t->options.real_hash_size,
       t->options.virtual_hash_size);

  /*
   * Get tun/tap/null device type
   */
  dev = dev_type_enum (t->options.dev, t->options.dev_type);

  /*
   * Init our multi_context object.
   */
  CLEAR (*m);
  t->mode = CM_TOP;

  /*
   * Real address hash table (source port number is
   * considered to be part of the address).  Used
   * to determine which client sent an incoming packet
   * which is seen on the TCP/UDP socket.
   */
  m->hash = hash_init (t->options.real_hash_size,
		       false,
		       mroute_addr_hash_function,
		       mroute_addr_compare_function);

  /*
   * Virtual address hash table.  Used to determine
   * which client to route a packet to. 
   */
  m->vhash = hash_init (t->options.virtual_hash_size,
			false,
			mroute_addr_hash_function,
			mroute_addr_compare_function);

  /*
   * This hash table is a clone of m->hash but with a
   * bucket size of one so that it can be used
   * for fast iteration through the list.
   */
  m->iter = hash_init (1,
		       false,
		       mroute_addr_hash_function,
		       mroute_addr_compare_function);

  /*
   * This is our scheduler.
   */
  m->schedule = schedule_init ();

  /*
   * Allocate broadcast/multicast buffer list
   */
  m->mbuf = mbuf_init (t->options.n_bcast_buf);

  /*
   * Possibly allocate an ifconfig pool, do it
   * differently based on whether a tun or tap style
   * tunnel.
   */
  if (t->options.ifconfig_pool_defined)
    {
      if (dev == DEV_TYPE_TUN)
	{
	  m->ifconfig_pool = ifconfig_pool_init (IFCONFIG_POOL_30NET,
						 t->options.ifconfig_pool_start,
						 t->options.ifconfig_pool_end);
	}
      else if (dev == DEV_TYPE_TAP)
	{
	  m->ifconfig_pool = ifconfig_pool_init (IFCONFIG_POOL_INDIV,
						 t->options.ifconfig_pool_start,
						 t->options.ifconfig_pool_end);
	}
    }

  /*
   * Allow client <-> client communication, without going through
   * tun/tap interface and network stack?
   */
  m->enable_c2c = t->options.enable_c2c;
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

static void
multi_close_context (struct context *c)
{
  c->sig->signal_received = SIGTERM;
  close_instance (c);
  context_gc_free (c);
  free (c->sig);
}

static void
multi_close_instance (struct multi_context *m, struct multi_instance *mi)
{
  msg (D_MULTI_DEBUG, "MULTI: multi_close_instance called");

  if (mi->context.options.client_disconnect_script)
    {
      struct gc_arena gc = gc_new ();
      struct buffer cmd = alloc_buf_gc (256, &gc);

      mutex_lock_static (L_SCRIPT);

      setenv_str ("script_type", "client-disconnect");

      /* setenv incoming cert common name for script */
      setenv_str ("common_name", tls_common_name (mi->context.c2.tls_multi));

      /* setenv client real IP address */
      setenv_trusted (&mi->context.c2.link_socket);

      buf_printf (&cmd, "%s", mi->context.options.client_disconnect_script);

      system_check (BSTR (&cmd), "client-disconnect command failed", false);

      mutex_unlock_static (L_SCRIPT);

      gc_free (&gc);
    }

  schedule_remove_entry (m->schedule, (struct schedule_entry *) mi);

  if (mi->did_open_context)
    {
      multi_close_context (&mi->context);
    }
  if (mi->did_real_hash)
    {
      ASSERT (hash_remove (m->hash, &mi->real));
    }
  if (mi->did_iter)
    {
      ASSERT (hash_remove (m->iter, &mi->real));
    }

  ifconfig_pool_release (m->ifconfig_pool, mi->vaddr_handle);

  /* free all virtual addresses tied to instance here */
  hash_remove_by_value (m->vhash, mi);

  gc_free (&mi->gc);

  free (mi);
}

void
multi_uninit (struct multi_context *m)
{
  if (m->hash)
    {
      struct hash_iterator hi;
      struct hash_element *he;

      hash_iterator_init (m->iter, &hi);

      while ((he = hash_iterator_next (&hi)))
	{
	  struct multi_instance *mi = (struct multi_instance *) he->value;
	  mi->did_iter = false;
	  multi_close_instance (m, mi);
	}

      hash_iterator_free (&hi);

      hash_free (m->hash);
      hash_free (m->vhash);
      hash_free (m->iter);
      m->hash = NULL;

      schedule_free (m->schedule);

      mbuf_free (m->mbuf);

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
  options_detach (&dest->options);

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

  mi->gc = gc_new ();
  mroute_addr_init (&mi->real);
  mi->vaddr_handle = -1;
  mi->created = now;

  /* remember source address for subsequent references to this instance */
  if (!mroute_extract_sockaddr_in (&mi->real, &t->c2.from, true))
    {
      msg (D_MULTI_DEBUG, "MULTI: unable to parse source address from incoming packet");
      goto err;
    }
  msg (D_MULTI_DEBUG, "MULTI: real address: %s", mroute_addr_print (&mi->real, &gc));

  if (!hash_add (m->hash, &mi->real, mi, false))
    {
      msg (D_MULTI_DEBUG, "MULTI: unable to add real address [%s] to global hash table",
	   mroute_addr_print (&mi->real, &gc));
      goto err;
    }
  mi->did_real_hash = true;

  if (!hash_add (m->iter, &mi->real, mi, false))
    {
      msg (D_MULTI_DEBUG, "MULTI: unable to add real address [%s] to iterator hash table",
	   mroute_addr_print (&mi->real, &gc));
      goto err;
    }
  mi->did_iter = true;

  multi_inherit_context (&mi->context, t);
  mi->did_open_context = true;

  if (!multi_process_post (m, mi))
    {
      msg (D_MULTI_ERRORS, "MULTI: signal occurred during client instance initialization");
      goto err;
    }

  gc_free (&gc);
  return mi;

 err:
  multi_close_instance (m, mi);
  gc_free (&gc);
  return NULL;
}

void
multi_print_status (struct multi_context *m, struct context *t)
{
  if (m->hash)
    {
      struct hash_iterator hi;
      struct multi_instance *mi;
      struct hash_element *he;
      const struct mroute_addr *ma;

      msg (M_INFO, "INSTANCE LIST");
      msg (M_INFO, "Common Name,Real Address,Connected Since,Read Bytes,Write Bytes");
      hash_iterator_init (m->hash, &hi);
      while ((he = hash_iterator_next (&hi)))
	{
	  struct gc_arena gc = gc_new ();
	  mi = (struct multi_instance *) he->value;
	  msg (M_INFO, "%s,%s,%s," counter_format_simple "," counter_format_simple,
	       tls_common_name (mi->context.c2.tls_multi),
	       mroute_addr_print (&mi->real, &gc),
	       time_string (mi->created, 0, false, &gc),
	       mi->context.c2.link_read_bytes,
	       mi->context.c2.link_write_bytes);
	  gc_free (&gc);
	}
      hash_iterator_free (&hi);

      msg (M_INFO, "ROUTING TABLE");
      msg (M_INFO, "Address,Common Name");
      hash_iterator_init (m->vhash, &hi);
      while ((he = hash_iterator_next (&hi)))
	{
	  struct gc_arena gc = gc_new ();
	  mi = (struct multi_instance *) he->value;
	  ma = (const struct mroute_addr *) he->key;
	  msg (M_INFO, "%s,%s",
	       mroute_addr_print (ma, &gc),
	       tls_common_name (mi->context.c2.tls_multi));
	  gc_free (&gc);
	}
      hash_iterator_free (&hi);
    }
}

static inline void
multi_learn_addr (struct multi_context *m,
		  struct multi_instance *mi,
		  const struct mroute_addr *addr)
{
  struct multi_instance *exists;

  /* already in list? */
  exists = (struct multi_instance *) hash_lookup (m->vhash, addr);

  if (exists != mi && mroute_learnable_address (addr)) /* add it if valid address */
    {
      struct mroute_addr *newaddr;
      ALLOC_OBJ_GC (newaddr, struct mroute_addr, &mi->gc);
      *newaddr = *addr;
      hash_add (m->vhash, newaddr, mi, true);
#ifdef MULTI_DEBUG
      {
	struct gc_arena gc = gc_new ();
	msg (D_MULTI_DEBUG, "MULTI: Learn: %s -> %s",
	     mroute_addr_print (newaddr, &gc),
	     tls_common_name (mi->context.c2.tls_multi));
	gc_free (&gc);
      }
#endif
    }
}

static void
multi_learn_in_addr_t (struct multi_context *m,
		       struct multi_instance *mi,
		       in_addr_t a)
{
  struct sockaddr_in remote_si;
  struct mroute_addr addr;
  CLEAR (remote_si);
  remote_si.sin_family = AF_INET;
  remote_si.sin_addr.s_addr = htonl (a);
  ASSERT (mroute_extract_sockaddr_in (&addr, &remote_si, false));
  multi_learn_addr (m, mi, &addr);
}

void
multi_connection_established (struct multi_context *m, struct multi_instance *mi)
{
  struct gc_arena gc = gc_new ();
  in_addr_t local=0, remote=0;
  const char *dynamic_config_file = NULL;
  bool dynamic_config_file_mark_for_delete = false;

  /* acquire script mutex */
  mutex_lock_static (L_SCRIPT);

  /*
   * Get a pool address, which may be released before the end
   * of this function if it's not needed.
   */
  if (m->ifconfig_pool)
    {
      mi->vaddr_handle = ifconfig_pool_acquire (m->ifconfig_pool, &local, &remote);
      if (mi->vaddr_handle >= 0)
	{
	  if (local)
	    setenv_in_addr_t ("ifconfig_pool_local", local);
	  if (remote)
	    setenv_in_addr_t ("ifconfig_pool_remote", remote);
	}
      else
	{
	  msg (D_MULTI_ERRORS, "MULTI: no free --ifconfig-pool addresses are available");
	}
    }

  /* setenv incoming cert common name for script */
  setenv_str ("common_name", tls_common_name (mi->context.c2.tls_multi));

  /* setenv client real IP address */
  setenv_trusted (&mi->context.c2.link_socket);

  /*
   * instance-specific directives to be processed:
   *
   *   iroute start-ip end-ip
   *   ifconfig-push local remote-netmask
   *   push
   */

  /*
   * Run --client-connect script.
   */
  if (mi->context.options.client_connect_script)
    {
      struct buffer cmd = alloc_buf_gc (256, &gc);
      setenv_str ("script_type", "client-connect");

      dynamic_config_file = create_temp_filename (mi->context.options.tmp_dir, &gc);

      delete_file (dynamic_config_file);

      buf_printf (&cmd, "%s %s",
		  mi->context.options.client_connect_script,
		  dynamic_config_file);

      system_check (BSTR (&cmd), "client-connect command failed", false);

      if (test_file (dynamic_config_file))
	{
	  dynamic_config_file_mark_for_delete = true;
	}
      else
	{
	  dynamic_config_file = NULL;
	}
    }

  /*
   * If client connect script was not run, or if it
   * was run but did not create a dynamic config file,
   * try to get a dynamic config file from the
   * --client-config-dir directory.
   */
  if (!dynamic_config_file)
    {
      dynamic_config_file = gen_path
	(mi->context.options.client_config_dir,
	 tls_common_name (mi->context.c2.tls_multi),
	 &gc);

      if (!test_file (dynamic_config_file))
	dynamic_config_file = NULL;
    }

  /*
   * Load the dynamic options.
   */
  if (dynamic_config_file)
    {
      unsigned int option_types_found = 0;
      options_server_import (&mi->context.options,
			     dynamic_config_file,
			     D_IMPORT_ERRORS,
			     OPT_P_PUSH|OPT_P_INSTANCE|OPT_P_TIMER|OPT_P_CONFIG,
			     &option_types_found);
      do_deferred_options (&mi->context, option_types_found);
    }

  /*
   * Delete script-generated dynamic config file.
   */
  if (dynamic_config_file && dynamic_config_file_mark_for_delete)
    {
      if (!delete_file (dynamic_config_file))
	msg (D_MULTI_ERRORS, "MULTI: problem deleting temporary file: %s",
	     dynamic_config_file);
    }

  /*
   * If ifconfig addresses were set by dynamic config file,
   * release pool addresses, otherwise keep them.
   */
  if (mi->context.options.push_ifconfig_defined)
    {
      /* ifconfig addresses were set statically,
	 release dynamic allocation */
      ifconfig_pool_release (m->ifconfig_pool, mi->vaddr_handle);
      mi->vaddr_handle = -1;

      mi->context.c2.push_ifconfig_defined = true;
      mi->context.c2.push_ifconfig_local = mi->context.options.push_ifconfig_local;
      mi->context.c2.push_ifconfig_remote_netmask = mi->context.options.push_ifconfig_remote_netmask;
    }
  else
    {
      if (mi->vaddr_handle >= 0)
	{
	  /* use pool ifconfig address(es) */
	  mi->context.c2.push_ifconfig_local = remote;
	  if (TUNNEL_TYPE (&mi->context.c1.tuntap) == DEV_TYPE_TUN)
	    {
	      mi->context.c2.push_ifconfig_remote_netmask = local;
	      mi->context.c2.push_ifconfig_defined = true;
	    }
	  else if (TUNNEL_TYPE (&mi->context.c1.tuntap) == DEV_TYPE_TAP)
	    {
	      mi->context.c2.push_ifconfig_remote_netmask = mi->context.c1.tuntap.remote_netmask;
	      mi->context.c2.push_ifconfig_defined = true;
	    }
	}
    }

  /*
   * make sure we got ifconfig settings from somewhere
   */
  if (!mi->context.c2.push_ifconfig_defined)
    {
      msg (D_MULTI_ERRORS, "MULTI: no dynamic or static remote --ifconfig address is available for %s",
	   tls_common_name (mi->context.c2.tls_multi));
    }

  /*
   * For routed tunnels, set up internal route to endpoint
   * plus add all iroute routes.
   */
  if (TUNNEL_TYPE (&mi->context.c1.tuntap) == DEV_TYPE_TUN)
    {
      const struct iroute *ir;

      if (mi->context.c2.push_ifconfig_defined)
	{
	  multi_learn_in_addr_t (m, mi, mi->context.c2.push_ifconfig_local);
	  msg (D_MULTI, "MULTI: primary virtual IP for %s: %s",
	       tls_common_name (mi->context.c2.tls_multi),
	       print_in_addr_t (mi->context.c2.push_ifconfig_local, false, &gc));
	}

      for (ir = mi->context.options.iroutes; ir != NULL; ir = ir->next)
	{
	  in_addr_t addr;
	  msg (D_MULTI, "MULTI: internal route [%s-%s] -> %s",
	       print_in_addr_t (ir->start, false, &gc),
	       print_in_addr_t (ir->end, false, &gc),
	       tls_common_name (mi->context.c2.tls_multi));
	  for (addr = ir->start; addr <= ir->end; ++addr)
	    multi_learn_in_addr_t (m, mi, addr);
	}
    }
  else if (mi->context.options.iroutes)
    {
      msg (D_MULTI_ERRORS, "MULTI: --iroute options rejected for %s -- iroute only works with tun-style tunnels",
	   tls_common_name (mi->context.c2.tls_multi));
    }

  mutex_unlock_static (L_SCRIPT);
  gc_free (&gc);
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
   * outgoing bcast buffer is waiting to be sent
   */
  if (mbuf_defined (m->mbuf))
    {
      SOCKET_SET_WRITE (&t->c2.event_wait, &t->c2.link_socket);
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

  update_time ();

  /* set signal_received if a signal was received */
  SELECT_SIGNAL_RECEIVED (&t->c2.event_wait, t->sig->signal_received);
}

/*
 * Add a multicast buffer to a particular
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

static inline void
multi_unicast (struct multi_context *m,
	       const struct buffer *buf,
	       struct multi_instance *mi)
{
  struct mbuf_buffer *mb;

  mb = mbuf_alloc_buf (buf);
  multi_add_mbuf (m, mi, mb);
  mbuf_free_buf (mb);
}

static void
multi_broadcast (struct multi_context *m,
		 const struct buffer *buf,
		 struct multi_instance *omit)
{
  struct hash_iterator hi;
  struct hash_element *he;
  struct multi_instance *mi;
  struct mbuf_buffer *mb;

  mb = mbuf_alloc_buf (buf);
  hash_iterator_init (m->iter, &hi);

  while ((he = hash_iterator_next (&hi)))
    {
      mi = (struct multi_instance *) he->value;
      if (mi != omit)
	multi_add_mbuf (m, mi, mb);
    }

  hash_iterator_free (&hi);
  mbuf_free_buf (mb);
}

/*
 * Given a time delta, indicating that we wish to be
 * awoken by the scheduler a time now + delta, figure
 * a sigma parameter (in microseconds) that represents
 * a sort of fuzz factor around delta, so that we're
 * really telling the scheduler to wake us up any time
 * between now + delta - sigma and now + delta + sigma.
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

	  /* connection is "established" when SSL/TLS key negotiation succeeds */
	  if (!mi->connection_established_flag && CONNECTION_ESTABLISHED (&mi->context.c2.link_socket))
	    {
	      multi_connection_established (m, mi);
	      mi->connection_established_flag = true;
	    }
	}
    }
  if (IS_SIG (&mi->context))
    {
      /* make sure that link_out or tun_out is nullified if
	 it points to our soon-to-be-deleted instance */
      if (m->link_out == mi)
	m->link_out = NULL;
      if (m->tun_out == mi)
	m->tun_out = NULL;
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
  if (BLEN (&t->c2.buf) > 0)
    {
      struct context *c;
      struct mroute_addr src, dest;
      unsigned int mroute_flags;
      struct multi_instance *mi;

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

      if (TUNNEL_TYPE (&t->c1.tuntap) == DEV_TYPE_TUN)
	{
	  /* client-to-client communication enabled? */
	  if (m->enable_c2c)
	    {
	      /* extract packet source and dest addresses */
	      mroute_flags = mroute_extract_addr_from_packet (&src,
							      &dest,
							      &c->c2.to_tun,
							      DEV_TYPE_TUN);

	      if (mroute_flags & MROUTE_EXTRACT_SUCCEEDED)
		{
		  /* multicast? */
		  if (mroute_flags & MROUTE_EXTRACT_MCAST)
		    {
		      /* for now, treat multicast as broadcast */
		      multi_broadcast (m, &c->c2.to_tun, m->tun_out);
		    }
		  else /* possible client to client routing */
		    {
		      ASSERT (!(mroute_flags & MROUTE_EXTRACT_BCAST));
		      mi = multi_get_instance_by_virtual_addr (m, &dest);

		      /* if dest addr is a known client, route to it */
		      if (mi)
			{
			  multi_unicast (m, &c->c2.to_tun, mi);
			  c->c2.to_tun.len = 0;
			}
		    }
		}
	    }
	}
      else if (TUNNEL_TYPE (&t->c1.tuntap) == DEV_TYPE_TAP)
	{
	  /* extract packet source and dest addresses */
	  mroute_flags = mroute_extract_addr_from_packet (&src,
							  &dest,
							  &c->c2.to_tun,
							  DEV_TYPE_TAP);

	  if (mroute_flags & MROUTE_EXTRACT_SUCCEEDED)
	    {
	      /* check for broadcast */
	      if (m->enable_c2c)
		{
		  if (mroute_flags & (MROUTE_EXTRACT_BCAST|MROUTE_EXTRACT_MCAST))
		    {
		      multi_broadcast (m, &c->c2.to_tun, m->tun_out);
		    }
		  else /* try client-to-client routing */
		    {
		      mi = multi_get_instance_by_virtual_addr (m, &dest);

		      /* if dest addr is a known client, route to it */
		      if (mi)
			{
			  multi_unicast (m, &c->c2.to_tun, mi);
			  c->c2.to_tun.len = 0;
			}
		    }
		}
		  
	      /* learn source address */
	      multi_learn_addr (m, m->tun_out, &src);
	    }
	}
      
      /* postprocess and set wakeup */
      multi_process_post (m, m->tun_out);
    }
}

static void
multi_process_incoming_tun (struct multi_context *m, struct context *t)
{
  if (BLEN (&t->c2.buf) > 0)
    {
      unsigned int mroute_flags;
      struct mroute_addr src, dest;

      ASSERT (!m->link_out);

      /* 
       * Route an incoming tun/tap packet to
       * the appropriate multi_instance object.
       */

      mroute_flags = mroute_extract_addr_from_packet (&src,
						      &dest,
						      &t->c2.buf,
						      TUNNEL_TYPE (&t->c1.tuntap));

      if (mroute_flags & MROUTE_EXTRACT_SUCCEEDED)
	{
	  struct context *c;

	  /* broadcast or multicast dest addr? */
	  if (mroute_flags & (MROUTE_EXTRACT_BCAST|MROUTE_EXTRACT_MCAST))
	    {
	      /* for now, treat multicast as broadcast */
	      multi_broadcast (m, &t->c2.buf, NULL);
	    }
	  else
	    {
	      m->link_out = multi_get_instance_by_virtual_addr (m, &dest);
	      if (m->link_out)
		{
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
	}
    }
}

static inline struct multi_instance *
multi_bcast_instance (struct multi_context *m)
{
  struct mbuf_item item;
  if (mbuf_extract_item (m->mbuf, &item))
    {
      item.instance->context.c2.buf = item.buffer->buf;
      encrypt_sign (&item.instance->context, true);
      mbuf_free_buf (item.buffer);
#ifdef MULTI_DEBUG
      msg (D_MULTI_DEBUG, "MULTI: BCAST INSTANCE");
#endif
      return item.instance;
    }
  else
    {
      return NULL;
    }
}

static inline void
multi_process_outgoing_link (struct multi_context *m, struct context *t)
{
  struct multi_instance *mi;

  if (m->link_out)
    {
      mi = m->link_out;
      m->link_out = NULL;
    }
  else
    mi = multi_bcast_instance (m);

  if (mi)
    {
      process_outgoing_link (&mi->context, &t->c2.link_socket);
      multi_process_post (m, mi);
    }
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
      /* Incoming data on TCP/UDP port */
      if (SOCKET_ISSET (&t->c2.event_wait, &t->c2.link_socket, reads))
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
      /* TUN device ready to accept write */
      else if (TUNTAP_ISSET (&t->c2.event_wait, &t->c1.tuntap, writes))
	{
	  multi_process_outgoing_tun (m, t);
	}
      /* TCP/UDP port ready to accept write */
      else if (SOCKET_ISSET (&t->c2.event_wait, &t->c2.link_socket, writes))
	{
	  multi_process_outgoing_link (m, t);
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

#else
static void dummy(void) {}
#endif /* P2MP */
