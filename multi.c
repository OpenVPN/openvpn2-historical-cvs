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
#include "push.h"
#include "misc.h"
#include "otime.h"

#include "memdbg.h"

#include "forward-inline.h"

#define MULTI_DEBUG
//#define MULTI_DEBUG_EVENT_LOOP

#ifdef MULTI_DEBUG_EVENT_LOOP
static const char *
id (struct multi_instance *mi)
{
  if (mi)
    return tls_common_name (mi->context.c2.tls_multi, false);
  else
    return "NULL";
}
#endif

static void
learn_address_script (const struct multi_context *m,
		      const struct multi_instance *mi,
		      const char *op,
		      const struct mroute_addr *addr)
{
  if (m->learn_address_script)
    {
      struct gc_arena gc = gc_new ();
      struct buffer cmd = alloc_buf_gc (256, &gc);

      mutex_lock_static (L_SCRIPT);

      setenv_str ("script_type", "learn-address");

      buf_printf (&cmd, "%s \"%s\" \"%s\"",
		  m->learn_address_script,
		  op,
		  mroute_addr_print (addr, &gc));
      if (mi)
	buf_printf (&cmd, " \"%s\"", tls_common_name (mi->context.c2.tls_multi, true));

      system_check (BSTR (&cmd), "learn-address command failed", false);

      mutex_unlock_static (L_SCRIPT);
      gc_free (&gc);
    }
}

static void
multi_reap_range (const struct multi_context *m,
		  int start_bucket,
		  int end_bucket)
{
  struct gc_arena gc = gc_new ();
  struct hash_iterator hi;
  struct hash_element *he;

  if (start_bucket < 0)
    {
      start_bucket = 0;
      end_bucket = hash_n_buckets (m->vhash);
    }

  msg (D_MULTI_DEBUG, "MULTI: REAP range %d -> %d", start_bucket, end_bucket);
  hash_iterator_init_range (m->vhash, &hi, true, start_bucket, end_bucket);
  while ((he = hash_iterator_next (&hi)) != NULL)
    {
      struct multi_route *r = (struct multi_route *) he->value;
      if (!multi_route_defined (m, r))
	{
	  msg (D_MULTI_DEBUG, "MULTI: REAP DEL %s",
	       mroute_addr_print (&r->addr, &gc));
	  learn_address_script (m, NULL, "delete", &r->addr);
	  multi_route_del (r);
	  hash_iterator_delete_element (&hi);
	}
    }
  hash_iterator_free (&hi);
  gc_free (&gc);
}

static void
multi_reap_all (const struct multi_context *m)
{
  multi_reap_range (m, -1, 0);
}

static struct multi_reap *
multi_reap_new (int buckets_per_pass)
{
  struct multi_reap *mr;
  ALLOC_OBJ (mr, struct multi_reap);
  mr->bucket_base = 0;
  mr->buckets_per_pass = buckets_per_pass;
  mr->last_call = now;
  return mr;
}

void
multi_reap_process_dowork (const struct multi_context *m)
{
  struct multi_reap *mr = m->reaper;
  if (mr->bucket_base >= hash_n_buckets (m->vhash))
    mr->bucket_base = 0;
  multi_reap_range (m, mr->bucket_base, mr->bucket_base + mr->buckets_per_pass); 
  mr->bucket_base += mr->buckets_per_pass;
  mr->last_call = now;
}

static void
multi_reap_free (struct multi_reap *mr)
{
  free (mr);
}

/*
 * How many buckets in vhash to reap per pass.
 */
static int
reap_buckets_per_pass (int n_buckets)
{
  return constrain_int (n_buckets / REAP_DIVISOR, REAP_MIN, REAP_MAX);
}

/*
 * Main initialization function, init multi_context object.
 */
void
multi_init (struct multi_context *m, struct context *t, bool tcp_mode)
{
  int dev = DEV_TYPE_UNDEF;

  msg (D_MULTI_LOW, "MULTI: multi_init called, r=%d v=%d",
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

  /*
   * Real address hash table (source port number is
   * considered to be part of the address).  Used
   * to determine which client sent an incoming packet
   * which is seen on the TCP/UDP socket.
   */
  m->hash = hash_init (t->options.real_hash_size,
		       mroute_addr_hash_function,
		       mroute_addr_compare_function);

  /*
   * Virtual address hash table.  Used to determine
   * which client to route a packet to. 
   */
  m->vhash = hash_init (t->options.virtual_hash_size,
			mroute_addr_hash_function,
			mroute_addr_compare_function);

  /*
   * This hash table is a clone of m->hash but with a
   * bucket size of one so that it can be used
   * for fast iteration through the list.
   */
  m->iter = hash_init (1,
		       mroute_addr_hash_function,
		       mroute_addr_compare_function);

  /*
   * This is our scheduler, for time-based wakeup
   * events.
   */
  m->schedule = schedule_init ();

  /*
   * Limit frequency of incoming connections to control
   * DoS.
   */
  m->new_connection_limiter = frequency_limit_init (t->options.cf_max,
						    t->options.cf_per);

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
   * Help us keep track of routing table.
   */
  m->route_helper = mroute_helper_init (MULTI_CACHE_ROUTE_TTL);

  /*
   * Initialize route and instance reaper.
   */
  m->reaper = multi_reap_new (reap_buckets_per_pass (t->options.virtual_hash_size));

  /*
   * Get local ifconfig address
   */
  CLEAR (m->local);
  ASSERT (t->c1.tuntap);
  mroute_extract_in_addr_t (&m->local, t->c1.tuntap->local);

  /*
   * Remember possible learn_address_script
   */
  m->learn_address_script = t->options.learn_address_script;
  
  /*
   * Limit total number of clients
   */
  m->max_clients = t->options.max_clients;

  /*
   * Initialize multi-socket TCP I/O wait object
   */
  if (tcp_mode)
    m->mtcp = multi_tcp_init (t->options.max_clients, &m->max_clients);
  
  /*
   * Allow client <-> client communication, without going through
   * tun/tap interface and network stack?
   */
  m->enable_c2c = t->options.enable_c2c;
}

const char *
multi_instance_string (struct multi_instance *mi, bool null, struct gc_arena *gc)
{
  if (mi)
    {
      struct buffer out = alloc_buf_gc (256, gc);
      const char *cn = tls_common_name (mi->context.c2.tls_multi, true);

      if (cn)
	buf_printf (&out, "%s/", cn);
      buf_printf (&out, "%s", mroute_addr_print (&mi->real, gc));
      return BSTR (&out);
    }
  else if (null)
    return NULL;
  else
    return "UNDEF";
}

void
generate_prefix (struct multi_instance *mi)
{
  mi->msg_prefix = multi_instance_string (mi, true, &mi->gc);
  set_prefix (mi);
}

void
ungenerate_prefix (struct multi_instance *mi)
{
  mi->msg_prefix = NULL;
  set_prefix (mi);
}

/*
 * Tell the route helper about deleted iroutes so
 * that it can update its mask of currently used
 * CIDR netlengths.
 */
static void
multi_del_iroutes (struct multi_context *m,
		   struct multi_instance *mi)
{
  const struct iroute *ir;
  for (ir = mi->context.options.iroutes; ir != NULL; ir = ir->next)
    mroute_helper_del_iroute (m->route_helper, ir);
}

void
multi_close_instance (struct multi_context *m,
		      struct multi_instance *mi,
		      bool shutdown)
{
  perf_push (PERF_MULTI_CLOSE_INSTANCE);

  ASSERT (!mi->halt);
  mi->halt = true;

  msg (D_MULTI_LOW, "MULTI: multi_close_instance called");

  /* prevent dangling pointers */
  if (m->pending == mi)
    m->pending = NULL;
  if (m->earliest_wakeup == mi)
    m->earliest_wakeup = NULL;

  if (!shutdown)
    {
      if (mi->did_real_hash)
	{
	  ASSERT (hash_remove (m->hash, &mi->real));
	}
      if (mi->did_iter)
	{
	  ASSERT (hash_remove (m->iter, &mi->real));
	}

      schedule_remove_entry (m->schedule, (struct schedule_entry *) mi);

      ifconfig_pool_release (m->ifconfig_pool, mi->vaddr_handle);

      multi_del_iroutes (m, mi);

      if (m->mtcp)
	multi_tcp_dereference_instance (m->mtcp, mi);

      mbuf_dereference_instance (m->mbuf, mi);
    }

  if (mi->context.options.client_disconnect_script)
    {
      struct gc_arena gc = gc_new ();
      struct buffer cmd = alloc_buf_gc (256, &gc);

      mutex_lock_static (L_SCRIPT);

      setenv_str ("script_type", "client-disconnect");

      /* setenv incoming cert common name for script */
      setenv_str ("common_name", tls_common_name (mi->context.c2.tls_multi, false));

      /* setenv client real IP address */
      setenv_trusted (get_link_socket_info (&mi->context));

      buf_printf (&cmd, "%s", mi->context.options.client_disconnect_script);

      system_check (BSTR (&cmd), "client-disconnect command failed", false);

      mutex_unlock_static (L_SCRIPT);

      gc_free (&gc);
    }

  if (mi->did_open_context)
    close_context (&mi->context, SIGTERM, CC_GC_FREE);

  multi_tcp_instance_specific_free (mi);

  ungenerate_prefix (mi);

  /*
   * Don't actually delete the instance memory allocation yet,
   * because virtual routes may still point to it.  Let the
   * vhash reaper deal with it.
   */
  multi_instance_dec_refcount (mi);

  perf_pop ();
}

/*
 * Called on shutdown or restart.
 */
void
multi_uninit (struct multi_context *m)
{
  if (m->hash)
    {
      struct hash_iterator hi;
      struct hash_element *he;

      hash_iterator_init (m->iter, &hi, true);
      while ((he = hash_iterator_next (&hi)))
	{
	  struct multi_instance *mi = (struct multi_instance *) he->value;
	  mi->did_iter = false;
	  multi_close_instance (m, mi, true);
	}
      hash_iterator_free (&hi);

      multi_reap_all (m);

      hash_free (m->hash);
      hash_free (m->vhash);
      hash_free (m->iter);
      m->hash = NULL;

      schedule_free (m->schedule);
      mbuf_free (m->mbuf);
      ifconfig_pool_free (m->ifconfig_pool);
      frequency_limit_free (m->new_connection_limiter);
      multi_reap_free (m->reaper);
      mroute_helper_free (m->route_helper);
      multi_tcp_free (m->mtcp);
    }
}

/*
 * Create a client instance object for a newly connected client.
 */
struct multi_instance *
multi_create_instance (struct multi_context *m, const struct mroute_addr *real)
{
  struct gc_arena gc = gc_new ();
  struct multi_instance *mi;

  perf_push (PERF_MULTI_CREATE_INSTANCE);

  msg (D_MULTI_LOW, "MULTI: multi_create_instance called");

  ALLOC_OBJ_CLEAR (mi, struct multi_instance);

  mi->gc = gc_new ();
  multi_instance_inc_refcount (mi);
  mi->vaddr_handle = -1;
  mi->created = now;
  mroute_addr_init (&mi->real);

  if (real)
    {
      mi->real = *real;
      generate_prefix (mi);
    }

  inherit_context_child (&mi->context, &m->top);
  if (IS_SIG (&mi->context))
    goto err;
  mi->did_open_context = true;

  if (hash_n_elements (m->hash) >= m->max_clients)
    {
      msg (D_MULTI_ERRORS, "MULTI: new incoming connection would exceed maximum number of clients (%d)", m->max_clients);
      goto err;
    }

  if (!real) /* TCP mode? */
    {
      if (!multi_tcp_instance_specific_init (m, mi))
	goto err;
      generate_prefix (mi);
    }

  if (!hash_add (m->iter, &mi->real, mi, false))
    {
      msg (D_MULTI_LOW, "MULTI: unable to add real address [%s] to iterator hash table",
	   mroute_addr_print (&mi->real, &gc));
      goto err;
    }
  mi->did_iter = true;

  mi->context.c2.push_reply_deferred = true;

  if (!multi_process_post (m, mi, MPP_PRE_SELECT))
    {
      msg (D_MULTI_ERRORS, "MULTI: signal occurred during client instance initialization");
      goto err;
    }

  perf_pop ();
  gc_free (&gc);
  return mi;

 err:
  multi_close_instance (m, mi, false);
  perf_pop ();
  gc_free (&gc);
  return NULL;
}

/*
 * Dump tables -- triggered by SIGUSR2.
 * If status file is defined, write to file.
 * If status file is NULL, write to syslog.
 */
void
multi_print_status (struct multi_context *m, struct status_output *so)
{
  if (m->hash)
    {
      struct gc_arena gc_top = gc_new ();
      struct hash_iterator hi;
      const struct hash_element *he;

      status_reset (so);

      status_printf (so, PACKAGE_NAME " CLIENT LIST");
      status_printf (so, "Updated,%s", time_string (0, 0, false, &gc_top));
      status_printf (so, "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since");
      hash_iterator_init (m->hash, &hi, true);
      while ((he = hash_iterator_next (&hi)))
	{
	  struct gc_arena gc = gc_new ();
	  const struct multi_instance *mi = (struct multi_instance *) he->value;

	  if (!mi->halt)
	    {
	      status_printf (so, "%s,%s," counter_format "," counter_format ",%s",
			     tls_common_name (mi->context.c2.tls_multi, false),
			     mroute_addr_print (&mi->real, &gc),
			     mi->context.c2.link_read_bytes,
			     mi->context.c2.link_write_bytes,
			     time_string (mi->created, 0, false, &gc));
	    }
	  gc_free (&gc);
	}
      hash_iterator_free (&hi);

      status_printf (so, "ROUTING TABLE");
      status_printf (so, "Virtual Address,Common Name,Real Address,Last Ref");
      hash_iterator_init (m->vhash, &hi, true);
      while ((he = hash_iterator_next (&hi)))
	{
	  struct gc_arena gc = gc_new ();
	  const struct multi_route *route = (struct multi_route *) he->value;

	  if (multi_route_defined (m, route))
	    {
	      const struct multi_instance *mi = route->instance;
	      const struct mroute_addr *ma = &route->addr;
	      char flags[2] = {0, 0};

	      if (route->flags & MULTI_ROUTE_CACHE)
		flags[0] = 'C';
	      status_printf (so, "%s%s,%s,%s,%s",
			     mroute_addr_print (ma, &gc),
			     flags,
			     tls_common_name (mi->context.c2.tls_multi, false),
			     mroute_addr_print (&mi->real, &gc),
			     time_string (route->last_reference, 0, false, &gc));
	    }
	  gc_free (&gc);
	}
      hash_iterator_free (&hi);

      status_printf (so, "GLOBAL STATS");
      if (m->mbuf)
	status_printf (so, "Max bcast/mcast queue length,%d",
		       mbuf_maximum_queued (m->mbuf));

      status_printf (so, "END");
      status_flush (so);
      gc_free (&gc_top);
    }
}

/*
 * Learn a virtual address or route.
 */
static void
multi_learn_addr (struct multi_context *m,
		  struct multi_instance *mi,
		  const struct mroute_addr *addr,
		  const unsigned int flags)
{
  struct hash_element *he;
  const uint32_t hv = hash_value (m->vhash, addr);
  struct hash_bucket *bucket = hash_bucket (m->vhash, hv);
  struct multi_route *oldroute = NULL;
  
  hash_bucket_lock (bucket);
  he = hash_lookup_fast (m->vhash, bucket, addr, hv);

  if (he)
    oldroute = (struct multi_route *) he->value;

  /* do we need to add address to hash table? */
  if ((!oldroute
       || oldroute->instance != mi
       || !multi_route_defined (m, oldroute))
      && mroute_learnable_address (addr)
      && !mroute_addr_equal (addr, &m->local))
    {
      struct gc_arena gc = gc_new ();
      struct multi_route *newroute;

      ALLOC_OBJ (newroute, struct multi_route);
      newroute->addr = *addr;
      newroute->instance = mi;
      newroute->flags = flags;
      newroute->last_reference = now;
      newroute->cache_generation = 0;

      /* The cache is invalidated when cache_generation is incremented */
      if (flags & MULTI_ROUTE_CACHE)
	newroute->cache_generation = m->route_helper->cache_generation;

      multi_instance_inc_refcount (mi);

      if (oldroute) /* route already exists? */
	{
	  /* delete old route */
	  multi_route_del (oldroute);

	  /* modify hash table entry, replacing old route */
	  he->key = &newroute->addr;
	  he->value = newroute;
	  learn_address_script (m, mi, "update", &newroute->addr);
	}
      else
	{
	  /* add new route */
	  hash_add_fast (m->vhash, bucket, &newroute->addr, hv, newroute);
	  learn_address_script (m, mi, "add", &newroute->addr);
	}

      msg (D_MULTI_LOW, "MULTI: Learn: %s -> %s",
	   mroute_addr_print (&newroute->addr, &gc),
	   multi_instance_string (mi, false, &gc));

      gc_free (&gc);
    }

  hash_bucket_unlock (bucket);
}

/*
 * Get client instance based on virtual address.
 */
static struct multi_instance *
multi_get_instance_by_virtual_addr (struct multi_context *m,
				    const struct mroute_addr *addr,
				    bool cidr_routing)
{
  struct multi_route *route;
  struct multi_instance *ret = NULL;

  /* check for local address */
  if (mroute_addr_equal (addr, &m->local))
    return NULL;

  route = (struct multi_route *) hash_lookup (m->vhash, addr);

  /* does host route (possible cached) exist? */
  if (route && multi_route_defined (m, route))
    {
      struct multi_instance *mi = route->instance;
      route->last_reference = now;
      ret = mi;
    }
  else if (cidr_routing) /* do we need to regenerate a host route cache entry? */
    {
      struct mroute_helper *rh = m->route_helper;
      struct mroute_addr tryaddr;
      int i;

      mroute_helper_lock (rh);

      /* cycle through each CIDR length */
      for (i = 0; i < rh->n_net_len; ++i)
	{
	  tryaddr = *addr;
	  tryaddr.type |= MR_WITH_NETBITS;
	  tryaddr.netbits = rh->net_len[i];
	  mroute_addr_mask_host_bits (&tryaddr);

	  /* look up a possible route with netbits netmask */
	  route = (struct multi_route *) hash_lookup (m->vhash, &tryaddr);

	  if (route && multi_route_defined (m, route))
	    {
	      /* found an applicable route, cache host route */
	      struct multi_instance *mi = route->instance;
	      multi_learn_addr (m, mi, addr, MULTI_ROUTE_CACHE|MULTI_ROUTE_AGEABLE);
	      ret = mi;
	      break;
	    }
	}
      
      mroute_helper_unlock (rh);
    }
  
#ifdef MULTI_DEBUG
  if (check_debug_level (D_MULTI_DEBUG))
    {
      struct gc_arena gc = gc_new ();
      const char *addr_text = mroute_addr_print (addr, &gc);
      if (ret)
	{
	  msg (D_MULTI_DEBUG, "GET INST BY VIRT: %s -> %s via %s",
	       addr_text,
	       multi_instance_string (ret, false, &gc),
	       mroute_addr_print (&route->addr, &gc));
	}
      else
	{
	  msg (D_MULTI_DEBUG, "GET INST BY VIRT: %s [failed]",
	       addr_text);
	}
      gc_free (&gc);
    }
#endif

  ASSERT (!(ret && ret->halt));
  return ret;
}

/*
 * Helper function to multi_learn_addr().
 */
static void
multi_learn_in_addr_t (struct multi_context *m,
		       struct multi_instance *mi,
		       in_addr_t a,
		       int netbits) /* -1 if host route, otherwise # of network bits in address */
{
  struct sockaddr_in remote_si;
  struct mroute_addr addr;

  CLEAR (remote_si);
  remote_si.sin_family = AF_INET;
  remote_si.sin_addr.s_addr = htonl (a);
  ASSERT (mroute_extract_sockaddr_in (&addr, &remote_si, false));

  if (netbits >= 0)
    {
      addr.type |= MR_WITH_NETBITS;
      addr.netbits = (uint8_t) netbits;
    }
  multi_learn_addr (m, mi, &addr, 0);
}

/*
 * A new client has connected, add routes (server -> client)
 * to internal routing table.
 */
static void
multi_add_iroutes (struct multi_context *m,
		   struct multi_instance *mi)
{
  struct gc_arena gc = gc_new ();
  const struct iroute *ir;
  for (ir = mi->context.options.iroutes; ir != NULL; ir = ir->next)
    {
      if (ir->netbits >= 0)
	msg (D_MULTI_LOW, "MULTI: internal route %s/%d -> %s",
	     print_in_addr_t (ir->network, 0, &gc),
	     ir->netbits,
	     multi_instance_string (mi, false, &gc));
      else
	msg (D_MULTI_LOW, "MULTI: internal route %s -> %s",
	     print_in_addr_t (ir->network, 0, &gc),
	     multi_instance_string (mi, false, &gc));

      mroute_helper_add_iroute (m->route_helper, ir);
      multi_learn_in_addr_t (m, mi, ir->network, ir->netbits);
    }
  gc_free (&gc);
}

/*
 * Given an instance (new_mi), delete all other instances which use the
 * same common name.
 */
static void
multi_delete_dup (struct multi_context *m, struct multi_instance *new_mi)
{
  if (new_mi)
    {
      const char *new_cn = tls_common_name (new_mi->context.c2.tls_multi, true);
      if (new_cn)
	{
	  struct hash_iterator hi;
	  struct hash_element *he;

	  hash_iterator_init (m->iter, &hi, true);
	  while ((he = hash_iterator_next (&hi)))
	    {
	      struct multi_instance *mi = (struct multi_instance *) he->value;
	      if (mi != new_mi)
		{
		  const char *cn = tls_common_name (mi->context.c2.tls_multi, true);
		  if (cn && !strcmp (cn, new_cn))
		    {
		      mi->did_iter = false;
		      multi_close_instance (m, mi, false);
		      hash_iterator_delete_element (&hi);
		    }
		}
	    }
	  hash_iterator_free (&hi);
	}
    }
}

/*
 * Called as soon as the SSL/TLS connection authenticates.
 */
static void
multi_connection_established (struct multi_context *m, struct multi_instance *mi)
{
  struct gc_arena gc = gc_new ();
  in_addr_t local=0, remote=0;
  const char *dynamic_config_file = NULL;
  bool dynamic_config_file_mark_for_delete = false;

  ASSERT (mi->context.c1.tuntap);

  /* acquire script mutex */
  mutex_lock_static (L_SCRIPT);

  /* generate a msg() prefix for this client instance */
  generate_prefix (mi);

  /* delete instances of previous clients with same common-name */
  if (!mi->context.options.duplicate_cn)
    multi_delete_dup (m, mi);

  /*
   * Get a pool address, which may be released before the end
   * of this function if it's not needed.
   */
  if (m->ifconfig_pool)
    {
      mi->vaddr_handle = ifconfig_pool_acquire (m->ifconfig_pool, &local, &remote, tls_common_name (mi->context.c2.tls_multi, true));
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
  setenv_str ("common_name", tls_common_name (mi->context.c2.tls_multi, false));

  /* setenv client real IP address */
  setenv_trusted (get_link_socket_info (&mi->context));

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
	 tls_common_name (mi->context.c2.tls_multi, false),
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
	  if (TUNNEL_TYPE (mi->context.c1.tuntap) == DEV_TYPE_TUN)
	    {
	      mi->context.c2.push_ifconfig_remote_netmask = local;
	      mi->context.c2.push_ifconfig_defined = true;
	    }
	  else if (TUNNEL_TYPE (mi->context.c1.tuntap) == DEV_TYPE_TAP)
	    {
	      mi->context.c2.push_ifconfig_remote_netmask = mi->context.options.ifconfig_pool_netmask;
	      if (!mi->context.c2.push_ifconfig_remote_netmask)
		mi->context.c2.push_ifconfig_remote_netmask = mi->context.c1.tuntap->remote_netmask;
	      if (mi->context.c2.push_ifconfig_remote_netmask)
		mi->context.c2.push_ifconfig_defined = true;
	      else
		msg (D_MULTI_ERRORS, "MULTI: no --ifconfig-pool netmask parameter is available to push to %s",
		     multi_instance_string (mi, false, &gc));
	    }
	}
    }

  /*
   * make sure we got ifconfig settings from somewhere
   */
  if (!mi->context.c2.push_ifconfig_defined)
    {
      msg (D_MULTI_ERRORS, "MULTI: no dynamic or static remote --ifconfig address is available for %s",
	   multi_instance_string (mi, false, &gc));
    }

  /*
   * For routed tunnels, set up internal route to endpoint
   * plus add all iroute routes.
   */
  if (TUNNEL_TYPE (mi->context.c1.tuntap) == DEV_TYPE_TUN)
    {
      if (mi->context.c2.push_ifconfig_defined)
	{
	  multi_learn_in_addr_t (m, mi, mi->context.c2.push_ifconfig_local, -1);
	  msg (D_MULTI_LOW, "MULTI: primary virtual IP for %s: %s",
	       multi_instance_string (mi, false, &gc),
	       print_in_addr_t (mi->context.c2.push_ifconfig_local, 0, &gc));
	}

      /* add routes locally, pointing to new client, if
	 --iroute options have been specified */
      multi_add_iroutes (m, mi);
    }
  else if (mi->context.options.iroutes)
    {
      msg (D_MULTI_ERRORS, "MULTI: --iroute options rejected for %s -- iroute only works with tun-style tunnels",
	   multi_instance_string (mi, false, &gc));
    }

  /*
   * Reply now to client's PUSH_REQUEST query
   */
  mi->context.c2.push_reply_deferred = false;

  mutex_unlock_static (L_SCRIPT);
  gc_free (&gc);
}

/*
 * Add a packet to a client instance output queue.
 */
static inline void
multi_unicast (struct multi_context *m,
	       const struct buffer *buf,
	       struct multi_instance *mi)
{
  struct mbuf_buffer *mb;

  if (BLEN (buf) > 0)
    {
      mb = mbuf_alloc_buf (buf);
      mb->flags = MF_UNICAST;
      multi_add_mbuf (m, mi, mb);
      mbuf_free_buf (mb);
    }
}

/*
 * Broadcast a packet to all clients.
 */
void
multi_bcast (struct multi_context *m,
	     const struct buffer *buf,
	     struct multi_instance *omit)
{
  struct hash_iterator hi;
  struct hash_element *he;
  struct multi_instance *mi;
  struct mbuf_buffer *mb;

  if (BLEN (buf) > 0)
    {
      perf_push (PERF_MULTI_BCAST);
#ifdef MULTI_DEBUG_EVENT_LOOP
      printf ("BCAST len=%d\n", BLEN (buf));
#endif
      mb = mbuf_alloc_buf (buf);
      hash_iterator_init (m->iter, &hi, true);

      while ((he = hash_iterator_next (&hi)))
	{
	  mi = (struct multi_instance *) he->value;
	  if (mi != omit)
	    multi_add_mbuf (m, mi, mb);
	}

      hash_iterator_free (&hi);
      mbuf_free_buf (mb);
      perf_pop ();
    }
}

/*
 * Given a time delta, indicating that we wish to be
 * awoken by the scheduler at time now + delta, figure
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
bool
multi_process_post (struct multi_context *m, struct multi_instance *mi, const unsigned int flags)
{
  bool ret = true;

  if (!IS_SIG (&mi->context) && (flags & MPP_PRE_SELECT))
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
	  if (!mi->connection_established_flag && CONNECTION_ESTABLISHED (&mi->context))
	    {
	      multi_connection_established (m, mi);
	      mi->connection_established_flag = true;
	    }
	}
    }
  if (IS_SIG (&mi->context))
    {
      if (flags & MPP_CLOSE_ON_SIGNAL)
	{
	  multi_close_instance (m, mi, false);
	  ret = false;
	}
    }
  else
    {
      /* continue to pend on output? */
      m->pending = ANY_OUT (&mi->context) ? mi : NULL;
#ifdef MULTI_DEBUG_EVENT_LOOP
      printf ("POST %s[%d] to=%d lo=%d/%d w=%d/%d\n",
	      id(mi),
	      (int) (mi == m->pending),
	      mi ? mi->context.c2.to_tun.len : -1,
	      mi ? mi->context.c2.to_link.len : -1,
	      (mi && mi->context.c2.fragment) ? mi->context.c2.fragment->outgoing.len : -1,
	      (int)mi->context.c2.timeval.tv_sec,
	      (int)mi->context.c2.timeval.tv_usec);
#endif
    }

  if (flags & MPP_RECORD_TOUCH && m->mpp_touched)
    *m->mpp_touched = mi;

  return ret;
}

/*
 * Process packets in the TCP/UDP socket -> TUN/TAP interface direction,
 * i.e. client -> server direction.
 */
bool
multi_process_incoming_link (struct multi_context *m, struct multi_instance *instance, const unsigned int mpp_flags)
{
  struct gc_arena gc = gc_new ();

  struct context *c;
  struct mroute_addr src, dest;
  unsigned int mroute_flags;
  struct multi_instance *mi;
  bool ret = true;

  ASSERT (!m->pending);

  if (!instance)
    {
#ifdef MULTI_DEBUG_EVENT_LOOP
      printf ("TCP/UDP -> TUN [%d]\n", BLEN (&m->top.c2.buf));
#endif
      m->pending = multi_get_create_instance_udp (m);
    }
  else
    m->pending = instance;

  if (m->pending)
    {
      set_prefix (m->pending);

      /* get instance context */
      c = &m->pending->context;

      if (!instance)
	{
	  /* transfer packet pointer from top-level context buffer to instance */
	  c->c2.buf = m->top.c2.buf;

	  /* transfer from-addr from top-level context buffer to instance */
	  c->c2.from = m->top.c2.from;
	}

      if (BLEN (&c->c2.buf) > 0)
	{
	  /* decrypt in instance context */
	  process_incoming_link (c);

	  if (TUNNEL_TYPE (m->top.c1.tuntap) == DEV_TYPE_TUN)
	    {
	      /* extract packet source and dest addresses */
	      mroute_flags = mroute_extract_addr_from_packet (&src,
							      &dest,
							      &c->c2.to_tun,
							      DEV_TYPE_TUN);

	      /* drop packet if extract failed */
	      if (!(mroute_flags & MROUTE_EXTRACT_SUCCEEDED))
		{
		  c->c2.to_tun.len = 0;
		}
	      /* make sure that source address is associated with this client */
	      else if (multi_get_instance_by_virtual_addr (m, &src, true) != m->pending)
		{
		  msg (D_MULTI_DEBUG, "MULTI: bad source address from client [%s], packet dropped",
		       mroute_addr_print (&src, &gc));
		  c->c2.to_tun.len = 0;
		}
	      /* client-to-client communication enabled? */
	      else if (m->enable_c2c)
		{
		  /* multicast? */
		  if (mroute_flags & MROUTE_EXTRACT_MCAST)
		    {
		      /* for now, treat multicast as broadcast */
		      multi_bcast (m, &c->c2.to_tun, m->pending);
		    }
		  else /* possible client to client routing */
		    {
		      ASSERT (!(mroute_flags & MROUTE_EXTRACT_BCAST));
		      mi = multi_get_instance_by_virtual_addr (m, &dest, true);
		  
		      /* if dest addr is a known client, route to it */
		      if (mi)
			{
			  multi_unicast (m, &c->c2.to_tun, mi);
			  register_activity (c);
			  c->c2.to_tun.len = 0;
			}
		    }
		}
	    }
	  else if (TUNNEL_TYPE (m->top.c1.tuntap) == DEV_TYPE_TAP)
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
			  multi_bcast (m, &c->c2.to_tun, m->pending);
			}
		      else /* try client-to-client routing */
			{
			  mi = multi_get_instance_by_virtual_addr (m, &dest, false);

			  /* if dest addr is a known client, route to it */
			  if (mi)
			    {
			      multi_unicast (m, &c->c2.to_tun, mi);
			      register_activity (c);
			      c->c2.to_tun.len = 0;
			    }
			}
		    }
		  
		  /* learn source address */
		  multi_learn_addr (m, m->pending, &src, 0);
		}
	      else
		{
		  c->c2.to_tun.len = 0;
		}
	    }
	}

      /* postprocess and set wakeup */
      ret = multi_process_post (m, m->pending, mpp_flags);

      clear_prefix ();
    }

  gc_free (&gc);
  return ret;
}

/*
 * Process packets in the TUN/TAP interface -> TCP/UDP socket direction,
 * i.e. server -> client direction.
 */
bool
multi_process_incoming_tun (struct multi_context *m, const unsigned int mpp_flags)
{
  struct gc_arena gc = gc_new ();
  bool ret = true;

  if (BLEN (&m->top.c2.buf) > 0)
    {
      unsigned int mroute_flags;
      struct mroute_addr src, dest;
      const int dev_type = TUNNEL_TYPE (m->top.c1.tuntap);

#ifdef MULTI_DEBUG_EVENT_LOOP
      printf ("TUN -> TCP/UDP [%d]\n", BLEN (&m->top.c2.buf));
#endif

      ASSERT (!m->pending);

      /* 
       * Route an incoming tun/tap packet to
       * the appropriate multi_instance object.
       */

      mroute_flags = mroute_extract_addr_from_packet (&src,
						      &dest,
						      &m->top.c2.buf,
						      dev_type);

      if (mroute_flags & MROUTE_EXTRACT_SUCCEEDED)
	{
	  struct context *c;

	  /* broadcast or multicast dest addr? */
	  if (mroute_flags & (MROUTE_EXTRACT_BCAST|MROUTE_EXTRACT_MCAST))
	    {
	      /* for now, treat multicast as broadcast */
	      multi_bcast (m, &m->top.c2.buf, NULL);
	    }
	  else
	    {
	      m->pending = multi_get_instance_by_virtual_addr (m, &dest, dev_type == DEV_TYPE_TUN);
	      if (m->pending)
		{
		  /* get instance context */
		  c = &m->pending->context;
		  
		  set_prefix (m->pending);

		  /* transfer packet pointer from top-level context buffer to instance */
		  c->c2.buf = m->top.c2.buf;
     
		  /* encrypt in instance context */
		  process_incoming_tun (c);
	      
		  /* postprocess and set wakeup */
		  ret = multi_process_post (m, m->pending, mpp_flags);

		  clear_prefix ();
		}
	    }
	}
    }
  gc_free (&gc);
  return ret;
}

/*
 * Process a possible client-to-client/bcast/mcast message in the
 * queue.
 */
struct multi_instance *
multi_get_queue (struct mbuf_set *ms)
{
  struct mbuf_item item;

  if (mbuf_extract_item (ms, &item)) /* cleartext IP packet */
    {
      unsigned int pipv4_flags = PIPV4_PASSTOS;

      set_prefix (item.instance);
      item.instance->context.c2.buf = item.buffer->buf;
      if (item.buffer->flags & MF_UNICAST) /* --mssfix doesn't make sense for broadcast or multicast */
	pipv4_flags |= PIPV4_MSSFIX;
      process_ipv4_header (&item.instance->context, pipv4_flags, &item.instance->context.c2.buf);
      encrypt_sign (&item.instance->context, true);
      mbuf_free_buf (item.buffer);

#ifdef MULTI_DEBUG
      msg (D_MULTI_DEBUG, "MULTI: C2C/MCAST/BCAST");
#endif
      clear_prefix ();
      return item.instance;
    }
  else
    {
      return NULL;
    }
}

/*
 * Called when an I/O wait times out.  Usually means that a particular
 * client instance object needs timer-based service.
 */
bool
multi_process_timeout (struct multi_context *m, const unsigned int mpp_flags)
{
  bool ret = true;

#ifdef MULTI_DEBUG_EVENT_LOOP
  printf ("%s -> TIMEOUT\n", id(m->earliest_wakeup));
#endif

  /* instance marked for wakeup? */
  if (m->earliest_wakeup)
    {
      set_prefix (m->earliest_wakeup);
      ret = multi_process_post (m, m->earliest_wakeup, mpp_flags);
      m->earliest_wakeup = NULL;
      clear_prefix ();
    }
  return ret;
}

/*
 * Process timers in the top-level context
 */
void
multi_process_per_second_timers_dowork (struct multi_context *m)
{
  /* possibly reap instances/routes in vhash */
  multi_reap_process (m);

  /* possibly print to status log */
  if (m->top.c1.status_output)
    {
      if (status_trigger (m->top.c1.status_output))
	multi_print_status (m, m->top.c1.status_output);
    }
}

void
multi_top_init (struct multi_context *m, const struct context *top)
{
  inherit_context_top (&m->top, top);
  m->top.c2.buffers = init_context_buffers (&top->c2.frame);
}

void
multi_top_free (struct multi_context *m)
{
  close_context (&m->top, -1, CC_GC_FREE);
  free_context_buffers (m->top.c2.buffers);
}

/*
 * Top level event loop.
 */
void
tunnel_server (struct context *top)
{
  ASSERT (top->options.mode == MODE_SERVER);

  switch (top->options.proto) {
  case PROTO_UDPv4:
    tunnel_server_udp (top);
    break;
  case PROTO_TCPv4_SERVER:
    tunnel_server_tcp (top);
    break;
  default:
    ASSERT (0);
  }
}

#else
static void dummy(void) {}
#endif /* P2MP */
