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

#include "forward-inline.h"

#define MULTI_DEBUG // JYFIXME

/*
 * Reaper constants.  The reaper is the process where the virtual address
 * and virtual route hash table is scanned for dead entries which are
 * then removed.  The hash table could potentially be quite large, so we
 * don't want to reap in a single pass.
 */
#define REAP_MAX_WAKEUP   10  /* Do reap pass at least once per n seconds */
#define REAP_DIVISOR     256  /* How many passes to cover whole hash table */
#define REAP_MIN          16  /* Minimum number of buckets per pass */
#define REAP_MAX        1024  /* Maximum number of buckets per pass */

/*
 * Mark a cached host route for deletion after this
 * many seconds without any references.
 */
#define MULTI_CACHE_ROUTE_TTL 60

static bool multi_process_post (struct multi_thread *mt, struct multi_instance *mi);

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

static void
multi_reap_process_dowork (const struct multi_context *m)
{
  struct multi_reap *mr = m->reaper;
  if (mr->bucket_base >= hash_n_buckets (m->vhash))
    mr->bucket_base = 0;
  multi_reap_range (m, mr->bucket_base, mr->bucket_base + mr->buckets_per_pass); 
  mr->bucket_base += mr->buckets_per_pass;
  mr->last_call = now;
}

static inline void
multi_reap_process (const struct multi_context *m)
{
  if (m->reaper->last_call != now)
    multi_reap_process_dowork (m);
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
static void
multi_init (struct multi_context *m, struct context *t)
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

/*
 * Set a msg() function prefix with our current client instance ID.
 */

static inline void
set_prefix (struct multi_instance *mi)
{
  msg_set_prefix (mi->msg_prefix);
}

static inline void
clear_prefix (void)
{
  msg_set_prefix (NULL);
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

static void
multi_close_instance (struct multi_context *m,
		      struct multi_instance *mi,
		      bool shutdown)
{
  mi->halt = true;

  msg (D_MULTI_LOW, "MULTI: multi_close_instance called");

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
    {
      close_context (&mi->context, SIGTERM);
    }

  ungenerate_prefix (mi);

  /*
   * Don't actually delete the instance memory allocation yet,
   * because virtual routes may still point to it.  Let the
   * vhash reaper deal with it.
   */
  multi_instance_dec_refcount (mi);
}

/*
 * Called on shutdown or restart.
 */
static void
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
    }
}

/*
 * Create a client instance object for a newly connected client.
 */
static struct multi_instance *
multi_create_instance (struct multi_thread *mt, const struct mroute_addr *real)
{
  struct gc_arena gc = gc_new ();
  struct multi_instance *mi;

  ALLOC_OBJ_CLEAR (mi, struct multi_instance);

  msg (D_MULTI_LOW, "MULTI: multi_create_instance called");

  mi->gc = gc_new ();
  multi_instance_inc_refcount (mi);
  mroute_addr_init (&mi->real);
  mi->vaddr_handle = -1;
  mi->created = now;

  mi->real = *real;
  generate_prefix (mi);

  if (!hash_add (mt->multi->iter, &mi->real, mi, false))
    {
      msg (D_MULTI_LOW, "MULTI: unable to add real address [%s] to iterator hash table",
	   mroute_addr_print (&mi->real, &gc));
      goto err;
    }
  mi->did_iter = true;

  inherit_context_child (&mi->context, &mt->top);
  mi->did_open_context = true;

  if (!multi_process_post (mt, mi))
    {
      msg (D_MULTI_ERRORS, "MULTI: signal occurred during client instance initialization");
      goto err;
    }

  gc_free (&gc);
  return mi;

 err:
  multi_close_instance (mt->multi, mi, false);
  gc_free (&gc);
  return NULL;
}

/*
 * Get a client instance based on real address.  If
 * the instance doesn't exist, create it while
 * maintaining real address hash table atomicity.
 */
static struct multi_instance *
multi_get_create_instance (struct multi_thread *mt)
{
  struct gc_arena gc = gc_new ();
  struct mroute_addr real;
  struct multi_instance *mi = NULL;
  struct hash *hash = mt->multi->hash;

  if (mroute_extract_sockaddr_in (&real, &mt->top.c2.from, true))
    {
      struct hash_element *he;
      const uint32_t hv = hash_value (hash, &real);
      struct hash_bucket *bucket = hash_bucket (hash, hv);
  
      hash_bucket_lock (bucket);
      he = hash_lookup_fast (hash, bucket, &real, hv);

      if (he)
	{
	  mi = (struct multi_instance *) he->value;
	}
      else
	{
	  if (frequency_limit_event_allowed (mt->multi->new_connection_limiter))
	    {
	      mi = multi_create_instance (mt, &real);
	      if (mi)
		{
		  hash_add_fast (hash, bucket, &mi->real, hv, mi);
		  mi->did_real_hash = true;
		}
	    }
	  else
	    {
	      msg (D_MULTI_ERRORS,
		   "MULTI: Connection from %s would exceed new connection frequency limit as controlled by --connect-freq",
		   mroute_addr_print (&real, &gc));
	    }
	}

      hash_bucket_unlock (bucket);

#ifdef MULTI_DEBUG
      if (check_debug_level (D_MULTI_DEBUG))
	{
	  const char *status;

	  if (he && mi)
	    status = "[succeeded]";
	  else if (!he && mi)
	    status = "[created]";
	  else
	    status = "[failed]";
	
	  msg (D_MULTI_DEBUG, "GET INST BY REAL: %s %s",
	       mroute_addr_print (&real, &gc),
	       status);
	}
#endif
    }

  gc_free (&gc);
  return mi;
}

/*
 * Dump tables -- triggered by SIGUSR2.
 */
static void
multi_print_status (struct multi_context *m)
{
  if (m->hash)
    {
      struct hash_iterator hi;
      const struct hash_element *he;

      msg (M_INFO, "CLIENT LIST");
      msg (M_INFO, "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since");
      hash_iterator_init (m->hash, &hi, true);
      while ((he = hash_iterator_next (&hi)))
	{
	  struct gc_arena gc = gc_new ();
	  const struct multi_instance *mi = (struct multi_instance *) he->value;

	  if (!mi->halt)
	    {
	      msg (M_INFO, "%s,%s," counter_format_simple "," counter_format_simple ",%s",
		   tls_common_name (mi->context.c2.tls_multi, false),
		   mroute_addr_print (&mi->real, &gc),
		   mi->context.c2.link_read_bytes,
		   mi->context.c2.link_write_bytes,
		   time_string (mi->created, 0, false, &gc));
	    }
	  gc_free (&gc);
	}
      hash_iterator_free (&hi);

      msg (M_INFO, "ROUTING TABLE");
      msg (M_INFO, "Virtual Address,Common Name,Real Address,Last Ref");
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
	      msg (M_INFO, "%s%s,%s,%s,%s",
		   mroute_addr_print (ma, &gc),
		   flags,
		   tls_common_name (mi->context.c2.tls_multi, false),
		   mroute_addr_print (&mi->real, &gc),
		   time_string (route->last_reference, 0, false, &gc));
	    }
	  gc_free (&gc);
	}
      hash_iterator_free (&hi);

      msg (M_INFO, "GLOBAL STATS");
      msg (M_INFO, "Max bcast/mcast queue length: %d",
	   mbuf_maximum_queued (m->mbuf));
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
	}
      else
	{
	  /* add new route */
	  hash_add_fast (m->vhash, bucket, &newroute->addr, hv, newroute);
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
	     print_in_addr_t (ir->network, false, &gc),
	     ir->netbits,
	     multi_instance_string (mi, false, &gc));
      else
	msg (D_MULTI_LOW, "MULTI: internal route %s -> %s",
	     print_in_addr_t (ir->network, false, &gc),
	     multi_instance_string (mi, false, &gc));

      mroute_helper_add_iroute (m->route_helper, ir);
      multi_learn_in_addr_t (m, mi, ir->network, ir->netbits);
    }
  gc_free (&gc);
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

  /* acquire script mutex */
  mutex_lock_static (L_SCRIPT);

  /* generate a msg() prefix for this client instance */
  generate_prefix (mi);

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
	      mi->context.c2.push_ifconfig_remote_netmask = mi->context.c1.tuntap->remote_netmask;
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
	       print_in_addr_t (mi->context.c2.push_ifconfig_local, false, &gc));
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
multi_get_timeout (struct multi_thread *mt, struct timeval *dest)
{
  struct timeval tv, current;

  mt->earliest_wakeup = (struct multi_instance *) schedule_get_earliest_wakeup (mt->multi->schedule, &tv);
  if (mt->earliest_wakeup)
    {
      ASSERT (!gettimeofday (&current, NULL));
      tv_delta (dest, &current, &tv);
      if (dest->tv_sec >= REAP_MAX_WAKEUP)
	{
	  mt->earliest_wakeup = NULL;
	  dest->tv_sec = REAP_MAX_WAKEUP;
	  dest->tv_usec = 0;
	}
    }
  else
    {
      dest->tv_sec = REAP_MAX_WAKEUP;
      dest->tv_usec = 0;
    }
}

/*
 * Wait for an event.
 */
static void
multi_select (struct multi_thread *mt)
{
  /*
   * Set up for select call.
   *
   * Decide what kind of events we want to wait for.
   */
  wait_reset (&mt->top.c2.event_wait);

  /*
   * On win32 we use the keyboard or an event object as a source
   * of asynchronous signals.
   */
  WAIT_SIGNAL (&mt->top.c2.event_wait);

  /*
   * If outgoing data (for TCP/UDP port) pending, wait for ready-to-send
   * status from TCP/UDP port. Otherwise, wait for incoming data on
   * TUN/TAP device.
   */
  if (mt->link_out)
    {
      SOCKET_SET_WRITE (&mt->top.c2.event_wait, mt->top.c2.link_socket);
    }
  else
    {
      TUNTAP_SET_READ (&mt->top.c2.event_wait, mt->top.c1.tuntap);
    }

  /*
   * outgoing bcast buffer is waiting to be sent
   */
  if (mbuf_defined (mt->multi->mbuf))
    {
      SOCKET_SET_WRITE (&mt->top.c2.event_wait, mt->top.c2.link_socket);
    }

  /*
   * If outgoing data (for TUN/TAP device) pending, wait for ready-to-send status
   * from device.  Otherwise, wait for incoming data on TCP/UDP port.
   */
  if (mt->tun_out)
    {
      TUNTAP_SET_WRITE (&mt->top.c2.event_wait, mt->top.c1.tuntap);
    }
  else
    {
      SOCKET_SET_READ (&mt->top.c2.event_wait, mt->top.c2.link_socket);
    }

  /*
   * Wait for something to happen.
   */
  mt->top.c2.select_status = 1;	/* this will be our return "status" if select doesn't get called */
  if (!mt->top.sig->signal_received)
    {
      multi_get_timeout (mt, &mt->top.c2.timeval);
      if (check_debug_level (D_SELECT))
	show_select_status (&mt->top);
      mt->top.c2.select_status = SELECT (&mt->top.c2.event_wait, &mt->top.c2.timeval);
      check_status (mt->top.c2.select_status, "multi-select", NULL, NULL);
    }

  update_time ();

  /* set signal_received if a signal was received */
  SELECT_SIGNAL_RECEIVED (&mt->top.c2.event_wait, mt->top.sig->signal_received);
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
static bool
multi_process_post (struct multi_thread *mt, struct multi_instance *mi)
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
	  schedule_add_entry (mt->multi->schedule,
			      (struct schedule_entry *) mi,
			      &mi->wakeup,
			      compute_wakeup_sigma (&mi->context.c2.timeval));

	  /* connection is "established" when SSL/TLS key negotiation succeeds */
	  if (!mi->connection_established_flag && CONNECTION_ESTABLISHED (&mi->context))
	    {
	      multi_connection_established (mt->multi, mi);
	      mi->connection_established_flag = true;
	    }
	}
    }
  if (IS_SIG (&mi->context))
    {
      /* make sure that link_out or tun_out is nullified if
	 it points to our soon-to-be-deleted instance */
      if (mt->link_out == mi)
	mt->link_out = NULL;
      if (mt->tun_out == mi)
	mt->tun_out = NULL;
      multi_close_instance (mt->multi, mi, false);
      return false;
    }
  else
    {
      /* did pre_select produce any to_link or to_tun output packets? */
      if (mt->link_out)
	{
	  if (!BLEN (&mi->context.c2.to_link))
	    mt->link_out = NULL;
	}
      else
	{
	  if (BLEN (&mi->context.c2.to_link))
	    mt->link_out = mi;
	}
      if (mt->tun_out)
	{
	  if (!BLEN (&mi->context.c2.to_tun))
	    mt->tun_out = NULL;
	}
      else
	{
	  if (BLEN (&mi->context.c2.to_tun))
	    mt->tun_out = mi;
	}
      return true;
    }
}

/*
 * Process packets in the TCP/UDP socket -> TUN/TAP interface direction,
 * i.e. client -> server direction.
 */
static void
multi_process_incoming_link (struct multi_thread *mt)
{
  if (BLEN (&mt->top.c2.buf) > 0)
    {
      struct context *c;
      struct mroute_addr src, dest;
      unsigned int mroute_flags;
      struct multi_instance *mi;
      struct multi_context *m = mt->multi;

      ASSERT (!mt->tun_out);

      mt->tun_out = multi_get_create_instance (mt);
      if (!mt->tun_out)
	return;

      set_prefix (mt->tun_out);

      /* get instance context */
      c = &mt->tun_out->context;

      /* transfer packet pointer from top-level context buffer to instance */
      c->c2.buf = mt->top.c2.buf;

      /* transfer from-addr from top-level context buffer to instance */
      c->c2.from = mt->top.c2.from;

      /* decrypt in instance context */
      process_incoming_link (c);

      if (TUNNEL_TYPE (mt->top.c1.tuntap) == DEV_TYPE_TUN)
	{
	  /* extract packet source and dest addresses */
	  mroute_flags = mroute_extract_addr_from_packet (&src,
							  &dest,
							  &c->c2.to_tun,
							  DEV_TYPE_TUN);

	  /* drop packet if extract failed */
	  if (!(mroute_flags & MROUTE_EXTRACT_SUCCEEDED))
	    {
	      msg (D_MULTI_DEBUG, "MULTI: badly formed packet from client, packet dropped");
	      c->c2.to_tun.len = 0;
	    }
	  /* make sure that source address is associated with this client */
	  else if (multi_get_instance_by_virtual_addr (m, &src, true) != mt->tun_out)
	    {
	      msg (D_MULTI_DEBUG, "MULTI: bad source address from client, packet dropped");
	      c->c2.to_tun.len = 0;
	    }
	  /* client-to-client communication enabled? */
	  else if (m->enable_c2c)
	    {
	      /* multicast? */
	      if (mroute_flags & MROUTE_EXTRACT_MCAST)
		{
		  /* for now, treat multicast as broadcast */
		  multi_bcast (m, &c->c2.to_tun, mt->tun_out);
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
      else if (TUNNEL_TYPE (mt->top.c1.tuntap) == DEV_TYPE_TAP)
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
		      multi_bcast (m, &c->c2.to_tun, mt->tun_out);
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
	      multi_learn_addr (m, mt->tun_out, &src, 0);
	    }
	}
      
      /* postprocess and set wakeup */
      multi_process_post (mt, mt->tun_out);

      clear_prefix ();
    }
}

/*
 * Process packets in the TUN/TAP interface -> TCP/UDP socket direction,
 * i.e. server -> client direction.
 */
static void
multi_process_incoming_tun (struct multi_thread *mt)
{
  struct multi_context *m = mt->multi;
  if (BLEN (&mt->top.c2.buf) > 0)
    {
      unsigned int mroute_flags;
      struct mroute_addr src, dest;
      const int dev_type = TUNNEL_TYPE (mt->top.c1.tuntap);

      ASSERT (!mt->link_out);

      /* 
       * Route an incoming tun/tap packet to
       * the appropriate multi_instance object.
       */

      mroute_flags = mroute_extract_addr_from_packet (&src,
						      &dest,
						      &mt->top.c2.buf,
						      dev_type);

      if (mroute_flags & MROUTE_EXTRACT_SUCCEEDED)
	{
	  struct context *c;

	  /* broadcast or multicast dest addr? */
	  if (mroute_flags & (MROUTE_EXTRACT_BCAST|MROUTE_EXTRACT_MCAST))
	    {
	      /* for now, treat multicast as broadcast */
	      multi_bcast (m, &mt->top.c2.buf, NULL);
	    }
	  else
	    {
	      mt->link_out = multi_get_instance_by_virtual_addr (m, &dest, dev_type == DEV_TYPE_TUN);
	      if (mt->link_out)
		{
		  set_prefix (mt->link_out);

		  /* get instance context */
		  c = &mt->link_out->context;

		  /* transfer packet pointer from top-level context buffer to instance */
		  c->c2.buf = mt->top.c2.buf;
     
		  /* encrypt in instance context */
		  process_incoming_tun (c);
	      
		  /* postprocess and set wakeup */
		  multi_process_post (mt, mt->link_out);

		  clear_prefix ();
		}
	    }
	}
    }
}

/*
 * Process a possible client-to-client/bcast/mcast message in the
 * queue.
 */
static inline struct multi_instance *
multi_bcast_instance (struct multi_context *m)
{
  struct mbuf_item item;
  if (mbuf_extract_item_lock (m->mbuf, &item, true))
    {
      set_prefix (item.instance);

      item.instance->context.c2.buf = item.buffer->buf;
      encrypt_sign (&item.instance->context, true);
      mbuf_free_buf (item.buffer);
      mbuf_extract_item_unlock (m->mbuf);

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
 * Send a packet to TCP/UDP socket.
 */
static inline void
multi_process_outgoing_link (struct multi_thread *mt)
{
  struct multi_instance *mi;

  if (mt->link_out)
    {
      mi = mt->link_out;
      mt->link_out = NULL;
    }
  else
    mi = multi_bcast_instance (mt->multi);

  if (mi)
    {
      set_prefix (mi);
      process_outgoing_link (&mi->context);
      multi_process_post (mt, mi);
      clear_prefix ();
    }
}

/*
 * Send a packet to TUN/TAP interface.
 */
static inline void
multi_process_outgoing_tun (struct multi_thread *mt)
{
  struct multi_instance *mi = mt->tun_out;
  ASSERT (mi);
  set_prefix (mi);
  mt->tun_out = NULL;
  process_outgoing_tun (&mi->context);
  multi_process_post (mt, mi);
  clear_prefix ();
}

/*
 * Process an I/O event.
 */
void
multi_process_io (struct multi_thread *mt)
{
  if (mt->top.c2.select_status > 0)
    {
      /* Incoming data on TCP/UDP port */
      if (SOCKET_ISSET (&mt->top.c2.event_wait, mt->top.c2.link_socket, reads))
	{
	  read_incoming_link (&mt->top);
	  if (!IS_SIG (&mt->top))
	    multi_process_incoming_link (mt);
	}
      /* Incoming data on TUN device */
      else if (TUNTAP_ISSET (&mt->top.c2.event_wait, mt->top.c1.tuntap, reads))
	{
	  read_incoming_tun (&mt->top);
	  if (!IS_SIG (&mt->top))
	    multi_process_incoming_tun (mt);
	}
      /* TUN device ready to accept write */
      else if (TUNTAP_ISSET (&mt->top.c2.event_wait, mt->top.c1.tuntap, writes))
	{
	  multi_process_outgoing_tun (mt);
	}
      /* TCP/UDP port ready to accept write -- we put this last in the list so
         that broadcast/multicast forwards don't cause client receive starvation */
      else if (SOCKET_ISSET (&mt->top.c2.event_wait, mt->top.c2.link_socket, writes))
	{
	  multi_process_outgoing_link (mt);
	}
    }
}

/*
 * Called when an I/O wait times out.  Usually means that a particular
 * client instance object needs timer-based service.
 */
static inline void
multi_process_timeout (struct multi_thread *mt)
{
  /* instance marked for wakeup? */
  if (mt->earliest_wakeup)
    {
      set_prefix (mt->earliest_wakeup);
      multi_process_post (mt, mt->earliest_wakeup);
      mt->earliest_wakeup = NULL;
      clear_prefix ();
    }
}

/*
 * Check for signals.
 */
#define TNUS_SIG() \
  if (IS_SIG (&thread->top)) \
  { \
    if (thread->top.sig->signal_received == SIGUSR2) \
      { \
        multi_print_status (thread->multi); \
        thread->top.sig->signal_received = 0; \
        continue; \
      } \
    break; \
  }

/*
 * The idea of struct multi_thread is that multiple threads could handle
 * the event loop simultaneously.
 */

static struct multi_thread *
multi_thread_init (struct multi_context *multi, const struct context *top)
{
  struct multi_thread *thread;
  ALLOC_OBJ_CLEAR (thread, struct multi_thread);
  thread->multi = multi;
  inherit_context_thread (&thread->top, top);
  thread->context_buffers = thread->top.c2.buffers = init_context_buffers (&top->c2.frame);
  return thread;
}

static void
multi_thread_free (struct multi_thread *thread)
{
  close_context (&thread->top, -1);
  free_context_buffers (thread->context_buffers);
  free (thread);
}

/*
 * Top level event loop for single-threaded operation.
 */
void
tunnel_server_single_threaded (struct context *top)
{
  struct multi_context multi;
  struct multi_thread *thread;

  ASSERT (top->options.proto == PROTO_UDPv4
	  || top->options.proto == PROTO_TCPv4_SERVER);
  ASSERT (top->options.mode == MODE_SERVER);

  top->mode = CM_TOP;
  context_clear_2 (top);

  /* initialize top-tunnel instance */
  init_instance (top);
  if (IS_SIG (top))
    return;
  
  /* initialize global multi_context object */
  multi_init (&multi, top);

  /* initialize a single multi_thread object */
  thread = multi_thread_init (&multi, top);

  /* per-packet event loop */
  while (true)
    {
      /* set up and do the select() */
      multi_select (thread);
      TNUS_SIG ();

      /* possibly reap instances/routes in vhash */
      multi_reap_process (&multi);

      /* timeout? */
      if (!thread->top.c2.select_status)
	{
	  multi_process_timeout (thread);
	}
      else
	{
	  /* process the I/O which triggered select */
	  multi_process_io (thread);
	  TNUS_SIG ();
	}
    }

  /* tear down tunnel instance (unless --persist-tun) */
  multi_thread_free (thread);
  close_instance (top);
  multi_uninit (&multi);
  top->first_time = false;
}

#ifdef USE_PTHREAD

/*
 * NOTE: multi-threaded mode is not finished yet.
 */

void
tunnel_server_multi_threaded (struct context *top)
{
  ASSERT (top->options.n_threads >= 2);
  openvpn_thread_init ();
  tunnel_server_single_threaded (top);
  openvpn_thread_cleanup ();
}
#endif

#else
static void dummy(void) {}
#endif /* P2MP */
