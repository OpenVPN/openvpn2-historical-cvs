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

#include "pool.h"
#include "buffer.h"
#include "error.h"
#include "socket.h"
#include "otime.h"

#include "memdbg.h"

#if P2MP

static void
ifconfig_pool_entry_free (struct ifconfig_pool_entry *ipe, bool hard)
{
  ipe->in_use = false;
  if (hard && ipe->common_name)
    {
      free (ipe->common_name);
      ipe->common_name = NULL;
    }
  if (hard)
    ipe->last_release = 0;
  else
    ipe->last_release = now;
}

static int
ifconfig_pool_find (struct ifconfig_pool *pool, const char *common_name)
{
  int i;
  int n = 0;
  time_t earliest_release = 0;
  int previous_usage = -1;
  int new_usage = -1;

  for (i = 0; i < pool->size; ++i)
    {
      struct ifconfig_pool_entry *ipe = &pool->list[i];
      if (!ipe->in_use)
	{
	  /*
	   * Keep track of the unused IP address entry which
	   * was released earliest.
	   */
	  if (!n || ipe->last_release < earliest_release)
	    {
	      earliest_release = ipe->last_release;
	      new_usage = i;
	    }

	  /*
	   * Keep track of a possible allocation to us
	   * from an earlier session.
	   */
	  if (previous_usage < 0
	      && common_name
	      && ipe->common_name
	      && !strcmp (common_name, ipe->common_name))
	    previous_usage = i;

	  ++n;
	}
    }

  if (previous_usage >= 0)
    return previous_usage;

  if (new_usage >= 0)
    return new_usage;

  return -1;
}


struct ifconfig_pool *
ifconfig_pool_init (int type, in_addr_t start, in_addr_t end)
{
  struct gc_arena gc = gc_new ();
  struct ifconfig_pool *pool = NULL;

  ASSERT (start <= end && end - start < IFCONFIG_POOL_MAX);
  ALLOC_OBJ (pool, struct ifconfig_pool);

  pool->type = type;

  switch (type)
    {
    case IFCONFIG_POOL_30NET:
      pool->base = start & ~3;
      pool->size = (((end | 3) + 1) - pool->base) >> 2;
      break;
    case IFCONFIG_POOL_INDIV:
      pool->base = start;
      pool->size = end - start + 1;
      break;
    default:
      ASSERT (0);
    }

  ALLOC_ARRAY_CLEAR (pool->list, struct ifconfig_pool_entry, pool->size);

  msg (D_IFCONFIG_POOL, "IFCONFIG POOL: base=%s size=%d",
       print_in_addr_t (pool->base, 0, &gc),
       pool->size);

  gc_free (&gc);
  return pool;
}

void
ifconfig_pool_free (struct ifconfig_pool *pool)
{
  if (pool)
    {
      int i;
      for (i = 0; i < pool->size; ++i)
	ifconfig_pool_entry_free (&pool->list[i], true);
      free (pool->list);
      free (pool);
    }
}

ifconfig_pool_handle
ifconfig_pool_acquire (struct ifconfig_pool *pool, in_addr_t *local, in_addr_t *remote, const char *common_name)
{
  int i;

  i = ifconfig_pool_find (pool, common_name);
  if (i >= 0)
    {
      struct ifconfig_pool_entry *ipe = &pool->list[i];
      ASSERT (!ipe->in_use);
      ifconfig_pool_entry_free (ipe, true);
      ipe->in_use = true;
      if (common_name)
	ipe->common_name = string_alloc (common_name, NULL);

      switch (pool->type)
	{
	case IFCONFIG_POOL_30NET:
	  {
	    in_addr_t b = pool->base + (i << 2);
	    *local = b + 1;
	    *remote = b + 2;
	    break;
	  }
	case IFCONFIG_POOL_INDIV:
	  {
	    in_addr_t b = pool->base + i;
	    *local = 0;
	    *remote = b;
	    break;
	  }
	default:
	  ASSERT (0);
	}
    }
  return i;
}

bool
ifconfig_pool_release (struct ifconfig_pool* pool, ifconfig_pool_handle hand)
{
  bool ret = false;
  if (pool && hand >= 0 && hand < pool->size)
    {
      ifconfig_pool_entry_free (&pool->list[hand], false);
      ret = true;
    }
  return ret;
}

#ifdef IFCONFIG_POOL_TEST

void
ifconfig_pool_test (in_addr_t start, in_addr_t end)
{
  struct gc_arena gc = gc_new ();
  struct ifconfig_pool *p = ifconfig_pool_init (IFCONFIG_POOL_30NET, start, end); 
  //struct ifconfig_pool *p = ifconfig_pool_init (IFCONFIG_POOL_INDIV, start, end);
  ifconfig_pool_handle array[256];
  int i;

  CLEAR (array);

  msg (M_INFO | M_NOPREFIX, "************ 1");
  for (i = 0; i < (int) SIZE (array); ++i)
    {
      ifconfig_pool_handle h;
      in_addr_t local, remote;
      char buf[256];
      openvpn_snprintf (buf, sizeof(buf), "common-name-%d", i); 
      h = ifconfig_pool_acquire (p, &local, &remote, buf);
      if (h < 0)
	break;
      msg (M_INFO | M_NOPREFIX, "IFCONFIG_POOL TEST pass 1: l=%s r=%s cn=%s",
	   print_in_addr_t (local, 0, &gc),
	   print_in_addr_t (remote, 0, &gc),
	   buf);
      array[i] = h;
      
    }

  msg (M_INFO | M_NOPREFIX, "************* 2");
  for (i = (int) SIZE (array) / 16; i < (int) SIZE (array) / 8; ++i)
    {
      msg (M_INFO, "Attempt to release %d cn=%s", array[i], p->list[i].common_name);
      if (!ifconfig_pool_release (p, array[i]))
	break;
      msg (M_INFO, "Succeeded");
    }

  CLEAR (array);

  msg (M_INFO | M_NOPREFIX, "**************** 3");
  for (i = 0; i < (int) SIZE (array); ++i)
    {
      ifconfig_pool_handle h;
      in_addr_t local, remote;
      char buf[256];
      snprintf (buf, sizeof(buf), "common-name-%d", i+24); 
      h = ifconfig_pool_acquire (p, &local, &remote, buf);
      if (h < 0)
	break;
      msg (M_INFO | M_NOPREFIX, "IFCONFIG_POOL TEST pass 3: l=%s r=%s cn=%s",
	   print_in_addr_t (local, 0, &gc),
	   print_in_addr_t (remote, 0, &gc),
	   buf);
      array[i] = h;
      
    }

  ifconfig_pool_free (p);
  gc_free (&gc);
}

#endif

#endif
