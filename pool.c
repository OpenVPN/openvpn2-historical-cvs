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

#include "memdbg.h"

#if P2MP

struct ifconfig_pool *
ifconfig_pool_init (int type, in_addr_t start, in_addr_t end)
{
  struct gc_arena gc = gc_new ();
  struct ifconfig_pool *pool = NULL;

  ASSERT (start <= end && end - start < IFCONFIG_POOL_MAX);
  ALLOC_OBJ (pool, struct ifconfig_pool);

  mutex_init (&pool->mutex);
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

  ALLOC_ARRAY_CLEAR (pool->in_use, uint8_t, pool->size);

  msg (D_IFCONFIG_POOL, "IFCONFIG POOL: base=%s size=%d",
       print_in_addr_t (pool->base, false, &gc),
       pool->size);

  gc_free (&gc);
  return pool;
}

void
ifconfig_pool_free (struct ifconfig_pool *pool)
{
  if (pool)
    {
      free (pool->in_use);
      mutex_destroy (&pool->mutex);
      free (pool);
    }
}

ifconfig_pool_handle
ifconfig_pool_acquire (struct ifconfig_pool *pool, in_addr_t *local, in_addr_t *remote)
{
  ifconfig_pool_handle i;
  int ret = -1;

  mutex_lock (&pool->mutex);
  for (i = 0; i < pool->size; ++i)
    {
      if (!pool->in_use[i])
	{
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
	  pool->in_use[i] = true;
	  ret = i;
	  break;
	}
    }
  mutex_unlock (&pool->mutex);
  return ret;
}

bool
ifconfig_pool_release (struct ifconfig_pool* pool, ifconfig_pool_handle hand)
{
  bool ret = false;
  mutex_lock (&pool->mutex);
  if (pool && hand >= 0 && hand < pool->size)
    {
      pool->in_use[hand] = false;
      ret = true;;
    }
  mutex_unlock (&pool->mutex);
  return ret;
}

#ifdef IFCONFIG_POOL_TEST

void
ifconfig_pool_test (in_addr_t start, in_addr_t end)
{
  struct gc_arena gc = gc_new ();
  struct ifconfig_pool *p = ifconfig_pool_init (start, end);
  ifconfig_pool_handle array[256];
  int i;

  CLEAR (array);

  msg (M_INFO | M_NOPREFIX, "************ 1");
  for (i = 0; i < (int) SIZE (array); ++i)
    {
      ifconfig_pool_handle h;
      in_addr_t local, remote;
      h = ifconfig_pool_acquire_30_net (p, &local, &remote);
      if (h < 0)
	break;
      msg (M_INFO | M_NOPREFIX, "IFCONFIG_POOL TEST pass 1: l=%s r=%s",
	   print_in_addr_t (local, false, &gc),
	   print_in_addr_t (remote, false, &gc));
      array[i] = h;
      
    }

  msg (M_INFO | M_NOPREFIX, "************* 2");
  for (i = (int) SIZE (array) / 16; i < (int) SIZE (array) / 8; ++i)
    {
      msg (M_INFO, "Attempt to release %d", array[i]);
      if (!ifconfig_pool_release (p, array[i]))
	break;
      msg (M_INFO, "Suceeded");
    }

  CLEAR (array);

  msg (M_INFO | M_NOPREFIX, "**************** 3");
  for (i = 0; i < (int) SIZE (array); ++i)
    {
      ifconfig_pool_handle h;
      in_addr_t local, remote;
      h = ifconfig_pool_acquire_30_net (p, &local, &remote);
      if (h < 0)
	break;
      msg (M_INFO | M_NOPREFIX, "IFCONFIG_POOL TEST pass 3: l=%s r=%s",
	   print_in_addr_t (local, false, &gc),
	   print_in_addr_t (remote, false, &gc));
      array[i] = h;
      
    }

  gc_free (&gc);
}

#endif

#endif
