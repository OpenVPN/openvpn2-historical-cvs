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

#ifndef POOL_H
#define POOL_H

#if P2MP

/*#define IFCONFIG_POOL_TEST*/

#include "basic.h"

#define IFCONFIG_POOL_MAX 65536

struct ifconfig_pool
{
  in_addr_t base;
  int size;
  uint8_t *in_use;
};

typedef int ifconfig_pool_handle;

struct ifconfig_pool *ifconfig_pool_init (in_addr_t start, in_addr_t end);

void ifconfig_pool_free (struct ifconfig_pool *pool);

ifconfig_pool_handle ifconfig_pool_acquire_30_net (struct ifconfig_pool *pool, in_addr_t *local, in_addr_t *remote);

bool ifconfig_pool_release (struct ifconfig_pool* pool, ifconfig_pool_handle hand);

#ifdef IFCONFIG_POOL_TEST
void ifconfig_pool_test (in_addr_t start, in_addr_t end);
#endif

#endif
#endif
