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

#ifndef MROUTE_H
#define MROUTE_H

#if P2MP

#include "buffer.h"
#include "list.h"

struct mroute_list {
};

/*
 * Choose the largest address possible with
 * any of our supported types, which is IPv6
 * with port number.
 */
#define MR_MAX_ADDR_LEN 18

/*
 * Address Types
 */
#define MR_ADDR_NONE             0
#define MR_ADDR_ETHER            1
#define MR_ADDR_IPV4             2
#define MR_ADDR_IPV6             3
#define MR_ADDR_MASK             3

/* Address type mask indicating that port # is part of address */
#define MR_WITH_PORT             4

struct mroute_addr {
  uint8_t type;
  uint8_t len;
  uint8_t addr[MR_MAX_ADDR_LEN];
};

struct mroute_list {
  struct mroute_addr addr;
};

bool mroute_extract_addr_from_packet (struct mroute_addr *addr, const struct buffer *buf, int tunnel_type, bool dest);
bool mroute_extract_sockaddr_in (struct mroute_addr *addr, const struct sockaddr_in *saddr, bool use_port);

void mroute_list_init (struct mroute_list *list);
void mroute_list_free (struct mroute_list *list);

static inline bool
mroute_addr_equal (const struct mroute_addr *a1, const struct mroute_addr *a2)
{
  if (a1->type != a2->type)
    return false;
  if (a1->len != a2->len)
    return false;
  return memcmp (a1->addr, a2->addr, a1->len) == 0;
}

#endif /* P2MP */
#endif /* MROUTE_H */
