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

/* Maximum number of clients */
#define MULTI_N_INSTANCE 10

struct multi_instance {
  bool defined;
  struct mroute_list real;
  struct mroute_list virtual;
  struct context context;
};

struct multi_context {
  struct multi_instance *link_out;
  struct multi_instance *tun_out;
  struct multi_instance *array;
};

void multi_init (struct multi_context *m, struct context *t);
void multi_select (struct multi_context *m, struct context *t);
void multi_print_status (struct multi_context *m, struct context *t);
void multi_process_io (struct multi_context *m, struct context *t);
void multi_process_timeout (struct multi_context *m, struct context *t);
void multi_uninit (struct multi_context *m);

void multi_get_timeout (struct multi_context *m, struct timeval *tv, time_t current);

#endif /* P2MP */
#endif /* MULTI_H */
