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

#ifndef INIT_H
#define INIT_H

#include "openvpn.h"

void context_clear (struct context *c);
void context_clear_1 (struct context *c);
void context_clear_2 (struct context *c);
void context_init_1 (struct context *c);
void context_clear_all_except_first_time (struct context *c);

bool init_static (void);

void uninit_static (void);

void init_verb_mute (const struct options *options);

void init_options_dev (struct options *options);

bool print_openssl_info (const struct options *options);

bool do_genkey (const struct options *options);

bool do_persist_tuntap (const struct options *options);

void pre_setup (const struct options *options);

void init_instance (struct context *c);

void do_route (const struct options *options, struct route_list *route_list);

bool do_open_tun (const struct options *options,
		  struct frame *frame,
		  struct link_socket *link_socket,
		  struct tuntap *tuntap, struct route_list *route_list);

void close_instance (struct context *c);

bool do_test_crypto (const struct options *o);

void context_gc_detach (struct context *c, bool options_only);
void context_gc_free (struct context *c);

void inherit_buffers (struct context *dest, const struct context *src);

#endif
