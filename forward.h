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

#ifndef FORWARD_H
#define FORWARD_H

#include "openvpn.h"
#include "occ.h"
#include "ping.h"

void pre_select (struct context *c);

void single_select (struct context *c);

void process_io (struct context *c);

void encrypt_sign (struct context *c, bool comp_frag);

const char *select_status_string (struct context *c, struct gc_arena *gc);
void show_select_status (struct context *c);

void read_incoming_link (struct context *c);
void process_incoming_link (struct context *c);
void read_incoming_tun (struct context *c);
void process_incoming_tun (struct context *c);
void process_outgoing_link (struct context *c);
void process_outgoing_tun (struct context *c);

bool send_control_channel_string (struct context *c, char *str);

#endif /* FORWARD_H */
