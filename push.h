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

#ifndef PUSH_H
#define PUSH_H

#if P2MP

#include "forward.h"

#define PUSH_MSG_ERROR     0
#define PUSH_MSG_REQUEST   1
#define PUSH_MSG_REPLY     2

int process_incoming_push_msg (struct context *c,
			       struct buffer *buf,
			       bool honor_received_options,
			       unsigned int permission_mask,
			       int *option_types_found);

void push_option (struct options *o, const char *opt, int msglevel);

bool send_push_request (struct context *c);
bool send_push_reply (struct context *c);

#endif
#endif
