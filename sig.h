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

#ifndef SIG_H
#define SIG_H

#include "status.h"

/*
 * Signal information, including signal code
 * and descriptive text.
 */
struct signal_info
{
  volatile int signal_received;
  volatile bool hard;
  const char *signal_text;
};

#define IS_SIG(c) ((c)->sig->signal_received)

struct context;

extern struct signal_info siginfo_static;

void pre_init_signal_catch (void);
void post_init_signal_catch (void);

const char *signal_description (int signum, const char *sigtext);
void print_signal (const struct signal_info *si, const char *title);
void print_status (const struct context *c, struct status_output *so);

#endif
