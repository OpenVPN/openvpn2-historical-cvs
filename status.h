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

#ifndef STATUS_H
#define STATUS_H

#include "interval.h"

/*
 * printf-style interface for outputting status info
 */

struct status_output
{
  char *filename;
  int fd;
  int msglevel;
  struct event_timeout et;
};

struct status_output *status_open (const char *filename, int refresh_freq, int msglevel);
bool status_trigger_tv (struct status_output *so, struct timeval *tv);
bool status_trigger (struct status_output *so);
void status_reset (struct status_output *so);
void status_flush (struct status_output *so);
void status_close (struct status_output *so);
void status_printf (struct status_output *so, const char *format, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)))
#endif
    ;

#endif
